// Filename: src/main.rs
// IRFARP (IRan Freedom ARP) System - Monolithic Codebase
// Combines all modules into a single file for simplified deployment and resource management.
// Designed for banking-grade reliability, performance, and security,
// specifically targeting evasion of common DPI by using custom raw IP protocols
// with a focus on low-resource and cross-architecture compatibility.
// This system comprises a server component (IRFARP-Server) and a client component (IRFARP-Client).
// It implements a custom reliable, encrypted tunnel over raw IP protocols (ICMP, Custom IP, and IRP).

// --- IMPORTANT SECURITY AND RELIABILITY NOTICE ---
// This version retains the use of external, audited cryptographic libraries (`aes-gcm`, `hkdf`, `rand`)
// and a robust binary serialization library (`bincode`). This is CRITICAL for achieving
// "banking-grade security" and "99% reliability". Implementing these primitives from scratch
// is inherently insecure and unreliable for production use.
//
// Raw socket operations are OS-specific and require elevated privileges (CAP_NET_RAW on Linux).

// Standard library imports
use std::{
    collections::HashMap,
    fs::{self, File},
    io::{self, BufReader},
    net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket},
    path::Path,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

// External crate imports (crucial for security and reliability)
use aes_gcm::{
    aead::{Aead, KeyInit, Nonce},
    Aes256Gcm,
};
use async_trait::async_trait;
use base64::{engine::general_purpose, Engine as _};
use bincode::{deserialize, serialize};
use byteorder::{BigEndian, ByteOrder};
use env_logger::{Builder, Target};
use hkdf::Hkdf;
use log::{debug, error, info, trace, warn};
use rand::{rngs::OsRng, RngCore, Rng};
use sha2::Sha256;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::{mpsc, Mutex},
    time,
};

// Linux-specific imports for raw sockets
#[cfg(target_os = "linux")]
use std::os::unix::io::AsRawFd;
#[cfg(target_os = "linux")]
use libc::{setsockopt, IP_HDRINCL, IPPROTO_IP};

// --- Custom Pseudo-Random Number Generator (PRNG) for Non-Crypto Uses ---
// Used for non-security-critical values (e.g., ICMP ID/Sequence hopping).
// NOT CRYPTOGRAPHICALLY SEC “

static mut PRNG_STATE: u64 = 0;

/// Seeds the custom PRNG with a non-zero value.
fn custom_rng_seed(seed: u64) {
    unsafe {
        PRNG_STATE = if seed == 0 { 1 } else { seed }; // Ensure non-zero seed
    }
}

/// Generates the next 64-bit value from the custom PRNG.
fn custom_rng_next_u64() -> u64 {
    unsafe {
        PRNG_STATE ^= PRNG_STATE << 13;
        PRNG_STATE ^= PRNG_STATE >> 7;
        PRNG_STATE ^= PRNG_STATE << 17;
        PRNG_STATE.wrapping_mul(2685821657736338717)
    }
}

/// Generates a random u16 using the custom PRNG.
fn custom_rng_gen_u16() -> u16 {
    (custom_rng_next_u64() >> 32) as u16
}

/// Generates a random u32 using the custom PRNG.
fn custom_rng_gen_u32() -> u32 {
    custom_rng_next_u64() as u32
}

// --- Cryptographically Secure Random Number Generator (CSPRNG) ---

/// Generates N cryptographically secure random bytes using OsRng.
fn get_csprng_bytes<const N: usize>() -> [u8; N] {
    let mut bytes = [0u8; N];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

// --- Key Derivation Function (KDF) ---

/// Derives a 32-byte session key using HKDF-SHA256.
/// - `master_key`: Pre-shared key from config.
/// - `salt`: Unique nonce per session.
/// - `info`: Contextual info (e.g., "irp-session-key").
fn derive_session_key(master_key: &[u8], salt: &[u8], info: &[u8]) -> io::Result<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(Some(salt), master_key);
    let mut okm = [0u8; 32]; // 32 bytes for AES-256
    hk.expand(info, &mut okm)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("HKDF expansion failed: {}", e)))?;
    Ok(okm)
}

// --- Authenticated Encryption (AES-256-GCM) ---

/// Manages AES-256-GCM encryption and decryption.
struct IrpCipher {
    cipher: Aes256Gcm,
}

impl IrpCipher {
    /// Creates a new cipher instance with a 32-byte key.
    fn new(key: &[u8; 32]) -> Self {
        IrpCipher {
            cipher: Aes256Gcm::new(key.into()),
        }
    }

    /// Encrypts plaintext, returning ciphertext and a 12-byte nonce.
    fn encrypt(&self, plaintext: &[u8]) -> io::Result<(Vec<u8>, [u8; 12])> {
        let nonce_bytes = get_csprng_bytes::<12>();
        let nonce = Nonce::from_slice(&nonce_bytes);
        self.cipher
            .encrypt(nonce, plaintext)
            .map(|ciphertext| (ciphertext, nonce_bytes))
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Encryption failed: {}", e)))
    }

    /// Decrypts ciphertext using the provided nonce.
    fn decrypt(&self, ciphertext: &[u8], nonce_bytes: &[u8; 12]) -> io::Result<Vec<u8>> {
        let nonce = Nonce::from_slice(nonce_bytes);
        self.cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Decryption failed: {}", e)))
    }
}

// --- Constants ---

const IPV4_HEADER_SIZE: usize = 20;
const ICMP_HEADER_SIZE: usize = 8;
const MAX_IP_PAYLOAD_SIZE: usize = 1480; // Fits within typical MTU (1500 - 20 IP)
const TUNNEL_ID_SIZE: usize = 16; // Unique tunnel identifier size
const SEQUENCE_NUM_SIZE: usize = 4; // Sequence number size
const ACK_NUM_SIZE: usize = 4; // Acknowledgment number size
const FLAGS_SIZE: usize = 1; // Control flags size
const NONCE_SIZE: usize = 12; // AES-GCM nonce size
const DATA_LENGTH_SIZE: usize = 2; // Encrypted payload length size

/// Fixed size of the IRFARP header (excluding padding).
const CUSTOM_IRFARP_HEADER_SIZE: usize =
    TUNNEL_ID_SIZE + SEQUENCE_NUM_SIZE + ACK_NUM_SIZE + FLAGS_SIZE + NONCE_SIZE + DATA_LENGTH_SIZE;

// --- Custom Packet Structures ---

/// Represents IRFARP packet control flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct IrpFlags {
    syn: bool,  // Connection start
    ack: bool,  // Acknowledgment
    fin: bool,  // Connection end
    psh: bool,  // Push data
    rst: bool,  // Reset connection
    pad: bool,  // Padding present (IRP only)
}

impl IrpFlags {
    /// Creates a new flags instance with all set to false.
    fn new() -> Self {
        IrpFlags {
            syn: false,
            ack: false,
            fin: false,
            psh: false,
            rst: false,
            pad: false,
        }
    }

    /// Converts flags to a single byte.
    fn as_byte(&self) -> u8 {
        let mut byte = 0;
        if self.syn {
            byte |= 0b00000001;
        }
        if self.ack {
            byte |= 0b00000010;
        }
        if self.fin {
            byte |= 0b00000100;
        }
        if self.psh {
            byte |= 0b00001000;
        }
        if self.rst {
            byte |= 0b00010000;
        }
        if self.pad {
            byte |= 0b00100000;
        }
        byte
    }

    /// Creates flags from a byte.
    fn from_byte(byte: u8) -> Self {
        IrpFlags {
            syn: (byte & 0b00000001) != 0,
            ack: (byte & 0b00000010) != 0,
            fin: (byte & 0b00000100) != 0,
            psh: (byte & 0b00001000) != 0,
            rst: (byte & 0b00010000) != 0,
            pad: (byte & 0b00100000) != 0,
        }
    }
}

/// IRFARP packet header structure.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct IrpHeader {
    tunnel_id: [u8; TUNNEL_ID_SIZE],
    sequence_num: u32,
    ack_num: u32,
    flags: IrpFlags,
    nonce: [u8; NONCE_SIZE],
    data_len: u16,
}

/// Full IRFARP packet structure.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct IrpPacket {
    header: IrpHeader,
    padding: Vec<u8>, // Random padding for IRP obfuscation
    encrypted_payload: Vec<u8>,
}

impl IrpPacket {
    /// Creates a new IRFARP packet.
    fn new(
        tunnel_id: [u8; TUNNEL_ID_SIZE],
        sequence_num: u32,
        ack_num: u32,
        flags: IrpFlags,
        nonce: [u8; NONCE_SIZE],
        padding: Vec<u8>,
        encrypted_payload: Vec<u8>,
    ) -> Self {
        let data_len = encrypted_payload.len() as u16;
        IrpPacket {
            header: IrpHeader {
                tunnel_id,
                sequence_num,
                ack_num,
                flags,
                nonce,
                data_len,
            },
            padding,
            encrypted_payload,
        }
    }

    /// Serializes the packet to bytes.
    fn to_bytes(&self) -> io::Result<Vec<u8>> {
        serialize(self).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Failed to serialize IRP packet: {}", e),
            )
        })
    }

    /// Deserializes bytes into a packet.
    fn from_bytes(bytes: &[u8]) -> io::Result<Self> {
        deserialize(bytes).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Failed to deserialize IRP packet: {}", e),
            )
        })
    }
}

// --- Configuration Structures ---

#[derive(Debug, serde::Deserialize, serde::Serialize, Clone)]
struct ServerConfig {
    icmp_bind_addr: String,
    custom_ip_bind_addr: String,
    irp_bind_addr: String,
    services: HashMap<String, ServiceConfig>,
    log_level: String,
    metrics_interval_sec: u64,
    auth_key_base64: String,
}

#[derive(Debug, serde::Deserialize, serde::Serialize, Clone)]
struct ClientConfig {
    server_icmp_addr: String,
    server_custom_ip_addr: String,
    server_irp_addr: String,
    client_id: String,
    auth_token: String,
    local_services: HashMap<String, LocalServiceConfig>,
    log_level: String,
    protocol_pool: Vec<CovertProtocol>,
    connect_timeout_ms: u64,
    retry_delay_ms: u64,
    max_retries: u32,
    initial_rto_ms: u64,
    max_rto_ms: u64,
    irp_obfuscation_min_padding: usize,
    irp_obfuscation_max_padding: usize,
    auth_key_base64: String,
}

#[derive(Debug, serde::Deserialize, serde::Serialize, Clone)]
struct ServiceConfig {
    token: String,
    bind_addr: String,
    client_service_id: String,
}

#[derive(Debug, serde::Deserialize, serde::Serialize, Clone)]
struct LocalServiceConfig {
    local_addr: String,
}

#[derive(Debug, serde::Deserialize, serde::Serialize, Clone, PartialEq, Eq, Hash)]
#[serde(rename_all = "kebab-case")]
enum CovertProtocol {
    ICMP,
    CustomIP(u8),
    IRP,
}

impl CovertProtocol {
    /// Converts the protocol to a string representation.
    fn to_string(&self) -> String {
        match self {
            CovertProtocol::ICMP => "icmp".to_string(),
            CovertProtocol::CustomIP(p) => format!("custom-ip-{}", p),
            CovertProtocol::IRP => "irp".to_string(),
        }
    }

    /// Returns the IP protocol number.
    fn get_protocol_number(&self) -> u8 {
        match self {
            CovertProtocol::ICMP => 1,
            CovertProtocol::CustomIP(p) => *p,
            CovertProtocol::IRP => 254,
        }
    }
}

/// Loads a configuration from a JSON file.
fn load_config<T: for<'de> serde::Deserialize<'de>>(path: &str) -> io::Result<T> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let config = serde_json::from_reader(reader).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Failed to parse config: {}", e),
        )
    })?;
    info!("Loaded config from: {}", path);
    Ok(config)
}

// --- IP/ICMP Packet Manipulation ---

/// Calculates the IPv4 header checksum.
fn calculate_ipv4_checksum(header: &[u8]) -> u16 {
    let mut sum = 0u32;
    for i in (0..header.len()).step_by(2) {
        sum += BigEndian::read_u16(&header[i..i + 2]) as u32;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !sum as u16
}

/// Calculates the ICMP checksum.
fn calculate_icmp_checksum(packet: &[u8]) -> u16 {
    let mut sum = 0u32;
    for i in (0..packet.len()).step_by(2) {
        sum += BigEndian::read_u16(&packet[i..i + 2]) as u32;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !sum as u16
}

/// Builds an IPv4 header with randomized fields for obfuscation.
fn build_ipv4_header(src_ip: Ipv4Addr, dest_ip: Ipv4Addr, protocol: u8, payload_len: usize) -> Vec<u8> {
    let total_len = (IPV4_HEADER_SIZE + payload_len) as u16;
    let mut header = Vec::with_capacity(IPV4_HEADER_SIZE);
    header.extend_from_slice(&[
        0x45,                          // Version (4) + IHL (5)
        rand::random::<u8>(),          // DSCP + ECN (randomized)
        (total_len >> 8) as u8,        // Total length (high byte)
        total_len as u8,               // Total length (low byte)
        (custom_rng_gen_u16() >> 8) as u8, // Identification (randomized)
        custom_rng_gen_u16() as u8,
        0x40,                          // Flags (Don't Fragment)
        0x00,                          // Fragment Offset
        rand::random::<u8>().max(32).min(128), // TTL (randomized)
        protocol,                      // Protocol
        0x00, 0x00,                    // Checksum (to be calculated)
    ]);
    header.extend_from_slice(&src_ip.octets());
    header.extend_from_slice(&dest_ip.octets());
    let checksum = calculate_ipv4_checksum(&header);
    BigEndian::write_u16(&mut header[10..12], checksum);
    header
}

/// Builds an ICMP Echo Request packet.
fn build_icmp_echo_request_packet(id: u16, sequence: u16, payload: &[u8]) -> Vec<u8> {
    let mut packet = Vec::with_capacity(ICMP_HEADER_SIZE + payload.len());
    packet.extend_from_slice(&[
        8, // Type: Echo Request
        0, // Code
        0, 0, // Checksum placeholder
        (id >> 8) as u8, id as u8,
        (sequence >> 8) as u8, sequence as u8,
    ]);
    packet.extend_from_slice(payload);
    let checksum = calculate_icmp_checksum(&packet);
    BigEndian::write_u16(&mut packet[2..4], checksum);
    packet
}

/// Parses an IPv4 packet to extract its payload and metadata.
fn parse_ipv4_packet(
    packet_buf: &[u8],
) -> Option<(Ipv4Addr, Ipv4Addr, u8, Vec<u8>, Option<(u16, u16)>)> {
    if packet_buf.len() < IPV4_HEADER_SIZE {
        return None;
    }
    let ihl = (packet_buf[0] & 0x0F) as usize * 4;
    if packet_buf.len() < ihl {
        return None;
    }
    let protocol = packet_buf[9];
    let src_ip = Ipv4Addr::new(packet_buf[12], packet_buf[13], packet_buf[14], packet_buf[15]);
    let dest_ip = Ipv4Addr::new(packet_buf[16], packet_buf[17], packet_buf[18], packet_buf[19]);
    let payload = packet_buf[ihl..].to_vec();

    if protocol == 1 && payload.len() >= ICMP_HEADER_SIZE {
        let icmp_id = BigEndian::read_u16(&payload[4..6]);
        let icmp_seq = BigEndian::read_u16(&payload[6..8]);
        Some((
            src_ip,
            dest_ip,
            protocol,
            payload[ICMP_HEADER_SIZE..].to_vec(),
            Some((icmp_id, icmp_seq)),
        ))
    } else {
        Some((src_ip, dest_ip, protocol, payload, None))
    }
}

// --- OS Abstraction Layer for Raw Sockets ---

#[async_trait]
trait RawSocketTrait: Send + Sync {
    fn new(local_ip: IpAddr) -> io::Result<Self>
    where
        Self: Sized;
    async fn send_raw_packet(&self, remote_ip: IpAddr, raw_packet: &[u8]) -> io::Result<usize>;
    async fn recv_raw_packet(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)>;
    fn local_ip(&self) -> IpAddr;
}

/// Linux-specific raw socket implementation.
struct LinuxRawSocket {
    socket: UdpSocket,
    local_ip_addr: IpAddr,
}

#[async_trait]
impl RawSocketTrait for LinuxRawSocket {
    #[cfg(target_os = "linux")]
    fn new(local_ip: IpAddr) -> io::Result<Self> {
        let socket = UdpSocket::bind(SocketAddr::new(local_ip, 0))?;
        socket.set_nonblocking(true)?;
        let fd = socket.as_raw_fd();
        let enable: i32 = 1;
        if unsafe {
            setsockopt(
                fd,
                IPPROTO_IP,
                IP_HDRINCL,
                &enable as *const _ as *const libc::c_void,
                std::mem::size_of_val(&enable) as libc::socklen_t,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        info!("LinuxRawSocket bound to {} with IP_HDRINCL", local_ip);
        Ok(LinuxRawSocket {
            socket,
            local_ip_addr: local_ip,
        })
    }

    #[cfg(not(target_os = "linux"))]
    fn new(_local_ip: IpAddr) -> io::Result<Self> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Raw sockets not supported on this OS",
        ))
    }

    async fn send_raw_packet(&self, remote_ip: IpAddr, raw_packet: &[u8]) -> io::Result<usize> {
        let socket = self.socket.try_clone()?;
        let packet = raw_packet.to_vec();
        tokio::task::spawn_blocking(move || socket.send_to(&packet, SocketAddr::new(remote_ip, 0)))
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Send error: {}", e)))?
    }

    async fn recv_raw_packet(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let socket = self.socket.try_clone()?;
        tokio::task::spawn_blocking(move || socket.recv_from(buf))
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Recv error: {}", e)))?
    }

    fn local_ip(&self) -> IpAddr {
        self.local_ip_addr
    }
}

/// Platform-agnostic raw socket wrapper.
struct PlatformRawSocket {
    inner: Box<dyn RawSocketTrait + Send + Sync>,
}

impl PlatformRawSocket {
    fn new(local_ip: IpAddr) -> io::Result<Self> {
        #[cfg(target_os = "linux")]
        return Ok(PlatformRawSocket {
            inner: Box::new(LinuxRawSocket::new(local_ip)?),
        });
        #[cfg(not(target_os = "linux"))]
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Raw sockets not supported on this OS",
        ))
    }

    async fn send_raw_packet(&self, remote_ip: IpAddr, raw_packet: &[u8]) -> io::Result<usize> {
        self.inner.send_raw_packet(remote_ip, raw_packet).await
    }

    async fn recv_raw_packet(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        self.inner.recv_raw_packet(buf).await
    }

    fn local_ip(&self) -> IpAddr {
        self.inner.local_ip()
    }
}

// --- Connection Metrics ---

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct ConnectionMetrics {
    timestamp_ms: u64,
    client_id: String,
    service_id: String,
    bytes_uploaded: u64,
    bytes_downloaded: u64,
    duration_sec: u64,
    status: String,
    error_message: Option<String>,
    peer_addr: String,
    server_addr: String,
    protocol_used: String,
}

// --- Covert Tunnel Stream ---

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConnectionState {
    Closed,
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    TimeWait,
    CloseWait,
    LastAck,
    Closing,
}

struct CovertTunnelStream {
    raw_socket: Arc<PlatformRawSocket>,
    remote_ip: IpAddr,
    local_ip: IpAddr,
    tunnel_id: [u8; TUNNEL_ID_SIZE],
    protocol_type: u8,
    cipher: Arc<IrpCipher>,
    next_send_seq: Arc<Mutex<u32>>,
    last_acked_seq: Arc<Mutex<u32>>,
    next_recv_seq: Arc<Mutex<u32>>,
    send_window_size: Arc<Mutex<u32>>,
    recv_window_size: Arc<Mutex<u32>>,
    initial_rto_ms: u64,
    max_rto_ms: u64,
    current_rto_ms: Arc<Mutex<u64>>,
    send_buffer: Arc<Mutex<HashMap<u32, (IrpPacket, Instant, u32)>>>,
    recv_buffer: Arc<Mutex<HashMap<u32, IrpPacket>>>,
    connection_state: Arc<Mutex<ConnectionState>>,
    irp_obfuscation_min_padding: usize,
    irp_obfuscation_max_padding: usize,
    data_to_read_tx: mpsc::Sender<Vec<u8>>,
    data_to_read_rx: mpsc::Receiver<Vec<u8>>,
    control_tx: mpsc::Sender<IrpFlags>,
    status_tx: mpsc::Sender<ConnectionState>,
    status_rx: mpsc::Receiver<ConnectionState>,
}

impl CovertTunnelStream {
    async fn new(
        local_ip: IpAddr,
        remote_ip: IpAddr,
        tunnel_id: [u8; TUNNEL_ID_SIZE],
        protocol_type: u8,
        cipher: Arc<IrpCipher>,
        initial_rto_ms: u64,
        max_rto_ms: u64,
        irp_obfuscation_min_padding: usize,
        irp_obfuscation_max_padding: usize,
    ) -> io::Result<Self> {
        let raw_socket = Arc::new(PlatformRawSocket::new(local_ip)?);
        let (data_to_read_tx, data_to_read_rx) = mpsc::channel(1024);
        let (control_tx, mut control_rx) = mpsc::channel(16);
        let (status_tx, status_rx) = mpsc::channel(1);

        let stream = CovertTunnelStream {
            raw_socket: raw_socket.clone(),
            remote_ip,
            local_ip,
            tunnel_id,
            protocol_type,
            cipher,
            next_send_seq: Arc::new(Mutex::new(custom_rng_gen_u32())),
            last_acked_seq: Arc::new(Mutex::new(0)),
            next_recv_seq: Arc::new(Mutex::new(0)),
            send_window_size: Arc::new(Mutex::new(initial_rto_ms as u32 / 100)),
            recv_window_size: Arc::new(Mutex::new(10)),
            initial_rto_ms,
            max_rto_ms,
            current_rto_ms: Arc::new(Mutex::new(initial_rto_ms)),
            send_buffer: Arc::new(Mutex::new(HashMap::new())),
            recv_buffer: Arc::new(Mutex::new(HashMap::new())),
            connection_state: Arc::new(Mutex::new(ConnectionState::Closed)),
            irp_obfuscation_min_padding,
            irp_obfuscation_max_padding,
            data_to_read_tx,
            data_to_read_rx,
            control_tx,
            status_tx,
            status_rx,
        };

        let socket = raw_socket.clone();
        let remote_ip_clone = remote_ip;
        let tunnel_id_clone = tunnel_id;
        let protocol_type_clone = protocol_type;
        let cipher_clone = stream.cipher.clone();
        let next_send_seq = stream.next_send_seq.clone();
        let last_acked_seq = stream.last_acked_seq.clone();
        let next_recv_seq = stream.next_recv_seq.clone();
        let send_window_size = stream.send_window_size.clone();
        let recv_window_size = stream.recv_window_size.clone();
        let send_buffer = stream.send_buffer.clone();
        let recv_buffer = stream.recv_buffer.clone();
        let data_to_read_tx = stream.data_to_read_tx.clone();
        let connection_state = stream.connection_state.clone();
        let current_rto_ms = stream.current_rto_ms.clone();
        let status_tx = stream.status_tx.clone();

        tokio::spawn(async move {
            let mut recv_buf = vec![0; MAX_IP_PAYLOAD_SIZE + IPV4_HEADER_SIZE + ICMP_HEADER_SIZE];
            let mut retransmit_interval = tokio::time::interval(Duration::from_millis(10));
            let mut keep_alive_interval = tokio::time::interval(Duration::from_secs(5));

            loop {
                tokio::select! {
                    result = socket.recv_raw_packet(&mut recv_buf) => {
                        match result {
                            Ok((n, src_addr)) => {
                                if src_addr.ip() != remote_ip_clone || n > recv_buf.len() {
                                    warn!("Invalid packet from {} (size: {})", src_addr.ip(), n);
                                    continue;
                                }
                                if let Some((_, _, proto, payload, _)) = parse_ipv4_packet(&recv_buf[..n]) {
                                    if proto == protocol_type_clone {
                                        if let Ok(packet) = IrpPacket::from_bytes(&payload) {
                                            if packet.header.tunnel_id == tunnel_id_clone {
                                                let mut state = connection_state.lock().await;
                                                if packet.header.flags.rst {
                                                    *state = ConnectionState::Closed;
                                                    status_tx.send(ConnectionState::Closed).await.ok();
                                                    return;
                                                }
                                                if packet.header.flags.ack {
                                                    let mut buffer = send_buffer.lock().await;
                                                    buffer.retain(|&seq, _| seq >= packet.header.ack_num);
                                                    *last_acked_seq.lock().await = packet.header.ack_num;
                                                    let mut window = send_window_size.lock().await;
                                                    *window = window.saturating_add(1);
                                                }
                                                if packet.header.flags.syn {
                                                    match *state {
                                                        ConnectionState::Closed => {
                                                            *next_recv_seq.lock().await = packet.header.sequence_num + 1;
                                                            *state = ConnectionState::SynReceived;
                                                            let mut flags = IrpFlags::new();
                                                            flags.syn = true;
                                                            flags.ack = true;
                                                            let (payload, nonce) = cipher_clone.encrypt(&[])?;
                                                            let packet = IrpPacket::new(
                                                                tunnel_id_clone,
                                                                *next_send_seq.lock().await,
                                                                *next_recv_seq.lock().await,
                                                                flags,
                                                                nonce,
                                                                Vec::new(),
                                                                payload,
                                                            );
                                                            CovertTunnelStream::send_irp_packet(&socket, remote_ip_clone, protocol_type_clone, &packet).await?;
                                                            *next_send_seq.lock().await += 1;
                                                        }
                                                        ConnectionState::SynSent => {
                                                            *next_recv_seq.lock().await = packet.header.sequence_num + 1;
                                                            *state = ConnectionState::Established;
                                                            status_tx.send(ConnectionState::Established).await.ok();
                                                            let mut flags = IrpFlags::new();
                                                            flags.ack = true;
                                                            let (payload, nonce) = cipher_clone.encrypt(&[])?;
                                                            let packet = IrpPacket::new(
                                                                tunnel_id_clone,
                                                                *next_send_seq.lock().await,
                                                                *next_recv_seq.lock().await,
                                                                flags,
                                                                nonce,
                                                                Vec::new(),
                                                                payload,
                                                            );
                                                            CovertTunnelStream::send_irp_packet(&socket, remote_ip_clone, protocol_type_clone, &packet).await?;
                                                        }
                                                        _ => debug!("Unexpected SYN in state {:?}", *state),
                                                    }
                                                }
                                                if packet.header.flags.psh {
                                                    let mut next_seq = next_recv_seq.lock().await;
                                                    if packet.header.sequence_num == *next_seq {
                                                        let data = cipher_clone.decrypt(&packet.encrypted_payload, &packet.header.nonce)?;
                                                        data_to_read_tx.send(data).await.ok();
                                                        *next_seq += 1;
                                                        let mut buffer = recv_buffer.lock().await;
                                                        while let Some(p) = buffer.remove(&*next_seq) {
                                                            let data = cipher_clone.decrypt(&p.encrypted_payload, &p.header.nonce)?;
                                                            data_to_read_tx.send(data).await.ok();
                                                            *next_seq += 1;
                                                        }
                                                    }
                                                    let (payload, nonce) = cipher_clone.encrypt(&[])?;
                                                    let ack_packet = IrpPacket::new(
                                                        tunnel_id_clone,
                                                        0,
                                                        *next_seq,
                                                        IrpFlags { ack: true, ..IrpFlags::new() },
                                                        nonce,
                                                        Vec::new(),
                                                        payload,
                                                    );
                                                    CovertTunnelStream::send_irp_packet(&socket, remote_ip_clone, protocol_type_clone, &ack_packet).await?;
                                                }
                                                if packet.header.flags.fin {
                                                    match *state {
                                                        ConnectionState::Established => {
                                                            *state = ConnectionState::CloseWait;
                                                            let (payload, nonce) = cipher_clone.encrypt(&[])?;
                                                            let fin_ack = IrpPacket::new(
                                                                tunnel_id_clone,
                                                                0,
                                                                packet.header.sequence_num + 1,
                                                                IrpFlags { fin: true, ack: true, ..IrpFlags::new() },
                                                                nonce,
                                                                Vec::new(),
                                                                payload,
                                                            );
                                                            CovertTunnelStream::send_irp_packet(&socket, remote_ip_clone, protocol_type_clone, &fin_ack).await?;
                                                            data_to_read_tx.send(Vec::new()).await.ok();
                                                        }
                                                        _ => debug!("Unexpected FIN in state {:?}", *state),
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                            Err(e) => error!("Receive error: {}", e),
                        }
                    }
                    _ = retransmit_interval.tick() => {
                        let mut buffer = send_buffer.lock().await;
                        let now = Instant::now();
                        let rto = *current_rto_ms.lock().await;
                        for (_, (packet, last_sent, count)) in buffer.iter_mut() {
                            if now.duration_since(*last_sent) > Duration::from_millis(rto) {
                                CovertTunnelStream::send_irp_packet(&socket, remote_ip_clone, protocol_type_clone, packet).await?;
                                *last_sent = now;
                                *count += 1;
                            }
                        }
                    }
                    _ = keep_alive_interval.tick() => {
                        if *connection_state.lock().await == ConnectionState::Established {
                            let (payload, nonce) = cipher_clone.encrypt(&[])?;
                            let keep_alive = IrpPacket::new(
                                tunnel_id_clone,
                                *next_send_seq.lock().await,
                                *next_recv_seq.lock().await,
                                IrpFlags { ack: true, ..IrpFlags::new() },
                                nonce,
                                Vec::new(),
                                payload,
                            );
                            CovertTunnelStream::send_irp_packet(&socket, remote_ip_clone, protocol_type_clone, &keep_alive).await?;
                        }
                    }
                    msg = control_rx.recv() => {
                        if let Some(flags) = msg {
                            if flags.fin {
                                let (payload, nonce) = cipher_clone.encrypt(&[])?;
                                let fin_packet = IrpPacket::new(
                                    tunnel_id_clone,
                                    *next_send_seq.lock().await,
                                    *next_recv_seq.lock().await,
                                    IrpFlags { fin: true, ..IrpFlags::new() },
                                    nonce,
                                    Vec::new(),
                                    payload,
                                );
                                CovertTunnelStream::send_irp_packet(&socket, remote_ip_clone, protocol_type_clone, &fin_packet).await?;
                                *next_send_seq.lock().await += 1;
                                *connection_state.lock().await = ConnectionState::FinWait1;
                            }
                            if flags.rst {
                                let (payload, nonce) = cipher_clone.encrypt(&[])?;
                                let rst_packet = IrpPacket::new(
                                    tunnel_id_clone,
                                    0,
                                    0,
                                    IrpFlags { rst: true, ..IrpFlags::new() },
                                    nonce,
                                    Vec::new(),
                                    payload,
                                );
                                CovertTunnelStream::send_irp_packet(&socket, remote_ip_clone, protocol_type_clone, &rst_packet).await?;
                                *connection_state.lock().await = ConnectionState::Closed;
                                status_tx.send(ConnectionState::Closed).await.ok();
                                return;
                            }
                        }
                    }
                }
            }
        });

        Ok(stream)
    }

    async fn send_irp_packet(
        socket: &Arc<PlatformRawSocket>,
        remote_ip: IpAddr,
        protocol_type: u8,
        irp_packet: &IrpPacket,
    ) -> io::Result<()> {
        let bytes = irp_packet.to_bytes()?;
        if bytes.len() > MAX_IP_PAYLOAD_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Packet too large",
            ));
        }
        let raw_packet = match (socket.local_ip(), remote_ip) {
            (IpAddr::V4(src), IpAddr::V4(dst)) => {
                let mut packet = build_ipv4_header(src, dst, protocol_type, bytes.len());
                if protocol_type == 1 {
                    let icmp = build_icmp_echo_request_packet(custom_rng_gen_u16(), custom_rng_gen_u16(), &bytes);
                    packet.extend_from_slice(&icmp);
                } else {
                    packet.extend_from_slice(&bytes);
                }
                packet
            }
            _ => return Err(io::Error::new(io::ErrorKind::AddrNotAvailable, "IPv4 only")),
        };
        socket.send_raw_packet(remote_ip, &raw_packet).await?;
        Ok(())
    }

    async fn read_data(&mut self) -> io::Result<Vec<u8>> {
        let state = *self.connection_state.lock().await;
        if !matches!(
            state,
            ConnectionState::Established | ConnectionState::FinWait2 | ConnectionState::CloseWait
        ) {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                format!("Invalid state: {:?}", state),
            ));
        }
        self.data_to_read_rx
            .recv()
            .await
            .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "Data channel closed"))
    }

    async fn write_data(&mut self, buf: &[u8]) -> io::Result<usize> {
        let state = *self.connection_state.lock().await;
        if state != ConnectionState::Established {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                format!("Invalid state: {:?}", state),
            ));
        }
        let mut offset = 0;
        while offset < buf.len() {
            let chunk_size = (MAX_IP_PAYLOAD_SIZE - CUSTOM_IRFARP_HEADER_SIZE).min(buf.len() - offset);
            let chunk = &buf[offset..offset + chunk_size];
            let (encrypted, nonce) = self.cipher.encrypt(chunk)?;
            let mut flags = IrpFlags::new();
            flags.psh = true;
            flags.ack = true;
            let packet = IrpPacket::new(
                self.tunnel_id,
                *self.next_send_seq.lock().await,
                *self.next_recv_seq.lock().await,
                flags,
                nonce,
                Vec::new(),
                encrypted,
            );
            self.send_buffer
                .lock()
                .await
                .insert(*self.next_send_seq.lock().await, (packet.clone(), Instant::now(), 0));
            CovertTunnelStream::send_irp_packet(&self.raw_socket, self.remote_ip, self.protocol_type, &packet).await?;
            *self.next_send_seq.lock().await += 1;
            offset += chunk_size;
        }
        Ok(buf.len())
    }

    async fn close(&mut self) -> io::Result<()> {
        let mut flags = IrpFlags::new();
        flags.fin = true;
        self.control_tx.send(flags).await?;
        tokio::time::timeout(Duration::from_secs(15), self.status_rx.recv())
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "Close timeout"))?
            .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "Status channel closed"))?;
        Ok(())
    }

    async fn reset(&mut self) -> io::Result<()> {
        let mut flags = IrpFlags::new();
        flags.rst = true;
        self.control_tx.send(flags).await?;
        *self.connection_state.lock().await = ConnectionState::Closed;
        Ok(())
    }

    fn get_state(&self) -> ConnectionState {
        *self.connection_state.blocking_lock()
    }
}

// --- IRFARP Server ---

struct IrfarpServer {
    config: ServerConfig,
    metrics_sender: mpsc::Sender<ConnectionMetrics>,
    active_tunnels: Arc<Mutex<HashMap<[u8; TUNNEL_ID_SIZE], Arc<tokio::net::TcpStream>>>>,
    covert_data_tx_map: Arc<Mutex<HashMap<[u8; TUNNEL_ID_SIZE], mpsc::Sender<Vec<u8>>>>>,
    session_cipher_map: Arc<Mutex<HashMap<[u8; TUNNEL_ID_SIZE], Arc<IrpCipher>>>>,
}

impl IrfarpServer {
    async fn new(config_path: &str) -> io::Result<(Self, mpsc::Receiver<ConnectionMetrics>)> {
        let config = load_config(config_path)?;
        let (metrics_sender, metrics_receiver) = mpsc::channel(1024);
        Ok((
            IrfarpServer {
                config,
                metrics_sender,
                active_tunnels: Arc::new(Mutex::new(HashMap::new())),
                covert_data_tx_map: Arc::new(Mutex::new(HashMap::new())),
                session_cipher_map: Arc::new(Mutex::new(HashMap::new())),
            },
            metrics_receiver,
        ))
    }

    async fn run(self) -> io::Result<()> {
        let icmp_ip: IpAddr = self.config.icmp_bind_addr.parse()?;
        let custom_ip: IpAddr = self.config.custom_ip_bind_addr.parse()?;
        let irp_ip: IpAddr = self.config.irp_bind_addr.parse()?;
        let icmp_socket = Arc::new(PlatformRawSocket::new(icmp_ip)?);
        let custom_socket = Arc::new(PlatformRawSocket::new(custom_ip)?);
        let irp_socket = Arc::new(PlatformRawSocket::new(irp_ip)?);
        let services = Arc::new(self.config.services.clone());
        let metrics_sender = self.metrics_sender.clone();
        let tunnels = self.active_tunnels.clone();
        let data_tx = self.covert_data_tx_map.clone();
        let ciphers = self.session_cipher_map.clone();
        let key = Arc::new(
            general_purpose::STANDARD
                .decode(&self.config.auth_key_base64)?
                .try_into()
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "Invalid key length"))?,
        );

        tokio::join!(
            Self::spawn_raw_protocol_listener(
                icmp_socket,
                1,
                services.clone(),
                metrics_sender.clone(),
                tunnels.clone(),
                data_tx.clone(),
                ciphers.clone(),
                key.clone(),
            ),
            Self::spawn_raw_protocol_listener(
                custom_socket,
                253,
                services.clone(),
                metrics_sender.clone(),
                tunnels.clone(),
                data_tx.clone(),
                ciphers.clone(),
                key.clone(),
            ),
            Self::spawn_raw_protocol_listener(
                irp_socket,
                254,
                services,
                metrics_sender,
                tunnels,
                data_tx,
                ciphers,
                key,
            )
        );
        Ok(())
    }

    async fn spawn_raw_protocol_listener(
        socket: Arc<PlatformRawSocket>,
        proto: u8,
        services: Arc<HashMap<String, ServiceConfig>>,
        metrics: mpsc::Sender<ConnectionMetrics>,
        tunnels: Arc<Mutex<HashMap<[u8; TUNNEL_ID_SIZE], Arc<tokio::net::TcpStream>>>>,
        data_tx: Arc<Mutex<HashMap<[u8; TUNNEL_ID_SIZE], mpsc::Sender<Vec<u8>>>>>,
        ciphers: Arc<Mutex<HashMap<[u8; TUNNEL_ID_SIZE], Arc<IrpCipher>>>>,
        key: Arc<[u8; 32]>,
    ) -> io::Result<()> {
        let mut buf = vec![0; MAX_IP_PAYLOAD_SIZE + IPV4_HEADER_SIZE + ICMP_HEADER_SIZE];
        loop {
            match socket.recv_raw_packet(&mut buf).await {
                Ok((n, src_addr)) => {
                    if let Some((src_ip, _, p, payload, _)) = parse_ipv4_packet(&buf[..n]) {
                        if p == proto {
                            if let Ok(packet) = IrpPacket::from_bytes(&payload) {
                                let tunnel_id = packet.header.tunnel_id;
                                let mut data_tx_map = data_tx.lock().await;
                                let mut cipher_map = ciphers.lock().await;

                                if packet.header.flags.syn {
                                    let session_key = derive_session_key(&key, &packet.header.nonce, b"irp-session-key")?;
                                    let cipher = Arc::new(IrpCipher::new(&session_key));
                                    let auth_info = cipher.decrypt(&packet.encrypted_payload, &packet.header.nonce)?;
                                    let parts: Vec<&str> = String::from_utf8_lossy(&auth_info).splitn(2, ':').collect();
                                    if parts.len() == 2 {
                                        if let Some(service) = services.values().find(|s| s.token == parts[1]) {
                                            let tcp_stream = Arc::new(tokio::net::TcpStream::connect(&service.bind_addr).await?);
                                            let (tx, rx) = mpsc::channel(1024);
                                            data_tx_map.insert(tunnel_id, tx);
                                            tunnels.lock().await.insert(tunnel_id, tcp_stream.clone());
                                            cipher_map.insert(tunnel_id, cipher.clone());

                                            tokio::spawn(Self::handle_covert_tunnel_data(
                                                tunnel_id,
                                                tcp_stream,
                                                socket.clone(),
                                                src_ip,
                                                proto,
                                                rx,
                                                metrics.clone(),
                                                socket.local_ip().to_string(),
                                                service.client_service_id.clone(),
                                                parts[0].to_string(),
                                                cipher,
                                                200,
                                                2000,
                                            ));

                                            let (payload, nonce) = cipher.encrypt(&[])?;
                                            let syn_ack = IrpPacket::new(
                                                tunnel_id,
                                                0,
                                                packet.header.sequence_num + 1,
                                                IrpFlags { syn: true, ack: true, ..IrpFlags::new() },
                                                nonce,
                                                Vec::new(),
                                                payload,
                                            );
                                            CovertTunnelStream::send_irp_packet(&socket, src_ip, proto, &syn_ack).await?;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                Err(e) => error!("Receive error: {}", e),
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    }

    async fn handle_covert_tunnel_data(
        tunnel_id: [u8; TUNNEL_ID_SIZE],
        tcp_stream: Arc<tokio::net::TcpStream>,
        socket: Arc<PlatformRawSocket>,
        client_ip: IpAddr,
        proto: u8,
        mut rx: mpsc::Receiver<Vec<u8>>,
        metrics: mpsc::Sender<ConnectionMetrics>,
        server_addr: String,
        service_id: String,
        client_id: String,
        cipher: Arc<IrpCipher>,
        _initial_rto_ms: u64,
        _max_rto_ms: u64,
    ) -> io::Result<()> {
        let start = SystemTime::now();
        let mut uploaded = 0u64;
        let mut downloaded = 0u64;
        let (mut reader, mut writer) = tokio::io::split(tcp_stream);
        let next_seq = Arc::new(Mutex::new(0u32));

        tokio::select! {
            res = async {
                let mut buf = vec![0; MAX_IP_PAYLOAD_SIZE - CUSTOM_IRFARP_HEADER_SIZE];
                loop {
                    let n = reader.read(&mut buf).await?;
                    if n == 0 { break; }
                    let (data, nonce) = cipher.encrypt(&buf[..n])?;
                    let packet = IrpPacket::new(
                        tunnel_id,
                        *next_seq.lock().await,
                        0,
                        IrpFlags { psh: true, ack: true, ..IrpFlags::new() },
                        nonce,
                        Vec::new(),
                        data,
                    );
                    CovertTunnelStream::send_irp_packet(&socket, client_ip, proto, &packet).await?;
                    *next_seq.lock().await += 1;
                    uploaded += n as u64;
                }
                Ok(())
            } => res,
            res = async {
                while let Some(data) = rx.recv().await {
                    writer.write_all(&data).await?;
                    downloaded += data.len() as u64;
                }
                Ok(())
            } => res,
        }?;

        let duration = SystemTime::now().duration_since(start)?.as_secs();
        metrics
            .send(ConnectionMetrics {
                timestamp_ms: SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as u64,
                client_id,
                service_id,
                bytes_uploaded: uploaded,
                bytes_downloaded: downloaded,
                duration_sec: duration,
                status: "success".to_string(),
                error_message: None,
                peer_addr: client_ip.to_string(),
                server_addr,
                protocol_used: format!("raw-{}", proto),
            })
            .await
            .ok();
        Ok(())
    }
}

// --- IRFARP Client ---

struct IrfarpClient {
    config: ClientConfig,
    metrics_sender: mpsc::Sender<ConnectionMetrics>,
    active_tunnels: Arc<Mutex<HashMap<String, Arc<Mutex<CovertTunnelStream>>>>>,
}

impl IrfarpClient {
    async fn new(config_path: &str) -> io::Result<(Self, mpsc::Receiver<ConnectionMetrics>)> {
        let config = load_config(config_path)?;
        let (metrics_sender, metrics_receiver) = mpsc::channel(1024);
        Ok((
            IrfarpClient {
                config,
                metrics_sender,
                active_tunnels: Arc::new(Mutex::new(HashMap::new())),
            },
            metrics_receiver,
        ))
    }

    async fn run(self) -> io::Result<()> {
        let services = Arc::new(self.config.local_services.clone());
        let metrics = self.metrics_sender.clone();
        let tunnels = self.active_tunnels.clone();
        let key = Arc::new(
            general_purpose::STANDARD
                .decode(&self.config.auth_key_base64)?
                .try_into()
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "Invalid key length"))?,
        );

        loop {
            for (id, config) in services.iter() {
                let listener = tokio::net::TcpListener::bind(&config.local_addr).await?;
                let (stream, peer) = listener.accept().await?;
                let metrics_clone = metrics.clone();
                let tunnels_clone = tunnels.clone();
                let key_clone = key.clone();
                tokio::spawn(Self::handle_local_connection(
                    stream,
                    peer,
                    metrics_clone,
                    self.config.server_icmp_addr.clone(),
                    self.config.server_custom_ip_addr.clone(),
                    self.config.server_irp_addr.clone(),
                    self.config.client_id.clone(),
                    self.config.auth_token.clone(),
                    id.clone(),
                    tunnels_clone,
                    key_clone,
                ));
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }

    async fn handle_local_connection(
        stream: tokio::net::TcpStream,
        peer: SocketAddr,
        metrics: mpsc::Sender<ConnectionMetrics>,
        icmp_addr: String,
        custom_addr: String,
        irp_addr: String,
        client_id: String,
        auth_token: String,
        service_id: String,
        tunnels: Arc<Mutex<HashMap<String, Arc<Mutex<CovertTunnelStream>>>>>,
        key: Arc<[u8; 32]>,
    ) -> io::Result<()> {
        let local_ip = stream.local_addr()?.ip();
        let config = load_config::<ClientConfig>("client_config_example.json")?;
        let mut tunnel = None;
        let mut proto_used = String::new();
        let mut server_addr = String::new();

        for attempt in 1..=config.max_retries {
            let proto = config.protocol_pool[(attempt as usize - 1) % config.protocol_pool.len()].clone();
            let addr = match proto {
                CovertProtocol::ICMP => icmp_addr.clone(),
                CovertProtocol::CustomIP(_) => custom_addr.clone(),
                CovertProtocol::IRP => irp_addr.clone(),
            };
            let remote_ip: IpAddr = addr.parse()?;
            proto_used = proto.to_string();
            server_addr = addr.clone();

            let tunnel_id = get_csprng_bytes();
            let nonce = get_csprng_bytes();
            let session_key = derive_session_key(&key, &nonce, b"irp-session-key")?;
            let cipher = Arc::new(IrpCipher::new(&session_key));
            let (encrypted, _) = cipher.encrypt(format!("{}:{}", client_id, auth_token).as_bytes())?;
            let syn_packet = IrpPacket::new(
                tunnel_id,
                custom_rng_gen_u32(),
                0,
                IrpFlags { syn: true, ..IrpFlags::new() },
                nonce,
                Vec::new(),
                encrypted,
            );
            let socket = Arc::new(PlatformRawSocket::new(local_ip)?);
            CovertTunnelStream::send_irp_packet(&socket, remote_ip, proto.get_protocol_number(), &syn_packet).await?;

            let mut buf = vec![0; MAX_IP_PAYLOAD_SIZE + IPV4_HEADER_SIZE + ICMP_HEADER_SIZE];
            if let Ok(Ok((n, src))) = tokio::time::timeout(Duration::from_millis(config.connect_timeout_ms), socket.recv_raw_packet(&mut buf)).await {
                if src.ip() == remote_ip {
                    if let Some((_, _, p, payload, _)) = parse_ipv4_packet(&buf[..n]) {
                        if p == proto.get_protocol_number() {
                            if let Ok(packet) = IrpPacket::from_bytes(&payload) {
                                if packet.header.tunnel_id == tunnel_id && packet.header.flags.syn && packet.header.flags.ack {
                                    let new_tunnel = CovertTunnelStream::new(
                                        local_ip,
                                        remote_ip,
                                        tunnel_id,
                                        proto.get_protocol_number(),
                                        cipher.clone(),
                                        config.initial_rto_ms,
                                        config.max_rto_ms,
                                        config.irp_obfuscation_min_padding,
                                        config.irp_obfuscation_max_padding,
                                    ).await?;
                                    tunnel = Some(Arc::new(Mutex::new(new_tunnel)));
                                    tunnels.lock().await.insert(service_id.clone(), tunnel.as_ref().unwrap().clone());
                                    break;
                                }
                            }
                        }
                    }
                }
            }
            tokio::time::sleep(Duration::from_millis(config.retry_delay_ms)).await;
        }

        let tunnel = tunnel.ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "Failed to establish tunnel"))?;
        let start = SystemTime::now();
        let (mut reader, mut writer) = stream.split();
        let uploaded = Arc::new(Mutex::new(0u64));
        let downloaded = Arc::new(Mutex::new(0u64));
        let tunnel_clone = tunnel.clone();

        tokio::select! {
            res = async {
                let mut buf = vec![0; MAX_IP_PAYLOAD_SIZE - CUSTOM_IRFARP_HEADER_SIZE];
                loop {
                    let n = reader.read(&mut buf).await?;
                    if n == 0 { break; }
                    let mut t = tunnel_clone.lock().await;
                    t.write_data(&buf[..n]).await?;
                    *uploaded.lock().await += n as u64;
                }
                Ok(())
            } => res,
            res = async {
                let mut t = tunnel_clone.lock().await;
                while let Ok(data) = t.read_data().await {
                    writer.write_all(&data).await?;
                    *downloaded.lock().await += data.len() as u64;
                }
                Ok(())
            } => res,
        }?;

        let duration = SystemTime::now().duration_since(start)?.as_secs();
        metrics
            .send(ConnectionMetrics {
                timestamp_ms: SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as u64,
                client_id,
                service_id,
                bytes_uploaded: *uploaded.lock().await,
                bytes_downloaded: *downloaded.lock().await,
                duration_sec: duration,
                status: "success".to_string(),
                error_message: None,
                peer_addr: peer.to_string(),
                server_addr,
                protocol_used: proto_used,
            })
            .await
            .ok();
        tunnel.lock().await.close().await?;
        Ok(())
    }
}

// --- Main Application Logic ---

#[tokio::main]
async fn main() -> io::Result<()> {
    custom_rng_seed(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs());
    Builder::new()
        .filter_level(log::LevelFilter::Info)
        .target(Target::Stdout)
        .init();

    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <mode> [config_file]", args[0]);
        std::process::exit(1);
    }

    match args[1].as_str() {
        "generate-config" => {
            fs::write("server_config_example.json", SERVER_CONFIG_EXAMPLE)?;
            fs::write("client_config_example.json", CLIENT_CONFIG_EXAMPLE)?;
            info!("Config files generated");
            Ok(())
        }
        "server" => {
            if args.len() < 3 {
                eprintln!("Usage: {} server <config_file>", args[0]);
                std::process::exit(1);
            }
            let (server, mut metrics_rx) = IrfarpServer::new(&args[2]).await?;
            Builder::new()
                .filter_level(server.config.log_level.parse().unwrap_or(log::LevelFilter::Info))
                .init();
            tokio::spawn(async move {
                let mut interval = time::interval(Duration::from_secs(server.config.metrics_interval_sec));
                let mut metrics = Vec::new();
                loop {
                    tokio::select! {
                        Some(metric) = metrics_rx.recv() => metrics.push(metric),
                        _ = interval.tick() => {
                            if !metrics.is_empty() {
                                info!("Server Metrics: {:?}", metrics);
                                metrics.clear();
                            }
                        }
                    }
                }
            });
            server.run().await
        }
        "client" => {
            if args.len() < 3 {
                eprintln!("Usage: {} client <config_file>", args[0]);
                std::process::exit(1);
            }
            let (client, mut metrics_rx) = IrfarpClient::new(&args[2]).await?;
            Builder::new()
                .filter_level(client.config.log_level.parse().unwrap_or(log::LevelFilter::Info))
                .init();
            tokio::spawn(async move {
                let mut interval = time::interval(Duration::from_secs(60));
                let mut metrics = Vec::new();
                loop {
                    tokio::select! {
                        Some(metric) = metrics_rx.recv() => metrics.push(metric),
                        _ = interval.tick() => {
                            if !metrics.is_empty() {
                                info!("Client Metrics: {:?}", metrics);
                                metrics.clear();
                            }
                        }
                    }
                }
            });
            client.run().await
        }
        _ => {
            eprintln!("Invalid mode: {}", args[1]);
            std::process::exit(1);
        }
    }
}

const SERVER_CONFIG_EXAMPLE: &str = r#"{
  "icmp_bind_addr": "YOUR_SERVER_PUBLIC_IP",
  "custom_ip_bind_addr": "YOUR_SERVER_PUBLIC_IP",
  "irp_bind_addr": "YOUR_SERVER_PUBLIC_IP",
  "services": {
    "my_iran_server_ssh": {
      "token": "UNIQUE_SSH_SERVICE_TOKEN_12345",
      "bind_addr": "127.0.0.1:22",
      "client_service_id": "ssh_tunnel"
    }
  },
  "log_level": "info",
  "metrics_interval_sec": 300,
  "auth_key_base64": "YOUR_SECURE_32_BYTE_BASE64_ENCODED_KEY_HERE"
}"#;

const CLIENT_CONFIG_EXAMPLE: &str = r#"{
  "server_icmp_addr": "YOUR_SERVER_PUBLIC_IP",
  "server_custom_ip_addr": "YOUR_SERVER_PUBLIC_IP",
  "server_irp_addr": "YOUR_SERVER_PUBLIC_IP",
  "client_id": "IRAN_SERVER_10GBPS_PISHGAMAN",
  "auth_token": "UNIQUE_SSH_SERVICE_TOKEN_12345",
  "local_services": {
    "ssh_tunnel": {
      "local_addr": "127.0.0.1:22"
    }
  },
  "log_level": "debug",
  "protocol_pool": ["irp", "icmp", "custom-ip-253"],
  "connect_timeout_ms": 7000,
  "retry_delay_ms": 1500,
  "max_retries": 20,
  "initial_rto_ms": 200,
  "max_rto_ms": 5000,
  "irp_obfuscation_min_padding": 16,
  "irp_obfuscation_max_padding": 64,
  "auth_key_base64": "YOUR_SECURE_32_BYTE_BASE64_ENCODED_KEY_HERE"
}"#;
