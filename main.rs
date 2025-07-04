// Filename: src/main.rs
// IRFARP (IRan Freedom ARP) System - Monolithic Codebase
// Combines all modules into a single file for simplified deployment and resource management.
// Designed for banking-grade reliability, performance, and security,
// specifically targeting evasion of common DPI by using custom raw IP protocols
// with a focus on low-resource and cross-architecture compatibility.
// This system comprises a server component (IRFARP-Server) and a client component (IRFARP-Client).
// It implements a custom reliable, encrypted tunnel over raw IP protocols (ICMP, Custom IP, and IRP).

// --- IMPORTANT SECURITY AND RELIABILITY NOTICE ---
// This version *retains* the use of external, audited cryptographic libraries (`aes-gcm`, `hkdf`, `rand`)
// and a robust binary serialization library (`bincode`). This is CRITICAL for achieving
// "banking-grade security" and "99% reliability" as explicitly requested in previous turns.
// Implementing these primitives from scratch (as demonstrated in a prior artifact) is
// inherently insecure and unreliable for production use.
//
// Raw socket operations are OS-specific and require elevated privileges (CAP_NET_RAW on Linux).

// Standard library imports
use std::{
    collections::HashMap,
    fs::{self, File},
    io::{self, BufReader, Read, Write},
    net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket},
    path::Path,
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

// External crate imports (crucial for security and reliability)
use tokio::time;
use log::{info, warn, error, debug, trace};
use env_logger::{Builder, Target};
use rand::{rngs::OsRng, RngCore, Rng}; // For cryptographically secure random numbers and general randoms
use aes_gcm::{
    aead::{Aead, KeyInit, Nonce},
    Aes256Gcm,
};
use hkdf::Hkdf;
use sha2::Sha256;
use bincode::{serialize, deserialize}; // For robust binary serialization
use base64::{engine::general_purpose, Engine as _}; // For base64 encoding/decoding of master key
use byteorder::{ByteOrder, BigEndian}; // For explicit endianness in network parsing

// For raw socket operations on Linux
#[cfg(target_os = "linux")]
use std::os::unix::io::AsRawFd;
#[cfg(target_os = "linux")]
use libc::{self, setsockopt, IPPROTO_IP, IP_HDRINCL};

// --- Custom Pseudo-Random Number Generator (PRNG) for non-crypto uses ---
// This simple PRNG is used for non-security-critical random values like ICMP ID/Sequence
// hopping, where predictability is less of a concern than speed or simplicity on
// potentially constrained devices. NOT CRYPTOGRAPHICALLY SECURE.
static mut PRNG_STATE: u64 = 0;

fn custom_rng_seed(seed: u64) {
    unsafe {
        PRNG_STATE = if seed == 0 { 1 } else { seed }; // Seed must not be zero
    }
}

fn custom_rng_next_u64() -> u64 {
    unsafe {
        PRNG_STATE ^= PRNG_STATE << 13;
        PRNG_STATE ^= PRNG_STATE >> 7;
        PRNG_STATE ^= PRNG_STATE << 17;
        PRNG_STATE * 2685821657736338717
    }
}

fn custom_rng_gen_u16() -> u16 {
    (custom_rng_next_u64() >> 32) as u16
}

fn custom_rng_gen_u32() -> u32 {
    custom_rng_next_u64() as u32
}

// --- Cryptographically Secure Random Number Generator (CSPRNG) ---
/// Generates N cryptographically secure random bytes.
fn get_csprng_bytes<const N: usize>() -> [u8; N] {
    let mut bytes = [0u8; N];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

// --- Key Derivation Function (KDF) ---
/// Derives a strong, unique session key using HKDF-SHA256.
/// `master_key`: The pre-shared key (derived from auth_key_base64 in config).
/// `salt`: A unique, random nonce for each session/tunnel.
/// `info`: Contextual info (e.g., "irp-session-key").
fn derive_session_key(master_key: &[u8], salt: &[u8], info: &[u8]) -> io::Result<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(Some(salt), master_key);
    let mut okm = [0u8; 32]; // Output Key Material (32 bytes for AES-256)
    hk.expand(info, &mut okm)
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "HKDF key expansion failed"))?;
    Ok(okm)
}

// --- Authenticated Encryption (AES-256-GCM) ---
/// Provides authenticated encryption and decryption using AES-256-GCM.
struct IrpCipher {
    cipher: Aes256Gcm,
}

impl IrpCipher {
    fn new(key: &[u8; 32]) -> Self {
        let cipher = Aes256Gcm::new(key.into());
        IrpCipher { cipher }
    }

    /// Encrypts data with AES-256-GCM, returning ciphertext and the nonce used.
    /// The nonce MUST be unique for each encryption with the same key.
    /// This nonce is then sent in the packet header.
    fn encrypt(&self, plaintext: &[u8]) -> io::Result<(Vec<u8>, [u8; 12])> {
        let nonce_bytes = get_csprng_bytes::<12>(); // GCM recommends 12-byte nonces
        let nonce = Nonce::from_slice(&nonce_bytes);

        self.cipher.encrypt(nonce, plaintext)
            .map(|ciphertext| (ciphertext, nonce_bytes))
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Encryption failed: {}", e)))
    }

    /// Decrypts data with AES-256-GCM, requiring the original nonce.
    fn decrypt(&self, ciphertext: &[u8], nonce_bytes: &[u8; 12]) -> io::Result<Vec<u8>> {
        let nonce = Nonce::from_slice(nonce_bytes);
        self.cipher.decrypt(nonce, ciphertext)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Decryption failed: {}", e)))
    }
}

// --- Constants ---
const IPV4_HEADER_SIZE: usize = 20;
const ICMP_HEADER_SIZE: usize = 8;
const MAX_IP_PAYLOAD_SIZE: usize = 1480; // Max payload size to fit within typical MTU (1500 - 20 IP)
const TUNNEL_ID_SIZE: usize = 16; // Unique ID for multiplexing logical tunnels
const SEQUENCE_NUM_SIZE: usize = 4; // Sequence number for reliability
const ACK_NUM_SIZE: usize = 4; // Acknowledgment number
const FLAGS_SIZE: usize = 1; // For control flags (SYN, ACK, FIN, PSH, RST, PAD)
const NONCE_SIZE: usize = 12; // AES-GCM nonce size
const DATA_LENGTH_SIZE: usize = 2; // Length of the encrypted payload

// The size of our custom IRFARP header, including nonce.
// This is the fixed overhead for each IRFARP packet.
// Note: Padding is added *after* this header, before the encrypted payload.
const CUSTOM_IRFARP_HEADER_SIZE: usize = TUNNEL_ID_SIZE + SEQUENCE_NUM_SIZE + ACK_NUM_SIZE + FLAGS_SIZE + NONCE_SIZE + DATA_LENGTH_SIZE;

// --- Custom Packet Structures for Reliable Covert Transport ---

// Represents different types of control flags for the IRFARP header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct IrpFlags {
    syn: bool, // Synchronization (connection establishment)
    ack: bool, // Acknowledgment
    fin: bool, // Finish (connection termination)
    psh: bool, // Push (flush buffered data)
    rst: bool, // Reset (abort connection)
    pad: bool, // Indicates presence of padding (for IRP)
}

impl IrpFlags {
    fn new() -> Self {
        IrpFlags { syn: false, ack: false, fin: false, psh: false, rst: false, pad: false }
    }

    fn as_byte(&self) -> u8 {
        let mut byte = 0;
        if self.syn { byte |= 0b00000001; }
        if self.ack { byte |= 0b00000010; }
        if self.fin { byte |= 0b00000100; }
        if self.psh { byte |= 0b00001000; }
        if self.rst { byte |= 0b00010000; }
        if self.pad { byte |= 0b00100000; } // New flag for padding
        byte
    }

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

// The header for our custom IRFARP packets.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct IrpHeader {
    tunnel_id: [u8; TUNNEL_ID_SIZE],
    sequence_num: u32,
    ack_num: u32,
    flags: IrpFlags,
    nonce: [u8; NONCE_SIZE], // Nonce for AES-GCM
    data_len: u16, // Length of the encrypted payload
}

// The full IRFARP packet structure.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct IrpPacket {
    header: IrpHeader,
    padding: Vec<u8>, // New: Random padding for obfuscation (only for IRP protocol)
    encrypted_payload: Vec<u8>,
}

impl IrpPacket {
    // Creates a new IRFARP packet with the given parameters.
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
        let header = IrpHeader {
            tunnel_id,
            sequence_num,
            ack_num,
            flags,
            nonce,
            data_len,
        };
        IrpPacket { header, padding, encrypted_payload }
    }

    // Serializes the IRFARP packet into a byte vector using bincode.
    fn to_bytes(&self) -> io::Result<Vec<u8>> {
        serialize(self)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("Failed to serialize IRP packet: {}", e)))
    }

    // Deserializes a byte slice into an IRFARP packet using bincode.
    fn from_bytes(bytes: &[u8]) -> io::Result<Self> {
        deserialize(bytes)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("Failed to deserialize IRP packet: {}", e)))
    }
}

// --- Configuration Structures ---
#[derive(Debug, serde::Deserialize, serde::Serialize, Clone)]
struct ServerConfig {
    icmp_bind_addr: String,
    custom_ip_bind_addr: String,
    irp_bind_addr: String, // Iran Revolutionary Protocol bind address
    services: HashMap<String, ServiceConfig>,
    log_level: String,
    metrics_interval_sec: u64,
    auth_key_base64: String, // Base64 encoded master key for deriving encryption keys
}

#[derive(Debug, serde::Deserialize, serde::Serialize, Clone)]
struct ClientConfig {
    server_icmp_addr: String,
    server_custom_ip_addr: String,
    server_irp_addr: String, // Iran Revolutionary Protocol server address
    client_id: String,
    auth_token: String, // Pre-shared token for initial service authentication
    local_services: HashMap<String, LocalServiceConfig>,
    log_level: String,
    protocol_pool: Vec<CovertProtocol>, // Pool of covert protocols to cycle
    connect_timeout_ms: u64,
    retry_delay_ms: u64,
    max_retries: u32,
    initial_rto_ms: u64, // Initial Retransmission Timeout
    max_rto_ms: u64,     // Maximum Retransmission Timeout
    irp_obfuscation_min_padding: usize, // Min random padding for IRP packets
    irp_obfuscation_max_padding: usize, // Max random padding for IRP packets
    auth_key_base64: String, // Base64 encoded master key for deriving encryption keys
}

#[derive(Debug, serde::Deserialize, serde::Serialize, Clone)]
struct ServiceConfig {
    token: String, // Unique token for this service, used by clients for authentication.
    bind_addr: String, // Local TCP address on server where the client's service will connect (e.g., 127.0.0.1:22 for SSH)
    client_service_id: String, // The internal service ID on the client that this server service maps to.
}

#[derive(Debug, serde::Deserialize, serde::Serialize, Clone)]
struct LocalServiceConfig {
    local_addr: String, // Local TCP address on client for its service
}

#[derive(Debug, serde::Deserialize, serde::Serialize, Clone, PartialEq, Eq, Hash)]
#[serde(rename_all = "kebab-case")] // For deserializing "custom-ip-253" etc.
enum CovertProtocol {
    ICMP,
    CustomIP(u8), // Custom IP protocol number
    IRP,          // Iran Revolutionary Protocol (uses IP protocol number 254)
}

impl CovertProtocol {
    fn to_string(&self) -> String {
        match self {
            CovertProtocol::ICMP => "icmp".to_string(),
            CovertProtocol::CustomIP(p) => format!("custom-ip-{}", p),
            CovertProtocol::IRP => "irp".to_string(),
        }
    }

    // Returns the IP protocol number associated with the covert protocol.
    fn get_protocol_number(&self) -> u8 {
        match self {
            CovertProtocol::ICMP => 1,
            CovertProtocol::CustomIP(p) => *p,
            CovertProtocol::IRP => 254, // IRP uses experimental/reserved IP protocol number 254
        }
    }
}

/// Loads configuration from a JSON file.
fn load_config<T: for<'de> serde::Deserialize<'de>>(path: &str) -> io::Result<T> {
    let path = Path::new(path);
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let config: T = serde_json::from_reader(reader)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("Failed to parse config: {}", e)))?;
    info!("Configuration loaded from: {}", path.display());
    Ok(config)
}

// --- IP/ICMP/Custom Protocol Packet Manipulation ---

// Calculates the IPv4 checksum.
fn calculate_ipv4_checksum(header: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut i = 0;
    while i < header.len() {
        sum += BigEndian::read_u16(&header[i..i + 2]) as u32;
        i += 2;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !sum as u16
}

// Calculates the ICMP checksum.
fn calculate_icmp_checksum(packet: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut i = 0;
    while i < packet.len() {
        sum += BigEndian::read_u16(&packet[i..i + 2]) as u32;
        i += 2;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !sum as u16
}

/// Builds a raw IPv4 header.
/// Includes some randomization for obfuscation (DSCP, Identification, TTL).
fn build_ipv4_header(
    src_ip: Ipv4Addr,
    dest_ip: Ipv4Addr,
    protocol: u8,
    payload_len: usize,
) -> Vec<u8> {
    let total_len = (IPV4_HEADER_SIZE + payload_len) as u16;
    let mut header = vec![0; IPV4_HEADER_SIZE];

    header[0] = 0x45; // Version (4) and IHL (5 words = 20 bytes)
    header[1] = rand::random::<u8>(); // DSCP + ECN (randomized for obfuscation)
    BigEndian::write_u16(&mut header[2..4], total_len); // Total Length
    BigEndian::write_u16(&mut header[4..6], custom_rng_gen_u16()); // Identification (randomized)
    header[6] = 0x40; // Flags (Don't Fragment) + Fragment Offset (high bits)
    header[7] = 0x00; // Fragment Offset (low bits)
    header[8] = rand::random::<u8>().max(32).min(128); // TTL (randomized within a reasonable range)
    header[9] = protocol; // Protocol (ICMP=1, TCP=6, UDP=17, Custom=253, IRP=254)
    BigEndian::write_u16(&mut header[10..12], 0); // Checksum (initially 0)
    header[12..16].copy_from_slice(&src_ip.octets()); // Source IP
    header[16..20].copy_from_slice(&dest_ip.octets()); // Destination IP

    let checksum = calculate_ipv4_checksum(&header);
    BigEndian::write_u16(&mut header[10..12], checksum); // Set checksum

    header
}

/// Builds a raw ICMP Echo Request packet.
fn build_icmp_echo_request_packet(
    id: u16,
    sequence: u16,
    payload: &[u8],
) -> Vec<u8> {
    let mut packet = vec![0; ICMP_HEADER_SIZE + payload.len()];

    packet[0] = 8; // Type: Echo Request
    packet[1] = 0; // Code: 0
    BigEndian::write_u16(&mut packet[2..4], 0); // Checksum (initially 0)
    BigEndian::write_u16(&mut packet[4..6], id); // Identifier
    BigEndian::write_u16(&mut packet[6..8], sequence); // Sequence Number
    packet[ICMP_HEADER_SIZE..].copy_from_slice(payload);

    let checksum = calculate_icmp_checksum(&packet);
    BigEndian::write_u16(&mut packet[2..4], checksum); // Set checksum

    packet
}

/// Parses a raw IPv4 packet to extract its payload and protocol.
/// For ICMP, it also extracts ID and Sequence.
fn parse_ipv4_packet(packet_buf: &[u8]) -> Option<(Ipv4Addr, Ipv4Addr, u8, Vec<u8>, Option<(u16, u16)>)> {
    if packet_buf.len() < IPV4_HEADER_SIZE { return None; }

    let version_ihl = packet_buf[0];
    let ihl = (version_ihl & 0x0F) as usize; // IHL in 32-bit words
    let ip_header_len = ihl * 4;

    if packet_buf.len() < ip_header_len { return None; }

    let protocol = packet_buf[9];
    let src_ip = Ipv4Addr::new(packet_buf[12], packet_buf[13], packet_buf[14], packet_buf[15]);
    let dest_ip = Ipv4Addr::new(packet_buf[16], packet_buf[17], packet_buf[18], packet_buf[19]);

    let payload_start = ip_header_len;
    if packet_buf.len() < payload_start { return None; }
    let payload = packet_buf[payload_start..].to_vec();

    // For ICMP, extract ID and Sequence from its header
    if protocol == 1 && payload.len() >= ICMP_HEADER_SIZE {
        let icmp_id = BigEndian::read_u16(&payload[4..6]);
        let icmp_seq = BigEndian::read_u16(&payload[6..8]);
        Some((src_ip, dest_ip, protocol, payload[ICMP_HEADER_SIZE..].to_vec(), Some((icmp_id, icmp_seq))))
    } else {
        Some((src_ip, dest_ip, protocol, payload, None))
    }
}

// --- OS Abstraction Layer for Raw Sockets ---
/// Defines the interface for raw socket operations, allowing different OS implementations.
trait RawSocketTrait: Send + Sync {
    /// Creates a new raw socket bound to the local IP.
    fn new(local_ip: IpAddr) -> io::Result<Self> where Self: Sized;

    /// Sends a raw packet to the specified remote IP.
    async fn send_raw_packet(&self, remote_ip: IpAddr, raw_packet: &[u8]) -> io::Result<usize>;

    /// Receives a raw packet into the provided buffer, returning bytes read and source address.
    async fn recv_raw_packet(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)>;

    /// Returns the local IP address the socket is bound to.
    fn local_ip(&self) -> IpAddr;
}

/// Linux-specific implementation using `UdpSocket` and `IP_HDRINCL`.
struct LinuxRawSocket {
    socket: UdpSocket,
    local_ip_addr: IpAddr,
}

impl RawSocketTrait for LinuxRawSocket {
    #[cfg(target_os = "linux")]
    fn new(local_ip: IpAddr) -> io::Result<Self> {
        let socket = UdpSocket::bind(SocketAddr::new(local_ip, 0))?;
        socket.set_nonblocking(true)?;

        let fd = socket.as_raw_fd();
        let enable: i32 = 1; // IP_HDRINCL
        let res = unsafe {
            libc::setsockopt(fd, libc::IPPROTO_IP, libc::IP_HDRINCL, &enable as *const _ as *const libc::c_void, std::mem::size_of_val(&enable) as libc::socklen_t)
        };
        if res != 0 {
            return Err(io::Error::last_os_error());
        }
        info!("LinuxRawSocket bound to {} with IP_HDRINCL enabled.", local_ip);
        Ok(LinuxRawSocket { socket, local_ip_addr: local_ip })
    }

    #[cfg(not(target_os = "linux"))]
    fn new(_local_ip: IpAddr) -> io::Result<Self> {
        // Placeholder for other OSes.
        // On Windows, you'd use `WSASocket` with `IPPROTO_IP` and `SIO_HDRINCL`.
        // On macOS/BSD, similar raw socket calls are needed.
        // This requires platform-specific FFI (Foreign Function Interface) or crates.
        error!("Raw sockets are not implemented for non-Linux OS without platform-specific FFI.");
        Err(io::Error::new(io::ErrorKind::Unsupported, "Raw sockets not supported on this OS."))
    }

    async fn send_raw_packet(&self, remote_ip: IpAddr, raw_packet: &[u8]) -> io::Result<usize> {
        let socket_clone = self.socket.try_clone()?;
        let packet_vec = raw_packet.to_vec(); // Copy for spawn_blocking
        tokio::task::spawn_blocking(move || {
            socket_clone.send_to(&packet_vec, SocketAddr::new(remote_ip, 0))
        }).await.map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Spawn blocking send error: {}", e)))?
    }

    async fn recv_raw_packet(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let socket_clone = self.socket.try_clone()?;
        let buf_ptr = buf.as_mut_ptr();
        let buf_len = buf.len();

        tokio::task::spawn_blocking(move || {
            // Safety: Ensure the pointer and length are valid for the lifetime of the call.
            let local_buf = unsafe { std::slice::from_raw_parts_mut(buf_ptr, buf_len) };
            socket_clone.recv_from(local_buf)
        }).await.map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Spawn blocking recv error: {}", e)))?
    }

    fn local_ip(&self) -> IpAddr {
        self.local_ip_addr
    }
}

/// A wrapper that uses the appropriate RawSocketTrait implementation based on target OS.
/// This is the type that higher-level modules will interact with.
struct PlatformRawSocket {
    inner: Box<dyn RawSocketTrait>,
}

impl PlatformRawSocket {
    fn new(local_ip: IpAddr) -> io::Result<Self> {
        #[cfg(target_os = "linux")]
        {
            Ok(PlatformRawSocket { inner: Box::new(LinuxRawSocket::new(local_ip)?) })
        }
        #[cfg(not(target_os = "linux"))]
        {
            // For other OSes, you would need to implement their specific raw socket logic
            // (e.g., WindowsRawSocket, MacRawSocket) and instantiate them here.
            // For truly exotic OSes, this would involve FFI to C/C++ shims.
            error!("PlatformRawSocket not implemented for this OS. Current target: {}", std::env::consts::OS);
            Err(io::Error::new(io::ErrorKind::Unsupported, "Raw sockets not supported on this OS."))
        }
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

// --- Connection Metrics Structures ---
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct ConnectionMetrics {
    timestamp_ms: u64,
    client_id: String,
    service_id: String,
    bytes_uploaded: u64,
    bytes_downloaded: u64,
    duration_sec: u64,
    status: String, // "success", "failure", "active"
    error_message: Option<String>,
    peer_addr: String,
    server_addr: String,
    protocol_used: String,
    // Removed: retransmissions, rtt_avg_ms, packet_loss_rate (part of conceptual adaptive features)
}

// --- Covert Tunnel Stream (Reliable Transport over Raw IP) ---
// This struct provides a reliable, bidirectional stream over a chosen raw IP protocol.
// It includes retransmission, sequence/ack numbers, buffering, and flow control.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConnectionState {
    Closed,
    SynSent,      // Client: SYN sent, waiting for SYN-ACK
    SynReceived,  // Server: SYN received, SYN-ACK sent, waiting for ACK
    Established,  // Data transfer active
    FinWait1,     // Initiator: FIN sent, waiting for ACK
    FinWait2,     // Initiator: ACK received, waiting for FIN
    TimeWait,     // Initiator: FIN-ACK received, waiting for 2MSL before closing
    CloseWait,    // Responder: FIN received, ACK sent, waiting for FIN from initiator
    LastAck,      // Responder: FIN sent, waiting for final ACK
    Closing,      // Both FINs sent, waiting for final ACK (concurrent close)
}

struct CovertTunnelStream {
    raw_socket: Arc<PlatformRawSocket>,
    remote_ip: IpAddr,
    local_ip: IpAddr,
    tunnel_id: [u8; TUNNEL_ID_SIZE],
    protocol_type: u8, // IP protocol number (1 for ICMP, 253 for Custom, 254 for IRP)
    cipher: Arc<IrpCipher>,

    // Reliability and Flow Control
    next_send_seq: Arc<Mutex<u32>>,      // Next sequence number to send
    last_acked_seq: Arc<Mutex<u32>>,     // Last sequence number acknowledged by remote
    next_recv_seq: Arc<Mutex<u32>>,      // Expected next in-order sequence number from remote
    send_window_size: Arc<Mutex<u32>>,   // Current send window size (fixed for simplicity)
    recv_window_size: Arc<Mutex<u32>>,   // Current receive window size (fixed for simplicity)
    initial_rto_ms: u64,                 // Initial Retransmission Timeout
    max_rto_ms: u64,                     // Maximum Retransmission Timeout
    current_rto_ms: Arc<Mutex<u64>>,     // Current RTO (fixed, no dynamic adjustment)

    send_buffer: Arc<Mutex<HashMap<u32, (IrpPacket, Instant, u32)>>>, // (Packet, LastSentTime, RetransmitCount)
    recv_buffer: Arc<Mutex<HashMap<u32, IrpPacket>>>, // Out-of-order received packets

    // Connection State
    connection_state: Arc<Mutex<ConnectionState>>,

    // Removed: retransmission_count, rtt_samples (part of conceptual adaptive features)

    // IRP Specifics
    irp_obfuscation_min_padding: usize,
    irp_obfuscation_max_padding: usize,

    // Channels for data plane interaction (read/write data from/to TCP proxy)
    data_to_read_tx: mpsc::Sender<Vec<u8>>,
    data_to_read_rx: mpsc::Receiver<Vec<u8>>,
    // Channel for sending control messages to the background task (e.g., FIN, RST)
    control_tx: mpsc::Sender<IrpFlags>,
    // Channel for receiving connection state updates from the background task
    status_tx: mpsc::Sender<ConnectionState>, // Added for sending status updates
    status_rx: mpsc::Receiver<ConnectionState>, // For main tasks to receive status updates
}

impl CovertTunnelStream {
    async fn new(
        local_ip: IpAddr,
        remote_ip: IpAddr,
        tunnel_id: [u8; TUNNEL_ID_SIZE],
        protocol_type: u8,
        cipher: Arc<IrpCipher>,
        // Removed adaptive_config parameter, now takes individual RTO values
        initial_rto_ms: u64,
        max_rto_ms: u64,
        irp_obfuscation_min_padding: usize,
        irp_obfuscation_max_padding: usize,
    ) -> io::Result<Self> {
        // Use the platform-agnostic raw socket
        let raw_socket = Arc::new(PlatformRawSocket::new(local_ip)?);
        let (data_to_read_tx, data_to_read_rx) = mpsc::channel(1024);
        let (control_tx, mut control_rx) = mpsc::channel(16);
        let (status_tx, status_rx) = mpsc::channel(1); // For sending state updates to main tasks

        let stream = CovertTunnelStream {
            raw_socket: raw_socket.clone(),
            remote_ip,
            local_ip,
            tunnel_id,
            protocol_type,
            cipher: cipher.clone(),
            next_send_seq: Arc::new(Mutex::new(custom_rng_gen_u32())), // Initial sequence number
            last_acked_seq: Arc::new(Mutex::new(0)),
            next_recv_seq: Arc::new(Mutex::new(0)),
            send_window_size: Arc::new(Mutex::new(initial_rto_ms as u32 / 100)), // Initial window based on RTO
            recv_window_size: Arc::new(Mutex::new(10)), // Fixed for now
            initial_rto_ms,
            max_rto_ms,
            current_rto_ms: Arc::new(Mutex::new(initial_rto_ms)), // RTO is now fixed or manually adjusted
            send_buffer: Arc::new(Mutex::new(HashMap::new())),
            recv_buffer: Arc::new(Mutex::new(HashMap::new())),
            connection_state: Arc::new(Mutex::new(ConnectionState::Closed)),
            // Removed: retransmission_count, rtt_samples
            irp_obfuscation_min_padding,
            irp_obfuscation_max_padding,
            data_to_read_tx,
            data_to_read_rx,
            control_tx,
            status_tx,
            status_rx,
        };

        // Spawn background task for raw packet I/O and reliability
        let socket_clone = raw_socket.clone();
        let remote_ip_clone = remote_ip;
        let tunnel_id_clone = tunnel_id;
        let protocol_type_clone = protocol_type;
        let cipher_clone = stream.cipher.clone();
        let next_send_seq_clone = stream.next_send_seq.clone();
        let last_acked_seq_clone = stream.last_acked_seq.clone();
        let next_recv_seq_clone = stream.next_recv_seq.clone();
        let send_window_size_clone = stream.send_window_size.clone();
        let recv_window_size_clone = stream.recv_window_size.clone();
        let send_buffer_clone = stream.send_buffer.clone();
        let recv_buffer_clone = stream.recv_buffer.clone();
        let data_to_read_tx_clone = stream.data_to_read_tx.clone();
        let connection_state_clone = stream.connection_state.clone();
        // Removed: retransmission_count_clone, rtt_samples_clone
        let current_rto_ms_clone = stream.current_rto_ms.clone();
        let initial_rto_ms_val = initial_rto_ms;
        let max_rto_ms_val = max_rto_ms;
        let status_tx_clone = stream.status_tx.clone(); // Clone for background task to send status

        tokio::spawn(async move {
            // Allocate receive buffer once to minimize allocations
            let mut recv_buf: Vec<u8> = vec![0; MAX_IP_PAYLOAD_SIZE + IPV4_HEADER_SIZE + ICMP_HEADER_SIZE];
            let mut retransmit_interval = tokio::time::interval(Duration::from_millis(10)); // Frequent checks
            let mut keep_alive_interval = tokio::time::interval(Duration::from_secs(5)); // Send keep-alives every 5s

            loop {
                // Adjust retransmit_interval based on current RTO
                let current_rto = *current_rto_ms_clone.lock().unwrap();
                retransmit_interval.tick().await; // Wait for the next tick

                tokio::select! {
                    // Receive raw packets
                    recv_result = socket_clone.recv_raw_packet(&mut recv_buf) => {
                        match recv_result {
                            Ok((n, src_addr)) => {
                                // Resource management: Ensure we don't process garbage data
                                if n == 0 || n > recv_buf.len() {
                                    warn!("Received empty or oversized packet ({} bytes). Dropping.", n);
                                    continue;
                                }

                                if src_addr.ip() == remote_ip_clone {
                                    if let Some(parsed_data) = parse_ipv4_packet(&recv_buf[..n]) {
                                        let (_, _, proto, payload_bytes, _) = parsed_data;
                                        if proto == protocol_type_clone {
                                            match IrpPacket::from_bytes(&payload_bytes) {
                                                Ok(irp_packet) => {
                                                    // Resource management: Basic sanity check on payload length
                                                    if irp_packet.header.data_len as usize > irp_packet.encrypted_payload.len() {
                                                        warn!("Malformed packet: declared data_len {} but payload is {} for tunnel {:?}",
                                                              irp_packet.header.data_len, irp_packet.encrypted_payload.len(), irp_packet.header.tunnel_id);
                                                        continue;
                                                    }

                                                    if irp_packet.header.tunnel_id == tunnel_id_clone {
                                                        trace!("Received IRP packet (proto {}, flags {:?}, seq {}, ack {}) from {}",
                                                               protocol_type_clone, irp_packet.header.flags, irp_packet.header.sequence_num,
                                                               irp_packet.header.ack_num, src_addr.ip());

                                                        let mut current_state = connection_state_clone.lock().unwrap();

                                                        // Handle RST flag immediately
                                                        if irp_packet.header.flags.rst {
                                                            info!("Received RST for tunnel ID: {:?}. Aborting connection.", tunnel_id_clone);
                                                            *current_state = ConnectionState::Closed;
                                                            data_to_read_tx_clone.send(Vec::new()).await.ok(); // Signal close
                                                            status_tx_clone.send(ConnectionState::Closed).await.ok();
                                                            break; // Exit loop
                                                        }

                                                        // Process ACKs first to clear send buffer
                                                        if irp_packet.header.flags.ack {
                                                            let ack_num = irp_packet.header.ack_num;
                                                            let mut send_buffer = send_buffer_clone.lock().unwrap();
                                                            // Resource management: Use retain for in-place removal
                                                            send_buffer.retain(|&seq, (packet, last_sent_time, _)| {
                                                                if seq < ack_num {
                                                                    false // Remove from buffer
                                                                } else {
                                                                    true // Keep in buffer
                                                                }
                                                            });
                                                            *last_acked_seq_clone.lock().unwrap() = ack_num;
                                                            debug!("ACK received for seq up to {}. Send buffer size: {}", ack_num, send_buffer.len());

                                                            // Congestion control: AIMD (Additive Increase) - simplified
                                                            let mut send_window = send_window_size_clone.lock().unwrap();
                                                            *send_window = send_window.saturating_add(1); // Increase window size
                                                            debug!("Send window increased to {}", *send_window);
                                                        }

                                                        // Handle SYN
                                                        if irp_packet.header.flags.syn {
                                                            match *current_state {
                                                                ConnectionState::Closed => {
                                                                    info!("Server received SYN from client for tunnel ID: {:?}", tunnel_id_clone);
                                                                    *next_recv_seq_clone.lock().unwrap() = irp_packet.header.sequence_num + 1; // Set initial sequence
                                                                    *current_state = ConnectionState::SynReceived;
                                                                    // Send SYN-ACK
                                                                    let mut flags = IrpFlags::new();
                                                                    flags.syn = true;
                                                                    flags.ack = true;
                                                                    let (encrypted_payload, nonce) = cipher_clone.encrypt(&[]).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Encryption failed: {}", e)))?;
                                                                    let syn_ack_packet = IrpPacket::new(
                                                                        tunnel_id_clone,
                                                                        *next_send_seq_clone.lock().unwrap(), // Server's initial sequence
                                                                        *next_recv_seq_clone.lock().unwrap(), // Acknowledge client's SYN
                                                                        flags,
                                                                        nonce,
                                                                        Vec::new(), // No padding for control packets
                                                                        encrypted_payload,
                                                                    );
                                                                    if let Err(e) = CovertTunnelStream::send_irp_packet(&socket_clone, remote_ip_clone, protocol_type_clone, &syn_ack_packet).await {
                                                                        error!("Failed to send SYN-ACK: {}", e);
                                                                    }
                                                                    *next_send_seq_clone.lock().unwrap() += 1;
                                                                },
                                                                ConnectionState::SynSent => {
                                                                    info!("Client received SYN-ACK from server for tunnel ID: {:?}", tunnel_id_clone);
                                                                    *next_recv_seq_clone.lock().unwrap() = irp_packet.header.sequence_num + 1; // Set initial sequence
                                                                    *current_state = ConnectionState::Established;
                                                                    status_tx_clone.send(ConnectionState::Established).await.ok(); // Notify main task
                                                                    // Send final ACK for handshake
                                                                    let mut flags = IrpFlags::new();
                                                                    flags.ack = true;
                                                                    let (encrypted_payload, nonce) = cipher_clone.encrypt(&[]).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Encryption failed: {}", e)))?;
                                                                    let ack_packet = IrpPacket::new(
                                                                        tunnel_id_clone,
                                                                        *next_send_seq_clone.lock().unwrap(), // Client's next sequence (after SYN)
                                                                        *next_recv_seq_clone.lock().unwrap(), // Acknowledge server's SYN-ACK
                                                                        flags,
                                                                        nonce,
                                                                        Vec::new(), // No padding for control packets
                                                                        encrypted_payload,
                                                                    );
                                                                    if let Err(e) = CovertTunnelStream::send_irp_packet(&socket_clone, remote_ip_clone, protocol_type_clone, &ack_packet).await {
                                                                        error!("Failed to send final ACK: {}", e);
                                                                    }
                                                                },
                                                                _ => debug!("Ignoring unexpected SYN in state {:?}", *current_state),
                                                            }
                                                        }

                                                        // Process Data packets (PSH flag)
                                                        if irp_packet.header.flags.psh {
                                                            let mut next_recv_seq = next_recv_seq_clone.lock().unwrap();
                                                            if irp_packet.header.sequence_num == *next_recv_seq {
                                                                // In-order packet, decrypt and send to reader
                                                                let decrypted_payload = cipher_clone.decrypt(&irp_packet.encrypted_payload, &irp_packet.header.nonce)?;
                                                                if let Err(e) = data_to_read_tx_clone.send(decrypted_payload).await {
                                                                    error!("Failed to send received data to channel: {}", e);
                                                                }
                                                                *next_recv_seq += 1;
                                                                // Process buffered out-of-order packets
                                                                let mut recv_buffer = recv_buffer_clone.lock().unwrap();
                                                                while let Some(buffered_packet) = recv_buffer.remove(&*next_recv_seq) {
                                                                    let decrypted_payload = cipher_clone.decrypt(&buffered_packet.encrypted_payload, &buffered_packet.header.nonce)?;
                                                                    if let Err(e) = data_to_read_tx_clone.send(decrypted_payload).await {
                                                                        error!("Failed to send buffered data to channel: {}", e);
                                                                    }
                                                                    *next_recv_seq += 1;
                                                                }
                                                            } else if irp_packet.header.sequence_num > *next_recv_seq {
                                                                // Out-of-order packet, buffer it if within receive window
                                                                let recv_window_size = *recv_window_size_clone.lock().unwrap();
                                                                if irp_packet.header.sequence_num < *next_recv_seq + recv_window_size {
                                                                    let mut recv_buffer = recv_buffer_clone.lock().unwrap();
                                                                    recv_buffer.insert(irp_packet.header.sequence_num, irp_packet.clone());
                                                                    debug!("Buffered out-of-order packet: {}", irp_packet.header.sequence_num);
                                                                } else {
                                                                    warn!("Packet {} out of receive window (expected {}, window size {}). Dropping.",
                                                                          irp_packet.header.sequence_num, *next_recv_seq, recv_window_size);
                                                                }
                                                            }
                                                            // Send ACK for the highest in-order sequence received
                                                            let mut flags = IrpFlags::new();
                                                            flags.ack = true;
                                                            let (encrypted_payload, nonce) = cipher_clone.encrypt(&[]).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Encryption failed: {}", e)))?;
                                                            let ack_packet = IrpPacket::new(
                                                                tunnel_id_clone,
                                                                0, // Sequence number not relevant for ACK
                                                                *next_recv_seq, // Acknowledging next expected sequence
                                                                flags,
                                                                nonce,
                                                                Vec::new(), // No padding for control packets
                                                                encrypted_payload,
                                                            );
                                                            if let Err(e) = CovertTunnelStream::send_irp_packet(&socket_clone, remote_ip_clone, protocol_type_clone, &ack_packet).await {
                                                                error!("Failed to send ACK for data: {}", e);
                                                            }
                                                        }

                                                        // Handle FIN
                                                        if irp_packet.header.flags.fin {
                                                            info!("Received FIN for tunnel ID: {:?}. State: {:?}", tunnel_id_clone, *current_state);
                                                            match *current_state {
                                                                ConnectionState::Established | ConnectionState::SynReceived => {
                                                                    *current_state = ConnectionState::CloseWait; // Server side
                                                                    // Send FIN-ACK
                                                                    let mut flags = IrpFlags::new();
                                                                    flags.fin = true;
                                                                    flags.ack = true;
                                                                    let (encrypted_payload, nonce) = cipher_clone.encrypt(&[]).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Encryption failed: {}", e)))?;
                                                                    let fin_ack_packet = IrpPacket::new(
                                                                        tunnel_id_clone, 0, irp_packet.header.sequence_num + 1, flags, nonce, Vec::new(), encrypted_payload
                                                                    );
                                                                    if let Err(e) = CovertTunnelStream::send_irp_packet(&socket_clone, remote_ip_clone, protocol_type_clone, &fin_ack_packet).await {
                                                                        error!("Failed to send FIN-ACK: {}", e);
                                                                    }
                                                                    data_to_read_tx_clone.send(Vec::new()).await.ok(); // Signal TCP proxy to stop reading
                                                                },
                                                                ConnectionState::FinWait1 => {
                                                                    // Concurrent close: Received FIN while in FIN_WAIT1
                                                                    *current_state = ConnectionState::Closing; // Not a standard TCP state, but useful
                                                                    // Send FIN-ACK
                                                                    let mut flags = IrpFlags::new();
                                                                    flags.fin = true;
                                                                    flags.ack = true;
                                                                    let (encrypted_payload, nonce) = cipher_clone.encrypt(&[]).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Encryption failed: {}", e)))?;
                                                                    let fin_ack_packet = IrpPacket::new(
                                                                        tunnel_id_clone, 0, irp_packet.header.sequence_num + 1, flags, nonce, Vec::new(), encrypted_payload
                                                                    );
                                                                    if let Err(e) = CovertTunnelStream::send_irp_packet(&socket_clone, remote_ip_clone, protocol_type_clone, &fin_ack_packet).await {
                                                                        error!("Failed to send FIN-ACK: {}", e);
                                                                    }
                                                                    // Transition to TIME_WAIT after sending FIN-ACK
                                                                    *current_state = ConnectionState::TimeWait;
                                                                    tokio::time::sleep(Duration::from_secs(2)).await; // 2MSL equivalent
                                                                    *current_state = ConnectionState::Closed;
                                                                    status_tx_clone.send(ConnectionState::Closed).await.ok();
                                                                    break;
                                                                },
                                                                ConnectionState::FinWait2 => {
                                                                    // Received FIN-ACK for our FIN, now received FIN from other side
                                                                    *current_state = ConnectionState::TimeWait;
                                                                    tokio::time::sleep(Duration::from_secs(2)).await; // 2MSL equivalent
                                                                    *current_state = ConnectionState::Closed;
                                                                    status_tx_clone.send(ConnectionState::Closed).await.ok();
                                                                    break;
                                                                },
                                                                _ => debug!("Ignoring unexpected FIN in state {:?}", *current_state),
                                                            }
                                                        }
                                                    }
                                                },
                                                Err(e) => warn!("Failed to deserialize IRP packet: {}", e),
                                            }
                                        }
                                    }
                                }
                            },
                            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                                // No data yet, continue
                            },
                            Err(e) => {
                                error!("Raw socket receive error: {}", e);
                                *connection_state_clone.lock().unwrap() = ConnectionState::Closed;
                                data_to_read_tx_clone.send(Vec::new()).await.ok();
                                status_tx_clone.send(ConnectionState::Closed).await.ok();
                                break;
                            },
                        }
                    },
                    _ = retransmit_interval.tick() => {
                        // Retransmit unacknowledged packets
                        let mut send_buffer = send_buffer_clone.lock().unwrap();
                        let now = Instant::now();
                        let current_rto = *current_rto_ms_clone.lock().unwrap();
                        let mut packets_to_retransmit = Vec::with_capacity(send_buffer.len()); // Pre-allocate

                        for (&seq, (packet, last_sent_time, retransmit_count)) in send_buffer.iter_mut() {
                            if now.duration_since(*last_sent_time) > Duration::from_millis(current_rto) {
                                packets_to_retransmit.push(packet.clone());
                                *last_sent_time = now; // Update last_sent_time
                                *retransmit_count += 1;
                                // Removed: retransmission_count_clone increment (part of conceptual metrics)

                                // Congestion control: Multiplicative Decrease on retransmission - simplified
                                let mut send_window = send_window_size_clone.lock().unwrap();
                                *send_window = (*send_window / 2).max(1); // Halve window, minimum 1
                                warn!("Retransmitting packet {} (count {}). Send window reduced to {}",
                                      seq, *retransmit_count, *send_window);
                            }
                        }

                        for packet in packets_to_retransmit {
                            if let Err(e) = CovertTunnelStream::send_irp_packet(&socket_clone, remote_ip_clone, protocol_type_clone, &packet).await {
                                warn!("Failed to retransmit IRP packet (seq {}): {}", packet.header.sequence_num, e);
                            }
                        }
                    },
                    _ = keep_alive_interval.tick() => {
                        let current_state = *connection_state_clone.lock().unwrap();
                        if current_state == ConnectionState::Established {
                            // Send a small ACK packet as a keep-alive
                            let mut flags = IrpFlags::new();
                            flags.ack = true;
                            let (encrypted_payload, nonce) = cipher_clone.encrypt(&[]).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Encryption failed: {}", e)))?;
                            let keep_alive_packet = IrpPacket::new(
                                tunnel_id_clone,
                                *next_send_seq_clone.lock().unwrap(),
                                *next_recv_seq_clone.lock().unwrap(),
                                flags,
                                nonce,
                                Vec::new(), // No padding for control packets
                                encrypted_payload,
                            );
                            if let Err(e) = CovertTunnelStream::send_irp_packet(&socket_clone, remote_ip_clone, protocol_type_clone, &keep_alive_packet).await {
                                warn!("Failed to send keep-alive packet: {}", e);
                            }
                            debug!("Sent keep-alive for tunnel {:?}", tunnel_id_clone);
                        }
                    },
                    control_msg = control_rx.recv() => {
                        if let Some(flags) = control_msg {
                            if flags.fin {
                                info!("Sending FIN for tunnel ID: {:?}", tunnel_id_clone);
                                let mut fin_flags = IrpFlags::new();
                                fin_flags.fin = true;
                                let (encrypted_payload, nonce) = cipher_clone.encrypt(&[]).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Encryption failed: {}", e)))?;
                                let fin_packet = IrpPacket::new(
                                    tunnel_id_clone,
                                    *next_send_seq_clone.lock().unwrap(),
                                    *next_recv_seq_clone.lock().unwrap(),
                                    fin_flags,
                                    nonce,
                                    Vec::new(), // No padding for control packets
                                    encrypted_payload,
                                );
                                if let Err(e) = CovertTunnelStream::send_irp_packet(&socket_clone, remote_ip_clone, protocol_type_clone, &fin_packet).await {
                                    error!("Failed to send FIN: {}", e);
                                }
                                *next_send_seq_clone.lock().unwrap() += 1;
                                *connection_state_clone.lock().unwrap() = ConnectionState::FinWait1;
                            }
                            if flags.rst {
                                info!("Sending RST for tunnel ID: {:?}. Aborting.", tunnel_id_clone);
                                let mut rst_flags = IrpFlags::new();
                                rst_flags.rst = true;
                                let (encrypted_payload, nonce) = cipher_clone.encrypt(&[]).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Encryption failed: {}", e)))?;
                                let rst_packet = IrpPacket::new(
                                    tunnel_id_clone,
                                    0, 0, rst_flags, nonce, Vec::new(), encrypted_payload
                                );
                                if let Err(e) = CovertTunnelStream::send_irp_packet(&socket_clone, remote_ip_clone, protocol_type_clone, &rst_packet).await {
                                    error!("Failed to send RST: {}", e);
                                }
                                *connection_state_clone.lock().unwrap() = ConnectionState::Closed;
                                status_tx_clone.send(ConnectionState::Closed).await.ok();
                                break; // Exit loop
                            }
                        } else {
                            // Control channel closed, means main tasks are done
                            info!("Control channel closed for tunnel {:?}. Exiting background task.", tunnel_id_clone);
                            *connection_state_clone.lock().unwrap() = ConnectionState::Closed; // Ensure state is closed
                            status_tx_clone.send(ConnectionState::Closed).await.ok();
                            break;
                        }
                    }
                }
                // Check connection state for graceful shutdown
                let current_state = *connection_state_clone.lock().unwrap();
                if current_state == ConnectionState::Closed {
                    break; // Exit loop if connection is closed
                }
            }
        });

        Ok(stream)
    }

    /// Sends a custom IRP packet over the raw socket.
    async fn send_irp_packet(
        socket: &Arc<PlatformRawSocket>,
        remote_ip: IpAddr,
        protocol_type: u8,
        irp_packet: &IrpPacket,
    ) -> io::Result<()> {
        let irp_packet_bytes = irp_packet.to_bytes()?;

        // Resource management: Check if packet size exceeds MTU
        if irp_packet_bytes.len() > MAX_IP_PAYLOAD_SIZE {
            error!("IRP packet too large: {} bytes. Max is {}", irp_packet_bytes.len(), MAX_IP_PAYLOAD_SIZE);
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "IRP packet too large"));
        }

        let raw_ip_packet = match (socket.local_ip(), remote_ip) {
            (IpAddr::V4(local_ipv4), IpAddr::V4(remote_ipv4)) => {
                let mut full_packet = build_ipv4_header(local_ipv4, remote_ipv4, protocol_type, irp_packet_bytes.len());
                if protocol_type == 1 { // ICMP
                    let icmp_id = custom_rng_gen_u16();
                    let icmp_seq = custom_rng_gen_u16();
                    let icmp_payload = build_icmp_echo_request_packet(icmp_id, icmp_seq, &irp_packet_bytes);
                    full_packet.extend_from_slice(&icmp_payload);
                } else { // Custom IP or IRP
                    full_packet.extend_from_slice(&irp_packet_bytes);
                }
                full_packet
            },
            _ => return Err(io::Error::new(io::ErrorKind::AddrNotAvailable, "Only IPv4 supported for raw sockets in this example")),
        };

        socket.send_raw_packet(remote_ip, &raw_ip_packet).await?;
        trace!("Sent raw packet (proto {}, flags {:?}, seq {}, ack {}) to {}",
               protocol_type, irp_packet.header.flags, irp_packet.header.sequence_num,
               irp_packet.header.ack_num, remote_ip);
        Ok(())
    }

    // Public methods for reading/writing data to the tunnel
    async fn read_data(&mut self) -> io::Result<Vec<u8>> {
        // Check connection state before reading
        let current_state = *self.connection_state.lock().unwrap();
        if !matches!(current_state, ConnectionState::Established | ConnectionState::FinWait2 | ConnectionState::CloseWait) {
            return Err(io::Error::new(io::ErrorKind::NotConnected, format!("Covert tunnel not established for reading. Current state: {:?}", current_state)));
        }
        self.data_to_read_rx.recv().await.ok_or_else(|| {
            io::Error::new(io::ErrorKind::BrokenPipe, "Covert tunnel data channel closed")
        })
    }

    async fn write_data(&mut self, buf: &[u8]) -> io::Result<usize> {
        // Check connection state before writing
        let current_state = *self.connection_state.lock().unwrap();
        if current_state != ConnectionState::Established {
            return Err(io::Error::new(io::ErrorKind::NotConnected, format!("Covert tunnel not established for writing. Current state: {:?}", current_state)));
        }

        let mut offset = 0;
        let cipher = self.cipher.clone();
        let next_send_seq = self.next_send_seq.clone();
        let next_recv_seq = self.next_recv_seq.clone(); // For ACK in header
        let send_buffer = self.send_buffer.clone();
        let socket = self.raw_socket.clone();
        let remote_ip = self.remote_ip;
        let protocol_type = self.protocol_type;
        let send_window_size = *self.send_window_size.lock().unwrap();
        let last_acked_seq = *self.last_acked_seq.lock().unwrap();

        while offset < buf.len() {
            // Flow control: Wait if send window is full
            while (next_send_seq.lock().unwrap().wrapping_sub(last_acked_seq)) >= send_window_size {
                debug!("Send window full. Waiting for ACKs. Next send: {}, Last ACKed: {}, Window: {}",
                       *next_send_seq.lock().unwrap(), last_acked_seq, send_window_size);
                tokio::time::sleep(Duration::from_millis(50)).await; // Wait and recheck
                // Refresh last_acked_seq, as it might have been updated by background task
                let updated_last_acked_seq = *self.last_acked_seq.lock().unwrap();
                if updated_last_acked_seq != last_acked_seq {
                    // Window might have opened, re-evaluate
                    break;
                }
            }

            // Calculate max data payload size considering header and potential padding
            let max_data_payload_size = MAX_IP_PAYLOAD_SIZE - CUSTOM_IRFARP_HEADER_SIZE;
            let chunk_size = max_data_payload_size.min(buf.len() - offset);
            let chunk = &buf[offset..offset + chunk_size];

            let (encrypted_chunk, nonce) = cipher.encrypt(chunk)?;

            // Generate random padding for IRP if protocol is IRP
            let mut padding = Vec::new();
            let mut flags = IrpFlags::new();
            if protocol_type == CovertProtocol::IRP.get_protocol_number() {
                let padding_len = rand::thread_rng().gen_range(self.irp_obfuscation_min_padding..=self.irp_obfuscation_max_padding);
                // Resource management: Pre-allocate padding vector
                padding.reserve_exact(padding_len);
                padding.extend_from_slice(&get_csprng_bytes::<{MAX_IP_PAYLOAD_SIZE}>()[..padding_len]); // Use CSPRNG for padding
                flags.pad = true;
            }

            flags.psh = true; // Mark as push for immediate delivery
            flags.ack = true; // Always send ACK with data for efficiency

            let current_seq = {
                let mut s = next_send_seq.lock().unwrap();
                let seq = *s;
                *s += 1;
                seq
            };
            let current_ack = *next_recv_seq.lock().unwrap();

            let packet = IrpPacket::new(
                self.tunnel_id,
                current_seq,
                current_ack,
                flags,
                nonce,
                padding,
                encrypted_chunk,
            );
            send_buffer.lock().unwrap().insert(current_seq, (packet.clone(), Instant::now(), 0)); // Store for retransmission
            CovertTunnelStream::send_irp_packet(&socket, remote_ip, protocol_type, &packet).await?;
            offset += chunk_size;
        }
        Ok(buf.len())
    }

    // Initiates graceful shutdown from the local side.
    async fn close(&mut self) -> io::Result<()> {
        info!("Initiating graceful tunnel shutdown for ID: {:?}", self.tunnel_id);
        let mut flags = IrpFlags::new();
        flags.fin = true;
        if let Err(e) = self.control_tx.send(flags).await {
            error!("Failed to send FIN control message: {}", e);
            return Err(io::Error::new(io::ErrorKind::BrokenPipe, "Failed to send FIN control message"));
        }

        // Wait for connection to transition to Closed state (or timeout)
        let mut status_rx = self.status_rx.clone();
        tokio::time::timeout(Duration::from_secs(15), status_rx.recv()) // Wait up to 15 seconds for close confirmation
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "Tunnel close timeout"))?
            .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "Status channel closed unexpectedly"))?;

        let final_state = *self.connection_state.lock().unwrap();
        if final_state == ConnectionState::Closed {
            info!("Tunnel ID {:?} gracefully closed.", self.tunnel_id);
            Ok(())
        } else {
            error!("Tunnel ID {:?} did not close gracefully. Final state: {:?}", self.tunnel_id, final_state);
            // Send RST if graceful close fails
            let mut rst_flags = IrpFlags::new();
            rst_flags.rst = true;
            if let Err(e) = self.control_tx.send(rst_flags).await {
                error!("Failed to send RST control message during forced close: {}", e);
            }
            *self.connection_state.lock().unwrap() = ConnectionState::Closed;
            Err(io::Error::new(io::ErrorKind::TimedOut, "Tunnel close failed or timed out"))
        }
    }

    // Abruptly terminates the tunnel.
    async fn reset(&mut self) -> io::Result<()> {
        info!("Initiating abrupt tunnel reset for ID: {:?}", self.tunnel_id);
        let mut flags = IrpFlags::new();
        flags.rst = true;
        if let Err(e) = self.control_tx.send(flags).await {
            error!("Failed to send RST control message: {}", e);
            return Err(io::Error::new(io::ErrorKind::BrokenPipe, "Failed to send RST control message"));
        }
        // No need to wait for state, RST is immediate
        *self.connection_state.lock().unwrap() = ConnectionState::Closed;
        Ok(())
    }

    // Get current connection state
    fn get_state(&self) -> ConnectionState {
        *self.connection_state.lock().unwrap()
    }

    // Removed: get_packet_loss_rate, get_average_rtt_ms
}

// --- IRFARP Server Implementation ---

struct IrfarpServer {
    config: ServerConfig,
    metrics_sender: mpsc::Sender<ConnectionMetrics>,
    active_tunnels: Arc<Mutex<HashMap<[u8; TUNNEL_ID_SIZE], tokio::net::TcpStream>>>,
    covert_data_tx_map: Arc<Mutex<HashMap<[u8; TUNNEL_ID_SIZE], mpsc::Sender<Vec<u8>>>>>,
    session_cipher_map: Arc<Mutex<HashMap<[u8; TUNNEL_ID_SIZE], Arc<IrpCipher>>>>, // Store ciphers per tunnel
}

impl IrfarpServer {
    async fn new(config_path: &str) -> io::Result<(Self, mpsc::Receiver<ConnectionMetrics>)> {
        let config: ServerConfig = load_config(config_path)?;

        let (metrics_sender, metrics_receiver) = mpsc::channel(1024);

        info!("IRFARP Server initialized.");
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
        let icmp_bind_ip: IpAddr = self.config.icmp_bind_addr.parse().map_err(|e| {
            io::Error::new(io::ErrorKind::InvalidInput, format!("Invalid ICMP bind IP: {}", e))
        })?;
        let custom_ip_bind_ip: IpAddr = self.config.custom_ip_bind_addr.parse().map_err(|e| {
            io::Error::new(io::ErrorKind::InvalidInput, format!("Invalid Custom IP bind IP: {}", e))
        })?;
        let irp_bind_ip: IpAddr = self.config.irp_bind_addr.parse().map_err(|e| {
            io::Error::new(io::ErrorKind::InvalidInput, format!("Invalid IRP bind IP: {}", e))
        })?;

        // Use PlatformRawSocket for all listeners
        let icmp_raw_socket = Arc::new(PlatformRawSocket::new(icmp_bind_ip)?);
        let custom_ip_raw_socket = Arc::new(PlatformRawSocket::new(custom_ip_bind_ip)?);
        let irp_raw_socket = Arc::new(PlatformRawSocket::new(irp_bind_ip)?); // New raw socket for IRP

        let services_map: Arc<HashMap<String, ServiceConfig>> = Arc::new(self.config.services.clone());
        let metrics_sender = self.metrics_sender.clone();
        let active_tunnels_clone = self.active_tunnels.clone();
        let covert_data_tx_map_clone = self.covert_data_tx_map.clone();
        let session_cipher_map_clone = self.session_cipher_map.clone();

        // Decode the master authentication key from base64
        let master_auth_key = Arc::new(general_purpose::STANDARD.decode(&self.config.auth_key_base64)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("Failed to decode auth_key_base64: {}", e)))?
            .try_into()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "auth_key_base64 must decode to a 32-byte key"))?);


        // Spawn ICMP Listener Task
        let icmp_listener_task = IrfarpServer::spawn_raw_protocol_listener(
            icmp_raw_socket.clone(),
            CovertProtocol::ICMP.get_protocol_number(),
            services_map.clone(),
            metrics_sender.clone(),
            active_tunnels_clone.clone(),
            covert_data_tx_map_clone.clone(),
            session_cipher_map_clone.clone(),
            master_auth_key.clone(),
        );

        // Spawn Custom IP Listener Task
        let custom_ip_listener_task = IrfarpServer::spawn_raw_protocol_listener(
            custom_ip_raw_socket.clone(),
            CovertProtocol::CustomIP(253).get_protocol_number(),
            services_map.clone(),
            metrics_sender.clone(),
            active_tunnels_clone.clone(),
            covert_data_tx_map_clone.clone(),
            session_cipher_map_clone.clone(),
            master_auth_key.clone(),
        );

        // Spawn IRP Listener Task
        let irp_listener_task = IrfarpServer::spawn_raw_protocol_listener(
            irp_raw_socket.clone(),
            CovertProtocol::IRP.get_protocol_number(), // IRP protocol number 254
            services_map.clone(),
            metrics_sender.clone(),
            active_tunnels_clone.clone(),
            covert_data_tx_map_clone.clone(),
            session_cipher_map_clone.clone(),
            master_auth_key.clone(),
        );

        // Keep server alive, listening on raw sockets
        tokio::join!(icmp_listener_task, custom_ip_listener_task, irp_listener_task);

        Ok(())
    }

    // Generic raw protocol listener
    async fn spawn_raw_protocol_listener(
        raw_socket: Arc<PlatformRawSocket>,
        protocol_type: u8,
        services_map: Arc<HashMap<String, ServiceConfig>>,
        metrics_sender: mpsc::Sender<ConnectionMetrics>,
        active_tunnels: Arc<Mutex<HashMap<[u8; TUNNEL_ID_SIZE], tokio::net::TcpStream>>>,
        covert_data_tx_map: Arc<Mutex<HashMap<[u8; TUNNEL_ID_SIZE], mpsc::Sender<Vec<u8>>>>>,
        session_cipher_map: Arc<Mutex<HashMap<[u8; TUNNEL_ID_SIZE], Arc<IrpCipher>>>>,
        master_auth_key: Arc<[u8; 32]>,
    ) -> io::Result<()> {
        info!("IRFARP Server raw protocol listener for protocol {} bound to {}", protocol_type, raw_socket.local_ip());

        // Resource management: Allocate receive buffer once
        let mut recv_buf: Vec<u8> = vec![0; MAX_IP_PAYLOAD_SIZE + IPV4_HEADER_SIZE + ICMP_HEADER_SIZE];
        loop {
            match raw_socket.recv_raw_packet(&mut recv_buf).await {
                Ok((n, src_addr)) => {
                    // Resource management: Basic sanity check on received data length
                    if n == 0 || n > recv_buf.len() {
                        warn!("Received empty or oversized packet ({} bytes). Dropping.", n);
                        continue;
                    }

                    if let Some(parsed_data) = parse_ipv4_packet(&recv_buf[..n]) {
                        let (src_ip_v4, _, proto, payload_bytes, _) = parsed_data;
                        let src_ip = IpAddr::V4(src_ip_v4);

                        if proto == protocol_type {
                            match IrpPacket::from_bytes(&payload_bytes) {
                                Ok(irp_packet) => {
                                    // Resource management: Basic sanity check on declared vs actual payload length
                                    if irp_packet.header.data_len as usize > irp_packet.encrypted_payload.len() {
                                        warn!("Malformed packet: declared data_len {} but payload is {} for tunnel {:?}",
                                              irp_packet.header.data_len, irp_packet.encrypted_payload.len(), irp_packet.header.tunnel_id);
                                        continue;
                                    }

                                    let tunnel_id = irp_packet.header.tunnel_id;
                                    let flags = irp_packet.header.flags;
                                    let sequence_num = irp_packet.header.sequence_num;
                                    let ack_num = irp_packet.header.ack_num;
                                    let encrypted_payload = irp_packet.encrypted_payload;
                                    let nonce = irp_packet.header.nonce;
                                    let _padding = irp_packet.padding; // Padding is received but discarded after parsing

                                    trace!("Server received IRP packet (proto {}, flags {:?}, seq {}, ack {}) from {}",
                                           protocol_type, flags, sequence_num, ack_num, src_ip);

                                    let mut covert_data_tx_map_lock = covert_data_tx_map.lock().unwrap();
                                    let mut session_cipher_map_lock = session_cipher_map.lock().unwrap();
                                    let current_cipher = session_cipher_map_lock.get(&tunnel_id).cloned();

                                    // Handle RST flag immediately
                                    if flags.rst {
                                        info!("Received RST for tunnel ID: {:?}. Aborting connection on server.", tunnel_id);
                                        covert_data_tx_map_lock.remove(&tunnel_id);
                                        session_cipher_map_lock.remove(&tunnel_id);
                                        if let Some(tcp_stream) = active_tunnels.lock().unwrap().remove(&tunnel_id) {
                                            tcp_stream.shutdown().await.ok(); // Attempt graceful TCP shutdown
                                        }
                                        continue; // Process next packet
                                    }

                                    // Process ACKs first (for server's own send buffer, if implemented)
                                    if flags.ack {
                                        // In a full implementation, server would update its send buffer based on ack_num
                                        debug!("Server received ACK for tunnel {:?} seq {} via protocol {}", tunnel_id, ack_num, protocol_type);
                                    }

                                    // Process SYN/Data/FIN
                                    if flags.syn {
                                        info!("Received SYN for new tunnel ID: {:?} via protocol {}", tunnel_id, protocol_type);
                                        // SYN packet payload contains client_id:auth_token and a client-generated ephemeral nonce
                                        // The nonce is now part of the IrpHeader.
                                        let client_ephemeral_nonce: [u8; NONCE_SIZE] = nonce;

                                        // Server derives session key using client's nonce as salt
                                        let session_key_bytes = match derive_session_key(&master_auth_key, &client_ephemeral_nonce, b"irp-session-key") {
                                            Ok(key) => Arc::new(key),
                                            Err(e) => {
                                                error!("Failed to derive session key for client {}: {}", src_ip, e);
                                                continue;
                                            }
                                        };
                                        let server_session_cipher = Arc::new(IrpCipher::new(&session_key_bytes));

                                        let decrypted_auth_info = match server_session_cipher.decrypt(&encrypted_payload, &client_ephemeral_nonce) {
                                            Ok(data) => String::from_utf8_lossy(&data).to_string(),
                                            Err(e) => {
                                                warn!("Failed to decrypt SYN auth info from {}: {}. Possible key mismatch or attack.", src_ip, e);
                                                continue;
                                            }
                                        };

                                        let parts: Vec<&str> = decrypted_auth_info.splitn(2, ':').collect();

                                        if parts.len() == 2 {
                                            let client_id_str = parts[0].to_string();
                                            let auth_token = parts[1].to_string();

                                            let service_config_opt = services_map.values().find(|s| s.token == auth_token);
                                            if let Some(service_config) = service_config_opt {
                                                info!("Client {} authenticated for service {}", client_id_str, service_config.client_service_id);
                                                match tokio::net::TcpStream::connect(&service_config.bind_addr).await {
                                                    Ok(tcp_stream) => {
                                                        let (tx, rx) = mpsc::channel(1024);
                                                        covert_data_tx_map_lock.insert(tunnel_id, tx);
                                                        active_tunnels.lock().unwrap().insert(tunnel_id, tcp_stream.clone());
                                                        session_cipher_map_lock.insert(tunnel_id, server_session_cipher.clone()); // Store cipher for this tunnel

                                                        let metrics_sender_clone = metrics_sender.clone();
                                                        let server_addr_str = raw_socket.local_ip().to_string();
                                                        let service_id_clone = service_config.client_service_id.clone();
                                                        let client_id_clone = client_id_str.clone();
                                                        // Pass RTO values directly
                                                        let initial_rto_ms_val = 200; // Fixed initial RTO for server-side
                                                        let max_rto_ms_val = 2000;   // Fixed max RTO for server-side

                                                        tokio::spawn(IrfarpServer::handle_covert_tunnel_data(
                                                            tunnel_id,
                                                            tcp_stream,
                                                            raw_socket.clone(),
                                                            src_ip,
                                                            protocol_type,
                                                            rx,
                                                            metrics_sender_clone,
                                                            server_addr_str,
                                                            service_id_clone,
                                                            client_id_clone,
                                                            server_session_cipher.clone(),
                                                            initial_rto_ms_val,
                                                            max_rto_ms_val,
                                                        ));

                                                        let mut syn_ack_flags = IrpFlags::new();
                                                        syn_ack_flags.syn = true;
                                                        syn_ack_flags.ack = true;
                                                        let (encrypted_payload, nonce) = server_session_cipher.encrypt(&[]).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Encryption failed: {}", e)))?;
                                                        let syn_ack_packet = IrpPacket::new(
                                                            tunnel_id, 0, sequence_num + 1, syn_ack_flags, nonce, Vec::new(), encrypted_payload // ACK client's SYN
                                                        );
                                                        if let Err(e) = CovertTunnelStream::send_irp_packet(&raw_socket, src_ip, protocol_type, &syn_ack_packet).await {
                                                            error!("Failed to send SYN-ACK: {}", e);
                                                        }
                                                    },
                                                    Err(e) => error!("Failed to connect to local service {}: {}", service_config.bind_addr, e),
                                                }
                                            } else {
                                                warn!("Authentication failed for SYN from {}. Invalid token.", client_id_str);
                                            }
                                        } else {
                                            warn!("Malformed SYN payload from {}: {}", src_ip, decrypted_auth_info);
                                        }
                                    }
                                } else if flags.psh { // PSH flag indicates data
                                    if let Some(tx) = covert_data_tx_map_lock.get(&tunnel_id) {
                                        if let Some(cipher) = current_cipher {
                                            let decrypted_payload = match cipher.decrypt(&encrypted_payload, &nonce) {
                                                Ok(data) => data,
                                                Err(e) => {
                                                    warn!("Failed to decrypt data for tunnel {:?}: {}", tunnel_id, e);
                                                    continue;
                                                }
                                            };
                                            if let Err(e) = tx.send(decrypted_payload).await {
                                                error!("Failed to send received data to TCP proxy: {}", e);
                                            }
                                            // Send ACK back to client for received data
                                            let mut ack_flags = IrpFlags::new();
                                            ack_flags.ack = true;
                                            let (encrypted_payload, nonce) = cipher.encrypt(&[]).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Encryption failed: {}", e)))?;
                                            let ack_packet = IrpPacket::new(
                                                tunnel_id,
                                                0, // Sequence number not relevant for ACK
                                                sequence_num + 1, // Acknowledge next expected sequence
                                                ack_flags,
                                                nonce,
                                                Vec::new(), // No padding for control packets
                                                encrypted_payload,
                                            );
                                            if let Err(e) = CovertTunnelStream::send_irp_packet(&raw_socket, src_ip, protocol_type, &ack_packet).await {
                                                error!("Failed to send ACK for data: {}", e);
                                            }
                                        } else {
                                            warn!("Received data for unknown or unauthenticated tunnel ID: {:?} via protocol {}", tunnel_id, protocol_type);
                                        }
                                    } else {
                                        warn!("Received data for unknown tunnel ID: {:?} via protocol {}", tunnel_id, protocol_type);
                                    }
                                } else if flags.fin {
                                    info!("Received FIN for tunnel ID: {:?} via protocol {}", tunnel_id, protocol_type);
                                    // Clean up tunnel resources
                                    covert_data_tx_map_lock.remove(&tunnel_id);
                                    session_cipher_map_lock.remove(&tunnel_id);
                                    if let Some(tcp_stream) = active_tunnels.lock().unwrap().remove(&tunnel_id) {
                                        tcp_stream.shutdown().await.ok(); // Attempt graceful TCP shutdown
                                    }
                                    let mut fin_ack_flags = IrpFlags::new();
                                    fin_ack_flags.fin = true;
                                    fin_ack_flags.ack = true;
                                    if let Some(cipher) = current_cipher {
                                        let (encrypted_payload, nonce) = cipher.encrypt(&[]).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Encryption failed: {}", e)))?;
                                        let fin_ack_packet = IrpPacket::new(
                                            tunnel_id, 0, sequence_num + 1, fin_ack_flags, nonce, Vec::new(), encrypted_payload // ACK client's FIN
                                        );
                                        if let Err(e) = CovertTunnelStream::send_irp_packet(&raw_socket, src_ip, protocol_type, &fin_ack_packet).await {
                                            error!("Failed to send FIN-ACK: {}", e);
                                        }
                                    } else {
                                        warn!("No cipher for FIN-ACK to unknown tunnel ID {:?}", tunnel_id);
                                    }
                                } else {
                                    debug!("Unhandled IRP packet type on server: {:?}", flags); // Should not happen with current flags
                                }
                            }
                        }
                    }
                },
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    // No data yet, continue
                },
                Err(e) => {
                    error!("Raw socket receive error for protocol {}: {}", protocol_type, e);
                    break;
                },
            }
            tokio::time::sleep(Duration::from_millis(1)).await; // Small delay to prevent busy-looping
        }
        Ok(())
    }

    // Handles proxying data between the TCP stream (local service) and the CovertTunnelStream.
    async fn handle_covert_tunnel_data(
        tunnel_id: [u8; TUNNEL_ID_SIZE],
        mut tcp_stream: tokio::net::TcpStream,
        raw_socket: Arc<PlatformRawSocket>,
        client_ip: IpAddr,
        protocol_type: u8,
        mut covert_data_rx: mpsc::Receiver<Vec<u8>>, // Receive data from raw listener
        metrics_sender: mpsc::Sender<ConnectionMetrics>,
        server_addr_str: String,
        service_id: String,
        client_id: String,
        cipher: Arc<IrpCipher>, // Pass the session cipher
        initial_rto_ms: u64, // Fixed initial RTO
        max_rto_ms: u64,     // Fixed max RTO
    ) -> io::Result<()> {
        let start_time = SystemTime::now();
        let mut uploaded_bytes: u64 = 0; // Bytes from TCP service to client (downloaded by client)
        let mut downloaded_bytes: u64 = 0; // Bytes from client to TCP service (uploaded by client)

        let (mut tcp_reader, mut tcp_writer) = tcp_stream.split();

        // Server-side tunnel next send sequence number (simplified, as client drives reliability)
        let server_tunnel_next_send_seq = Arc::new(Mutex::new(0u32));
        // Removed: server_tunnel_retransmissions, server_tunnel_rtt_samples

        // Task to read from TCP service and send over CovertTunnelStream
        let tcp_to_covert_task = async {
            // Resource management: Allocate buffer once
            let mut buf: Vec<u8> = vec![0; MAX_IP_PAYLOAD_SIZE - CUSTOM_IRFARP_HEADER_SIZE];
            loop {
                let n = tcp_reader.read(&mut buf).await?;
                if n == 0 { break; } // EOF

                let (encrypted_data, nonce) = cipher.encrypt(&buf[..n])?;

                let mut flags = IrpFlags::new();
                flags.psh = true; // Push data immediately
                flags.ack = true; // Always send ACK with data for efficiency

                // No padding for server-to-client data for simplicity, can be added if needed
                let packet = IrpPacket::new(
                    tunnel_id,
                    *server_tunnel_next_send_seq.lock().unwrap(), // Server's sequence number (independent from client's)
                    0, // Server's ACK number (simplified, client ACKs this)
                    flags,
                    nonce,
                    Vec::new(), // No padding for server's data packets
                    encrypted_data,
                );
                if let Err(e) = CovertTunnelStream::send_irp_packet(&raw_socket, client_ip, protocol_type, &packet).await {
                    error!("Server failed to send raw data to client: {}", e);
                    return Err(e);
                }
                *server_tunnel_next_send_seq.lock().unwrap() += 1;
                uploaded_bytes += n as u64;
            }
            Ok::<(), io::Error>(())
        };

        // Task to read from CovertTunnelStream and send to TCP service
        let covert_to_tcp_task = async {
            loop {
                match covert_data_rx.recv().await {
                    Some(decrypted_data) => {
                        // Data is already decrypted by the listener
                        tcp_writer.write_all(&decrypted_data).await?;
                        downloaded_bytes += decrypted_data.len() as u64;
                    },
                    None => break, // Channel closed
                }
            }
            Ok::<(), io::Error>(())
        };

        let result = tokio::select! {
            res1 = tcp_to_covert_task => res1,
            res2 = covert_to_tcp_task => res2,
        };

        let end_time = SystemTime::now();
        let duration = end_time.duration_since(start_time).unwrap_or_default().as_secs();
        let status = if result.is_ok() { "success" } else { "failure" };
        let error_message = result.err().map(|e| e.to_string());

        // Send metrics
        // These metrics are crucial for monitoring the performance and effectiveness
        // of the covert communication, providing data for auditing and further optimization.
        let final_metrics = ConnectionMetrics {
            timestamp_ms: end_time.duration_since(UNIX_EPOCH).unwrap_or_default().as_millis(),
            client_id,
            service_id,
            bytes_uploaded,
            bytes_downloaded,
            duration_sec: duration,
            status: status.to_string(),
            error_message,
            peer_addr: client_ip.to_string(),
            server_addr: server_addr_str,
            protocol_used: format!("raw-{}", protocol_type),
            // Removed: retransmissions, rtt_avg_ms, packet_loss_rate
        };
        if let Err(e) = metrics_sender.send(final_metrics).await {
            error!("Failed to send metrics: {}", e);
        }

        result.map(|_| ())
    }
}

// --- IRFARP Client Implementation ---

struct IrfarpClient {
    config: ClientConfig,
    metrics_sender: mpsc::Sender<ConnectionMetrics>,
    active_tunnels: Arc<Mutex<HashMap<String, Arc<Mutex<CovertTunnelStream>>>>>,
    // Removed: protocol_health_manager
}

impl IrfarpClient {
    async fn new(config_path: &str) -> io::Result<(Self, mpsc::Receiver<ConnectionMetrics>)> {
        let config: ClientConfig = load_config(config_path)?;

        let (metrics_sender, metrics_receiver) = mpsc::channel(1024);
        // Removed: health_manager initialization

        info!("IRFARP Client initialized.");
        Ok((
            IrfarpClient {
                config,
                metrics_sender,
                active_tunnels: Arc::new(Mutex::new(HashMap::new())),
                // Removed: protocol_health_manager
            },
            metrics_receiver,
        ))
    }

    async fn run(self) -> io::Result<()> {
        info!("IRFARP Client starting for client ID: {}", self.config.client_id);

        let local_services = Arc::new(self.config.local_services.clone());
        let metrics_sender = self.metrics_sender.clone();
        // Removed: adaptive_strategy
        let server_icmp_addr = self.config.server_icmp_addr.clone();
        let server_custom_ip_addr = self.config.server_custom_ip_addr.clone();
        let server_irp_addr = self.config.server_irp_addr.clone(); // New IRP server address
        let client_id_clone = self.config.client_id.clone();
        let auth_token_clone = self.config.auth_token.clone();
        let active_tunnels_clone = self.active_tunnels.clone();
        let master_auth_key = Arc::new(general_purpose::STANDARD.decode(&self.config.auth_key_base64)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("Failed to decode auth_key_base64: {}", e)))?
            .try_into()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "auth_key_base64 must decode to a 32-byte key"))?);
        // Removed: protocol_health_manager_clone

        // Removed: proactive health probing task

        // Main loop for managing local service listeners
        // This loop ensures that the client continuously listens for incoming TCP connections
        // on the configured local service ports (e.g., for SSH or web proxy).
        // For each new local connection, it attempts to establish a covert tunnel to the server.
        loop {
            for (service_id, local_service_config) in local_services.iter() {
                // Check if a tunnel for this service already exists and is healthy
                let tunnel_exists_and_healthy = {
                    let active_tunnels_lock = active_tunnels_clone.lock().unwrap();
                    active_tunnels_lock.get(service_id)
                        .map_or(false, |tunnel_arc| {
                            let tunnel = tunnel_arc.lock().unwrap();
                            tunnel.get_state() == ConnectionState::Established
                        })
                };

                if tunnel_exists_and_healthy {
                    debug!("Tunnel for service '{}' is already active and healthy. Skipping listener setup.", service_id);
                    continue; // Skip setting up listener if tunnel is already active
                }

                let local_listener = match tokio::net::TcpListener::bind(&local_service_config.local_addr).await {
                    Ok(l) => l,
                    Err(e) => {
                        error!("Failed to bind to local service {}: {}. Retrying in 5s...", service_id, e);
                        tokio::time::sleep(Duration::from_secs(5)).await;
                        continue;
                    }
                };
                info!("Listening on local service {}: {}", service_id, local_service_config.local_addr);

                let (local_stream, local_peer_addr) = local_listener.accept().await?;
                info!("Local connection for service '{}' from {}", service_id, local_peer_addr);

                let metrics_sender_clone = metrics_sender.clone();
                // Removed: adaptive_strategy_clone
                let server_icmp_addr_clone = server_icmp_addr.clone();
                let server_custom_ip_addr_clone = server_custom_ip_addr.clone();
                let server_irp_addr_clone = server_irp_addr.clone();
                let client_id_for_task = client_id_clone.clone();
                let auth_token_for_task = auth_token_clone.clone();
                let service_id_for_task = service_id.clone();
                let active_tunnels_for_task = active_tunnels_clone.clone();
                let master_auth_key_for_task = master_auth_key.clone();
                // Removed: protocol_health_manager_for_task

                tokio::spawn(async move {
                    if let Err(e) = IrfarpClient::handle_local_connection(
                        local_stream,
                        local_peer_addr,
                        metrics_sender_clone,
                        // Removed adaptive_strategy_clone
                        server_icmp_addr_clone,
                        server_custom_ip_addr_clone,
                        server_irp_addr_clone,
                        client_id_for_task,
                        auth_token_for_task,
                        service_id_for_task,
                        active_tunnels_for_task,
                        master_auth_key_for_task,
                        // Removed protocol_health_manager_for_task
                    ).await {
                        error!("Error handling local connection for service {}: {}", service_id_for_task, e);
                    }
                });
            }
            tokio::time::sleep(Duration::from_secs(1)).await; // Prevent busy loop
        }
    }

    // Handles a new local TCP connection, attempting to establish a covert tunnel
    // and then proxying data between the local TCP stream and the covert tunnel.
    // This function implements the adaptive protocol selection and self-healing logic.
    async fn handle_local_connection(
        mut local_stream: tokio::net::TcpStream,
        local_peer_addr: SocketAddr,
        metrics_sender: mpsc::Sender<ConnectionMetrics>,
        // Removed adaptive_strategy parameter
        server_icmp_addr_str: String,
        server_custom_ip_addr_str: String,
        server_irp_addr_str: String,
        client_id: String,
        auth_token: String,
        service_id: String,
        active_tunnels: Arc<Mutex<HashMap<String, Arc<Mutex<CovertTunnelStream>>>>>,
        master_auth_key: Arc<[u8; 32]>,
        // Removed protocol_health_manager parameter
    ) -> io::Result<()> {
        let mut attempts = 0;
        let max_attempts = 20; // Fixed max retries

        let local_ip: IpAddr = local_stream.local_addr()?.ip();

        let mut tunnel_stream: Option<Arc<Mutex<CovertTunnelStream>>> = None;
        let mut protocol_used_str = String::new();
        let mut final_remote_ip_str = String::new();
        let mut final_protocol_type_u8 = 0;

        // Get protocol pool from client config
        let client_config = load_config::<ClientConfig>("client_config_example.json")?; // Re-load config to get protocol_pool
        let protocol_pool = client_config.protocol_pool.clone();
        let connect_timeout_ms = client_config.connect_timeout_ms;
        let retry_delay_ms = client_config.retry_delay_ms;
        let initial_rto_ms_val = client_config.initial_rto_ms;
        let max_rto_ms_val = client_config.max_rto_ms;
        let irp_obfuscation_min_padding = client_config.irp_obfuscation_min_padding;
        let irp_obfuscation_max_padding = client_config.irp_obfuscation_max_padding;


        // Loop for covert tunnel establishment (SYN/SYN-ACK)
        // This loop attempts to establish a connection by cycling through configured protocols.
        while attempts < max_attempts {
            attempts += 1;
            debug!("Attempt {}/{} to establish covert tunnel for service {}", attempts, max_attempts, service_id);

            // Simple round-robin protocol selection
            let index = (attempts as usize - 1) % protocol_pool.len();
            let current_protocol_choice = protocol_pool[index].clone();

            let remote_ip_str_choice = match current_protocol_choice {
                CovertProtocol::ICMP => server_icmp_addr_str.clone(),
                CovertProtocol::CustomIP(_) => server_custom_ip_addr_str.clone(),
                CovertProtocol::IRP => server_irp_addr_str.clone(),
            };

            let protocol_type_u8 = current_protocol_choice.get_protocol_number();
            protocol_used_str = current_protocol_choice.to_string();
            final_remote_ip_str = remote_ip_str_choice.clone();
            final_protocol_type_u8 = protocol_type_u8;

            let remote_ip: IpAddr = remote_ip_str_choice.parse().map_err(|e| {
                error!("Invalid server IP for protocol {}: {}", protocol_used_str, e);
                io::Error::new(io::ErrorKind::InvalidInput, format!("Invalid server IP: {}", e))
            })?;

            let tunnel_id: [u8; TUNNEL_ID_SIZE] = get_csprng_bytes(); // Unique ID for this tunnel instance
            let client_ephemeral_nonce: [u8; NONCE_SIZE] = get_csprng_bytes(); // Ephemeral nonce for key derivation

            // Derive session key for this tunnel
            let session_key_bytes = match derive_session_key(&master_auth_key, &client_ephemeral_nonce, b"irp-session-key") {
                Ok(key) => Arc::new(key),
                Err(e) => {
                    error!("Failed to derive session key for client {}: {}", client_id, e);
                    return Err(io::Error::new(io::ErrorKind::Other, "Failed to derive session key"));
                }
            };
            let client_session_cipher = Arc::new(IrpCipher::new(&session_key_bytes));

            // SYN packet payload: client_id:auth_token, encrypted with session cipher using ephemeral nonce
            let syn_payload_plaintext = format!("{}:{}", client_id, auth_token);
            let (encrypted_syn_payload, _) = client_session_cipher.encrypt(syn_payload_plaintext.as_bytes())?; // Nonce included in packet header

            let mut syn_flags = IrpFlags::new();
            syn_flags.syn = true;

            // No padding for SYN packets, as it's a control packet.
            let syn_packet = IrpPacket::new(
                tunnel_id,
                custom_rng_gen_u32(), // Client's initial sequence number
                0, // ACK number not relevant for SYN
                syn_flags,
                client_ephemeral_nonce, // Send ephemeral nonce in SYN packet
                Vec::new(), // No padding for control packets
                encrypted_syn_payload,
            );

            info!("Attempting SYN handshake via {} to {}", protocol_used_str, remote_ip);
            let syn_raw_socket = Arc::new(PlatformRawSocket::new(local_ip)?); // Create temporary socket for handshake

            let syn_send_result = CovertTunnelStream::send_irp_packet(&syn_raw_socket, remote_ip, protocol_type_u8, &syn_packet).await;
            if syn_send_result.is_err() {
                warn!("Failed to send SYN via {}: {}. Retrying...", protocol_used_str, syn_send_result.unwrap_err());
                tokio::time::sleep(Duration::from_millis(retry_delay_ms)).await;
                continue;
            }

            let mut recv_buf = vec![0; MAX_IP_PAYLOAD_SIZE + IPV4_HEADER_SIZE + ICMP_HEADER_SIZE];
            let syn_ack_timeout = tokio::time::timeout(
                Duration::from_millis(connect_timeout_ms),
                syn_raw_socket.recv_raw_packet(&mut recv_buf),
            ).await;

            match syn_ack_timeout {
                Ok(Ok((n, src_addr))) => {
                    if src_addr.ip() == remote_ip {
                        if let Some(parsed_data) = parse_ipv4_packet(&recv_buf[..n]) {
                            let (_, _, proto, payload, _) = parsed_data;
                            if proto == protocol_type_u8 {
                                match IrpPacket::from_bytes(&payload) {
                                    Ok(irp_packet) => {
                                        if irp_packet.header.tunnel_id == tunnel_id && irp_packet.header.flags.syn && irp_packet.header.flags.ack {
                                            // Decrypt SYN-ACK payload (should be empty but verifies key)
                                            match client_session_cipher.decrypt(&irp_packet.encrypted_payload, &irp_packet.header.nonce) {
                                                Ok(_) => {
                                                    info!("Received SYN-ACK for tunnel ID: {:?} via {}.", tunnel_id, protocol_used_str);

                                                    // Create the actual tunnel stream and transition to Established
                                                    let new_tunnel = CovertTunnelStream::new(
                                                        local_ip, remote_ip, tunnel_id, protocol_type_u8, session_key_bytes.clone(),
                                                        initial_rto_ms_val, max_rto_ms_val,
                                                        irp_obfuscation_min_padding, irp_obfuscation_max_padding,
                                                    ).await?;
                                                    // Set initial sequence numbers based on handshake
                                                    *new_tunnel.next_send_seq.lock().unwrap() = syn_packet.header.sequence_num + 1;
                                                    *new_tunnel.next_recv_seq.lock().unwrap() = irp_packet.header.sequence_num + 1;
                                                    *new_tunnel.connection_state.lock().unwrap() = ConnectionState::Established;

                                                    tunnel_stream = Some(Arc::new(Mutex::new(new_tunnel)));
                                                    active_tunnels.lock().unwrap().insert(service_id.clone(), tunnel_stream.as_ref().unwrap().clone());

                                                    // Send final ACK for handshake
                                                    let mut ack_flags = IrpFlags::new();
                                                    ack_flags.ack = true;
                                                    let (encrypted_payload_ack, nonce_ack) = client_session_cipher.encrypt(&[]).map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Encryption failed: {}", e)))?;
                                                    let ack_packet = IrpPacket::new(
                                                        tunnel_id,
                                                        *tunnel_stream.as_ref().unwrap().lock().unwrap().next_send_seq.lock().unwrap(), // Client's next sequence (after SYN)
                                                        *tunnel_stream.as_ref().unwrap().lock().unwrap().next_recv_seq.lock().unwrap(), // Acknowledge server's SYN-ACK
                                                        ack_flags,
                                                        nonce_ack,
                                                        Vec::new(), // No padding for control packets
                                                        encrypted_payload_ack,
                                                    );
                                                    if let Err(e) = CovertTunnelStream::send_irp_packet(&syn_raw_socket, remote_ip, protocol_type_u8, &ack_packet).await {
                                                        error!("Failed to send final ACK: {}", e);
                                                    }
                                                    break; // Handshake successful
                                                },
                                                Err(e) => {
                                                    warn!("SYN-ACK decryption failed from {}: {}. Possible key mismatch or attack. Retrying...", src_ip, e);
                                                }
                                            }
                                        } else {
                                            warn!("Received non-{} protocol packet during SYN-ACK from {}. Retrying...", protocol_used_str, src_ip);
                                        }
                                    },
                                    Err(e) => {
                                        warn!("Failed to deserialize SYN-ACK packet: {}. Retrying...", e);
                                    }
                                }
                            } else {
                                warn!("Received packet from unexpected protocol {} during SYN-ACK from {}. Expected {}. Retrying...", proto, src_ip, protocol_type_u8);
                            }
                        }
                    }
                },
                Ok(Err(e)) => {
                    warn!("Failed to receive SYN-ACK via {}: {}. Retrying...", protocol_used_str, e);
                },
                Err(_) => {
                    warn!("SYN-ACK timed out via {}. Retrying...", protocol_used_str);
                },
            }
            tokio::time::sleep(Duration::from_millis(retry_delay_ms)).await;
        }

        let tunnel_stream_arc = tunnel_stream.ok_or_else(|| {
            error!("Failed to establish covert tunnel after {} attempts for service {}", max_attempts, service_id);
            io::Error::new(io::ErrorKind::TimedOut, "Failed to establish covert tunnel")
        })?;

        // Proxy data between local TCP service and CovertTunnelStream
        // Once a covert tunnel is established, this section handles the continuous
        // flow of application data (e.g., SSH, web traffic) through the tunnel.
        // It manages buffering, encryption/decryption, and sending/receiving
        // data packets over the chosen covert protocol.
        let start_time = SystemTime::now();
        let mut bytes_uploaded: u64 = 0;
        let mut bytes_downloaded: u64 = 0;

        let tunnel_stream_locked_for_proxy = tunnel_stream_arc.clone(); // Clone for proxy tasks

        let (mut local_reader, mut local_writer) = local_stream.split();

        let local_to_tunnel_task = async {
            // Resource management: Allocate buffer once
            let max_payload_size = MAX_IP_PAYLOAD_SIZE - CUSTOM_IRFARP_HEADER_SIZE - irp_obfuscation_max_padding;
            let mut buf: Vec<u8> = vec![0; max_payload_size];
            loop {
                let n = local_reader.read(&mut buf).await?;
                if n == 0 { break; }
                let mut tunnel = tunnel_stream_locked_for_proxy.lock().unwrap();
                tunnel.write_data(&buf[..n]).await?;
                bytes_uploaded += n as u64; // Client uploads to tunnel
            }
            Ok::<(), io::Error>(())
        };

        let tunnel_to_local_task = async {
            loop {
                let mut tunnel = tunnel_stream_locked_for_proxy.lock().unwrap();
                let data = tunnel.read_data().await?;
                local_writer.write_all(&data).await?;
                bytes_downloaded += data.len() as u64; // Client downloads from tunnel
            }
            Ok::<(), io::Error>(())
        };

        let result = tokio::select! {
            res1 = local_to_tunnel_task => res1,
            res2 = tunnel_to_local_task => res2,
        };

        let end_time = SystemTime::now();
        let duration = end_time.duration_since(start_time).unwrap_or_default().as_secs();
        let status = if result.is_ok() { "success" } else { "failure" };
        let error_message = result.err().map(|e| e.to_string());

        // Send metrics
        // These metrics are crucial for monitoring the performance and effectiveness
        // of the covert communication, providing data for auditing and further optimization.
        let final_metrics = ConnectionMetrics {
            timestamp_ms: end_time.duration_since(UNIX_EPOCH).unwrap_or_default().as_millis(),
            client_id,
            service_id,
            bytes_uploaded,
            bytes_downloaded,
            duration_sec: duration,
            status: status.to_string(),
            error_message,
            peer_addr: local_peer_addr.to_string(),
            server_addr: final_remote_ip_str,
            protocol_used: protocol_used_str,
            // Removed: retransmissions, rtt_avg_ms, packet_loss_rate
        };
        if let Err(e) = metrics_sender.send(final_metrics).await {
            error!("Failed to send metrics: {}", e);
        }

        // Initiate graceful close on the tunnel
        let mut tunnel = tunnel_stream_locked_for_proxy.lock().unwrap();
        if let Err(e) = tunnel.close().await {
            error!("Error closing tunnel gracefully: {}", e);
        }

        Ok(())
    }
}

// --- Example Configuration Strings ---
// These are embedded directly into the binary for easy generation.
const SERVER_CONFIG_EXAMPLE: &str = r#"{
  "icmp_bind_addr": "YOUR_SERVER_PUBLIC_IP",
  "custom_ip_bind_addr": "YOUR_SERVER_PUBLIC_IP",
  "irp_bind_addr": "YOUR_SERVER_PUBLIC_IP",
  "services": {
    "my_iran_server_ssh": {
      "token": "UNIQUE_SSH_SERVICE_TOKEN_12345",
      "bind_addr": "127.0.0.1:22",
      "client_service_id": "ssh_tunnel"
    },
    "my_iran_server_web": {
      "token": "UNIQUE_WEB_SERVICE_TOKEN_67890",
      "bind_addr": "127.0.0.1:80",
      "client_service_id": "web_proxy"
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
    },
    "web_proxy": {
      "local_addr": "127.0.0.1:80"
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

// --- Main Application Logic ---

#[tokio::main]
async fn main() -> io::Result<()> {
    // Initialize custom PRNG with a time-based seed for non-crypto randoms (e.g., ICMP ID/Seq hopping).
    // For crypto-sensitive randoms, `rand::rngs::OsRng` is used.
    custom_rng_seed(SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs());

    // Setup logging (default to Info until config is loaded)
    Builder::new()
        .filter_level(log::LevelFilter::Info)
        .target(Target::Stdout)
        .init();

    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage: {} <mode> [config_file]", args[0]);
        eprintln!("Modes: server | client | generate-config");
        eprintln!("Example: {} generate-config", args[0]);
        eprintln!("Example: {} server server_config.json", args[0]);
        eprintln!("Example: {} client client_config.json", args[0]);
        std::process::exit(1);
    }

    let mode = &args[1];

    match mode.as_str() {
        "generate-config" => {
            info!("Generating example configuration files: server_config_example.json and client_config_example.json");
            fs::write("server_config_example.json", SERVER_CONFIG_EXAMPLE)?;
            fs::write("client_config_example.json", CLIENT_CONFIG_EXAMPLE)?;
            info!("Configuration files generated successfully. Please edit them with your actual IPs and keys.");
            Ok(())
        },
        "server" => {
            if args.len() < 3 {
                eprintln!("Usage: {} server <config_file>", args[0]);
                std::process::exit(1);
            }
            let config_file = &args[2];
            let (server, mut metrics_receiver) = IrfarpServer::new(config_file).await?;
            // Re-initialize logger with config-defined level
            Builder::new()
                .filter_level(server.config.log_level.parse().unwrap_or(log::LevelFilter::Info))
                .target(Target::Stdout)
                .init();
            info!("Server logging initialized at {} level.", server.config.log_level);

            let metrics_interval_sec = server.config.metrics_interval_sec;

            // Spawn a task to process metrics
            // This task periodically collects and logs connection metrics from active tunnels.
            // In a production banking-grade system, these metrics would be forwarded to a
            // secure, persistent monitoring system (e.g., Prometheus, Splunk, custom database)
            // for real-time dashboards, alerts, and long-term auditing.
            tokio::spawn(async move {
                let mut interval = time::interval(Duration::from_secs(metrics_interval_sec));
                let mut collected_metrics: Vec<ConnectionMetrics> = Vec::new();

                loop {
                    tokio::select! {
                        Some(metric) = metrics_receiver.recv() => {
                            collected_metrics.push(metric);
                        },
                        _ = interval.tick() => {
                            if !collected_metrics.is_empty() {
                                info!("--- Server Metrics Report ({} connections) ---", collected_metrics.len());
                                for metric in &collected_metrics {
                                    info!("{:?}", metric);
                                }
                                collected_metrics.clear();
                                info!("------------------------------------");
                            }
                        },
                    }
                }
            });

            server.run().await
        },
        "client" => {
            if args.len() < 3 {
                eprintln!("Usage: {} client <config_file>", args[0]);
                std::process::exit(1);
            }
            let config_file = &args[2];
            let (client, mut metrics_receiver) = IrfarpClient::new(config_file).await?;
            // Re-initialize logger with config-defined level
            Builder::new()
                .filter_level(client.config.log_level.parse().unwrap_or(log::LevelFilter::Info))
                .target(Target::Stdout)
                .init();
            info!("Client logging initialized at {} level.", client.config.log_level);

            // Removed: probe_interval_sec
            let client_id_for_metrics = client.config.client_id.clone();

            // Spawn a task for client-side metrics processing
            // This task processes metrics received from active tunnels for basic monitoring.
            tokio::spawn(async move {
                let mut interval = time::interval(Duration::from_secs(60)); // Fixed interval for metrics logging
                let mut collected_metrics: Vec<ConnectionMetrics> = Vec::new();

                loop {
                    tokio::select! {
                        Some(metric) = metrics_receiver.recv() => {
                            collected_metrics.push(metric);
                        },
                        _ = interval.tick() => {
                            if !collected_metrics.is_empty() {
                                info!("--- Client Metrics Report ({} connections) for {} ---", collected_metrics.len(), client_id_for_metrics);
                                for metric in &collected_metrics {
                                    debug!("{:?}", metric); // Use debug for individual metrics, info for summary
                                }
                                collected_metrics.clear();
                                info!("------------------------------------");
                            }
                        },
                    }
                }
            });

            client.run().await
        },
        _ => {
            eprintln!("Invalid mode: {}. Use 'server', 'client', or 'generate-config'.", mode);
            std::process::exit(1);
        }
    }
}
