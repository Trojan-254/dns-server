# DNS Server

A high-performance, feature-rich DNS server implementation written in Rust, providing both recursive and forwarding DNS resolution capabilities with built-in caching and zone management.

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Architecture](#architecture)
- [Core Components](#core-components)
  - [DNS Protocol Implementation](#dns-protocol-implementation)
  - [Buffer Management](#buffer-management)
  - [Caching System](#caching-system)
  - [Resolution Strategies](#resolution-strategies)
  - [Authority & Zone Management](#authority--zone-management)
  - [Network Client](#network-client)
  - [Server Context](#server-context)
- [Building the Project](#building-the-project)
- [Configuration](#configuration)
- [Technical Details](#technical-details)
- [Project Structure](#project-structure)

## Overview

This DNS server is a comprehensive implementation of the Domain Name System protocol in Rust. It supports standard DNS operations including query resolution, caching, zone file management, and both recursive and forwarding resolution strategies. The server is built with modern async/await patterns using Tokio and is designed for high performance and reliability.

## Features

### Core DNS Features
- ✅ **Full DNS Protocol Support**: Implements standard DNS packet parsing and serialization
- ✅ **Multiple Query Types**: Support for A, NS, CNAME, SOA, MX, TXT, AAAA, SRV, and OPT records
- ✅ **Recursive Resolution**: Can resolve queries using internet root servers
- ✅ **Forwarding Resolution**: Forward queries to upstream DNS servers
- ✅ **DNS Compression**: Implements DNS name compression (RFC 1035) for efficient packet sizes
- ✅ **Zone Management**: Load and manage authoritative DNS zones from files

### Performance & Reliability
- 🚀 **Asynchronous I/O**: Built on Tokio for high-concurrency async operations
- 💾 **Multi-tier Caching**: In-memory cache with TTL-based expiration and negative caching
- 📊 **Statistics Tracking**: Built-in metrics for TCP/UDP query counts
- 🔒 **Thread-Safe**: Uses Arc, RwLock, and DashMap for safe concurrent access

### Network Support
- 🌐 **UDP & TCP Support**: Dual protocol support for DNS queries
- 🔌 **Configurable Ports**: Customizable DNS and API ports
- 📡 **Prometheus Metrics**: Built-in Prometheus exporter for monitoring

## Architecture

The DNS server follows a modular architecture with clear separation of concerns:

```
┌─────────────────────────────────────────────────────────┐
│                    Server Context                        │
│  (Central configuration and shared state management)    │
└───┬──────────────┬──────────────┬──────────────┬────────┘
    │              │              │              │
    ▼              ▼              ▼              ▼
┌────────┐  ┌──────────┐  ┌──────────┐  ┌──────────────┐
│Authority│  │  Cache   │  │ Resolver │  │ Network Client│
│ (Zones) │  │ (Memory) │  │(Rec/Fwd) │  │  (UDP/TCP)   │
└────────┘  └──────────┘  └──────────┘  └──────────────┘
     │           │              │               │
     └───────────┴──────────────┴───────────────┘
                       │
                       ▼
            ┌──────────────────┐
            │  DNS Protocol    │
            │  & Buffer Layer  │
            └──────────────────┘
```

### Request Flow

1. **Query Reception**: Incoming DNS queries arrive via UDP or TCP
2. **Authority Check**: First checks if the server has authoritative data for the domain
3. **Cache Lookup**: If not authoritative, checks the cache for existing answers
4. **Resolution**: If cache miss, uses configured resolver (recursive or forwarding)
5. **Caching**: Successful responses are cached with TTL-based expiration
6. **Response**: Formatted DNS response is sent back to the client

## Core Components

### DNS Protocol Implementation

**Location**: `core-module/src/protocols/protocol.rs` (~900 lines)

The protocol module implements the complete DNS packet structure according to RFC 1035:

#### DNS Packet Structure
```rust
DnsPacket {
    header: DnsHeader,      // 12-byte header with flags and counts
    questions: Vec<DnsQuestion>,
    answers: Vec<DnsRecord>,
    authorities: Vec<DnsRecord>,
    resources: Vec<DnsRecord>
}
```

#### Supported Query Types
- **A (1)**: IPv4 address records
- **NS (2)**: Nameserver records
- **CNAME (5)**: Canonical name records
- **SOA (6)**: Start of authority records
- **MX (15)**: Mail exchange records
- **TXT (16)**: Text records
- **AAAA (28)**: IPv6 address records
- **SRV (33)**: Service locator records
- **OPT (41)**: EDNS extension records

#### Key Features
- **DNS Header Parsing**: Reads/writes 16-bit flags, query counts, response codes
- **Record Serialization**: Converts between binary DNS format and Rust structures
- **Query Type Conversion**: Bidirectional mapping between numeric codes and enum types
- **Result Codes**: Full support for DNS response codes (NOERROR, NXDOMAIN, SERVFAIL, etc.)

#### DNS Header Flags
```rust
DnsHeader {
    id: u16,                    // Transaction ID
    recursion_desired: bool,    // RD flag
    truncated_message: bool,    // TC flag
    authoritative_answer: bool, // AA flag
    opcode: u8,                 // Operation code
    response: bool,             // QR flag
    rescode: ResultCode,        // Response code
    checking_disabled: bool,    // CD flag
    authed_data: bool,         // AD flag
    z: bool,                   // Reserved
    recursion_available: bool, // RA flag
    questions: u16,            // QDCOUNT
    answers: u16,              // ANCOUNT
    authoritative_entries: u16, // NSCOUNT
    resource_entries: u16      // ARCOUNT
}
```

### Buffer Management

**Location**: `core-module/src/buffer/buffer.rs` (~700 lines)

The buffer system provides efficient reading and writing of DNS packets with three specialized buffer types:

#### Buffer Types

1. **BytePacketBuffer**: Fixed 512-byte buffer for UDP packets
   ```rust
   BytePacketBuffer {
       buf: [u8; 512],  // Fixed-size array
       pos: usize       // Current read/write position
   }
   ```

2. **VectorPacketBuffer**: Dynamic buffer for variable-length packets
   ```rust
   VectorPacketBuffer {
       buffer: Vec<u8>,                    // Dynamic buffer
       pos: usize,                         // Current position
       label_lookup: BTreeMap<String, usize> // For DNS compression
   }
   ```

3. **StreamPacketBuffer**: Async stream-based buffer for I/O operations
   ```rust
   StreamPacketBuffer<'a, T: AsyncRead> {
       stream: &'a mut T,
       buffer: Vec<u8>,
       pos: usize
   }
   ```

#### DNS Name Compression

The buffer implements DNS message compression per RFC 1035 Section 4.1.4:

- **Compression Pointers**: Uses 2-byte pointers (0xC0 prefix) to reference previously seen labels
- **Label Lookup**: Maintains a BTreeMap to track label positions for reuse
- **Decompression**: Follows compression pointers to reconstruct full domain names
- **Jump Detection**: Prevents infinite loops in malformed packets

**Example**: For "a.google.com" followed by "b.google.com":
```
[0x01, 'a', 0x06, 'g','o','o','g','l','e', 0x03, 'c','o','m', 0x00]
[0x01, 'b', 0xC0, 0x02]  // Pointer to "google.com" at offset 2
```

#### Buffer Operations
- **read_u8/u16/u32**: Read integers in network byte order (big-endian)
- **write_u8/u16/u32**: Write integers in network byte order
- **read_qname**: Parse domain names with compression support
- **write_qname**: Write domain names with automatic compression
- **seek/step**: Position manipulation
- **get_range**: Extract byte slices at specific positions

### Caching System

**Location**: `core-module/src/cache/memory_cache.rs` (~450 lines)

The caching system provides high-performance, thread-safe caching with TTL management:

#### Cache Architecture

```rust
SynchronizedCache {
    cache: RwLock<Cache>
} → Cache {
    domain_entries: BTreeMap<String, Arc<DomainEntry>>
} → DomainEntry {
    domain: String,
    record_types: DashMap<QueryType, RecordSet>,
    hits: usize,
    updates: usize
} → RecordSet {
    Records { qtype, records: HashSet<RecordEntry> }
    NoRecords { qtype, ttl, timestamp }  // Negative cache
}
```

#### Key Features

**1. Positive Caching**: Stores successful DNS responses
```rust
RecordSet::Records {
    qtype: QueryType,
    records: HashSet<RecordEntry> {
        record: DnsRecord,
        timestamp: DateTime<Local>
    }
}
```

**2. Negative Caching**: Caches NXDOMAIN responses to reduce query load
```rust
RecordSet::NoRecords {
    qtype: QueryType,
    ttl: u32,
    timestamp: DateTime<Local>
}
```

**3. Cache States**
- **PositiveCache**: Valid records exist in cache
- **NegativeCache**: Domain doesn't exist (NXDOMAIN cached)
- **NotCached**: No information in cache

**4. TTL-Based Expiration**
- Each record entry has a timestamp
- TTL is checked against current time
- Expired records are automatically invalidated

**5. Thread Safety**
- **RwLock**: Allows multiple readers or single writer
- **DashMap**: Lock-free concurrent hash map for record types
- **Arc**: Shared ownership of domain entries

**6. Statistics Tracking**
- Tracks cache hits per domain
- Counts updates to entries
- Useful for cache efficiency analysis

#### Cache Operations
```rust
// Store DNS records
cache.store(&[DnsRecord]) 

// Store negative response
cache.store_nxdomain(qname, qtype, ttl)

// Lookup with automatic packet construction
cache.lookup(qname, qtype) -> Option<DnsPacket>

// List all cached domains
cache.list() -> Vec<Arc<DomainEntry>>
```

### Resolution Strategies

**Location**: `core-module/src/resolvers/`

The server supports two resolution strategies:

#### 1. Recursive Resolver
**File**: `recursive_resolver.rs` (~150 lines)

Resolves queries by querying DNS root servers and following referrals:

**Algorithm**:
1. Start with internet root servers (a.root-servers.net, etc.)
2. Query for NS records of progressively specific domains
3. Follow delegation chain: `.` → `.com` → `google.com`
4. Cache intermediate results
5. Return final answer

**Features**:
- Iterative nameserver discovery
- Handles NS record resolution
- Follows CNAME chains
- Detects and handles resolution failures
- Caches all intermediate results

**Example Query Flow for "www.google.com"**:
```
1. Query root server for NS of "com"
2. Query .com nameserver for NS of "google.com"
3. Query google.com nameserver for A record of "www.google.com"
4. Return result
```

#### 2. Forwarding Resolver
**File**: `forwading_resolver.rs` (~50 lines)

Forwards queries to an upstream DNS server (e.g., 8.8.8.8):

**Algorithm**:
1. Receive query from client
2. Forward query to configured upstream server
3. Wait for response
4. Cache the response
5. Return answer to client

**Use Cases**:
- Corporate environments with internal DNS
- Privacy-focused configurations
- Testing and development
- Load distribution

#### Resolver Trait
**File**: `resolve.rs` (~70 lines)

Defines the common interface for all resolvers:

```rust
#[async_trait]
pub trait DnsResolver {
    fn get_context(&self) -> Arc<ServerContext>;
    
    async fn resolve(&mut self, qname: &str, qtype: QueryType, recursion: bool) 
        -> Result<DnsPacket>;
    
    async fn perform(&mut self, qname: &str, qtype: QueryType) 
        -> Result<DnsPacket>;
}
```

**Resolution Logic**:
1. Check for unsupported query types → return NOTIMP
2. Check authority (local zones) → return authoritative answer
3. Check recursion settings → return REFUSED if disabled
4. Check cache → return cached answer
5. Check CNAME cache for A/AAAA queries
6. Call perform() for external resolution

### Authority & Zone Management

**Location**: `core-module/src/authorities/authority.rs` (~200 lines)

Manages authoritative DNS zones loaded from zone files:

#### Zone Structure
```rust
Zone {
    domain: String,        // Zone apex (e.g., "example.com")
    m_name: String,        // Primary nameserver
    r_name: String,        // Responsible person email
    serial: u32,           // Zone serial number
    refresh: u32,          // Refresh interval
    retry: u32,            // Retry interval
    expire: u32,           // Expiration time
    minimum: u32,          // Minimum TTL
    records: BTreeSet<DnsRecord>  // All zone records
}
```

#### Authority Features

**1. Zone File Loading**
- Reads binary zone files from `zones/` directory
- Parses SOA record information
- Loads all DNS records for the zone
- Supports multiple zones simultaneously

**2. Zone File Format**
Binary format with:
```
- QNAME (domain)
- MNAME (primary nameserver)
- RNAME (responsible person)
- Serial (4 bytes)
- Refresh (4 bytes)
- Retry (4 bytes)
- Expire (4 bytes)
- Minimum (4 bytes)
- Record count (4 bytes)
- [DNS Records...]
```

**3. Query Handling**
```rust
authority.query(qname, qtype) -> Option<DnsPacket>
```
- Checks if domain is in managed zones
- Returns authoritative answer with AA flag set
- Includes SOA record in authority section if no match

**4. Zone Updates**
- Zones can be modified in memory
- Changes can be saved back to disk
- Thread-safe access via RwLock

**5. Authority Response**
Sets proper DNS flags:
- **AA (Authoritative Answer)**: Set to true
- **RA (Recursion Available)**: Set to false (authoritative-only)
- Includes SOA in authority section

### Network Client

**Location**: `core-module/src/client/network_client.rs` (~200 lines)

Handles outgoing DNS queries to external servers:

#### Client Architecture

```rust
DnsNetworkClient {
    total_sent: AtomicUsize,                      // Query counter
    total_failed: AtomicUsize,                    // Failure counter
    seq: AtomicUsize,                             // Sequence number generator
    socket: Arc<UdpSocket>,                       // Shared UDP socket
    pending_queries: Arc<Mutex<Vec<PendingQuery>>> // In-flight queries
}
```

#### Query Management

**1. Query Tracking**
```rust
PendingQuery {
    seq: u16,                           // Unique sequence number
    timestamp: DateTime<Local>,         // When query was sent
    tx: Sender<Option<DnsPacket>>      // Channel for response
}
```

**2. Async Query Process**
1. Generate unique sequence ID
2. Construct DNS packet with query
3. Send UDP packet to server
4. Add to pending queries list
5. Wait for response on channel
6. Match response by sequence ID
7. Remove from pending queries
8. Return result or timeout

**3. Background Listener**
- Runs in separate async task
- Continuously receives UDP responses
- Matches responses to pending queries
- Sends results through channels
- Cleans up expired queries

**4. Timeout Handling**
- Configurable timeout per query
- Automatic cleanup of stale queries
- Returns TimeOut error on expiration

**5. Statistics**
- Tracks total queries sent
- Tracks total failures
- Useful for monitoring and debugging

#### Supported Operations
```rust
// Send DNS query
client.send_query(qname, qtype, (server, port), recursive) 
    -> Result<DnsPacket>

// Get statistics
client.get_sent_count() -> usize
client.get_failed_count() -> usize

// Initialize listener
client.run() -> Result<()>
```

### Server Context

**Location**: `core-module/src/server/context.rs` (~150 lines)

Central configuration and state management for the server:

#### Context Structure
```rust
ServerContext {
    authority: Authority,                    // Zone management
    cache: SynchronizedCache,                // Query cache
    client: Box<dyn DnsClient>,             // Network client
    dns_port: u16,                          // DNS service port (53)
    api_port: u16,                          // Management API port (5380)
    resolve_strategy: ResolveStrategy,      // Recursive or Forward
    allow_recursive: bool,                  // Enable recursion
    enable_udp: bool,                       // Enable UDP protocol
    enable_tcp: bool,                       // Enable TCP protocol
    enable_api: bool,                       // Enable management API
    statistics: ServerStatistics,           // Query statistics
    zones_dir: &'static str                 // Zone files directory
}
```

#### Resolution Strategies
```rust
enum ResolveStrategy {
    Recursive,                               // Use recursive resolver
    Forward { host: String, port: u16 }     // Forward to upstream
}
```

#### Server Statistics
```rust
ServerStatistics {
    tcp_query_count: AtomicUsize,  // TCP queries processed
    udp_query_count: AtomicUsize   // UDP queries processed
}
```

#### Initialization
```rust
fn initialize(&mut self) -> Result<()> {
    // 1. Create zones directory
    fs::create_dir_all(self.zones_dir)?;
    
    // 2. Start network client listener
    self.client.run()?;
    
    // 3. Load authoritative zones
    self.authority.load()?;
    
    Ok(())
}
```

#### Resolver Factory
```rust
fn create_resolver(&self, ptr: Arc<Self>) -> Box<dyn DnsResolver> {
    match &self.resolve_strategy {
        ResolveStrategy::Recursive => 
            Box::new(RecursiveDnsResolver::new(ptr)),
        ResolveStrategy::Forward { host, port } => 
            Box::new(ForwardingDnsResolver::new(ptr, (host, port)))
    }
}
```

#### Default Configuration
- **DNS Port**: 53
- **API Port**: 5380
- **Zones Directory**: "zones"
- **Recursion**: Enabled
- **UDP/TCP**: Both enabled
- **Strategy**: Recursive resolution

## Building the Project

### Prerequisites
- Rust 1.90+ (2021 edition)
- Cargo package manager

### Build Commands

```bash
# Navigate to project directory
cd core-module

# Build in debug mode
cargo build

# Build in release mode (optimized)
cargo build --release

# Run tests
cargo test

# Run with logging
RUST_LOG=debug cargo run

# Build documentation
cargo doc --open
```

### Dependencies

The project uses the following key dependencies:

```toml
[dependencies]
tokio = { version = "1", features = ["full"] }    # Async runtime
async-trait = "0.1"                                # Async traits
chrono = { version = "0.4", features = ["serde"] } # Date/time
dashmap = "5.3"                                    # Concurrent hashmap
metrics = "0.20"                                   # Metrics collection
metrics-exporter-prometheus = "0.7"                # Prometheus exporter
tracing = "0.1"                                    # Structured logging
derive_more = "0.99.9"                            # Derive macros
serde = "1.0"                                      # Serialization
rand = "0.8.5"                                     # Random number generation
thiserror = "2.0"                                  # Error handling
```

## Configuration

### Server Configuration

The server can be configured through the `ServerContext`:

```rust
let mut context = ServerContext::new();

// Configure ports
context.dns_port = 53;
context.api_port = 5380;

// Set resolution strategy
context.resolve_strategy = ResolveStrategy::Recursive;
// or
context.resolve_strategy = ResolveStrategy::Forward {
    host: "8.8.8.8".to_string(),
    port: 53
};

// Enable/disable features
context.allow_recursive = true;
context.enable_udp = true;
context.enable_tcp = true;
context.enable_api = true;

// Initialize
context.initialize()?;
```

### Zone Files

Zone files should be placed in the `zones/` directory in binary format. The format is:

1. Domain name (QNAME format)
2. Primary nameserver (QNAME format)
3. Responsible person (QNAME format)
4. SOA fields (serial, refresh, retry, expire, minimum)
5. Record count (u32)
6. DNS records

## Technical Details

### DNS Packet Parsing

The packet parser handles:
- **Question Section**: Query name and type
- **Answer Section**: Response records
- **Authority Section**: Nameserver information
- **Additional Section**: Extra helpful records

### Error Handling

Comprehensive error types using `thiserror`:

```rust
BufferError: EndOfBuffer, InvalidCharacterInLabel, InvalidCompressionPointer
ProtocolError: Buffer errors, I/O errors
ClientError: Protocol errors, I/O errors, LookupFailed, TimeOut
CacheError: I/O errors, PoisonedLock
AuthorityError: Buffer, Protocol, I/O errors, PoisonedLock
ResolveError: Client, Cache, I/O errors, NoServerFound
```

### Async Architecture

Built on Tokio with:
- **Async DNS queries**: Non-blocking I/O operations
- **Concurrent request handling**: Multiple queries processed simultaneously
- **Async stream parsing**: Efficient TCP connection handling
- **Channel-based communication**: Thread-safe query/response matching

### Performance Optimizations

1. **DNS Compression**: Reduces packet sizes by 30-50%
2. **BTreeMap for Zones**: O(log n) lookups
3. **DashMap for Cache**: Lock-free concurrent access
4. **Arc for Sharing**: Zero-copy shared state
5. **RwLock**: Multiple concurrent readers
6. **Atomic Counters**: Lock-free statistics

### Security Considerations

- **Query ID Randomization**: Prevents cache poisoning
- **Timeout Management**: Prevents resource exhaustion
- **Buffer Bounds Checking**: Prevents overflows
- **Compression Loop Detection**: Prevents infinite loops
- **Input Validation**: Validates all DNS packet fields

## Project Structure

```
dns-server/
├── README.md
├── .gitignore
└── core-module/
    ├── Cargo.toml
    ├── Cargo.lock
    └── src/
        ├── lib.rs                      # Module exports
        ├── main.rs                     # Entry point
        ├── utils.rs                    # Utility functions
        ├── authorities/
        │   ├── mod.rs
        │   └── authority.rs            # Zone management
        ├── buffer/
        │   ├── mod.rs
        │   └── buffer.rs               # DNS packet buffers
        ├── cache/
        │   ├── mod.rs
        │   ├── memory_cache.rs         # In-memory cache
        │   └── disk_cache.rs           # Disk-based cache
        ├── client/
        │   ├── mod.rs
        │   └── network_client.rs       # DNS query client
        ├── monitoring/
        │   └── mod.rs                  # Metrics and monitoring
        ├── network_utilities/
        │   ├── mod.rs
        │   └── netutil.rs              # TCP/UDP utilities
        ├── protocols/
        │   ├── mod.rs
        │   └── protocol.rs             # DNS protocol implementation
        ├── resolvers/
        │   ├── mod.rs
        │   ├── resolve.rs              # Resolver trait
        │   ├── recursive_resolver.rs   # Recursive resolution
        │   └── forwading_resolver.rs   # Forwarding resolution
        └── server/
            ├── mod.rs
            └── context.rs              # Server configuration
```

## Implementation Highlights

### 1. DNS Name Compression (RFC 1035)
Implements pointer-based compression to reduce packet sizes:
- Tracks label positions in a BTreeMap
- Reuses previously written labels via 2-byte pointers
- Handles circular references and malformed packets

### 2. Async Query Pipeline
Fully asynchronous request processing:
- Non-blocking network I/O
- Concurrent query resolution
- Channel-based response routing
- Background task for receiving responses

### 3. Intelligent Caching
Multi-level caching strategy:
- Positive caching for successful responses
- Negative caching for NXDOMAIN
- TTL-based automatic expiration
- Per-query-type cache organization

### 4. Dual Resolution Modes
Flexible resolution strategies:
- Recursive: Full resolution from root servers
- Forwarding: Delegate to upstream servers
- Runtime switchable via configuration

### 5. Comprehensive Testing
Extensive test coverage including:
- DNS packet serialization/deserialization
- Buffer compression and decompression
- Cache TTL expiration
- CNAME resolution chains
- NS record handling
- Edge cases and error conditions

## Author

Samwuel Simiyu

## License

[License information not specified in source files]