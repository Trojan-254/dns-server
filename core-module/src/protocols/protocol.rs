// implementations of dns protocol


use std::fmt;
use rand::random;
use std::cmp::Ordering;
use std::hash::{Hash, Hasher};
use std::net::{Ipv4Addr, Ipv6Addr};
use derive_more::{Display, Error, From};
use serde_derive::{Deserialize, Serialize};
use crate::buffer::buffer;
use crate::buffer::buffer::{PacketBuffer, VectorPacketBuffer};


#[derive(Debug, Display, From, Error)]
pub enum ProtocolError {
    Buffer(buffer::BufferError),
    Io(std::io::Error),
}

type Result<T> = std::result::Result<T, ProtocolError>;


/// Represents various dns query types
#[derive(PartialEq, Eq, Debug, Clone, Hash, Copy, Serialize, Deserialize)]
pub enum QueryType {
    /// Represents an unrecognized or custom DNS Query type.
    UNKNOWN(u16),
    /// IPv4 address Query.
    A, // 1
    /// Authoritative name server.
    NS, // 2
    /// Canonical name.
    CNAME, // 5
    /// Start of authority record query.
    SOA, // 6
    /// Mail exchange record query.
    MX, // 15
    /// Text record query.
    TXT, //16
    /// IPv6 address query
    AAAA, // 28
    /// Service locator record query
    SRV, // 33
    /// Options for extended DNS packets
    OPT, // 41
}


impl QueryType {
    /// Converts the `QueryType` enum to its corresponding numeric code.
    ///
    /// # Examples
    /// ```
    /// let query_type = QueryType::A;
    /// assert_eq!(query_type.to_num(), 1);
    /// ```
    pub fn to_num(&self) -> u16 {
        match *self {
           QueryType::UNKNOWN(x) => x,
           QueryType::A => 1,
           QueryType::NS => 2, 
           QueryType::CNAME => 5,
           QueryType::SOA => 6,
           QueryType::MX => 15,
           QueryType::TXT => 16,
           QueryType::AAAA => 28,
           QueryType::SRV => 33,
           QueryType::OPT => 41,
        }
    }

    /// Creates a `QueryType` from a numeric code.
    ///
    /// # Examples
    /// ```
    /// let query_type = QueryType::from_num(15);
    /// assert_eq!(query_type, QueryType::MX);
    /// ```
    pub fn from_num(num: u16) -> QueryType {
        match num {
            1 => QueryType::A,
            2 => QueryType::NS,
            5 => QueryType::CNAME,
            6 => QueryType::SOA,
            15 => QueryType::MX,
            16 => QueryType::TXT,
            28 => QueryType::AAAA,
            33 => QueryType::SRV,
            41 => QueryType::OPT,
            _ => QueryType::UNKNOWN(num),
        }
    }
}


#[derive(Copy, Clone, Debug, Eq, Ord, Serialize, Deserialize)]
pub struct TransientTtl(pub u32);

impl PartialEq for TransientTtl {
    fn eq(&self, _: &Self) -> bool {
        true
    }
}

impl PartialOrd for TransientTtl {
    fn partial_cmp(&self, _: &Self) -> Option<Ordering> {
        Some(Ordering::Equal)
    }
}

impl Hash for TransientTtl {
    fn hash<H: Hasher>(&self, _: &mut H) {
       // Intetionally left empty
       // All TransientTtl instances are treated as equivalent.
    }
}

impl TransientTtl {
    /// Creates a new `TransientTtl` instance.
    pub fn new(value: u32) -> Self {
        TransientTtl(value)
    }

    /// Returns the underlying TTL value
    pub fn value(&self) -> u32 {
        self.0
    }
}


/// `DnsRecord` is the primary representation of a DNS record.
///
/// This enumeration is used for reading and writing records from the network
/// and storing authority data.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum DnsRecord {
    UNKNOWN {
        domain: String,
        qtype: u16,
        data_len: u16,
        ttl: TransientTtl,
    },
    A {
        domain: String,
        addr: Ipv4Addr,
        ttl: TransientTtl,
    },
    NS {
        domain: String,
        host: String,
        ttl: TransientTtl,
    },
    CNAME {
        domain: String,
        host: String,
        ttl: TransientTtl,
    },
    SOA {
        domain: String,
        m_name: String,
        r_name: String,
        serial: u32,
        refresh: u32,
        retry: u32,
        expire: u32,
        minimum: u32,
        ttl: TransientTtl,
    },
    MX {
        domain: String,
        priority: u16,
        host: String,
        ttl: TransientTtl,
    },
    TXT {
        domain: String,
        data: String,
        ttl: TransientTtl,
    },
    AAAA {
        domain: String,
        addr: Ipv6Addr,
        ttl: TransientTtl,
    },
    SRV {
        domain: String,
        priority: u16,
        weight: u16,
        port: u16,
        host: String,
        ttl: TransientTtl,
    },
    OPT {
        packet_len: u16,
        flags: u32,
        data: String,
    },
}


impl DnsRecord {
    pub fn read<T: PacketBuffer>(buffer: &mut T) -> Result<DnsRecord> {
        let mut domain = String::new();
        buffer.read_qname(&mut domain)?;

        let qtype_num = buffer.read_u16()?;
        let qtype = QueryType::from_num(qtype_num);
        let class = buffer.read_u16()?;
        let ttl = buffer.read_u32()?;
        let data_len = buffer.read_u16()?;

        // Process based on query type
        match qtype {
            // IPv4 Address (A record)
            QueryType::A => Self::read_a_record(buffer, domain, ttl),
            
            // IPv6 Address (AAAA record)
            QueryType::AAAA => Self::read_aaaa_record(buffer, domain, ttl),

            // Name Server (NS record)
            QueryType::NS => Self::read_ns_record(buffer, domain, ttl),

            // Canonical Name (CNAME record)
            QueryType::CNAME => Self::read_cname_record(buffer, domain, ttl),

            // Service Record (SRV record)
            QueryType::SRV => Self::read_srv_record(buffer, domain, ttl),

            // Mail Exchange (MX record)
            QueryType::MX => Self::read_mx_record(buffer, domain, ttl),

            // Start of Authority (SOA record)
            QueryType::SOA => Self::read_soa_record(buffer, domain, ttl),

            // Text Record (TXT record)
            QueryType::TXT => Self::read_txt_record(buffer, domain, ttl, data_len),

            // EDNS Option (OPT record)
            QueryType::OPT => Self::read_opt_record(buffer, class, ttl, data_len),

            // Unknown Record Type
            QueryType::UNKNOWN(_) => {
                buffer.step(data_len as usize)?;
                Ok(DnsRecord::UNKNOWN {
                    domain,
                    qtype: qtype_num,
                    data_len,
                    ttl: TransientTtl(ttl),
                })
            }
        }
    }

    // Helper functions for reading each record type
    fn read_a_record<T: PacketBuffer>(buffer: &mut T, domain: String, ttl: u32) -> Result<DnsRecord> {
        let raw_addr = buffer.read_u32()?;
        let addr = Ipv4Addr::new(
            ((raw_addr >> 24) & 0xFF) as u8,
            ((raw_addr >> 16) & 0xFF) as u8,
            ((raw_addr >> 8) & 0xFF) as u8,
            ((raw_addr >> 0) & 0xFF) as u8,
        );

        Ok(DnsRecord::A {
            domain,
            addr,
            ttl: TransientTtl(ttl),
        })
    }

    fn read_aaaa_record<T: PacketBuffer>(buffer: &mut T, domain: String, ttl: u32) -> Result<DnsRecord> {
        let raw_addr1 = buffer.read_u32()?;
        let raw_addr2 = buffer.read_u32()?;
        let raw_addr3 = buffer.read_u32()?;
        let raw_addr4 = buffer.read_u32()?;
        let addr = Ipv6Addr::new(
            ((raw_addr1 >> 16) & 0xFFFF) as u16,
            ((raw_addr1 >> 0) & 0xFFFF) as u16,
            ((raw_addr2 >> 16) & 0xFFFF) as u16,
            ((raw_addr2 >> 0) & 0xFFFF) as u16,
            ((raw_addr3 >> 16) & 0xFFFF) as u16,
            ((raw_addr3 >> 0) & 0xFFFF) as u16,
            ((raw_addr4 >> 16) & 0xFFFF) as u16,
            ((raw_addr4 >> 0) & 0xFFFF) as u16,
        );

        Ok(DnsRecord::AAAA {
            domain,
            addr,
            ttl: TransientTtl(ttl),
        })
    }

    fn read_ns_record<T: PacketBuffer>(buffer: &mut T, domain: String, ttl: u32) -> Result<DnsRecord> {
        let mut ns = String::new();
        buffer.read_qname(&mut ns)?;

        Ok(DnsRecord::NS {
            domain,
            host: ns,
            ttl: TransientTtl(ttl),
        })
    }

    fn read_cname_record<T: PacketBuffer>(buffer: &mut T, domain: String, ttl: u32) -> Result<DnsRecord> {
        let mut cname = String::new();
        buffer.read_qname(&mut cname)?;

        Ok(DnsRecord::CNAME {
            domain,
            host: cname,
            ttl: TransientTtl(ttl),
        })
    }

    fn read_srv_record<T: PacketBuffer>(buffer: &mut T, domain: String, ttl: u32) -> Result<DnsRecord> {
        let priority = buffer.read_u16()?;
        let weight = buffer.read_u16()?;
        let port = buffer.read_u16()?;
        let mut srv = String::new();
        buffer.read_qname(&mut srv)?;

        Ok(DnsRecord::SRV {
            domain,
            priority,
            weight,
            port,
            host: srv,
            ttl: TransientTtl(ttl),
        })
    }

    fn read_mx_record<T: PacketBuffer>(buffer: &mut T, domain: String, ttl: u32) -> Result<DnsRecord> {
        let priority = buffer.read_u16()?;
        let mut mx = String::new();
        buffer.read_qname(&mut mx)?;

        Ok(DnsRecord::MX {
            domain,
            priority,
            host: mx,
            ttl: TransientTtl(ttl),
        })
    }

    fn read_soa_record<T: PacketBuffer>(buffer: &mut T, domain: String, ttl: u32) -> Result<DnsRecord> {
        let mut m_name = String::new();
        buffer.read_qname(&mut m_name)?;

        let mut r_name = String::new();
        buffer.read_qname(&mut r_name)?;

        let serial = buffer.read_u32()?;
        let refresh = buffer.read_u32()?;
        let retry = buffer.read_u32()?;
        let expire = buffer.read_u32()?;
        let minimum = buffer.read_u32()?;

        Ok(DnsRecord::SOA {
            domain,
            m_name,
            r_name,
            serial,
            refresh,
            retry,
            expire,
            minimum,
            ttl: TransientTtl(ttl),
        })
    }

    fn read_txt_record<T: PacketBuffer>(buffer: &mut T, domain: String, ttl: u32, data_len: u16) -> Result<DnsRecord> {
        let cur_pos = buffer.pos();
        let txt = String::from_utf8_lossy(buffer.get_range(cur_pos, data_len as usize)?).to_string();
        buffer.step(data_len as usize)?;

        Ok(DnsRecord::TXT {
            domain,
            data: txt,
            ttl: TransientTtl(ttl),
        })
    }

    fn read_opt_record<T: PacketBuffer>(buffer: &mut T, class: u16, ttl: u32, data_len: u16) -> Result<DnsRecord> {
        let cur_pos = buffer.pos();
        let data = String::from_utf8_lossy(buffer.get_range(cur_pos, data_len as usize)?).to_string();
        buffer.step(data_len as usize)?;

        Ok(DnsRecord::OPT {
            packet_len: class,
            flags: ttl,
            data,
        })
    }


    pub fn write<T: PacketBuffer>(&self, buffer: &mut T) -> Result<usize> {
    let start_pos = buffer.pos();

    // Helper function to write common parts of the record (qname, query type, class, ttl)
    fn write_common<T: PacketBuffer>(
        buffer: &mut T,
        domain: &str,
        query_type: QueryType,
        ttl: u32,
    ) -> Result<()> {
        buffer.write_qname(domain)?;
        buffer.write_u16(query_type.to_num())?;
        buffer.write_u16(1)?; // Record class (IN)
        buffer.write_u32(ttl)?;
        Ok(())
    }

    match *self {
        DnsRecord::A {
            ref domain,
            ref addr,
            ttl: TransientTtl(ttl),
        } => {
            write_common(buffer, domain, QueryType::A, ttl)?;
            buffer.write_u16(4)?;
            let octets = addr.octets();
            for &octet in &octets {
                buffer.write_u8(octet)?;
            }
        }
        DnsRecord::AAAA {
            ref domain,
            ref addr,
            ttl: TransientTtl(ttl),
        } => {
            write_common(buffer, domain, QueryType::AAAA, ttl)?;
            buffer.write_u16(16)?;
            for &octet in &addr.segments() {
                buffer.write_u16(octet)?;
            }
        }
        DnsRecord::NS {
            ref domain,
            ref host,
            ttl: TransientTtl(ttl),
        } => {
            write_common(buffer, domain, QueryType::NS, ttl)?;
            let pos = buffer.pos();
            buffer.write_u16(0)?;
            buffer.write_qname(host)?;
            let size = buffer.pos() - (pos + 2);
            buffer.set_u16(pos, size as u16)?;
        }
        DnsRecord::CNAME {
            ref domain,
            ref host,
            ttl: TransientTtl(ttl),
        } => {
            write_common(buffer, domain, QueryType::CNAME, ttl)?;
            let pos = buffer.pos();
            buffer.write_u16(0)?;
            buffer.write_qname(host)?;
            let size = buffer.pos() - (pos + 2);
            buffer.set_u16(pos, size as u16)?;
        }
        DnsRecord::SRV {
            ref domain,
            priority,
            weight,
            port,
            ref host,
            ttl: TransientTtl(ttl),
        } => {
            write_common(buffer, domain, QueryType::SRV, ttl)?;
            let pos = buffer.pos();
            buffer.write_u16(0)?;
            buffer.write_u16(priority)?;
            buffer.write_u16(weight)?;
            buffer.write_u16(port)?;
            buffer.write_qname(host)?;
            let size = buffer.pos() - (pos + 2);
            buffer.set_u16(pos, size as u16)?;
        }
        DnsRecord::MX {
            ref domain,
            priority,
            ref host,
            ttl: TransientTtl(ttl),
        } => {
            write_common(buffer, domain, QueryType::MX, ttl)?;
            let pos = buffer.pos();
            buffer.write_u16(0)?;
            buffer.write_u16(priority)?;
            buffer.write_qname(host)?;
            let size = buffer.pos() - (pos + 2);
            buffer.set_u16(pos, size as u16)?;
        }
        DnsRecord::SOA {
            ref domain,
            ref m_name,
            ref r_name,
            serial,
            refresh,
            retry,
            expire,
            minimum,
            ttl: TransientTtl(ttl),
        } => {
            write_common(buffer, domain, QueryType::SOA, ttl)?;
            let pos = buffer.pos();
            buffer.write_u16(0)?;
            buffer.write_qname(m_name)?;
            buffer.write_qname(r_name)?;
            buffer.write_u32(serial)?;
            buffer.write_u32(refresh)?;
            buffer.write_u32(retry)?;
            buffer.write_u32(expire)?;
            buffer.write_u32(minimum)?;
            let size = buffer.pos() - (pos + 2);
            buffer.set_u16(pos, size as u16)?;
        }
        DnsRecord::TXT {
            ref domain,
            ref data,
            ttl: TransientTtl(ttl),
        } => {
            write_common(buffer, domain, QueryType::TXT, ttl)?;
            buffer.write_u16(data.len() as u16)?;
            for &b in data.as_bytes() {
                buffer.write_u8(b)?;
            }
        }
        DnsRecord::OPT { .. } => {} // OPT record doesn't need writing
        DnsRecord::UNKNOWN { .. } => {
            println!("Skipping record: {:?}", self);
        }
    }

    Ok(buffer.pos() - start_pos)
    }

    pub fn get_querytype(&self) -> QueryType {
        match *self {
            DnsRecord::A { .. } => QueryType::A,
            DnsRecord::AAAA { .. } => QueryType::AAAA,
            DnsRecord::NS { .. } => QueryType::NS,
            DnsRecord::CNAME { .. } => QueryType::CNAME,
            DnsRecord::SRV { .. } => QueryType::SRV,
            DnsRecord::MX { .. } => QueryType::MX,
            DnsRecord::SOA { .. } => QueryType::SOA,
            DnsRecord::TXT { .. } => QueryType::TXT,
            DnsRecord::OPT { .. } => QueryType::OPT,
            DnsRecord::UNKNOWN { qtype, .. } => QueryType::UNKNOWN(qtype), // Directly return the unknown query type
        }
    }

    pub fn get_domain(&self) -> Option<String> {
        match *self {
            DnsRecord::A { ref domain, .. }
            | DnsRecord::AAAA { ref domain, .. }
            | DnsRecord::NS { ref domain, .. }
            | DnsRecord::CNAME { ref domain, .. }
            | DnsRecord::SRV { ref domain, .. }
            | DnsRecord::MX { ref domain, .. }
            | DnsRecord::UNKNOWN { ref domain, .. }
            | DnsRecord::SOA { ref domain, .. }
            | DnsRecord::TXT { ref domain, .. } => Some(domain.clone()),
            DnsRecord::OPT { .. } => None,
        }
    }

    pub fn get_ttl(&self) -> u32 {
        match *self {
            DnsRecord::A { ttl: TransientTtl(ttl), .. }
            | DnsRecord::AAAA { ttl: TransientTtl(ttl), .. }
            | DnsRecord::NS { ttl: TransientTtl(ttl), .. }
            | DnsRecord::CNAME { ttl: TransientTtl(ttl), .. }
            | DnsRecord::SRV { ttl: TransientTtl(ttl), .. }
            | DnsRecord::MX { ttl: TransientTtl(ttl), .. }
            | DnsRecord::UNKNOWN { ttl: TransientTtl(ttl), .. }
            | DnsRecord::SOA { ttl: TransientTtl(ttl), .. }
            | DnsRecord::TXT { ttl: TransientTtl(ttl), .. } => ttl,
            DnsRecord::OPT { .. } => 0,
        }
    }    
}


/// The result code for a DNS query, as described in the specification
#[repr(u8)] // Specifies the enum's underlying type
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ResultCode {
    NOERROR = 0,
    FORMERR = 1,
    SERVFAIL = 2,
    NXDOMAIN = 3,
    NOTIMP = 4,
    REFUSED = 5,
    UNKNOWN(u8), // Handle unsupported result codes
}

impl Default for ResultCode {
    fn default() -> Self {
        ResultCode::NOERROR
    }
}

impl ResultCode {
    /// Create a `ResultCode` from a numeric value
    pub fn from_num(num: u8) -> ResultCode {
        match num {
            0 => ResultCode::NOERROR,
            1 => ResultCode::FORMERR,
            2 => ResultCode::SERVFAIL,
            3 => ResultCode::NXDOMAIN,
            4 => ResultCode::NOTIMP,
            5 => ResultCode::REFUSED,
            _ => ResultCode::UNKNOWN(num), // Handle unknown codes gracefully
        }
    }

    /// Get the numeric representation of the `ResultCode`
    pub fn to_num(&self) -> u8 {
        match *self {
            ResultCode::NOERROR => 0,
            ResultCode::FORMERR => 1,
            ResultCode::SERVFAIL => 2,
            ResultCode::NXDOMAIN => 3,
            ResultCode::NOTIMP => 4,
            ResultCode::REFUSED => 5,
            ResultCode::UNKNOWN(num) => num,
        }
    }
}


/// Representation of a DNS header
#[derive(Clone, Debug, Default)]
pub struct DnsHeader {
    pub id: u16, // Transaction ID

    // Flags
    pub recursion_desired: bool,    // Recursion desired
    pub truncated_message: bool,    // Message truncated
    pub authoritative_answer: bool, // Authoritative answer
    pub opcode: u8,                 // Opcode (4 bits)
    pub response: bool,             // Query/Response flag

    pub response_code: ResultCode,  // Response code (4 bits)
    pub checking_disabled: bool,    // Checking disabled
    pub authed_data: bool,          // Authenticated data
    pub z: bool,                    // Reserved (must be 0)
    pub recursion_available: bool,  // Recursion available

    // Record counts
    pub questions: u16,
    pub answers: u16,
    pub authoritative_entries: u16,
    pub resource_entries: u16,
}

impl DnsHeader {

    pub fn new() -> DnsHeader {
        DnsHeader {
            id: 0,

            recursion_desired: false,
            truncated_message: false,
            authoritative_answer: false,
            opcode: 0,
            response: false,

            rescode: ResultCode::NOERROR,
            checking_disabled: false,
            authed_data: false,
            z: false,
            recursion_available: false,

            questions: 0,
            answers: 0,
            authoritative_entries: 0,
            resource_entries: 0,
        }
    }
    /// Writes the DNS header to the provided buffer.
     pub fn write<T: PacketBuffer>(&self, buffer: &mut T) -> Result<()> {
        buffer.write_u16(self.id)?;

        buffer.write_u8(
            (self.recursion_desired as u8)
                | ((self.truncated_message as u8) << 1)
                | ((self.authoritative_answer as u8) << 2)
                | (self.opcode << 3)
                | ((self.response as u8) << 7) as u8,
        )?;

        buffer.write_u8(
            (self.rescode.clone() as u8)
                | ((self.checking_disabled as u8) << 4)
                | ((self.authed_data as u8) << 5)
                | ((self.z as u8) << 6)
                | ((self.recursion_available as u8) << 7),
        )?;

        buffer.write_u16(self.questions)?;
        buffer.write_u16(self.answers)?;
        buffer.write_u16(self.authoritative_entries)?;
        buffer.write_u16(self.resource_entries)?;

        Ok(())
    }

    pub fn binary_len(&self) -> usize {
        12
    }

    pub fn read<T: PacketBuffer>(&mut self, buffer: &mut T) -> Result<()> {
        self.id = buffer.read_u16()?;

        let flags = buffer.read_u16()?;
        let a = (flags >> 8) as u8;
        let b = (flags & 0xFF) as u8;
        self.recursion_desired = (a & (1 << 0)) > 0;
        self.truncated_message = (a & (1 << 1)) > 0;
        self.authoritative_answer = (a & (1 << 2)) > 0;
        self.opcode = (a >> 3) & 0x0F;
        self.response = (a & (1 << 7)) > 0;

        self.rescode = ResultCode::from_num(b & 0x0F);
        self.checking_disabled = (b & (1 << 4)) > 0;
        self.authed_data = (b & (1 << 5)) > 0;
        self.z = (b & (1 << 6)) > 0;
        self.recursion_available = (b & (1 << 7)) > 0;

        self.questions = buffer.read_u16()?;
        self.answers = buffer.read_u16()?;
        self.authoritative_entries = buffer.read_u16()?;
        self.resource_entries = buffer.read_u16()?;

        // Return the constant header size
        Ok(())
    }
}

impl fmt::Display for DnsHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "DnsHeader:")?;
        writeln!(f, "\tid: {}", self.id)?;
        writeln!(f, "\trecursion_desired: {}", self.recursion_desired)?;
        writeln!(f, "\ttruncated_message: {}", self.truncated_message)?;
        writeln!(f, "\tauthoritative_answer: {}", self.authoritative_answer)?;
        writeln!(f, "\topcode: {}", self.opcode)?;
        writeln!(f, "\tresponse: {}", self.response)?;
        writeln!(f, "\tresponse_code: {:?}", self.response_code)?;
        writeln!(f, "\tchecking_disabled: {}", self.checking_disabled)?;
        writeln!(f, "\tauthed_data: {}", self.authed_data)?;
        writeln!(f, "\tz: {}", self.z)?;
        writeln!(f, "\trecursion_available: {}", self.recursion_available)?;
        writeln!(f, "\tquestions: {}", self.questions)?;
        writeln!(f, "\tanswers: {}", self.answers)?;
        writeln!(f, "\tauthoritative_entries: {}", self.authoritative_entries)?;
        writeln!(f, "\tresource_entries: {}", self.resource_entries)
    }
}
