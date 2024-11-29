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
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)] // Specifies the enum's underlying type
pub enum ResultCode {
    NOERROR = 0,
    FORMERR = 1,
    SERVFAIL = 2,
    NXDOMAIN = 3,
    NOTIMP = 4,
    REFUSED = 5,
}

impl Default for ResultCode {
    fn default() -> Self {
        ResultCode::NOERROR
    }
}

impl ResultCode {
    pub fn from_num(num: u8) -> ResultCode {
        match num {
            1 => ResultCode::FORMERR,
            2 => ResultCode::SERVFAIL,
            3 => ResultCode::NXDOMAIN,
            4 => ResultCode::NOTIMP,
            5 => ResultCode::REFUSED,
            0 | _ => ResultCode::NOERROR,
        }
    }
}
    /// Get the numeric representation of the `ResultCode`
//     pub fn to_num(&self) -> u8 {
//         match *self {
//             ResultCode::NOERROR => 0,
//             ResultCode::FORMERR => 1,
//             ResultCode::SERVFAIL => 2,
//             ResultCode::NXDOMAIN => 3,
//             ResultCode::NOTIMP => 4,
//             ResultCode::REFUSED => 5,
//             ResultCode::UNKNOWN(num) => num,
//         }
//     }
// }


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

    pub rescode: ResultCode,  // Response code (4 bits)
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

impl DnsHeader{
    
    /// creates a new dns header with default values
    pub fn new() -> Self {
        Self::default()
    }
        
    /// Writes the DNS header to the provided buffer.
    pub fn write<T: PacketBuffer>(&self, buffer: &mut T) -> Result<()> {
        buffer.write_u16(self.id)?;
    
        // write the flag as two bytes
        let flags1 = (self.recursion_desired as u8)
            | ((self.truncated_message as u8) << 1)
            | ((self.authoritative_answer as u8) << 2)
            | (self.opcode << 3)
            | ((self.response as u8) << 7);

        let flags2 = (self.rescode as u8)
            | ((self.checking_disabled as u8) << 4)
            | ((self.authed_data as u8) << 5)
            | ((self.z as u8) << 6)
            | ((self.recursion_available as u8) << 7); 

        buffer.write_u8(flags1)?;
        buffer.write_u8(flags2)?;
            
        buffer.write_u16(self.questions)?;
        buffer.write_u16(self.answers)?;
        buffer.write_u16(self.authoritative_entries)?;
        buffer.write_u16(self.resource_entries)?;

        Ok(()) 
    }

    ///Returns the fixed binary size of the DNS Header
    pub fn binary_len(&self) -> usize {
        12 // DNS header being 12 bytes always.
    }

    pub fn read<T: PacketBuffer>(&mut self, buffer: &mut T) -> Result<()> {
        self.id = buffer.read_u16()?;

        let flags = buffer.read_u16()?;
        let flags1 = (flags >> 8) as u8;
        let flags2 = (flags & 0xFF) as u8;

        self.recursion_desired = (flags1 & (1 << 0)) > 0;
        self.truncated_message = (flags1 & (1 << 1)) > 0;
        self.authoritative_answer = (flags1 & (1 << 2)) > 0;
        self.opcode = (flags1 >> 3) & 0x0F;
        self.response = (flags1 & (1 << 7)) > 0;

        self.rescode = ResultCode::from_num(flags2 & 0x0F);
        self.checking_disabled = (flags2 & (1 << 4)) > 0;
        self.authed_data = (flags2 & (1 << 5)) > 0;
        self.z = (flags2 & (1 << 6)) > 0;
        self.recursion_available = (flags2 & (1 << 7)) > 0;

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
        writeln!(f, "\trescode: {:?}", self.rescode)?;
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

///DNS Question representation
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQuestion {
    pub name: String,
    pub qtype: QueryType,
}

impl DnsQuestion {
    /// creates a new dns question.
    pub fn new(name: String, qtype: QueryType) -> Self {
        Self { name, qtype }
    }

    /// calculates the binary length of a dns question.
    pub fn binary_len(&self) -> usize {
        self.name.split('.').map(|x| x.len() + 1).sum::<usize>() + 1
    }

    /// Wrte the dns question to a packet buffer
    pub fn write<T: PacketBuffer>(&self, buffer: &mut T) -> Result<()> {
        buffer.write_qname(&self.name)?;
        buffer.write_u16(self.qtype.to_num())?;
        buffer.write_u16(1)?; // Class (1 = IN)
        Ok(())
    }

    /// Reads the dns question from the packet buffer
    pub fn read<T: PacketBuffer>(&mut self, buffer: &mut T) -> Result<()> {
        buffer.read_qname(&mut self.name)?;
        self.qtype = QueryType::from_num(buffer.read_u16()?);
        buffer.read_u16()?;
        Ok(())
    }
}

impl fmt::Display for DnsQuestion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "DnsQuestion:")?;
        writeln!(f, "\tname: {}", self.name)?;
        writeln!(f, "\trecord type: {:?}", self.qtype)?;

        Ok(())
    }
}


/// Representation of a DNS Packet.
///
/// This was our end goal all along. the queen of our chess pieces.
/// A packet can be read and written in a single operation.
#[derive(Debug, Clone, Default)]
pub struct DnsPacket {
    pub header: DnsHeader,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsRecord>,
    pub authorities: Vec<DnsRecord>,
    pub resources: Vec<DnsRecord>,
}

impl DnsPacket {
    /// Creates a new, empty DNS packet
    pub fn new() -> Self {
        Self::default()
    }
    

    /// Reads a dns packet from the packet buffer
    pub fn from_buffer<T: PacketBuffer>(buffer: &mut T) -> Result<Self> {
        let mut packet = Self::new();

        // Read the dns header
        packet.header.read(buffer)?;

        // Helper functions to read the records to a target vector
        fn read_records<T: PacketBuffer>(
            count: u16,
            buffer: &mut T,
            target: &mut Vec<DnsRecord>,
        ) -> Result <()> {
            for _ in 0..count {
                target.push(DnsRecord::read(buffer)?);
            }
            
            Ok(())
        }

        // Read the questions
        for _ in 0..packet.header.questions {
            let mut question = DnsQuestion::new("".to_string(), QueryType::UNKNOWN(0));
            question.read(buffer)?;
            packet.question.push(question);
        }

        // Read answers, authorities, and additional resources
        read_records(packet.header.answers, buffer, &mut packet.answers)?;
        read_records(packet.header.authoritative_entries, buffer, &mut packet.authorities)?;
        read_records(packet.header.resource_entries, buffer, &mut packet.resources)?;

        Ok(packet)
    }

    #[allow(dead_code)]
    pub fn print(&self) {
        /// Prints the DNS Packet details for debbuging
        println!("{}", self.header);

        fn print_section<T: std::fmt::Debug>(label: &str, records: &[T]) {
            println!("{}:", label);
            for record in records {
                println!("\t{:?}", record);
            }
        }

        print_section("questions", &self.questions);
        print_section("answers", &self.answers);
        print_section("authorities", &self.authorities);
        print_section("resources", &self.resources);


    }

    /// Retrieves the ttl value from the first SOA record in the authorities section
    pub fn get_ttl_from_soa(&self) -> Option<u32> {
        self.authorities.iter().find_map(|record| {
            if let DnsRecord::SOA { minimum, .. } = record {
                Some(*minimum)
            } else {
                None
            }
        })
    }

    /// Gets a random A record's address from the answers section
    pub fn get_random_a(&self) -> Option<String> {
        self.answers.iter().filter_map(|record| {
            if let DnsRecord::A { addr, .. } = record {
                Some(addr.to_string())
            } else {
                None
            }
        }).next()
    }

    /// Retrieves unresolved CNAME records from the answers section
    pub fn get_unresolved_cnames(&self) -> Vec<DnsRecord> {
        self.answers
            .iter()
            .filter(|answer| {
                if let DnsRecord::CNAME { host, .. } = answer {
                    !self.answers.iter().any(|other| {
                        if let DnsRecord::A { domain, .. } = other {
                            domain == host
                        } else {
                            false
                        }
                    })
                } else {
                    false
                }
            })
            .cloned()
            .collect()
    }

    /// Retrieves a resolved NS record for the given query name
    pub fn get_resolved_ns(&self, qname: &str) -> Option<String> {
        self.authorities.iter().filter_map(|auth| {
            if let DnsRecord::NS { domain, host, .. } = auth {
                if qname.ends_with(domain) {
                    self.resources.iter().find_map(|resource| {
                        if let DnsRecord::A { domain, addr, .. } = resource {
                            if domain == host {
                                return Some(addr.to_string());
                            }
                        }
                        None
                    })
                } else {
                    None
                }
            } else {
                None
            }
        }).next()
    }

    /// Retrieves an unresolved NS record for the given query name
    pub fn get_unresolved_ns(&self, qname: &str) -> Option<String> {
        self.authorities.iter().filter_map(|auth| {
            if let DnsRecord::NS { domain, host, .. } = auth {
                if qname.ends_with(domain) {
                    Some(host.clone())
                } else {
                    None
                }
            } else {
                None
            }
        }).next()
    }

    /// Writes the DNS packet to a packet buffer with a specified maximum size
    pub fn write<T: PacketBuffer>(&mut self, buffer: &mut T, max_size: usize) -> Result<()> {
        let mut test_buffer = VectorPacketBuffer::new();
        let mut size = self.header.binary_len();

        // Write questions
        for question in &self.questions {
            size += question.binary_len();
            question.write(&mut test_buffer)?;
        }

        let mut record_count = 0;

        // Write answers, authorities, and resources
        for (i, rec) in self
            .answers
            .iter()
            .chain(&self.authorities)
            .chain(&self.resources)
            .enumerate()
        {
            size += rec.write(&mut test_buffer)?;
            if size > max_size {
                self.header.truncated_message = true;
                break;
            }

            record_count = i + 1;

            if i < self.answers.len() {
                self.header.answers += 1;
            } else if i < self.answers.len() + self.authorities.len() {
                self.header.authoritative_entries += 1;
            } else {
                self.header.resource_entries += 1;
            }
        }

        self.header.questions = self.questions.len() as u16;
        self.header.write(buffer)?;

        // Write questions and records to the buffer
        for question in &self.questions {
            question.write(buffer)?;
        }

        for rec in self
            .answers
            .iter()
            .chain(&self.authorities)
            .chain(&self.resources)
            .take(record_count)
        {
            rec.write(buffer)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::buffer::{PacketBuffer, VectorPacketBuffer};
    use std::net::Ipv4Addr;

    #[test]
    fn test_packet_serialization_and_deserialization() {
        let mut packet = DnsPacket::new();
        packet.header.id = 1337;
        packet.header.response = true;

        packet.questions.push(DnsQuestion::new(
            "google.com".to_string(),
            QueryType::NS,
        ));

        packet.answers.push(DnsRecord::NS {
            domain: "google.com".to_string(),
            host: "ns1.google.com".to_string(),
            ttl: TransientTtl(3600),
        });

        let mut buffer = VectorPacketBuffer::new();
        packet.write(&mut buffer, 0xFFFF).unwrap();

        buffer.seek(0).unwrap();

        let parsed_packet = DnsPacket::from_buffer(&mut buffer).unwrap();

        assert_eq!(packet.header, parsed_packet.header);
        assert_eq!(packet.questions, parsed_packet.questions);
        assert_eq!(packet.answers, parsed_packet.answers);
    }

    #[test]
    fn test_unresolved_cnames() {
        let mut packet = DnsPacket::new();
        packet.answers.push(DnsRecord::CNAME {
            domain: "example.com".to_string(),
            host: "alias.example.com".to_string(),
            ttl: TransientTtl(3600),
        });

        let unresolved = packet.get_unresolved_cnames();
        assert_eq!(unresolved.len(), 1);
        assert_eq!(
            unresolved[0],
            DnsRecord::CNAME {
                domain: "example.com".to_string(),
                host: "alias.example.com".to_string(),
                ttl: TransientTtl(3600),
            }
        );
    }

    #[test]
    fn test_random_a_record() {
        let mut packet = DnsPacket::new();
        packet.answers.push(DnsRecord::A {
            domain: "example.com".to_string(),
            addr: Ipv4Addr::new(127, 0, 0, 1),
            ttl: TransientTtl(3600),
        });

        let random_a = packet.get_random_a();
        assert_eq!(random_a, Some("127.0.0.1".to_string()));
    }

    #[test]
    fn test_ttl_from_soa() {
        let mut packet = DnsPacket::new();
        packet.authorities.push(DnsRecord::SOA {
            domain: "example.com".to_string(),
            mname: "ns1.example.com".to_string(),
            rname: "admin.example.com".to_string(),
            serial: 20231201,
            refresh: 7200,
            retry: 3600,
            expire: 1209600,
            minimum: 600,
        });

        let ttl = packet.get_ttl_from_soa();
        assert_eq!(ttl, Some(600));
    }

    #[test]
    fn test_resolved_ns() {
        let mut packet = DnsPacket::new();

        packet.authorities.push(DnsRecord::NS {
            domain: "example.com".to_string(),
            host: "ns1.example.com".to_string(),
            ttl: TransientTtl(3600),
        });

        packet.resources.push(DnsRecord::A {
            domain: "ns1.example.com".to_string(),
            addr: Ipv4Addr::new(192, 168, 1, 1),
            ttl: TransientTtl(3600),
        });

        let resolved_ns = packet.get_resolved_ns("example.com");
        assert_eq!(resolved_ns, Some("192.168.1.1".to_string()));
    }

    #[test]
    fn test_unresolved_ns() {
        let mut packet = DnsPacket::new();

        packet.authorities.push(DnsRecord::NS {
            domain: "example.com".to_string(),
            host: "ns1.example.com".to_string(),
            ttl: TransientTtl(3600),
        });

        let unresolved_ns = packet.get_unresolved_ns("example.com");
        assert_eq!(unresolved_ns, Some("ns1.example.com".to_string()));
    }

    #[test]
    fn test_packet_truncation() {
        let mut packet = DnsPacket::new();
        packet.header.id = 1337;

        // Add multiple records to exceed the size limit
        for i in 0..10 {
            packet.answers.push(DnsRecord::A {
                domain: format!("example{}.com", i),
                addr: Ipv4Addr::new(127, 0, 0, 1),
                ttl: TransientTtl(3600),
            });
        }

        let mut buffer = VectorPacketBuffer::new();
        let max_size = 512; // Typical DNS packet size limit for UDP
        let result = packet.write(&mut buffer, max_size);

        assert!(result.is_ok());
        assert!(packet.header.truncated_message);
    }

    #[test]
    fn test_empty_packet() {
        let packet = DnsPacket::new();
        let mut buffer = VectorPacketBuffer::new();

        let result = packet.write(&mut buffer, 0xFFFF);
        assert!(result.is_ok());

        buffer.seek(0).unwrap();
        let parsed_packet = DnsPacket::from_buffer(&mut buffer).unwrap();

        assert_eq!(packet.header, parsed_packet.header);
        assert!(parsed_packet.questions.is_empty());
        assert!(parsed_packet.answers.is_empty());
        assert!(parsed_packet.authorities.is_empty());
        assert!(parsed_packet.resources.is_empty());
    }

    #[test]
    fn test_packet_with_invalid_buffer() {
        let mut buffer = VectorPacketBuffer::new();
        buffer.write_u8(255).unwrap(); // Write invalid data to the buffer

        let result = DnsPacket::from_buffer(&mut buffer);
        assert!(result.is_err());
    }
}
