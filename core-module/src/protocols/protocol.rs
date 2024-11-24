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
}


