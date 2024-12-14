use chrono::{DateTime, Duration, Local};
use dashmap::DashMap;
use std::sync::Arc;
use std::cmp::Ordering;
use tokio::sync::RwLock;
use std::collections::BTreeMap;
//use serde::{Deserialize, Serialize};
use serde_derive::{Serialize, Deserialize};
use std::collections::HashSet;
use std::hash::{Hash, Hasher};

use crate::protocols::protocol::{DnsPacket, DnsRecord, QueryType, ResultCode};

#[derive(Debug, thiserror::Error)]
pub enum CacheError {
    #[error("I/O Error: {0}")]
    Io(std::io::Error),
    #[error("Poisoned lock")]
    PoisonedLock,
}

pub enum CacheState {
    PositiveCache,
    NegativeCache,
    NotCached,
}

#[derive(Clone, Eq, Debug, Serialize, Deserialize)]
pub struct RecordEntry {
    pub record: DnsRecord,
    pub timestamp: DateTime<Local>,
}

impl PartialEq for RecordEntry {
    fn eq(&self, other: &Self) -> bool {
        self.record == other.record
    }
}

impl Hash for RecordEntry {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.record.hash(state);
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum RecordSet {
    NoRecords {
        qtype: QueryType,
        ttl: u32,
        timestamp: DateTime<Local>,
    },
    Records {
        qtype: QueryType,
        records: HashSet<RecordEntry>,
    },
}

#[derive(Clone, Debug)]
pub struct DomainCache {
    inner: DashMap<String, DomainEntry>,
}

#[derive(Clone, Debug)]
pub struct DomainEntry {
    pub record_types: DashMap<QueryType, RecordSet>,
    pub hits: u32,
    pub updates: u32,
}

impl DomainEntry {
    pub fn new() -> Self {
        DomainEntry {
            record_types: DashMap::new(),
            hits: 0,
            updates: 0,
        }
    }

    pub fn store_nxdomain(&self, qtype: QueryType, ttl: u32) {
        self.updates += 1;

        let new_set = RecordSet::NoRecords {
            qtype,
            ttl,
            timestamp: Local::now(),
        };
        self.record_types.insert(qtype, new_set);
    }

    pub fn store_record(&mut self, rec: &DnsRecord) {
        self.updates += 1;

        let entry = RecordEntry {
            record: rec.clone(),
            timestamp: Local::now(),
        };

        self.record_types
            .entry(rec.get_querytype())
            .and_modify(|set| {
                if let RecordSet::Records { records, .. } = set {
                    records.insert(entry.clone());
                }
            })
            .or_insert_with(|| RecordSet::Records {
                qtype: rec.get_querytype(),
                records: {
                    let mut records = HashSet::new();
                    records.insert(entry);
                    records
                },
            });
    }

    pub fn get_cache_state(&self, qtype: QueryType) -> CacheState {
        match self.record_types.get(&qtype) {
            Some(set) => match set.value() {
                RecordSet::Records { records, .. } => {
                    if records.iter().any(|entry| entry.is_valid()) {
                        CacheState::PositiveCache
                    } else {
                        CacheState::NotCached
                    }
                }
                RecordSet::NoRecords { ttl, timestamp, .. } => {
                    if *timestamp + Duration::seconds(*ttl as i64) > Local::now() {
                        CacheState::NegativeCache
                    } else {
                        CacheState::NotCached
                    }
                }
            },
            None => CacheState::NotCached,
        }
    }

    pub fn fill_query_result(&self, qtype: QueryType, result_vec: &mut Vec<DnsRecord>) {
        if let Some(RecordSet::Records { records, .. }) = self.record_types.get(&qtype).map(|v| v.value().clone()) {
            result_vec.extend(
                records
                    .iter()
                    .filter(|entry| entry.is_valid())
                    .map(|entry| entry.record.clone()),
            );
        }
    }
}

impl RecordEntry {
    pub fn is_valid(&self) -> bool {
        self.timestamp + Duration::seconds(self.record.get_ttl() as i64) > Local::now()
    }
}


#[derive(Default)]
pub struct Cache {
    domain_entries: BTreeMap<String, Arc<DomainEntry>>,
}

impl Cache {
    pub fn new() -> Self {
        Cache {
            domain_entries: BTreeMap::new(),
        }
    }

    fn get_or_create_entry(&mut self, qname: &str) -> &mut Arc<DomainEntry> {
        self.domain_entries
            .entry(qname.to_string())
            .or_insert_with(|| Arc::new(DomainEntry::new(qname.to_string())))
    }

    fn get_cache_state(&self, qname: &str, qtype: QueryType) -> CacheState {
        self.domain_entries
            .get(qname)
            .map(|entry| entry.get_cache_state(qtype))
            .unwrap_or(CacheState::NotCached)
    }

    fn fill_queryresult(
        &self,
        qname: &str,
        qtype: QueryType,
        result_vec: &mut Vec<DnsRecord>,
        increment_stats: bool,
    ) {
        if let Some(domain_entry) = self.domain_entries.get(qname) {
            if increment_stats {
                domain_entry.hits.fetch_add(1, Ordering::Relaxed);
            }

            domain_entry.fill_queryresult(qtype, result_vec);
        }
    }

    pub fn lookup(&self, qname: &str, qtype: QueryType) -> Option<DnsPacket> {
        match self.get_cache_state(qname, qtype) {
            CacheState::PositiveCache => {
                let mut qr = DnsPacket::new();
                self.fill_queryresult(qname, qtype, &mut qr.answers, true);
                self.fill_queryresult(qname, QueryType::NS, &mut qr.authorities, false);
                Some(qr)
            }
            CacheState::NegativeCache => {
                let mut qr = DnsPacket::new();
                qr.header.rescode = ResultCode::NXDOMAIN;
                Some(qr)
            }
            CacheState::NotCached => None,
        }
    }

    pub fn store(&mut self, records: &[DnsRecord]) {
        for record in records {
            if let Some(domain) = record.get_domain() {
                let entry = self.get_or_create_entry(&domain);
                Arc::get_mut(entry).unwrap().store_record(record);
            }
        }
    }

    pub fn store_nxdomain(&mut self, qname: &str, qtype: QueryType, ttl: u32) {
        let entry = self.get_or_create_entry(qname);
        Arc::get_mut(entry).unwrap().store_nxdomain(qtype, ttl);
    }
}

#[derive(Default)]
pub struct SynchronizedCache {
    cache: RwLock<Cache>,
}

impl SynchronizedCache {
    pub fn new() -> Self {
        SynchronizedCache {
            cache: RwLock::new(Cache::new()),
        }
    }

    pub fn list(&self) -> Result<Vec<Arc<DomainEntry>>, CacheError> {
        let cache = self.cache.read().map_err(|_| CacheError::PoisonedLock)?;

        Ok(cache.domain_entries.values().cloned().collect())
    }

    pub fn lookup(&self, qname: &str, qtype: QueryType) -> Option<DnsPacket> {
        let cache = self.cache.read().ok()?;
        cache.lookup(qname, qtype)
    }

    pub fn store(&self, records: &[DnsRecord]) -> Result<(), CacheError> {
        let mut cache = self.cache.write().map_err(|_| CacheError::PoisonedLock)?;
        cache.store(records);
        Ok(())
    }

    pub fn store_nxdomain(&self, qname: &str, qtype: QueryType, ttl: u32) -> Result<(), CacheError> {
        let mut cache = self.cache.write().map_err(|_| CacheError::PoisonedLock)?;
        cache.store_nxdomain(qname, qtype, ttl);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::protocol::{DnsRecord, QueryType, ResultCode, TransientTtl};

    #[test]
    fn test_store_and_retrieve_multiple_records() {
        let mut cache = Cache::new();
    
        let records = vec![
            DnsRecord::A {
                domain: "example.com".to_string(),
                addr: "192.168.0.1".parse().unwrap(),
                ttl: TransientTtl(300),
            },
            DnsRecord::A {
                domain: "example.com".to_string(),
                addr: "192.168.0.2".parse().unwrap(),
                ttl: TransientTtl(300),
            },
        ];

        cache.store(&records);

        if let Some(packet) = cache.lookup("example.com", QueryType::A) {
            assert_eq!(2, packet.answers.len());
            assert_eq!(records[0], packet.answers[0]);
            assert_eq!(records[1], packet.answers[1]);
        } else {
            panic!("Expected multiple records for example.com");
        }
    } 

    #[test]
    fn test_case_insensitive_lookup() {
        let mut cache = Cache::new();

        let record = DnsRecord::A {
            domain: "CaseSensitive.com".to_string(),
            addr: "192.168.0.1".parse().unwrap(),
            ttl: TransientTtl(3600),
        };

        cache.store(&[record]);

        assert!(cache.lookup("casesensitive.com", QueryType::A).is_some());
        assert!(cache.lookup("CASESENSITIVE.COM", QueryType::A).is_some());
        assert!(cache.lookup("CaseSensitive.com", QueryType::A).is_some());
    }

    #[test]
    fn test_ttl_expiry_positive_record() {
        let mut cache = Cache::new();

        let record = DnsRecord::A {
            domain: "ttl-test.com".to_string(),
            addr: "192.168.0.1".parse().unwrap(),
            ttl: TransientTtl(1), // TTL of 1 second
        };

        cache.store(&[record]);

        // The record should exist initially
        assert!(cache.lookup("ttl-test.com", QueryType::A).is_some());

        // Simulate time passing (you'll need to implement TTL expiration logic in the cache)
        std::thread::sleep(std::time::Duration::from_secs(2));
    
        // The record should now be expired
        assert!(cache.lookup("ttl-test.com", QueryType::A).is_none());
    }

    #[test]
    fn test_concurrent_access() {
        use std::sync::Arc;
        use std::thread;
 
        let sync_cache = Arc::new(SynchronizedCache::new());
        let sync_cache_clone = Arc::clone(&sync_cache);

        let record = DnsRecord::A {
            domain: "concurrent-test.com".to_string(),
            addr: "192.168.0.1".parse().unwrap(),
            ttl: TransientTtl(300),
        };

        let handle = thread::spawn(move || {
            sync_cache_clone.store(&[record]).unwrap();
        });

        handle.join().unwrap();

        assert!(sync_cache.lookup("concurrent-test.com", QueryType::A).is_some());
    }

    #[test]
    fn test_negative_ttl_expiry() {
        let mut cache = Cache::new();

        cache.store_nxdomain("negative-ttl.com", QueryType::A, 1); // 1 second TTL

        // Verify the negative cache entry exists initially
        if let Some(packet) = cache.lookup("negative-ttl.com", QueryType::A) {
            assert_eq!(ResultCode::NXDOMAIN, packet.header.rescode);
        } else {
            panic!("Expected NXDOMAIN response");
        }

        // Simulate time passing
        std::thread::sleep(std::time::Duration::from_secs(2));

        // The entry should now be expired
        assert!(cache.lookup("negative-ttl.com", QueryType::A).is_none());
    }


    #[test]
    fn test_overwrite_records() {
        let mut cache = Cache::new();

        let old_record = DnsRecord::A {
            domain: "overwrite-test.com".to_string(),
            addr: "192.168.0.1".parse().unwrap(),
            ttl: TransientTtl(300),
        };

        let new_record = DnsRecord::A {
            domain: "overwrite-test.com".to_string(),
            addr: "192.168.0.2".parse().unwrap(),
            ttl: TransientTtl(600),
        };

        cache.store(&[old_record]);

        // Ensure the old record is returned
        if let Some(packet) = cache.lookup("overwrite-test.com", QueryType::A) {
            assert_eq!(1, packet.answers.len());
            assert_eq!("192.168.0.1".parse::<std::net::Ipv4Addr>().unwrap(), packet.answers[0].get_address().unwrap());
        } else {
            panic!("Expected old record");
        }

        cache.store(&[new_record]);

        // Ensure the new record is returned
        if let Some(packet) = cache.lookup("overwrite-test.com", QueryType::A) {
            assert_eq!(1, packet.answers.len());
            assert_eq!("192.168.0.2".parse::<std::net::Ipv4Addr>().unwrap(), packet.answers[0].get_address().unwrap());
        } else {
            panic!("Expected new record");
        }
     }

    #[test]
    fn test_cache_eviction_policy() {
        let mut cache = Cache::new();

        // Simulate cache size of 2 for this test
        let records = vec![
            DnsRecord::A {
                domain: "domain1.com".to_string(),
                addr: "192.168.0.1".parse().unwrap(),
                ttl: TransientTtl(300),
            },
            DnsRecord::A {
                domain: "domain2.com".to_string(),
                addr: "192.168.0.2".parse().unwrap(),
                ttl: TransientTtl(300),
            },
         ];

        cache.store(&records);

        // Add another record, simulating cache eviction of the oldest entry
        cache.store(&[DnsRecord::A {
            domain: "domain3.com".to_string(),
            addr: "192.168.0.3".parse().unwrap(),
            ttl: TransientTtl(300),
        }]);

        // Verify eviction
        assert!(cache.lookup("domain1.com", QueryType::A).is_none());
        assert!(cache.lookup("domain2.com", QueryType::A).is_some());
        assert!(cache.lookup("domain3.com", QueryType::A).is_some());
    }


}
