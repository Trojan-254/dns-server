//! Resolver implementations with startegies for answering incoming queries.
use std::sync::Arc;
use derive_more::{Display, Error, From};
use async_trait::async_trait;

use crate::server::context::ServerContext;
use crate::protocols::protocol::{DnsPacket, QueryType, ResultCode};

#[derive(Debug, Display, From, Error)]
pub enum ResolveError {
    Client(crate::client::network_client::ClientError),
    Cache(crate::cache::memory_cache::CacheError),
    Io(std::io::Error),
    NoServerFound,
}

pub type Result<T> = std::result::Result<T, ResolveError>;

/// Asynchronous trait for DNS resolvers to implement various resolution strategies.
#[async_trait]
pub trait DnsResolver {
    /// Run the server context.
    fn get_context(&self) -> Arc<ServerContext>;

    /// Resolves a DNS Query Asynchronously using the specified query_name, query_type and recursion preference
    async fn resolve(&mut self, qname: &str, qtype: QueryType, recursion: bool) -> Result<DnsPacket> {
        // Handle unsupported query types.
        if let QueryType::UNKNOWN(_) = qtype {
           return Ok(create_error_response(RESULT_CODE::NO_TIMP));
        }

        let context = self.get_context();

        // Check if authority has answer.
        if let Some(response) = context.authority.query(qname, qtype) {
           return Ok(response);
        }

        // Refuse if recursion is disabled or not allowed.
        if !recursion || !context.allow_recursive {
           return Ok(create_error_response(ResultCode::REFUSED));
        }

        // Check the cache for the answer.
        if let Some(response) = context.cache.lookup(qname, qtype) {
            return Ok(response);
        }

        // Additional cache lookup for CNAME records when querying A or AAAA types.
        if matches!(qtype, QueryType::A | QueryType::AAAA) {
            if let Some(cname_response) = context.cache.lookup(qname, QueryType::CNAME) {
               return Ok(cname_response);
            }
        }

        // Perfom external resolution asynchronously if no local answer is found.
        self.perform(qname, qtype).await
    }

    /// Perfoms the actual DNS resolution asynchronously n/b forwarding or recursive resolution.
    async fn perform(&mut self, qname: &str, qtype: QueryType) -> Result<DnsPacket>;
}

/// Creates a dns packet with specific error result code.
fn create_error_response(rescode: ResultCode) -> DnsPacket {
    let mut packet = DnsPacket::new();
    packet.header.rescode = rescode;
    packet
}
