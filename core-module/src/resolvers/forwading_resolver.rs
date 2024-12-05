use std::sync::Arc;
use async_trait::async_trait;
use crate::server::context::ServerContext;
use crate::protocols::protocol::{DnsPacket, QueryType};
use crate::resolvers::resolve::{DnsResolver, ResolveError, Result};

/// A forwading DNS Resolver
///
/// The resolver uses an external DNS Server to service a query.
pub struct ForwadingDnsResolver {
    context: Arc<ServerContext>,
    server: (String, u16),
}

impl ForwadingDnsResolver {
    /// Creates a new `ForwadingDnsResolver` with the given server context and upstream server.
    pub fn new (context: Arc<ServerContext>, server: (String, u16)) -> ForwadingDnsResolver {
        ForwadingDnsResolver {
            context,
            server,
        }
    }
}

#[async_trait]
impl DnsResolver for ForwadingDnsResolver {
     /// Returns the shared server context.
     fn get_context(&self) -> Arc<ServerContext> {
        self.context.clone()
     }

     /// Perfoms an asynchronous DNS Query to the external server.
     async fn perfom(&mut self, qname: &str, qtype: QueryType) -> Result<DnsPacket> {
           let (host, port) = &self.server;

           // Asynchronous query to the external DNS server
           let result = self
               .context
               .client
               .send_query_async(qname, qtype, (host.as_str(), *port), true)
               .await?;

           // Cache the answers if the query suceeds
           self.context.cache.store_async(&result.answers).await?;

           Ok(result)
     }
}
