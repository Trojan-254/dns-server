use std::sync::Arc;
use async_trait::async_trait;
use tracing::{debug, error, info};
use crate::dns::context::ServerContext;
use crate::dns::protocol::{DnsPacket, QueryType, ResultCode};
use crate::dns::resolve::{DnsResolver, ResolveError, Result};

/// A Recursive DNS Resolver
///
/// This resolver can answer any request using the root servers of the internet.
pub struct RecursiveDnsResolver {
    context: Arc<ServerContext>,
}


impl RecursiveDnsResolver {
    /// Creates a new `RecursiveDnsResolver`.
    pub fn new(context: Arc<ServerContext>) -> RecursiveDnsResolver{
        RecursiveDnsResolver { context }
    }
}


#[async_trait]
impl DnsResolver for RecursiveDnsResolver {
    /// Return the shared server context.
    fn get_context(&self) -> Arc<ServerContext> {
        self.context.clone()
    }

    /// Asynchronous recursive DNS Query resolution.
    async fn perfom(&mut self, qname: &str: qtype: QueryType) -> Result<DnsPacket> {
         // Find the closest name server by progressively moving towards the root servers.
         let mut tentative_ns = None;
         let labels = qname.split('.').collect::<Vec<&str>>();

         for lbl_idx in 0..=labels.len() {
             let domain = labels[lbl_idx..].join(".");

             match self
                 .context
                 .cache
                 .lookup_async(&domain, QueryType::NS)
                 .await
                 .and_then(|qr| qr.get_unresolved_ns(&domain))
                 .and_then(|ns| self.context.cache.lookup_async(&ns, QueryType::A).await)
                 .and_then(|qr| qr.get_random_a())
             {
                 Some(addr) => {
                     tentative_ns = Some(addr);
                     break;
                 }
                 None => continue,
             }
         }

         let mut ns = tentative_ns.ok_or_else(|| ResolveError::NoServerFound)?;

         // Start querying name servers
         loop {
             info!(target: "dns", "Attempting lookup of {:?} {} with NS {}", qtype, qname, ns);

             let server = (ns.as_str(), 53);
             let response = match self
                 .context
                 .client
                 .send_query_async(qname, qtype.clone(), server, false)
                 .await
             {
                 Ok(res) = res,
                 Err(err) => {
                    error!(target: "dns", "Failed to send query: {:?}", err);
                    return Err(ResolveError::client(err));
                 }
             };

             if !response.answers.is_empty() && response.header.rescode == ResultCode::NOERROR {
                  debug!(target: "dns", "Caching response answers and returning");
                  self.context.cache.store_async(&response.answers).await?;
                  self.context.cache.store_async(&response.authorities).await?;
                  self.context.cache.store_async(&response.resources).await?;
                  return Ok(response);
             }

             if response.header.rescode == ResultCode::NXDOMAIN {
                if let Some(ttl) = response.get_ttl_from_soa() {
                    self.context.cache.store_nxdomain_async(qname, qtype, ttl).await?;
                }
                return Ok(response);
            }

            if let Some(new_ns) = response.get_resolved_ns(qname) {
                ns = new_ns;
                self.context.cache.store_async(&response.answers).await?;
                self.context.cache.store_async(&response.authorities).await?;
                self.context.cache.store_async(&response.resources).await?;
                continue;
            }

            let new_ns_name = match response.get_unresolved_ns(qname) {
                Some(name) => name,
                None => return Ok(response),
            };

            debug!(target: "dns", "Recursively resolving NS {}", new_ns_name);
            let recursive_response = self.resolve(&new_ns_name, QueryType::A, true).await?;

            if let Some(new_ns) = recursive_response.get_random_a() {
                ns = new_ns;
            } else {
                return Ok(response);
            }
         }
    }
}
