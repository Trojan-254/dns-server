use std::sync::Arc;
use async_trait::async_trait;
use tracing::{debug, error, info};
use crate::server::context::ServerContext;
use crate::protocols::protocol::{DnsPacket, QueryType, ResultCode};
use crate::resolvers::resolve::{DnsResolver, ResolveError, Result};

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
    fn get_context(&self) -> Arc<ServerContext> {
        self.context.clone()
    }

    async fn perform(&mut self, qname: &str, qtype: QueryType) -> Result<DnsPacket, ResolveError> {
        // Find the closest name server by progressively moving towards root servers.
        let mut tentative_ns = None;
        let labels = qname.split('.').collect::<Vec<&str>>();

        // Iterating over labels to find the closest nameserver
        for lbl_idx in 0..=labels.len() {
            let domain = labels[lbl_idx..].join(".");

            // Lookup NS records asynchronously and try to find an A record for the nameserver.
            match self
                .context
                .cache
                .lookup_async(&domain, QueryType::NS)
                .await
                .and_then(|qr| qr.get_unresolved_ns(&domain))
                .and_then(|ns| async {
                    self.context.cache.lookup_async(&ns, QueryType::A).await
                })
                .await
                .and_then(|qr| qr.get_random_a())

            {
                Some(addr) => {
                    tentative_ns = Some(addr);
                    break;
                }
                None => continue,
            }
        }

        // If no name servers are found, return an error
        let mut ns = tentative_ns.ok_or_else(|| ResolveError::NoServerFound)?;

        // Start Qerying the name servers
        loop {
            info!(target: "dns", "Attempting the lookup of {:?} {} with NS {}", qtype, qname, ns);

            let server = (ns.as_str(), 53);
            let response = match self.context.client.send_query_async(qname, qtype.clone(), server, false).await {
                Ok(res) => res,
                Err(err) => {
                    error!(target: "dns", "Failed to send query: {:?}", err);
                    return Err(ResolveError::client(err));
                }
            };

            // If we got an actual answer, we are done!.
            if !response.answers.is_empty() && response.header.rescode == ResultCode::NOERROR {
                debug!(target: "dns", "Caching response and answers are returning");
                self.context.cache.store_async(&response.answers).await?;
                self.context.cache.store_async(&response.authorities).await?;
                self.context.cache.store_async(&response.resources).await?;
                return Ok(response);
            }

            // Handle NXDOMAIN (non-existent domain) case
            if response.header.rescode == ResultCode::NXDOMAIN {
                if let Some(ttl) = response.get_ttl_from_soa() {
                    self.context.cache.store_nx_domain_async(qname, qtype, ttl).await?;
                }
                return Ok(response);
            }

            // Try to find a new nameserver based on NS records and a corresponding A record
            if let Some(new_ns) = response.get_resolved_ns(qname) {
                ns = new_ns.clone();
                self.context.cache.store_async(&response.answers).await?;
                self.context.cache.store_async(&response.authorities).await?;
                self.context.cache.store_async(&response.resources).await?;
                continue;
            }

            // Resolve IP for an unresolved NS record
            let new_ns_name = match response.get_unresolved_ns(qname) {
                Some(x) => x,
                None => return Ok(response),
            };

            debug!(target: "dns", "Recursively resolving NS {}", new_ns_name);
            let recursive_response = self.resolve(&new_ns_name, QueryType::A, true).await?;

            // Restart with a new NS if found
            if let Some(new_ns) = recursive_response.get_random_a() {
                ns = new_ns.clone();
            } else {
                return Ok(response);
            }
        }
    }
}
