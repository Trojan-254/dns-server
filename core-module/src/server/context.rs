//! The `ServerContext` in this module holds the common state across the server.

use std::fs;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use derive_more::{Display, Error, From};

use crate::dns::authority::Authority;
use crate::dns::cache::SynchronizedCache;
use crate::dns::client::{DnsClient, DnsNetworkClient};
use crate::dns::resolve::{DnsResolver, ForwardingDnsResolver, RecursiveDnsResolver};

#[derive(Debug, Display, From, Error)]
pub enum ContextError {
    #[display(fmt = "Authority Error: {}", _0)]
    Authority(crate::dns::authority::AuthorityError),
    #[display(fmt = "Client Error: {}", _0)]
    Client(crate::dns::client::ClientError),
    #[display(fmt = "IO Error: {}", _0)]
    Io(std::io::Error),
}

type Result<T> = std::result::Result<T, ContextError>;

/// Default configuration values for the server.
const DEFAULT_DNS_PORT: u16 = 53;
const DEFAULT_API_PORT: u16 = 5380;
const DEFAULT_ZONES_DIR: &str = "zones";

pub struct ServerStatistics {
    pub tcp_query_count: AtomicUsize,
    pub udp_query_count: AtomicUsize,
}

impl ServerStatistics {
    /// Returns the count of TCP queries processed by the server.
    pub fn get_tcp_query_count(&self) -> usize {
        self.tcp_query_count.load(Ordering::Acquire)
    }

    /// Returns the count of UDP queries processed by the server.
    pub fn get_udp_query_count(&self) -> usize {
        self.udp_query_count.load(Ordering::Acquire)
    }
}

pub enum ResolveStrategy {
    Recursive,
    Forward { host: String, port: u16 },
}

pub struct ServerContext {
    pub authority: Authority,
    pub cache: SynchronizedCache,
    pub client: Box<dyn DnsClient + Sync + Send>,
    pub dns_port: u16,
    pub api_port: u16,
    pub resolve_strategy: ResolveStrategy,
    pub allow_recursive: bool,
    pub enable_udp: bool,
    pub enable_tcp: bool,
    pub enable_api: bool,
    pub statistics: ServerStatistics,
    pub zones_dir: &'static str,
}

impl Default for ServerContext {
    fn default() -> Self {
        Self::new()
    }
}

impl ServerContext {
    /// Creates a new `ServerContext` with default settings.
    pub fn new() -> Self {
        ServerContext {
            authority: Authority::new(),
            cache: SynchronizedCache::new(),
            client: Box::new(DnsNetworkClient::new(34255)),
            dns_port: DEFAULT_DNS_PORT,
            api_port: DEFAULT_API_PORT,
            resolve_strategy: ResolveStrategy::Recursive,
            allow_recursive: true,
            enable_udp: true,
            enable_tcp: true,
            enable_api: true,
            statistics: ServerStatistics {
                tcp_query_count: AtomicUsize::new(0),
                udp_query_count: AtomicUsize::new(0),
            },
            zones_dir: DEFAULT_ZONES_DIR,
        }
    }

    /// Initializes the server context, setting up directories, clients, and authority data.
    pub fn initialize(&mut self) -> Result<()> {
        // Ensure zones directory exists.
        fs::create_dir_all(self.zones_dir)
            .map_err(ContextError::Io)?;

        // Start the client thread.
        self.client.run()?;

        // Load authority data.
        self.authority.load()?;

        Ok(())
    }

    /// Creates a DNS resolver based on the current resolution strategy.
    pub fn create_resolver(&self, ptr: Arc<Self>) -> Box<dyn DnsResolver> {
        match &self.resolve_strategy {
            ResolveStrategy::Recursive => Box::new(RecursiveDnsResolver::new(ptr)),
            ResolveStrategy::Forward { host, port } => {
                Box::new(ForwardingDnsResolver::new(ptr, (host.clone(), *port)))
            }
        }
    }
}
