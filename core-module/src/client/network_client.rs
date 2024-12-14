use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::mpsc::{channel, Sender};
use tokio::time::{self, Duration};
use tokio::io::AsyncWriteExt;
use tracing::{instrument};

use chrono::{DateTime, Local};
use derive_more::{Display, Error, From};

use crate::buffer::buffer::{BytePacketBuffer, PacketBuffer, StreamPacketBuffer};
use crate::network_utilities::netutil::{read_packet_length, write_packet_length};
use crate::protocols::protocol::{DnsPacket, DnsQuestion, QueryType};

#[derive(Debug, Display, From, Error)]
pub enum ClientError {
    Protocol(crate::protocols::protocol::ProtocolError),
    Io(std::io::Error),
    PoisonedLock,
    LookupFailed,
    TimeOut,
}

type Result<T> = std::result::Result<T, ClientError>;

pub trait DnsClient {
    fn get_sent_count(&self) -> usize;
    fn get_failed_count(&self) -> usize;
    fn run(&self) -> Result<()>;
    fn send_query (
       &self,
       qname: &str,
       qtype: QueryType,
       server: (&str, u16),
       recursive: bool,
    ) -> Result<DnsPacket>;
}

#[derive(Debug)]
struct PendingQuery {
    seq: u16,
    timestamp: DateTime<Local>,
    tx: Sender<Option<DnsPacket>>,
}

#[derive(Debug)]
pub struct DnsNetworkClient {
    total_sent: AtomicUsize,
    total_failed: AtomicUsize,
    seq: AtomicUsize,
    socket: Arc<UdpSocket>,
    pending_queries: Arc<Mutex<Vec<PendingQuery>>>,
}

impl DnsNetworkClient {
    pub async fn new(port: u16) -> Result<DnsNetworkClient> {
        let socket = UdpSocket::bind(("0.0.0.0", port)).await.map_err(ClientError::Io)?;
        Ok(DnsNetworkClient {
            total_sent: AtomicUsize::new(0),
            total_failed: AtomicUsize::new(0),
            seq: AtomicUsize::new(0),
            socket: Arc::new(socket),
            pending_queries: Arc::new(Mutex::new(Vec::new())),
        })
    }

    #[instrument]
    pub async fn send_tcp_query(
        &self,
        qname: &str,
        qtype: QueryType,
        server: (&str, u16),
        recursive: bool,
    ) -> Result<DnsPacket> {
        self.total_sent.fetch_add(1, Ordering::Release);
        let mut packet = DnsPacket::new();
        packet.header.id = self.seq.fetch_add(1, Ordering::SeqCst) as u16;
        packet.header.questions = 1;
        packet.header.recursion_desired = recursive;
        packet.questions.push(DnsQuestion::new(qname.into(), qtype));

        let mut req_buffer = BytePacketBuffer::new();
        packet.write(&mut req_buffer, 0xFFFF)?;

        let address = format!("{}:{}", server.0, server.1);
        let mut socket = TcpStream::connect(address).await.map_err(ClientError::Io)?;

        write_packet_length(&mut socket, req_buffer.pos()).await?;
        socket.write_all(&req_buffer.buf[0..req_buffer.pos]).await?;
        socket.flush().await?;

        let _ = read_packet_length(&mut socket).await?;
        let mut stream_buffer = StreamPacketBuffer::new(&mut socket);
        let response_packet = DnsPacket::from_buffer(&mut stream_buffer)?;

        Ok(response_packet)
    }

    #[instrument]
    pub async fn send_udp_query(
        &self,
        qname: &str,
        qtype: QueryType,
        server: (&str, u16),
        recursive: bool,
    ) -> Result<DnsPacket> {
        self.total_sent.fetch_add(1, Ordering::Release);
        let mut packet = DnsPacket::new();
        packet.header.id = self.seq.fetch_add(1, Ordering::SeqCst) as u16;
        packet.header.questions = 1;
        packet.header.recursion_desired = recursive;
        packet.questions.push(DnsQuestion::new(qname.to_string(), qtype));

        let (tx, mut rx) = channel(1);
        {
            let mut pending_queries = self
                .pending_queries
                .lock()
                .map_err(|_| ClientError::PoisonedLock)?;
            pending_queries.push(PendingQuery {
                seq: packet.header.id,
                timestamp: Local::now(),
                tx,
            });
        }

        let mut req_buffer = BytePacketBuffer::new();
        packet.write(&mut req_buffer, 512)?;

        let address = format!("{}:{}", server.0, server.1);
        self.socket
            .send_to(&req_buffer.buf[0..req_buffer.pos], &address)
            .await
            .map_err(ClientError::Io)?;

        let response = time::timeout(Duration::from_secs(3), rx.recv()).await;

        match response {
            Ok(Some(Some(packet))) => Ok(packet),
            Ok(Some(None)) | Err(_) => {
                self.total_failed.fetch_add(1, Ordering::Release);
                Err(ClientError::TimeOut)
            }
            Ok(None) => {
                self.total_failed.fetch_add(1, Ordering::Release);
                Err(ClientError::LookupFailed)
            }
        }
    }
}
