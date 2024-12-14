//! Contains the network utilities

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

pub async fn read_packet_length(stream: &mut TcpStream) -> Result<u16, std::io::Error> {
    let mut len_buffer = [0; 2];
    stream.read_exact(&mut len_buffer).await?;
    let length = ((len_buffer[0] as u16) << 8) | (len_buffer[1] as u16);

    Ok(length)
}

pub async fn write_packet_length(stream: &mut TcpStream, len: usize) -> Result<(), std::io::Error> {
    let mut len_buffer = [0; 2];
    len_buffer[0] = (len >> 8) as u8;
    len_buffer[1] = (len & 0xFF) as u8;

    stream.write_all(&len_buffer).await?;

    Ok(())
}
