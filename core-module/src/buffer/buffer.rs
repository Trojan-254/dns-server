// Buffer for writing and reading dns packects

use std::io::Read;
use std::collections::BTreeMap;


use derive_more::{Display, Error, From};


#[derive(Debug, Display, From, Error)]
pub enum BufferError {
    #[display(fmt = "I/O Error: {}", _0)]
    Io(std::io::Error),
    #[display(fmt = "End of buffer reached")]
    EndOfBuffer,
    #[display(fmt = "Invalid buffer access at position {}", _0)]
    InvalidBufferAccess(usize),
}


type Result<T> = std::result::Result<T, BufferError>;

pub trait PacketBuffer {
    /// Reads the next byte from the buffer.
    fn read(&mut self) -> Result<u8>;

    /// Reads a 16-bit value from the buffer.
    fn read_u16(&mut self) -> Result<u16> {
       Ok(((self.read()? as u16) << 8) | (self.read()? as u16))
    }

    /// Reads a 32-bit value from the buffer.
    fn read_u32(&mut self) -> Result<u32> {
       Ok(((self.read()? as u32) << 24)
           | ((self.read()? as u32) << 16)
           | ((self.read()? as u32) << 8)
           | ((self.read()? as u32))
    }

    /// Reads a domain name (QNAME) from the buffer.
    fn read_qname(&mut self, outstr: &mut String) -> Result<()> {
       let mut pos = self.pos();
       let mut jumped = false;

       let mut delim = "";
       loop {
          let len = self.get(pos)?;

          // Two byte sequence where the highest two bits of the first byte is set
          // this represents the offset relative to the start of the buffer .
          // this is handled by jumping to the offset, setting a flag to indicate 
          // that we should NOT update the shared buffer position once done.
          if (len & 0xC0) > 0 {
             // Whenever a jump is perfomed, we only modify the shared buffer
             // positioning once, and avoid making the change later on.
             if !jumped {
                self.seek(pos + 2)?;
             }
             let offset = (((len as u16) ^ 0xC00) << 8) | self.get(pos + 1)? as u16;
             pos = offset as usize;
             jumped = true;
             continue;
          }

          // Names will be terminated by an empty label of lenght 0
          if len == 0 {
             break;
          }

          pos += 1;

          let label_bytes = self.get_range(pos, len as usize)?;
          outstr.push_str(delim);
          outstr.push_str(&String::from_utf8_lossy(label_bytes));
          delim = ".";
          pos += len as usize;

       }

       if !jumped {
          self.seek(pos)?;
       }
       Ok(())
    }

    /// Writes a buffer to the current position in the buffer.
    fn write(&mut self, val: u8) -> Result<()>;

    /// Writes a single byte to the buffer.
    fn write_u8(&mut self, val: u8) -> Result<()> {
       self.write(val)?;
       Ok(())
    }

    /// Writes a 16-bit value to the buffer.
    fn write_u16(&mut self, val: u16) -> Result<()> {
       self.write((val >> 8) as u8)?;
       self.write((val & 0xFF) as u8)?;
       Ok(())
    }

    /// Writes a 32-bit value to the buffer.
    fn write_u32(&mut self, val: u32) -> Result<()> {
       for i in (0..4).rev() {
           self.write(((val >> (i * 8)) & 0xFF) as u8)?;
       }
       Ok(())
    }

    /// Writes a domain name(QNAME) to the buffer.
    fn write_qname(&mut self, qname: &str) -> Result<()> {
        let labels = qname.split('.');
        for label in labels {
          if label.len() > 63 {
             return Err(BufferError::io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Label too long",
             )));
          }
          self.write_u8(label.len() as u8)?;
          self.write_all(label.as_bytes())?;
        }
        self.write_u8(0) // Null-terminate QNAME

        Ok(())
    }


    /// Gets the byte at a specific position.
    fn get(&mut self, pos: usize) -> Result<u8>;

    /// Gets a range of bytes starting from a specific position.
    fn get_range(&mut self, start: usize, len: usize) -> Result<&[u8]>


    /// Finds a saved label's position.
    fn find_label(&self, label: &str) -> Option<usize>;

    /// Saves a labe at athe current position.
    fn save_label(&mut self, label: &str, pos: usize);


    /// Seeks a specific position in the buffer.
    fn seek(&mut self, pos: usize) -> Result<()>;

    /// Moves the position by a specific number of steps.
    fn step(&mut self, steps: usize) -> Result<()>;

    /// Returns the current position in the buffer.
    fn pos(self) -> usize;

    /// Sets a byte at a specific position.
    fn set(&mut self, pos: usize, val: u8) -> Resutl<()>;
}


#[derive(Default)]
pub struct VectorPacketBuffer {
    pub buffer: Vec<u8>,
    pub pos: usize,
    pub label_lookup: BTreeMap<String, usize>,
}

impl VectorPacketBuffer {
    /// Creates a new `VectorPacketBuffer` with a default initial capacity 
    pub fn new() -> VectorPacketBuffer {
        VectorPacketBuffer {
            buffer: Vec::with_capacity(512),
            pos: 0,
            label_lookup: BTreeMap::new(),
        }
    }
}


impl PacketBuffer for VectorPacketBuffer {
    fn find_label(&self, label: &str) -> Option<usize> {
       self.label_lookup.get(label).cloned()
    }

    fn save_label(&mut self, label: &str, pos: usize) {
       self.label_lookup.insert(label.to_string(), pos);
    }

    fn read(&mut self) -> Result<u8> {
       if self.pos >= self.buffer.len() {
          return Err(BufferError::EndOfBuffer);
       }
       let res = self.buffer[self.pos];
       self.pos += 1;

       Ok(res)
    }

    fn get(&mut self, pos: usize) -> Result<u8> {
       if pos >= self.buffer.len() {
          return Err(BufferError::EndOfBuffer);
       }
       Ok(self.buffer[pos])
    }

    fn get_range(&mut self, start: usize, len: usize) -> Result<&[u8]> {
       if start + len > self.buffer.len() {
          return Err(BufferError::EndOfBuffer);
       }
       Ok(&self.buffer[start..start + len])
    }

    fn write(&mut self, val: u8) -> Result<()> {
       self.buffer.push(val);
       self.pos += 1;

       Ok(())
    }

    fn set(&mut self, pos: usize, val: u8) -> Result<()> {
       if pos >= self.buffer.len() {
          return Err(BufferError::EndOfBuffer);
       }
       self.buffer[pos] = val;

      Ok(())
    }

    fn pos(&self) -> usize {
       self.pos
    }

    fn seek(&mut self, pos: usize) -> Result<()> {
       if pos > self.buffer.len() {
          return Err(BufferError::EndOfBuffer);
       }
       self.pos = pos;

       Ok(())
    }

    fn step(&mut self, steps: usize) -> Result<()> {
       if self.pos + steps > self.buffer.len() {
          Err(BufferError::EndOfBuffer);
       }
       self.pos += steps;

       Ok(())
    }
}


pub struct StreamPacketBuffer<'a T>
where
    T: Read,
{
    pub stream: &'a mut T,
    pub buffer: Vec<u8>,
    pub pos: usize,
}

impl<'a, T> StreamPacketBuffer<'a, T> 
where
    T: Read + 'a,
{
    /// Creates a new `StreamPacketBuffer` with an optional pre-allocated buffer size.
    pub fn new(stream: &'a T) -> StreamPacketBuffer<'_, T> {
        StreamPacketBuffer {
           stream: stream,
           buffer: Vec::with_capacity(512),
           pos: 0,
        }
    }
}


impl<'a, T> PacketBuffer for StreamPacketBuffer<'a, T>
where
    T: Read + 'a,
{
    fn find_label(&self, _: &str) -> Option<usize> {
        None
    }

    fn save_label(&mut self, _:&str) {
       unimplemented!();
    }

    fn read(&mut self) -> Result<u8> {
       if self.pos >= self.buffer.len() {
          let mut temp_buffer = [0; 1];
          self.stream.read(&mut temp_buffer)?;
          self.buffer.push(temp_buffer[0]);
       }
       let res = self.buffer[self.pos];
       self.pos += 1;

       Ok(res)
    }

    fn get(&mut self, pos: usize) -> Result<u8> {
       while pos >= self.buffer.len() {
          let mut temp_buffer = [0; 1];
          self.stream.read(&mut temp_buffer)?;
          self.buffer.push(temp_buffer[0]);
       }
       Ok(self.buffer[pos])
    }

    fn get_range(&mut self, start: usize, len: usize) -> Result<&[u8]> {
       while start + len > self.buffer.len() {
            let mut temp_buffer = [0; len.min(512)];
            let bytes_read = self.stream.read(&mut temp_buffer)?;
            self.buffer.extend_from_slice(&temp_buffer[..bytes_read]);
       }
       Ok(&self.buffer[start..start + len])
    }

    fn write(&mut self, _: u8) -> Result<()> {
       unimplemented!();
    }

    fn set(&mut self, _: usize, _: u8) -> Result<()> {
       unimplemented!();
    }

    fn pos(&self) -> usize {
       self.pos
    }

    fn seek(&mut self, pos: usize) -> Result<()> {
        self.pos = pos;
        Ok(())
    }

    fn step(&mut self, steps: usize) -> Result<()> {
        self.pos += steps;
        Ok(())
    }
} 

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_qname() {
       let mut buffer = VectorPacketBuffer::new();

       let instr1 = "a.google.com".to_string();
       let instr2 = "b.google.com".to_string();

       // Write the first string
       buffer.write_qname(&instr1).unwrap();

      // Write the second string using a crafted jump pointer
      let crafted_data = [0x01, b'b', 0xC0, 0x02];
      for b in &crafted_data{
          buffer.write_u8(*b).unwrap();
      }

      // Reset the positioning for reading.
      buffer.seek(0).unwrap();

      // Read and verify the first srting.
      let mut outstr1 = String::new();
      buffer.read_qname(&mut outstr1).unwrap();
      assert_eq!(instr1, outstr1, "First read_qname result mismatch");

      // Readd and verify the second string with a jump
      let mut outstr2 = String::new();
      buffer.read_qname(&mut outstr2).unwrap();
      assert_eq!(instr2, outstr2, "Second read_qname result mismatch");

      // Verify the buffer position
      assert_eq!(buffer.pos, buffer.buffer.len(), "Buffer position mismatch");

     #[test]
     fn test_write_qname() {
        let mut buffer = VectorPacketBuffer::new();

        // Write two domain names
        buffer.write_qname(&"ns1.google.com".to_string()).unwrap();
        buffer.write_qname(&"ns2.google.com".to_string()).unwrap();

        assert_eq!(22, buffer.pos(), "Buffer position mismatch after writes");

       // reset the position for reading
       buffer.seek(0).unwrap();

       // Read and verify the first domain name
       let mut str1 = String::new();
       buffer.read_qname(&mut str1).unwrap();
       assert_eq!("ns1.google.com", str1, "First write_qname mismatch");

       // Read and verify the second domain.
       let mut str2 = String::new();
        buffer.read_qname(&mut str2).unwrap();
        assert_eq!("ns2.google.com", str2, "Second write_qname mismatch");
     }

     #[test]
     fn test_vector_packet_buffer_operations() {
        let mut buffer = VectorPacketBuffer::new();

        // Test writing bytes
        for i in 0..10 {
            buffer.write(i).unwrap();
        }

        assert_eq!(buffer.pos(), 10, "Position mismatch after writes");

       // Test reading bytes
       buffer.seek(0).unwrap();
       for i in 0..10 {
           assert_eq!(buffer.read().unwrap(), i, "Mismatch in reading bytes");
       }

       // Test get and get_range
       buffer.seek(0).unwrap();
       assert_eq!(buffer.get(2).unwrap(), 2, "Get operation mismatch");
       assert_eq!(buffer.get_range(2, 3).unwrap(), &[2, 3, 4], "Get range mismatch");

       // Test out of bound errors
       assert!(buffer.get(20).is_err(), "Expected out of bounds error on get");
       assert!(buffer.get_range(8, 5).is_err(), "Expected out of bounds on get_range");
     }

     #[test]
     fn test_stream_packet_buffer() {
        let data = vec![1, 2, 3, 4, 5];
        let mut stream = &data[..];
        let mut buffer = StreamPacketBuffer::new(&mut stream);

        // Test reading beyond the initial stream
        assert_eq!(buffer.read().unwrap(), 1, "First byte mismatch");
        assert_eq!(buffer.read().unwrap(), 2, "Second byte mismatch");

        // Test dynamic buffer growth
        assert_eq!(buffer.get(4).unwrap(), 5, "Get operation mismatch after dynamic read");

        // Test get_range with stream expansion
        buffer.seek(0).unwrap();
        assert_eq!(buffer.get_range(0, 5).unwrap(), &[1, 2, 3, 4, 5], "Get range mismatch");
    }

    #[test]
    fn test_byte_packet_buffer() {
        let mut buffer = BytePacketBuffer::new();

        // Test writing within buffer limits
        for i in 0..512 {
            buffer.write(i as u8).unwrap();
        }

        // Test boundary error
        assert!(buffer.write(0).is_err(), "Expected buffer overflow error");

        // Test reading bytes
        buffer.seek(0).unwrap();
        for i in 0..512 {
            assert_eq!(buffer.read().unwrap(), i as u8, "Mismatch in reading byte");
        }

        // Test get and get_range
        assert_eq!(buffer.get(100).unwrap(), 100, "Get operation mismatch");
        assert_eq!(buffer.get_range(100, 10).unwrap(), &[100, 101, 102, 103, 104, 105, 106, 107, 108, 109], "Get range mismatch");

        // Test out-of-bounds errors
        assert!(buffer.get(600).is_err(), "Expected out-of-bounds error on get");
        assert!(buffer.get_range(510, 5).is_err(), "Expected out-of-bounds error on get_range");
    }
}
