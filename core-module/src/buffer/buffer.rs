// Buffer for writing and reading dns packects

use std::io::Read;
use std::collections::BTreeMap;
use std::fmt;

use derive_more::{Display, Error, From};

#[derive(Debug)]
struct StringError(String);

impl fmt::Display for StringError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
       write!(f, "{}", self.0)
    }
}

impl std::error::Error for StringError {}

#[derive(Debug, Display, From, Error)]
pub enum BufferError {
    #[display(fmt = "I/O Error: {}", _0)]
    Io(std::io::Error),
    #[display(fmt = "End of buffer reached")]
    EndOfBuffer,
    #[display(fmt = "Invalid buffer access at position {}", _0)]
    InvalidBufferAccess(StringError),
}


type Result<T> = std::result::Result<T, BufferError>;

pub trait PacketBuffer {
    /// Reads the next byte from the buffer.
    fn read(&mut self) -> Result<u8>;

    fn write_all(&mut self, buf: &[u8]) -> Result<()> {
        for &byte in buf {

        self.write(byte)?;

        }
        Ok(())
    }
    
    /// Reads a 16-bit value from the buffer.
    fn read_u16(&mut self) -> Result<u16> {
       Ok(((self.read()? as u16) << 8) | (self.read()? as u16))
    }

    /// Reads a 32-bit value from the buffer
    fn read_u32(&mut self) -> Result<u32> {
      Ok(((self.read()? as u32) << 24)
          | ((self.read()? as u32) << 16)
          | ((self.read()? as u32) << 8)
          | (self.read()? as u32)
         )
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
        let labels: Vec<&str> = qname.split('.').collect();
        let mut jumps_perfomed: bool = false;

        // process each label
        for (index, label) in labels.iter().enumerate() {
            let remaining_labels = &labels[index..];
            let remaining_name = remaining_labels.join(".");

            if let Some(previous_position) = self.find_label(&remaining_name) {
               let jump_instruction = (previous_position as u16) | 0xC000;
               self.write_u16(jump_instruction)?;
               jumps_perfomed = true;
               break;
            }

            let current_position = self.pos();
            self.save_label(&remaining_name, current_position);

            let label_length = label.len();
            if label_length > 63 {
               return Err(BufferError::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Label too long"
               )));
            }
            self.write_u8(label_length as u8)?;
            for &byte in label.as_bytes() {
                self.write_u8(byte)?;
            }
        }

        if !jumps_perfomed {
           self.write_u8(0)?;
        }

        Ok(())
    }


    /// Gets the byte at a specific position.
    fn get(&mut self, pos: usize) -> Result<u8>;

    /// Gets a range of bytes starting from a specific position.
    fn get_range(&mut self, start: usize, len: usize) -> Result<&[u8]>;


    /// Finds a saved label's position.
    fn find_label(&self, label: &str) -> Option<usize>;

    /// Saves a labe at athe current position.
    fn save_label(&mut self, label: &str, pos: usize);


    /// Seeks a specific position in the buffer.
    fn seek(&mut self, pos: usize) -> Result<()>;

    /// Moves the position by a specific number of steps.
    fn step(&mut self, steps: usize) -> Result<()>;

    /// Returns the current position in the buffer.
    fn pos(&self) -> usize;

    /// Sets a byte at a specific position.
    fn set(&mut self, pos: usize, val: u8) -> Result<()>;
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
          return Err(BufferError::EndOfBuffer);
       }
       self.pos += steps;

       Ok(())
    }
}


pub struct StreamPacketBuffer<'a, T>
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
    pub fn new(stream: &'a mut T) -> StreamPacketBuffer<'_, T> {
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

    fn save_label(&mut self, _:&str, _:usize) {
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
          let mut temp_buffer = vec![0; len.min(512)];
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
    fn test_read_qname() {
       // Simulating a buffer with a domain name and compression
       let mut buffer = VectorPacketBuffer::new();

       // Write a domain name: "wwww.example.com"
       buffer.write_qname("www.example.com").unwrap();
       println!("Buffer after write: {:?}", buffer.data());

      // Add another pointer that uses a pointer to "example.com"
      buffer.write_qname("mail.example.com").unwrap();
      println!("Buffer after write: {:?}", buffer.data());

      // Reset position for reading
      buffer.seek(0).unwrap();

      // Case 1: Read full domain name
      let mut output1 = String::new();
      buffer.read_qname(&mut output1).unwrap();
      assert_eq!(output1, "www.example.com");

      // Case 2: Read the compressed domain
      let mut output2 = String::new();
      buffer.read_qname(&mut output2).unwrap();
      assert_eq!(output2, "mail.example.com");
    }

  

}
