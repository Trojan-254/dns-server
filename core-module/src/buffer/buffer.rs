//! buffers for use when writing and reading dns packets

use std::collections::BTreeMap;
use std::io::Read;

use derive_more::{Display, Error, From};

#[derive(Debug, Display, From, Error)]
pub enum BufferError {
    Io(std::io::Error),
    EndOfBuffer,
}

type Result<T> = std::result::Result<T, BufferError>;

/// A trait for managing operations on the packet buffer.
/// This trait abstracts reading, writing and manageing byte-level data.
pub trait PacketBuffer {
    /// Reads a single byte at the current buffer position.
    /// Advances the position by one byte.
    ///
    /// # Returns
    /// - `Ok(u8)` containing the byte if succesfull.
    /// - `Err(BufferError)` if reading fails.
    fn read(&mut self) -> Result<u8>;


    
    fn read_u16(&mut self) -> Result<u16> {
        let res = ((self.read()? as u16) << 8) | (self.read()? as u16);

        Ok(res)
    }

    fn read_u32(&mut self) -> Result<u32> {
        let res = ((self.read()? as u32) << 24)
            | ((self.read()? as u32) << 16)
            | ((self.read()? as u32) << 8)
            | ((self.read()? as u32) << 0);

        Ok(res)
    }

    fn get(&mut self, pos: usize) -> Result<u8>;
    fn get_range(&mut self, start: usize, len: usize) -> Result<&[u8]>;
    fn write(&mut self, val: u8) -> Result<()>;
    fn set(&mut self, pos: usize, val: u8) -> Result<()>;
    fn pos(&self) -> usize;
    fn seek(&mut self, pos: usize) -> Result<()>;
    fn step(&mut self, steps: usize) -> Result<()>;
    fn find_label(&self, label: &str) -> Option<usize>;
    fn save_label(&mut self, label: &str, pos: usize);

    fn write_u8(&mut self, val: u8) -> Result<()> {
        self.write(val)?;

        Ok(())
    }

    fn set_u16(&mut self, pos: usize, val: u16) -> Result<()> {
        self.set(pos, (val >> 8) as u8)?;
        self.set(pos + 1, (val & 0xFF) as u8)?;

        Ok(())
    }

    fn write_all(&mut self, bytes: &[u8]) -> Result<()> {
       for &b in bytes {
          self.write(b)?;
       }
       Ok(())
    }

    fn write_u16(&mut self, val: u16) -> Result<()> {
        self.write((val >> 8) as u8)?;
        self.write((val & 0xFF) as u8)?;

        Ok(())
    }

    fn write_u32(&mut self, val: u32) -> Result<()> {
        self.write(((val >> 24) & 0xFF) as u8)?;
        self.write(((val >> 16) & 0xFF) as u8)?;
        self.write(((val >> 8) & 0xFF) as u8)?;
        self.write(((val >> 0) & 0xFF) as u8)?;

        Ok(())
    }

    fn write_qname(&mut self, qname: &str) -> Result<()> {
        let labels = qname.split('.').collect::<Vec<&str>>();
        let mut jumped = false;

        for (i, label) in labels.iter().enumerate() {
            let remaining_qname = labels[i..].join(".");
            if let Some(pos) = self.find_label(&remaining_qname) {
                self.write_u16((pos as u16) | 0xC000)?;
                jumped = true;
                break;
            }

            self.save_label(&remaining_qname, self.pos());
            self.write_u8(label.len() as u8)?;
            self.write_all(label.as_bytes())?;
        }

        if !jumped {
            self.write_u8(0)?;
        }

        Ok(())
    }




    fn read_qname(&mut self, outstr: &mut String) -> Result<()> {
        let mut pos = self.pos();
        let mut jumped = false;

        let mut delimeter = "";
        loop {
            // Read the label length.
            let len = self.get(pos)?;

            // A two byte sequence, where the two highest bits of the first byte is
            // set, represents a offset relative to the start of the buffer. We
            // handle this by jumping to the offset, setting a flag to indicate
            // that we shouldn't update the shared buffer position once done.
            if (len & 0xC0) > 0 {
                // When a jump is performed, we only modify the shared buffer
                // position once, and avoid making the change later on.
                if !jumped {
                    self.seek(pos + 2)?;
                }
                let offset = (((len as u16) ^ 0xC0) << 8) | self.get(pos + 1)? as u16;
                pos = offset as usize;
                jumped = true;
                continue;
            }

            pos += 1;

            // Names are terminated by an empty label of length 0
            if len == 0 {
                break;
            }

            outstr.push_str(delimeter);

            let label = self.get_range(pos, len as usize)?;
            outstr.push_str(&String::from_utf8_lossy(label).to_lowercase());

            delimeter = ".";

            pos += len as usize;
        }

        if !jumped {
            self.seek(pos)?;
        }

        Ok(())
    }
}

#[derive(Default)]
pub struct VectorPacketBuffer {
    pub buffer: Vec<u8>,
    pub pos: usize,
    pub label_lookup: BTreeMap<String, usize>,
}

impl VectorPacketBuffer {
    pub fn new() -> VectorPacketBuffer {
        VectorPacketBuffer {
            buffer: Vec::new(),
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
        let res = self.buffer[self.pos];
        self.pos += 1;

        Ok(res)
    }

    fn get(&mut self, pos: usize) -> Result<u8> {
        Ok(self.buffer[pos])
    }

    fn get_range(&mut self, start: usize, len: usize) -> Result<&[u8]> {
        Ok(&self.buffer[start..start + len as usize])
    }

    fn write(&mut self, val: u8) -> Result<()> {
        self.buffer.push(val);
        self.pos += 1;

        Ok(())
    }

    fn set(&mut self, pos: usize, val: u8) -> Result<()> {
        self.buffer[pos] = val;

        Ok(())
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
    pub fn new(stream: &'a mut T) -> StreamPacketBuffer<'_, T> {
        StreamPacketBuffer {
            stream: stream,
            buffer: Vec::new(),
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

    fn save_label(&mut self, _: &str, _: usize) {
        unimplemented!();
    }

    fn read(&mut self) -> Result<u8> {
        while self.pos >= self.buffer.len() {
            let mut local_buffer = [0; 1];
            self.stream.read(&mut local_buffer)?;
            self.buffer.push(local_buffer[0]);
        }

        let res = self.buffer[self.pos];
        self.pos += 1;

        Ok(res)
    }

    fn get(&mut self, pos: usize) -> Result<u8> {
        while pos >= self.buffer.len() {
            let mut local_buffer = [0; 1];
            self.stream.read(&mut local_buffer)?;
            self.buffer.push(local_buffer[0]);
        }

        Ok(self.buffer[pos])
    }

    fn get_range(&mut self, start: usize, len: usize) -> Result<&[u8]> {
        while start + len > self.buffer.len() {
            let mut local_buffer = [0; 1];
            self.stream.read(&mut local_buffer)?;
            self.buffer.push(local_buffer[0]);
        }

        Ok(&self.buffer[start..start + len as usize])
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

pub struct BytePacketBuffer {
    pub buf: [u8; 512],
    pub pos: usize,
}

impl BytePacketBuffer {
    pub fn new() -> BytePacketBuffer {
        BytePacketBuffer {
            buf: [0; 512],
            pos: 0,
        }
    }
}

impl Default for BytePacketBuffer {
    fn default() -> Self {
        BytePacketBuffer::new()
    }
}

impl PacketBuffer for BytePacketBuffer {
    fn find_label(&self, _: &str) -> Option<usize> {
        None
    }

    fn save_label(&mut self, _: &str, _: usize) {}

    fn read(&mut self) -> Result<u8> {
        if self.pos >= 512 {
            return Err(BufferError::EndOfBuffer);
        }
        let res = self.buf[self.pos];
        self.pos += 1;

        Ok(res)
    }

    fn get(&mut self, pos: usize) -> Result<u8> {
        if pos >= 512 {
            return Err(BufferError::EndOfBuffer);
        }
        Ok(self.buf[pos])
    }

    fn get_range(&mut self, start: usize, len: usize) -> Result<&[u8]> {
        if start + len >= 512 {
            return Err(BufferError::EndOfBuffer);
        }
        Ok(&self.buf[start..start + len as usize])
    }

    fn write(&mut self, val: u8) -> Result<()> {
        if self.pos >= 512 {
            return Err(BufferError::EndOfBuffer);
        }
        self.buf[self.pos] = val;
        self.pos += 1;
        Ok(())
    }

    fn set(&mut self, pos: usize, val: u8) -> Result<()> {
        self.buf[pos] = val;

        Ok(())
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

        // First write the standard string
        match buffer.write_qname(&instr1) {
            Ok(_) => {}
            Err(_) => panic!(),
        }

        // Then we set up a slight variation with relies on a jump back to the data of
        // the first name
        let crafted_data = [0x01, b'b' as u8, 0xC0, 0x02];
        for b in &crafted_data {
            match buffer.write_u8(*b) {
                Ok(_) => {}
                Err(_) => panic!(),
            }
        }

        // Reset the buffer position for reading
        buffer.pos = 0;

        // Read the standard name
        let mut outstr1 = String::new();
        match buffer.read_qname(&mut outstr1) {
            Ok(_) => {}
            Err(_) => panic!(),
        }

        assert_eq!(instr1, outstr1);

        // Read the name with a jump
        let mut outstr2 = String::new();
        match buffer.read_qname(&mut outstr2) {
            Ok(_) => {}
            Err(_) => panic!(),
        }

        assert_eq!(instr2, outstr2);

        // Make sure we're now at the end of the buffer
        assert_eq!(buffer.pos, buffer.buffer.len());
    }

    #[test]
    fn test_write_qname() {
        let mut buffer = VectorPacketBuffer::new();

        // Write the domain names
        buffer.write_qname(&"ns1.google.com".to_string()).unwrap();
        buffer.write_qname(&"ns2.google.com".to_string()).unwrap();

        // Print the buffer contents for debugging
        println!("Buffer after writing qnames: {:?}", buffer.buffer);

        // Assert buffer position
        assert_eq!(22, buffer.pos());

        // Seek back to the beginning
        buffer.seek(0).unwrap();

        let mut str1 = String::new();
        buffer.read_qname(&mut str1).unwrap();
        assert_eq!("ns1.google.com", str1);

       let mut str2 = String::new();
       buffer.read_qname(&mut str2).unwrap();
       assert_eq!("ns2.google.com", str2);
    }


    #[test]
    fn test_write_qname_no_jump() {
        let mut buffer = VectorPacketBuffer::new();
        buffer.write_qname("example.com").unwrap();
     
        let expected = vec![
            7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', // "example"
            3, b'c', b'o', b'm',                          // "com"
            0, 
        ];

        assert_eq!(buffer.buffer, expected);
        
    }

    #[test]
    fn test_write_qname_with_jump() {
        let mut buffer = VectorPacketBuffer::new();
        buffer.write_qname("example.com").unwrap();

        // Save the position for "com"
        let pos_com = buffer.pos();

        // Write "com" should jump to the position stored for "com"
        buffer.write_qname("com").unwrap();

        let expected = vec![
            7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', // "example"
            3, b'c', b'o', b'm',                          // "com"
            0,
            0xC0, 0x08,                                          // end of qname
        ];

        // Check the data to see if jump worked correctly
        assert_eq!(buffer.buffer, expected);
    }
}
