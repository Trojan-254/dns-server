//! buffers for use when writing and reading dns packets

use std::collections::BTreeMap;
use std::io::Read;
use std::fmt;

use derive_more::{Display, Error, From};

#[derive(Debug)]
pub enum Error {
    InvalidCharacterInLabel,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
         match self {
            Error::InvalidCharacterInLabel => write!(f, "Invalid character in label"),
         }
    }
}

impl std::error::Error for Error {}

#[derive(Debug)]
pub struct InvalidUtf8;

impl fmt::Display for InvalidUtf8 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Encountered invalid UTF-8 data")
    }
}

impl std::error::Error for InvalidUtf8 {}

#[derive(Debug)]
pub struct InvalidCompressionPointer;

impl fmt::Display for InvalidCompressionPointer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Invalid compression pointer encountered")
    }
}

impl std::error::Error for InvalidCompressionPointer {}


#[derive(Debug, Display, From, Error)]
pub enum BufferError {
    Io(std::io::Error),
    EndOfBuffer,
    InvalidCharacterInLabel,
    InvalidCompressionPointer,
    InvalidUtf8,
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
        // Handle empty QName case.
        if qname.is_empty() {
           self.write_u8(0)?;
           return Ok(())
        }

        let labels = qname.split('.').collect::<Vec<&str>>();
        let mut jumped = false;

        for (i, label) in labels.iter().enumerate() {
            // Validate the label charactres
            for c in label.chars() {
               if !c.is_alphanumeric() && c != '-' {
                  return Err(BufferError::InvalidCharacterInLabel);
               }
            }
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




    // fn read_qname(&mut self, outstr: &mut String) -> Result<()> {
    //     let mut pos = self.pos();
    //     let mut jumped = false;
    //     let mut delim = "";

    //     loop {
    //         let len = self.read()? as usize;
            
    //         if self.is_compression_pointer(len) {
    //             if !jumped {
    //                 self.seek(pos + 2).map_err(|_| BufferError::EndOfBuffer)?;
    //             }
    //             let offset = self.calculate_offset(pos, len)?;
    //             pos = offset;
    //             jumped = true;
    //             continue;
    //         }
    //         pos += 1;

    //         if len == 0 {
    //             break;
    //         }
    //         outstr.push_str(delim);
    //         let str_buffer = self.get_range(pos, len as usize)?;
    //         let label = String::from_utf8(str_buffer.to_vec()).map_err(|_| BufferError::InvalidUtf8)?;
    //         outstr.push_str(&label.to_lowercase());

    //         delim = ".";
    //         pos += len as usize;
    //     }
    //     if !jumped {
    //         self.seek(pos)?;
    //     }
        
    //     Ok(())
    // }

    

    // fn is_compression_pointer(&mut self, len: u8) -> bool {
    //     (len & 0xC0) > 0
    // }

    // fn calculate_offset(&mut self, pos: usize, len: u8) -> Result<usize> {
    //     if pos + 1 >= self.buffer.len() {
    //         return Err(BufferError::InvalidCompressionPointer);
    //     }
    //     let b2 = self.get(pos + 1).map_err(|_| BufferError::InvalidCompressionPointer)? as u16;
    //     let offset = (((len as u16) ^ 0xC0) << 8) | b2;
    //     if offset as usize >= self.buffer.len() {
    //         return Err(BufferError::InvalidCompressionPointer);
    //     }
    //     offset as usize
    // }

    fn read_qname(&mut self, outstr: &mut String) -> Result<()> {
        let mut pos = self.pos();
        let mut jumped = false;
        let mut delim = "";

        loop {
            let len = self.get(pos)?;

            if self.is_compression_pointer(len) {
                if !jumped {
                    self.seek(pos + 2)?;
                }
                let offset = self.calculate_offset(pos, len);
                pos = offset;
                jumped = true;
                continue;
            }
            pos += 1;

            if len == 0 {
                break;
            }
            outstr.push_str(delim);
            let str_buffer = self.get_range(pos, len as usize)?;
            outstr.push_str(&String::from_utf8_lossy(str_buffer).to_lowercase());

            delim = ".";
            pos += len as usize;
        }
        if !jumped {
            self.seek(pos)?;
        }
        
        Ok(())
    }

    fn is_compression_pointer(&mut self, len: u8) -> bool {
        (len & 0xC0) > 0
    }

    fn calculate_offset(&mut self, pos: usize, len: u8) -> usize {
        let b2 = match self.get(pos + 1){
            Ok(val) => val as u16,
            Err(_) => return usize::MAX,
        };
        let offset = (((len as u16) ^ 0xC0) << 8) | b2;
        offset as usize
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
        if start + len > self.buffer.len() {
            return Err(BufferError::EndOfBuffer)
        }
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

    #[test]
    fn test_write_qname_empty() {
        let mut buffer = VectorPacketBuffer::new();
        
        // Writing an empty domain name should only produce the null byte (0x00)
        buffer.write_qname("").unwrap();
        
        let expected = vec![0]; // Null byte indicating end of domain name
        assert_eq!(buffer.buffer, expected);
    }
    
    #[test]
    fn test_write_qname_single_label() {
        let mut buffer = VectorPacketBuffer::new();
        
        // Writing a single label domain name
        buffer.write_qname("example").unwrap();
        
        let expected = vec![
            7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', // "example"
            0,                                         // End of name
        ];
    
        assert_eq!(buffer.buffer, expected);
    }
    
    #[test]
    fn test_write_qname_maximum_length_label() {
        let mut buffer = VectorPacketBuffer::new();
    
        // A label with 63 characters (maximum valid label length)
        let label = "a".repeat(63); // "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        buffer.write_qname(&label).unwrap();
    
        let mut expected = vec![63]; // Label length
        expected.extend(label.as_bytes()); // The label itself
        expected.push(0); // End of name
        
        assert_eq!(buffer.buffer, expected);
    }
    
    #[test]
    fn test_write_qname_invalid_characters() {
        let mut buffer = VectorPacketBuffer::new();
        
        // Invalid DNS label containing underscores should panic or return an error
        let result = buffer.write_qname("invalid_label_1.com");
        assert!(result.is_err(), "Expected error for invalid characters in label");
    }
    
    #[test]
    fn test_write_qname_multiple_repeated_labels_with_jump() {
        let mut buffer = VectorPacketBuffer::new();
    
        // Write the same label multiple times and expect compression
        buffer.write_qname("example.com").unwrap();
        buffer.write_qname("com").unwrap();  // This should jump to the previously written "com"
    
        let expected = vec![
            7, b'e', b'x', b'a', b'm', b'p', b'l', b'e',  // "example"
            3, b'c', b'o', b'm',                         // "com"
            0,                                          // End of name
            0xC0, 0x08,                                  // Compression pointer for "com"
        ];
    
        assert_eq!(buffer.buffer, expected);
    }
    
    // #[test]
    // fn test_write_qname_long_name_with_compression() {
    //     let mut buffer = VectorPacketBuffer::new();
    
    //     // Write a longer domain name and expect compression for repeated labels
    //     buffer.write_qname("a.b.c.d.e.f.g.h.i.j.k.l.m.n.o.p.q.r.s.t.u.v.w.x.y.z.com").unwrap();
    //     buffer.write_qname("com").unwrap();  // This should jump to the previously written "com"
    
    //     let expected = vec![
    //         1, b'a', 1, b'b', 1, b'c', 1, b'd', 1, b'e', 1, b'f', 1, b'g', 1, b'h', 
    //         1, b'i', 1, b'j', 1, b'k', 1, b'l', 1, b'm', 1, b'n', 1, b'o', 1, b'p', 
    //         1, b'q', 1, b'r', 1, b's', 1, b't', 1, b'u', 1, b'v', 1, b'w', 1, b'x',
    //         1, b'y', 1, b'z', 3, b'c', b'o', b'm', 0,              // Full name and end
    //         0xC0, 0x08,                                            // Compression pointer for "com"
    //     ];
    
    //     assert_eq!(buffer.buffer, expected);
    // }

    // Test case 1: Basic case without compression
    #[test]
    fn test_read_qname_basic() {
        let mut buffer = VectorPacketBuffer {
            buffer: vec![3, b'w', b'w', b'w', 3, b'c', b'o', b'm', 0],
            pos: 0,
            label_lookup: BTreeMap::new(),
        };
        let mut result = String::new();
        
        assert!(buffer.read_qname(&mut result).is_ok());
        assert_eq!(result, "www.com");
    }

    // Test case 2: Basic case with compression
    #[test]
    fn test_read_qname_compression() {
        let mut buffer = VectorPacketBuffer {
            buffer: vec![
                3, b'w', b'w', b'w', 3, b'c', b'o', b'm', 0, // "www.com"
                0xC0, 0x00 // Compression pointer to the first label
            ],
            pos: 0,
            label_lookup: BTreeMap::new(),
        };
        let mut result = String::new();
        
        assert!(buffer.read_qname(&mut result).is_ok());
        assert_eq!(result, "www.com");
    }

    // Test case 3: Empty label
    #[test]
    fn test_read_qname_empty_label() {
        let mut buffer = VectorPacketBuffer {
            buffer: vec![3, b'w', b'w', b'w', 3, b'c', b'o', b'm', 0, 0], // Empty label at the end
            pos: 0,
            label_lookup: BTreeMap::new(),
        };
        let mut result = String::new();
        
        assert!(buffer.read_qname(&mut result).is_ok());
        assert_eq!(result, "www.com");
    }

    // Test case 4: Compression pointer jump
    #[test]
    fn test_read_qname_compression_jump() {
        let mut buffer = VectorPacketBuffer {
            buffer: vec![
                3, b'w', b'w', b'w', 3, b'c', b'o', b'm', 0, // "www.com"
                0xC0, 0x00, // Compression pointer to the first label
                0xC0, 0x03  // Compression pointer to the second label
            ],
            pos: 0,
            label_lookup: BTreeMap::new(),
        };
        let mut result = String::new();
        
        assert!(buffer.read_qname(&mut result).is_ok());
        assert_eq!(result, "www.com");
    }

    // Test case 5: Multiple labels
    #[test]
    fn test_read_qname_multiple_labels() {
        let mut buffer = VectorPacketBuffer {
            buffer: vec![
                3, b'w', b'w', b'w', 3, b'c', b'o', b'm', 3, b'e', b'd', b'u', 0
            ],
            pos: 0,
            label_lookup: BTreeMap::new(),
        };
        let mut result = String::new();
        
        assert!(buffer.read_qname(&mut result).is_ok());
        assert_eq!(result, "www.com.edu");
    }

}
