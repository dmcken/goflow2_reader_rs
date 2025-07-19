// Protobuf structs and functions

// std
use std::collections::HashMap;
use std::io::{Cursor,Read};

// External
use serde::Serialize;

// Enums
#[derive(Debug, Serialize)]
pub enum ProtobufValue {
    Varint(u64),
    Fixed64(u64),
    LengthDelimited(Vec<u8>),
    Fixed32(u32),
}

// Utility functions
pub fn read_varint_reader<R: Read>(reader: &mut R) -> Option<u64> {
    let mut result = 0u64;
    let mut shift = 0;
    for _ in 0..10 {
        let mut byte = [0u8; 1];
        if reader.read_exact(&mut byte).is_err() {
            return None; // EOF or read error
        }
        let b = byte[0];
        result |= ((b & 0x7F) as u64) << shift;
        if b & 0x80 == 0 {
            return Some(result);
        }
        shift += 7;
    }
    None
}

fn read_varint(cursor: &mut Cursor<Vec<u8>>) -> Option<u64> {
    let mut result = 0u64;
    let mut shift = 0;
    for _ in 0..10 {
        let mut buf = [0u8; 1];
        cursor.read_exact(&mut buf).ok()?;
        let byte = buf[0];
        result |= ((byte & 0x7F) as u64) << shift;
        if byte & 0x80 == 0 {
            return Some(result);
        }
        shift += 7;
    }
    None
}

fn read_field(cursor: &mut Cursor<Vec<u8>>) -> Option<(u32, ProtobufValue)> {
    let key = read_varint(cursor)? as u32;
    let field_number = key >> 3;
    let wire_type = key & 0x07;

    let value = match wire_type {
        0 => { // varint
            let val = read_varint(cursor)?;
            ProtobufValue::Varint(val)
        },
        1 => { // 64-bit
            let mut buf = [0u8; 8];
            cursor.read_exact(&mut buf).ok()?;
            let val = u64::from_le_bytes(buf);
            ProtobufValue::Fixed64(val)
        },
        2 => { // length-delimited
            let len = read_varint(cursor)? as usize;
            let mut buf = vec![0u8; len];
            cursor.read_exact(&mut buf).ok()?;
            ProtobufValue::LengthDelimited(buf)
        },
        5 => { // 32-bit
            let mut buf = [0u8; 4];
            cursor.read_exact(&mut buf).ok()?;
            let val = u32::from_le_bytes(buf);
            ProtobufValue::Fixed32(val)
        },
        _ => return None, // Unsupported
    };

    Some((field_number, value))
}

pub fn parse_protobuf_message(data: Vec<u8>) -> HashMap<u32, ProtobufValue> {
    let mut cursor = Cursor::new(data);
    let mut map = HashMap::new();

    while (cursor.position() as usize) < cursor.get_ref().len() {
        if let Some((field_number, value)) = read_field(&mut cursor) {
            map.insert(field_number, value);
        } else {
            break;
        }
    }

    map
}
