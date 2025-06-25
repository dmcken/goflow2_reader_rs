
// std
use std::collections::HashMap;
use std::error::Error;
use std::fs::File;
use std::io::{BufRead, BufReader, Cursor, Read};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;

// External
use bzip2::read::BzDecoder;
use chrono::{DateTime, TimeZone, Utc};
use clap::Parser;
use ipnet::IpNet;
use rhai::{Engine, Scope};
use serde::Serialize;
use xz::read::XzDecoder;

// Data structures

#[derive(Debug, Serialize)]
#[allow(dead_code)]
enum ProtobufValue {
    Varint(u64),
    Fixed64(u64),
    LengthDelimited(Vec<u8>),
    Fixed32(u32),
}

#[derive(Clone, Debug)]
#[allow(dead_code)]
enum OutputFormat {
    JsonPretty,
    Json,
    Csv,
}

#[derive(Serialize, Debug)]
struct NetflowRecord {
    time_received_ns: DateTime<Utc>,
    sequence_num: u64,
    time_flow_start_ns: DateTime<Utc>,
    time_flow_end_ns: DateTime<Utc>,
    etype: u16,
    proto: u16,
    bytes: u64,
    packets: u64,
    addr_src: IpAddr,
    addr_dst: IpAddr,
    addr_sampler: IpAddr,
    addr_next_hop: IpAddr,
    port_src: u16,
    port_dst: u16,
    mac_src: Option<u64>,
    mac_dst: Option<u64>,
    post_nat_src_ipv4_address: Option<IpAddr>,
    post_nat_dst_ipv4_address: Option<IpAddr>,
    post_napt_src_transport_port: Option<u16>,
    post_napt_dst_transport_port: Option<u16>,
}

impl NetflowRecord {
    fn proto(&self) -> i64           {   self.proto as i64          }
    fn bytes(&self) -> i64           {   self.bytes as i64          }
    fn addr_src_str(&self) -> String {   self.addr_src.to_string()  }
    fn addr_dst_str(&self) -> String {   self.addr_dst.to_string()  }
}

#[derive(Parser, Debug)]
#[clap(about = "Load and print binary protobuf files created by goflow2.")]
struct Args {
    #[arg(short,long)]
    #[clap(help = "File to load")]
    path: String,
    #[arg(short,long)]
    #[clap(help = "Filter of what records to display")]
    filter: Option<String>,
    #[arg(short,long)]
    #[clap(help = "Limit number of results to display")]
    limit: Option<u64>,
    #[arg(short,long)]
    #[clap(help = "Output format to display records in (json, json-pretty, csv)")]
    output: Option<String>,
}

// Functions

// rhai helpers
fn option_ip(ip: Option<IpAddr>) -> String {
    ip.map(|v| v.to_string()).unwrap_or_default()
}

fn option_u16(v: Option<u16>) -> i64 {
    v.map(|v| v as i64).unwrap_or(-1)
}

fn option_dt(dt: Option<DateTime<Utc>>) -> i64 {
    dt.map(|v| v.timestamp()).unwrap_or(0)
}

fn ip_in_cidr(ip_str: &str, cidr_str: &str) -> bool {
    match (ip_str.parse::<IpAddr>(), cidr_str.parse::<IpNet>()) {
        (Ok(ip), Ok(net)) => net.contains(&ip),
        _ => false,
    }
}

// Protobuf helpers

fn read_varint_reader<R: Read>(reader: &mut R) -> Option<u64> {
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

fn parse_protobuf_message(data: Vec<u8>) -> HashMap<u32, ProtobufValue> {
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

// My helpers
fn vec_to_ip_addr(bytes: Vec<u8>) -> Option<IpAddr> {
    match bytes.len() {
        4 => {
            let arr: [u8; 4] = bytes.try_into().ok()?;
            Some(IpAddr::V4(Ipv4Addr::from(arr)))
        }
        16 => {
            let arr: [u8; 16] = bytes.try_into().ok()?;
            Some(IpAddr::V6(Ipv6Addr::from(arr)))
        }
        _ => None,
    }
}

fn protobuf_to_record(parsed: HashMap<u32, ProtobufValue>) -> NetflowRecord {
    let now = Utc::now();
    let ip = IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0));
    let mut record: NetflowRecord = NetflowRecord {
        time_received_ns: now,
        sequence_num: 0,
        time_flow_start_ns: now,
        time_flow_end_ns: now,
        etype: 0x0000,
        proto: 0,
        bytes: 0,
        packets: 0,
        addr_src: ip,
        addr_dst: ip,
        addr_sampler: ip,
        addr_next_hop: ip,
        port_src: 0,
        port_dst: 0,
        mac_src: None,
        mac_dst: None,
        post_nat_src_ipv4_address: None,
        post_nat_dst_ipv4_address: None,
        post_napt_src_transport_port: None,
        post_napt_dst_transport_port: None,
    };
    // https://github.com/netsampler/goflow2/blob/main/pb/flow.proto
    for (field, value) in parsed {
        // println!("Field {} => {:?}", field, value);
        match field {
            1 => (), // Don't care which flow protocol
            4 => if let ProtobufValue::Varint(v) = value { record.sequence_num = v; },
            6 => if let ProtobufValue::LengthDelimited(v) = value {
                if let Some(ip) = vec_to_ip_addr(v) {
                    record.addr_src = ip;
                }
            },
            7 => if let ProtobufValue::LengthDelimited(v) = value {
                if let Some(ip) = vec_to_ip_addr(v) {
                    record.addr_dst = ip;
                }
            },
            9   => if let ProtobufValue::Varint(v) = value { record.bytes = v;   },
            10  => if let ProtobufValue::Varint(v) = value { record.packets = v; },
            11 => if let ProtobufValue::LengthDelimited(v) = value {
                if let Some(ip) = vec_to_ip_addr(v) {
                    record.addr_sampler = ip;
                }
            },
            12 => if let ProtobufValue::LengthDelimited(v) = value {
                if let Some(ip) = vec_to_ip_addr(v) {
                    record.addr_next_hop = ip;
                }
            },
            18 | 19 => (), // in_if and out_if
            20  => if let ProtobufValue::Varint(v) = value { record.proto = v as u16;    },
            21  => if let ProtobufValue::Varint(v) = value { record.port_src = v as u16; },
            22  => if let ProtobufValue::Varint(v) = value { record.port_dst = v as u16; },
            23  => (), // IP TOS
            26  => (), // TCP Flags
            27  => if let ProtobufValue::Varint(v) = value { record.mac_src = Some(v);   },
            28  => if let ProtobufValue::Varint(v) = value { record.mac_dst = Some(v);   },
            30  => if let ProtobufValue::Varint(v) = value { record.etype = v as u16;    },
            31  => (), // ICMP type
            32  => (), // ICMP Code
            37  => (), // ipv6_flow_label
            110 => if let ProtobufValue::Varint(v) = value {
                let seconds = v / 1_000_000_000;
                let nanos = v % 1_000_000_000;
                record.time_received_ns = Utc.timestamp_opt(seconds as i64, nanos as u32).unwrap();
            },
            111 => if let ProtobufValue::Varint(v) = value {
                let seconds = v / 1_000_000_000;
                let nanos = v % 1_000_000_000;
                record.time_flow_start_ns = Utc.timestamp_opt(seconds as i64, nanos as u32).unwrap();
            },
            112 => if let ProtobufValue::Varint(v) = value {
                let seconds = v / 1_000_000_000;
                let nanos = v % 1_000_000_000;
                record.time_flow_end_ns = Utc.timestamp_opt(seconds as i64, nanos as u32).unwrap();
            },
            2225 => if let ProtobufValue::LengthDelimited(v) = value {
                if let Some(ip) = vec_to_ip_addr(v) {
                    record.post_nat_src_ipv4_address = Some(ip);
                }
            },
            2226 => if let ProtobufValue::LengthDelimited(v) = value {
                if let Some(ip) = vec_to_ip_addr(v) {
                    record.post_nat_dst_ipv4_address = Some(ip);
                }
            },
            2227 => if let ProtobufValue::Varint(v ) = value {
                record.post_napt_src_transport_port = Some(v as u16);
            },
            2228 => if let ProtobufValue::Varint(v ) = value {
                record.post_napt_dst_transport_port = Some(v as u16);
            },
            _ => println!("Unhandled protobuf field ID '{}' with value '{:?}'", field, value),
        }
    }

    record
}

// Serializer helpers

// Helper function to serialize a single record or iterable into CSV
fn csv_to_string<T: Serialize>(value: &T) -> Result<String, Box<dyn Error>> {
    let mut wtr = csv::WriterBuilder::new()
        .has_headers(false)
        .terminator(csv::Terminator::Any(b' '))
        .from_writer(vec![]);

    // Attempt to serialize the value as a record or sequence of records
    wtr.serialize(value)?;
    wtr.flush()?;

    let data = wtr.into_inner()?;
    Ok(String::from_utf8(data)?)
}

fn csv_header_only<T: Serialize + Default>() -> Result<String, Box<dyn std::error::Error>> {
    let mut wtr = csv::WriterBuilder::new()
        .has_headers(true)
        .terminator(csv::Terminator::Any(b'\n'))
        .from_writer(vec![]);

    // Serialize a dummy value just to force the header generation
    wtr.serialize(T::default())?;
    wtr.flush()?;

    let data = String::from_utf8(wtr.into_inner()?)?;

    // Get only the first line (the header)
    let header = data.lines().next().unwrap_or("").to_string();
    Ok(header)
}

fn output_serializer<T: Serialize>(value: &T, output_format: &OutputFormat) -> Result<String, Box<dyn Error>> {
    match output_format {
        OutputFormat::JsonPretty => Ok(serde_json::to_string_pretty(value)?),
        OutputFormat::Json       => Ok(serde_json::to_string(value)?),
        OutputFormat::Csv        => csv_to_string(value),
    }
}

fn main()  -> std::io::Result<()> {
    let args = Args::parse();

    // Start - CLI Params
    let mut query: &str = "blank";
    let limit: u64 = args.limit.unwrap_or(0);
    if let Some(filter) = args.filter.as_deref() {
        query = filter;
    }

    let output_format: OutputFormat = OutputFormat::Csv;
    let file_path = args.path;


    // End - CLI Params

    println!("Searching for '{query}' in '{file_path}' returning at most '{limit}' results");

    // Start - Open file

    let file = File::open(&file_path)?;
    let mut input_handle: Box<dyn BufRead> = match Path::new(&file_path)
                            .extension()
                            .and_then(|ext| ext.to_str())
    {
        Some("bz2") => Box::new(BufReader::new(BzDecoder::new(file))),
        Some("xz")  => Box::new(BufReader::new(XzDecoder::new(file))),
        _           => Box::new(BufReader::new(file)), // plain text
    };

    // End - Open file

    // Loop variable initalization
    let mut engine = Engine::new();
    engine.register_fn("ip_in_cidr", ip_in_cidr);

    let mut record_count: u64 = 0;

    // Print header
    match output_format {
        OutputFormat::Csv => {
            // let dummy = NetflowRecord {
            //     addr_dst, `addr_next_hop`, `addr_sampler
            // }
            // let header = csv_header_only(&dummy)?;
            let header = "time_received_ns,sequence_num,time_flow_start_ns,time_flow_end_ns,etype,proto,bytes,packets,addr_src,addr_dst,addr_sampler,addr_next_hop,port_src,port_dst,mac_src,mac_dst,post_nat_src_ipv4_address,post_nat_dst_ipv4_address,post_napt_src_transport_port,post_napt_dst_transport_port";

            println!("{}", header);
        },
        _ => (),
    }

    // Loop through file

    while let Some(record_length) = read_varint_reader(&mut input_handle) {

        // println!("Record length: {} => {}", count, record_length);

        // A record separator can be omited, make this optional
        let mut eor_value = [0u8; 1];
        // The protobuf bytes
        let mut raw_record_bytes = vec![0u8; record_length as usize];

        input_handle.read_exact(&mut raw_record_bytes)?;

        input_handle.read_exact(&mut eor_value)?;
        // println!("End of record value: {:02X}", eor_value[0]);

        // Parsed protobuf to
        let parsed = parse_protobuf_message(raw_record_bytes);
        // println!("Protobuf raw fields: {:#?}", record);

        let record = protobuf_to_record(parsed);
        // println!("Netflow struct: {:#?}", record);

        if let Some(ref _filter_str) = args.filter {
            let mut scope = Scope::new();

            scope.push("bytes", record.bytes());
            scope.push("proto", record.proto());
            scope.push("addr_src", record.addr_src_str());
            scope.push("addr_dst", record.addr_dst_str());
            scope.push("post_nat_src_ipv4_address", option_ip(record.post_nat_src_ipv4_address));
            scope.push("post_napt_src_transport_port", option_u16(record.post_napt_src_transport_port));
            scope.push("time_flow_start_ns", option_dt(Some(record.time_flow_start_ns)));


            let filter_expr = args
                .filter
                .as_deref()
                .unwrap_or("true"); // default: no filtering

            match engine.eval_with_scope::<bool>(&mut scope, filter_expr) {
                Ok(true) => {
                    let output_str = output_serializer(&record, &output_format).unwrap();
                    println!("{}", output_str);
                    record_count += 1;
                },
                Ok(false) => {},
                Err(e) => eprintln!("Filter error: {e}"),
            }
        } else {
            // No filter
            let output_str = output_serializer(&record, &output_format).unwrap();
            println!("{}", output_str);
            record_count += 1;
        }

        if limit != 0 && record_count >= limit {
            break;
        }
    }

    println!("Matched records: {}", record_count);

    Ok(())
}
