
// std
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufReader, Cursor, Read};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

// External
use bzip2::read::BzDecoder;
use chrono::{DateTime, TimeZone, Utc};
use clap::Parser;
use ipnet::IpNet;
use rhai::{Engine, Scope};
use serde::Serialize;

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
    fn proto(&self) -> i64 {
        self.proto as i64
    }

    fn bytes(&self) -> i64 {
        self.bytes as i64
    }

    fn addr_src_str(&self) -> String {
        self.addr_src.to_string()
    }
    fn addr_dst_str(&self) -> String {
        self.addr_dst.to_string()
    }
}

#[derive(Parser, Debug)]
#[clap(about = "Load and print protobuf files created by goflow2.")]
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
            4 => if let ProtobufValue::Varint(v) = value {
                record.sequence_num = v;
            },
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
            9 => if let ProtobufValue::Varint(v) = value {
                record.bytes = v;
            },
            10 => if let ProtobufValue::Varint(v) = value {
                record.packets = v;
            },
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
            20 => if let ProtobufValue::Varint(v) = value {
                record.proto = v as u16;
            },
            21 => if let ProtobufValue::Varint(v) = value {
                record.port_src = v as u16;
            },
            22 => if let ProtobufValue::Varint(v) = value {
                record.port_dst = v as u16;
            },
            23 => (), // IP TOS
            26 => (), // TCP Flags
            27 => if let ProtobufValue::Varint(v) = value {
                record.mac_src = Some(v);
            },
            28 => if let ProtobufValue::Varint(v) = value {
                record.mac_dst = Some(v);
            },
            30 => if let ProtobufValue::Varint(v ) = value {
                record.etype = v as u16;
            },
            31 => (), // ICMP type
            32 => (), // ICMP Code
            37 => (), // ipv6_flow_label
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
            _ => println!("Unhandled field ID '{}' with value '{:?}'", field, value),
        }
    }

    return record;
}

// Format the object to a string
fn csv_to_string<T: Serialize>(to_format: &T) -> Result<String, serde_json::Error> {
    let mut output = String::new();

    Ok(output)
}

fn output_serializer<T: Serialize>(value: &T, output_format: &OutputFormat) -> Result<String, serde_json::Error> {
    match output_format {
        OutputFormat::JsonPretty => serde_json::to_string_pretty(value),
        OutputFormat::Json        => serde_json::to_string(value),
        OutputFormat::Csv         => csv_to_string(value),
    }
}

/*
time cargo run --release -- \
    --limit 10
    --file-path data/goflow2_20250616_1430.log.bz2
    --filter 'post_napt_src_transport_port == 57068 && post_nat_src_ipv4_address == "103.153.239.42"'


    Alternative filters:
      'ip_in_cidr(addr_src,"10.1.0.0/16")'
      'addr_src == "103.153.238.161"'
*/
fn main()  -> std::io::Result<()> {
    let args = Args::parse();
    let mut engine = Engine::new();

    engine.register_fn("ip_in_cidr", ip_in_cidr);


    // let args: Vec<String> = env::args().collect();
    let mut query: &str = "blank";
    let limit: u64 = args.limit.unwrap_or(0);
    if let Some(filter) = args.filter.as_deref() {
        query = filter;
    }

    let output_format: OutputFormat = OutputFormat::Json;

    let file_path = args.path;

    println!("Searching for '{query}' in '{file_path}' returning at most '{limit}' results");

    let file = File::open(file_path)?;
    let file_buf = BufReader::new(file);
    let decompressor = BzDecoder::new(file_buf);
    let mut decompressed = BufReader::new(decompressor);

    let mut count: u64 = 0;

    while let Some(record_length) = read_varint_reader(&mut decompressed) {

        // println!("Record length: {} => {}", count, record_length);

        // A record separator can be omited, make this optional
        let mut eor_value = [0u8; 1];
        // The protobuf bytes
        let mut raw_record_bytes = vec![0u8; record_length as usize];

        decompressed.read_exact(&mut raw_record_bytes)?;

        decompressed.read_exact(&mut eor_value)?;
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
                    let json_str = output_serializer(&record, &output_format).unwrap();
                    println!("{}", json_str);
                    count += 1;
                },
                Ok(false) => {},
                Err(e) => eprintln!("Filter error: {e}"),
            }
        } else {
            // No filter
            let json_str = output_serializer(&record, &output_format).unwrap();
            println!("{}", json_str);
            count += 1;
        }

        if count >= limit {
            break;
        }

    }

    println!("Count: {}", count);

    Ok(())
}
