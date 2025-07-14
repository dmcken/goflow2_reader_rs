


// std
use std::collections::HashMap;
use std::error::Error;
use std::fmt;
use std::fs::File;
use std::io::{self,BufRead, BufReader, Cursor, Read};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::process::{Command, Stdio};

// External
use bzip2::read::BzDecoder;
use chrono::{DateTime, TimeZone, Utc};
use clap::{Parser,ValueEnum};
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

#[derive(Clone, Debug, ValueEnum, PartialEq)]
#[allow(dead_code)]
enum OutputFormat {
    JsonPretty,
    Json,
    Csv,
    None,
}

impl fmt::Display for OutputFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            OutputFormat::JsonPretty => "json-pretty",
            OutputFormat::Json       => "json",
            OutputFormat::Csv        => "csv",
            OutputFormat::None       => "none",
        };
        write!(f, "{}", s)
    }
}

#[derive(Serialize, Debug, PartialEq)]
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
impl Default for NetflowRecord {
    fn default() -> Self {
        let default_time = Utc.timestamp_opt(0, 0).unwrap(); // 1970-01-01T00:00:00Z
        let default_ip = IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0));

        NetflowRecord {
            time_received_ns: default_time,
            sequence_num: 0,
            time_flow_start_ns: default_time,
            time_flow_end_ns: default_time,
            etype: 0,
            proto: 0,
            bytes: 0,
            packets: 0,
            addr_src: default_ip,
            addr_dst: default_ip,
            addr_sampler: default_ip,
            addr_next_hop: default_ip,
            port_src: 0,
            port_dst: 0,
            mac_src: None,
            mac_dst: None,
            post_nat_src_ipv4_address: None,
            post_nat_dst_ipv4_address: None,
            post_napt_src_transport_port: None,
            post_napt_dst_transport_port: None,
        }
    }
}
impl NetflowRecord {
    pub fn new_with_defaults() -> Self {
        Self::default()
    }
    fn proto(&self) -> i64           {   self.proto as i64          }
    fn bytes(&self) -> i64           {   self.bytes as i64          }
    fn addr_src_str(&self) -> String {   self.addr_src.to_string()  }
    fn addr_dst_str(&self) -> String {   self.addr_dst.to_string()  }
}

// CLI interface
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
    #[arg(short,long, value_enum, default_value_t = OutputFormat::Json)]
    #[clap(help = "Output format")]
    output: OutputFormat,
    /// Disable header & footer output, useful to pipe raw output to other tools.
    #[arg(long = "frame", default_value_t = true, action = clap::ArgAction::SetTrue)]
    #[arg(long = "no-frame", action = clap::ArgAction::SetFalse, overrides_with = "frame")]
    frame: bool,
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
    let mut record = NetflowRecord::new_with_defaults();

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
fn csv_to_string<T: Serialize>(value: &T, print_header: &bool) -> Result<String, Box<dyn Error>> {
    let mut wtr: csv::Writer<Vec<u8>>;
    if *print_header {
        wtr = csv::WriterBuilder::new()
            .from_writer(vec![]);
    } else {
        wtr = csv::WriterBuilder::new()
            .has_headers(false)
            .terminator(csv::Terminator::Any(b' '))
            .from_writer(vec![]);
    }

    // Attempt to serialize the value as a record or sequence of records
    wtr.serialize(value)?;
    wtr.flush()?;

    let mut data = wtr.into_inner()?;

    // Trim trailing newline after the data record.
    if *print_header {
        if data.ends_with(b"\r\n") {
            data.truncate(data.len() - 2);
        } else if data.ends_with(b"\n") {
            data.truncate(data.len() - 1);
        }
    }

    Ok(String::from_utf8(data)?)
}

fn output_serializer<T: Serialize>(value: &T, output_format: &OutputFormat, first_record: &bool) -> Result<String, Box<dyn Error>> {
    match output_format {
        OutputFormat::JsonPretty => Ok(serde_json::to_string_pretty(value)?),
        OutputFormat::Json       => Ok(serde_json::to_string(value)?),
        OutputFormat::Csv        => csv_to_string(value, &first_record),
        OutputFormat::None       => Ok(String::new()),
    }
}

fn open_file(file_path: &String) -> io::Result<Box<dyn BufRead>> {

    let file = File::open(&file_path)?;
    let input_handle: Box<dyn BufRead> = match Path::new(&file_path)
                            .extension()
                            .and_then(|ext| ext.to_str())
    {
        Some("bz2") => Box::new(BufReader::new(BzDecoder::new(file))),
        Some("xz")  => Box::new(BufReader::new(XzDecoder::new(file))),
        Some("7z") => {
            let child = Command::new("7z")
                .arg("e")                         // Extract
                .arg("-so")                       // Write output to stdout
                .arg(file_path)
                .stdout(Stdio::piped())
                .spawn()
                .expect("Failed to spawn 7z");

            let stdout = child.stdout.expect("Failed to capture 7z stdout");
            Box::new(BufReader::new(stdout))
        },
        _           => Box::new(BufReader::new(file)), // plain text
    };

    Ok(input_handle)

}

fn main()  -> std::io::Result<()> {

    // TODO - The Start / End sections should be their own functions.

    // Start - CLI Params
    let args = Args::parse();

    let mut query: &str = "blank";
    let limit: u64 = args.limit.unwrap_or(0);
    if let Some(filter) = args.filter.as_deref() {
        query = filter;
    }

    let output_format: OutputFormat = args.output;
    let file_path = args.path;
    // End - CLI Params

    if args.frame {
        println!("Searching for '{query}' in '{file_path}' returning at most '{limit}' results");
    }

    let mut input_handle = open_file(&file_path)?;

    // Loop variable initalization
    let mut engine = Engine::new();
    engine.register_fn("ip_in_cidr", ip_in_cidr);

    let mut record_count: u64 = 0;
    let mut first_record: bool = true;

    // Loop through file
    while let Some(record_length) = read_varint_reader(&mut input_handle) {

        // Start - Read and parse protobuf

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

        // End - Read and parse protobuf

        // Filter check
        if let Some(ref _filter_str) = args.filter {
            let mut scope = Scope::new();

            // Start - Push search fields

            scope.push("bytes", record.bytes());
            scope.push("proto", record.proto());
            scope.push("addr_src", record.addr_src_str());
            scope.push("addr_dst", record.addr_dst_str());
            scope.push("post_nat_src_ipv4_address", option_ip(record.post_nat_src_ipv4_address));
            scope.push("post_nat_dst_ipv4_address", option_ip(record.post_nat_dst_ipv4_address));
            scope.push("post_napt_src_transport_port", option_u16(record.post_napt_src_transport_port));
            scope.push("post_napt_dst_transport_port", option_u16(record.post_napt_dst_transport_port));
            scope.push("time_flow_start_ns", option_dt(Some(record.time_flow_start_ns)));
            // TODO: Finish adding fields

            // End - Push search fields

            let filter_expr = args
                .filter
                .as_deref()
                .unwrap_or("true"); // default: no filtering

            match engine.eval_with_scope::<bool>(&mut scope, filter_expr) {
                Ok(true)  => { },
                Ok(false) => { continue; },
                Err(e) => { eprintln!("Filter error: {e}") },
            }
        }

        // Print record
        if output_format != OutputFormat::None {
            let output_str = output_serializer(&record, &output_format, &first_record).unwrap();
            println!("{}", output_str);
            if first_record == true {
                first_record = false;
            }
        }

        // Check for limit
        record_count += 1;
        if limit != 0 && record_count >= limit {
            break;
        }
    }

    if args.frame {
        println!("Matched records: {}", record_count);
    }

    Ok(())
}
