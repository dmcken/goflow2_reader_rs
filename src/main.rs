// Main for rust protobuf reader

// std
use std::collections::HashMap;
use std::error::Error;
use std::fs::File;
use std::io::{self,BufRead, BufReader, Read};
use std::path::Path;
use std::process::{Command, Stdio};

// External
use bzip2::read::BzDecoder;
use chrono::{TimeZone, Utc};
use clap::Parser;
use rhai::{Engine, Scope};
use serde::Serialize;
use xz::read::XzDecoder;

// Local
mod cli;
mod netflow_record;
mod protobuf;

// Functions

// My helpers
fn protobuf_to_record(parsed: HashMap<u32, protobuf::ProtobufValue>) -> netflow_record::NetflowRecord {
    let mut record = netflow_record::NetflowRecord::new_with_defaults();

    // https://github.com/netsampler/goflow2/blob/main/pb/flow.proto
    for (field, value) in parsed {
        // println!("Field {} => {:?}", field, value);
        match field {
            1 => (), // Don't care which flow protocol
            4 => if let protobuf::ProtobufValue::Varint(v) = value { record.sequence_num = v; },
            6 => if let protobuf::ProtobufValue::LengthDelimited(v) = value {
                if let Some(ip) = netflow_record::vec_to_ip_addr(v) {
                    record.addr_src = ip;
                }
            },
            7 => if let protobuf::ProtobufValue::LengthDelimited(v) = value {
                if let Some(ip) = netflow_record::vec_to_ip_addr(v) {
                    record.addr_dst = ip;
                }
            },
            9   => if let protobuf::ProtobufValue::Varint(v) = value { record.bytes = v;   },
            10  => if let protobuf::ProtobufValue::Varint(v) = value { record.packets = v; },
            11 => if let protobuf::ProtobufValue::LengthDelimited(v) = value {
                if let Some(ip) = netflow_record::vec_to_ip_addr(v) {
                    record.addr_sampler = ip;
                }
            },
            12 => if let protobuf::ProtobufValue::LengthDelimited(v) = value {
                if let Some(ip) = netflow_record::vec_to_ip_addr(v) {
                    record.addr_next_hop = ip;
                }
            },
            18 | 19 => (), // in_if and out_if
            20  => if let protobuf::ProtobufValue::Varint(v) = value { record.proto = v as u16;    },
            21  => if let protobuf::ProtobufValue::Varint(v) = value { record.port_src = v as u16; },
            22  => if let protobuf::ProtobufValue::Varint(v) = value { record.port_dst = v as u16; },
            23  => (), // IP TOS
            26  => (), // TCP Flags
            27  => if let protobuf::ProtobufValue::Varint(v) = value { record.mac_src = Some(v);   },
            28  => if let protobuf::ProtobufValue::Varint(v) = value { record.mac_dst = Some(v);   },
            30  => if let protobuf::ProtobufValue::Varint(v) = value { record.etype = v as u16;    },
            31  => (), // ICMP type
            32  => (), // ICMP Code
            37  => (), // ipv6_flow_label
            110 => if let protobuf::ProtobufValue::Varint(v) = value {
                let seconds = v / 1_000_000_000;
                let nanos = v % 1_000_000_000;
                record.time_received_ns = Utc.timestamp_opt(seconds as i64, nanos as u32).unwrap();
            },
            111 => if let protobuf::ProtobufValue::Varint(v) = value {
                let seconds = v / 1_000_000_000;
                let nanos = v % 1_000_000_000;
                record.time_flow_start_ns = Utc.timestamp_opt(seconds as i64, nanos as u32).unwrap();
            },
            112 => if let protobuf::ProtobufValue::Varint(v) = value {
                let seconds = v / 1_000_000_000;
                let nanos = v % 1_000_000_000;
                record.time_flow_end_ns = Utc.timestamp_opt(seconds as i64, nanos as u32).unwrap();
            },
            2225 => if let protobuf::ProtobufValue::LengthDelimited(v) = value {
                if let Some(ip) = netflow_record::vec_to_ip_addr(v) {
                    record.post_nat_src_ipv4_address = Some(ip);
                }
            },
            2226 => if let protobuf::ProtobufValue::LengthDelimited(v) = value {
                if let Some(ip) = netflow_record::vec_to_ip_addr(v) {
                    record.post_nat_dst_ipv4_address = Some(ip);
                }
            },
            2227 => if let protobuf::ProtobufValue::Varint(v ) = value {
                record.post_napt_src_transport_port = Some(v as u16);
            },
            2228 => if let protobuf::ProtobufValue::Varint(v ) = value {
                record.post_napt_dst_transport_port = Some(v as u16);
            },
            _ => println!("Unhandled protobuf field ID '{}' with value '{:?}'", field, value),
        }
    }

    record
}

// Serializer helpers
fn output_serializer<T: Serialize>(value: &T, output_format: &cli::OutputFormat, first_record: &bool) -> Result<String, Box<dyn Error>> {
    match output_format {
        cli::OutputFormat::JsonPretty => Ok(serde_json::to_string_pretty(value)?),
        cli::OutputFormat::Json       => Ok(serde_json::to_string(value)?),
        cli::OutputFormat::Csv        => cli::csv_to_string(value, first_record),
        cli::OutputFormat::None       => Ok(String::new()),
    }
}

fn open_file(file_path: &String) -> io::Result<Box<dyn BufRead>> {

    let file = File::open(file_path)?;
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
    let args = cli::Args::parse();

    let mut query: &str = "blank";
    let limit: u64 = args.limit.unwrap_or(0);
    if let Some(filter) = args.filter.as_deref() {
        query = filter;
    }

    let output_format: cli::OutputFormat = args.output;
    let file_path = args.path;
    // End - CLI Params

    if args.frame {
        println!("Searching for '{query}' in '{file_path}' returning at most '{limit}' results");
    }

    let mut input_handle = open_file(&file_path)?;

    // Loop variable initalization
    let mut engine = Engine::new();
    engine.register_fn("ip_in_cidr", netflow_record::ip_in_cidr);

    let mut record_count: u64 = 0;
    let mut first_record: bool = true;

    // Loop through file
    while let Some(record_length) = protobuf::read_varint_reader(&mut input_handle) {

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
        let parsed = protobuf::parse_protobuf_message(raw_record_bytes);
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
            scope.push("post_nat_src_ipv4_address", netflow_record::option_ip(record.post_nat_src_ipv4_address));
            scope.push("post_nat_dst_ipv4_address", netflow_record::option_ip(record.post_nat_dst_ipv4_address));
            scope.push("post_napt_src_transport_port", netflow_record::option_u16(record.post_napt_src_transport_port));
            scope.push("post_napt_dst_transport_port", netflow_record::option_u16(record.post_napt_dst_transport_port));
            scope.push("time_flow_start_ns", netflow_record::option_dt(Some(record.time_flow_start_ns)));
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
        if output_format != cli::OutputFormat::None {
            let output_str = output_serializer(&record, &output_format, &first_record).unwrap();
            println!("{}", output_str);
            if first_record {
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
