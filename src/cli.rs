// Command line interface structs and functions

// std
use std::error::Error;
use std::fmt;

// External
use clap::{Parser,ValueEnum};
use serde::Serialize;


#[derive(Clone, Debug, ValueEnum, PartialEq)]
pub enum OutputFormat {
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

// CLI arguments

#[derive(Parser, Debug)]
#[clap(about = "Load and print binary protobuf files created by goflow2.")]
pub struct Args {
    #[arg(short,long)]
    #[clap(help = "File to load")]
    pub path: String,
    #[arg(short,long)]
    #[clap(help = "Filter of what records to display")]
    pub filter: Option<String>,
    #[arg(short,long)]
    #[clap(help = "Limit number of results to display")]
    pub limit: Option<u64>,
    #[arg(short,long, value_enum, default_value_t = OutputFormat::Json)]
    #[clap(help = "Output format")]
    pub output: OutputFormat,
    /// Disable header & footer output, useful to pipe raw output to other tools.
    #[arg(long = "frame", default_value_t = true, action = clap::ArgAction::SetTrue)]
    #[arg(long = "no-frame", action = clap::ArgAction::SetFalse, overrides_with = "frame")]
    pub frame: bool,
}

// Helper function to serialize a single record or iterable into CSV
pub fn csv_to_string<T: Serialize>(value: &T, print_header: &bool) -> Result<String, Box<dyn Error>> {
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
