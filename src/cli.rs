// Command line interface structs and functions

// std
use std::error::Error;
use std::fmt;

// External
use clap::{Parser,ValueEnum};
use serde::Serialize;


#[derive(Clone, Debug, ValueEnum, PartialEq)]
pub enum OutputFormat {
    JsonPretty,   // Pretty-print multi-line JSON
    Json,         // Single line JSON
    Csv,          // Comma-separated values
    None,         // No output
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

/// Serializes a value to a CSV-formatted `String`.
///
/// This function uses the [`csv`] crate to serialize any type that implements [`serde::Serialize`]
/// into a CSV string. You can choose whether or not to include a header row.
///
/// # Type Parameters
///
/// * `T` – A type that implements [`serde::Serialize`].
///
/// # Arguments
///
/// * `value` – A reference to the value to serialize. This can be a single record (e.g., a struct)
///   or a sequence of records (e.g., a slice or vector of structs).
/// * `print_header` – Whether to include a header row in the CSV output.
///
/// # Returns
///
/// A `Result` containing the CSV data as a `String` on success, or a boxed `dyn Error` if
/// serialization or UTF-8 conversion fails.
///
/// # Behavior
///
/// - If `print_header` is `false`, no header row is included, and a custom space (`' '`) terminator is used.
/// - If `print_header` is `true`, a standard header row and newline terminator are included.
/// - The trailing newline (if present) is trimmed from the output for cleaner formatting.
///
/// # Errors
///
/// Returns an error if:
/// - Serialization via `csv::Writer::serialize()` fails
/// - The internal writer cannot be flushed
/// - The resulting byte buffer cannot be converted to a UTF-8 string
///
/// # Examples
///
/// ```
/// use serde::Serialize;
///
/// #[derive(Serialize)]
/// struct Record {
///     name: String,
///     age: u8,
/// }
///
/// let data = Record { name: "Alice".into(), age: 30 };
/// let csv = gf2_reader::csv_to_string(&data, &true).unwrap();
/// assert_eq!(csv, "name,age\nAlice,30");
/// ```
///
/// [`csv`]: https://docs.rs/csv
/// [`serde::Serialize`]: https://docs.rs/serde/latest/serde/trait.Serialize.html
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
