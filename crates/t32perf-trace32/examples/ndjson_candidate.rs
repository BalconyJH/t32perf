use std::{env, fs::File, io::BufReader, path::PathBuf, process::ExitCode, time::Instant};

use serde_json::json;
use t32perf_trace32::{LineLimits, NdjsonObservationReader};

fn main() -> ExitCode {
    match run() {
        Ok(document) => {
            println!("{document}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("{}", json!({"ok": false, "error": error.to_string()}));
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let mut arguments = env::args_os().skip(1);
    let input = arguments
        .next()
        .map(PathBuf::from)
        .ok_or(
            "usage: ndjson_candidate <observations.ndjson> [--max-dictionary-entries N] [--max-dictionary-bytes N]",
        )?;
    let mut limits = LineLimits {
        max_line_bytes: 1024 * 1024,
        max_records: u64::MAX,
        ..LineLimits::default()
    };
    while let Some(flag) = arguments.next() {
        let flag = flag
            .to_str()
            .ok_or("candidate option is not valid Unicode")?;
        let value = arguments
            .next()
            .ok_or("candidate option requires a value")?;
        let value = value
            .to_str()
            .ok_or("candidate option value is not valid Unicode")?;
        match flag {
            "--max-dictionary-entries" => limits.max_dictionary_entries = value.parse()?,
            "--max-dictionary-bytes" => limits.max_dictionary_bytes = value.parse()?,
            _ => return Err(format!("unknown candidate option `{flag}`").into()),
        }
    }
    let byte_count = input.metadata()?.len();
    let started = Instant::now();
    let file = File::open(&input)?;
    let mut reader = NdjsonObservationReader::new(BufReader::new(file), limits)?;
    let session_id = reader.header().session_id.clone();
    let dictionary_entries = reader.dictionary().entries.len();
    let dictionary_bytes = reader.dictionary_physical_bytes();
    let mut observations = 0_u64;
    for observation in &mut reader {
        observation?;
        observations = observations
            .checked_add(1)
            .ok_or("observation count overflow")?;
    }
    let elapsed = started.elapsed().as_secs_f64();
    Ok(json!({
        "ok": true,
        "candidate": "rust-t32perf-trace32",
        "input": input,
        "session_id": session_id,
        "bytes": byte_count,
        "dictionary_entries": dictionary_entries,
        "dictionary_bytes": dictionary_bytes,
        "max_dictionary_entries": limits.max_dictionary_entries,
        "max_dictionary_bytes": limits.max_dictionary_bytes,
        "observations": observations,
        "elapsed_seconds": elapsed,
        "observations_per_second": observations as f64 / elapsed,
        "bytes_per_second": byte_count as f64 / elapsed,
    }))
}
