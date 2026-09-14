use anyhow::Result;
use crate::analyzer::chains::ScanResults;

pub fn print_json(results: &ScanResults) -> Result<()> {
    let json = serde_json::to_string_pretty(results)?;
    println!("{}", json);
    Ok(())
}

pub fn write_json(results: &ScanResults, path: &str) -> Result<()> {
    let json = serde_json::to_string_pretty(results)?;
    std::fs::write(path, json)?;
    eprintln!("[+] Results written to {}", path);
    Ok(())
}
