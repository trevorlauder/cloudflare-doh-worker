// Copyright 2025-2026 Trevor Lauder.
// SPDX-License-Identifier: MIT

use std::io::{self, BufRead, Write};
use std::process::ExitCode;

use xorf::{BinaryFuse32, DmaSerializable};

fn run() -> Result<(), String> {
    let stdin = io::stdin();
    let mut keys: Vec<u64> = Vec::new();

    for (line_index, line) in stdin.lock().lines().enumerate() {
        let line = line.map_err(|e| format!("failed to read stdin: {e}"))?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let key: u64 = trimmed
            .parse()
            .map_err(|e| format!("line {}: invalid u64 key {trimmed:?}: {e}", line_index + 1))?;
        keys.push(key);
    }

    keys.sort_unstable();
    keys.dedup();

    let stdout = io::stdout();
    let mut out = stdout.lock();

    if keys.is_empty() {
        out.write_all(&[0u8; BinaryFuse32::DESCRIPTOR_LEN])
            .map_err(|e| format!("failed to write empty descriptor: {e}"))?;
        out.flush().map_err(|e| format!("failed to flush: {e}"))?;
        return Ok(());
    }

    let filter = BinaryFuse32::try_from(&keys).map_err(|e| {
        format!(
            "failed to build BinaryFuse32 filter ({} keys): {e}",
            keys.len()
        )
    })?;

    let mut descriptor = [0u8; BinaryFuse32::DESCRIPTOR_LEN];
    filter.dma_copy_descriptor_to(&mut descriptor);

    out.write_all(&descriptor)
        .map_err(|e| format!("failed to write descriptor: {e}"))?;
    out.write_all(filter.dma_fingerprints())
        .map_err(|e| format!("failed to write fingerprints: {e}"))?;
    out.flush().map_err(|e| format!("failed to flush: {e}"))?;

    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("filter-build: {message}");
            ExitCode::FAILURE
        }
    }
}
