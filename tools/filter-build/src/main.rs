// Copyright 2025-2026 Trevor Lauder.
// SPDX-License-Identifier: MIT

use std::io::{self, BufRead, Write};

use xorf::{BinaryFuse32, DmaSerializable};

fn main() {
    let stdin = io::stdin();
    let mut keys: Vec<u64> = Vec::new();

    for line in stdin.lock().lines() {
        let line = line.expect("failed to read line");
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let key: u64 = trimmed.parse().expect("invalid u64 key");
        keys.push(key);
    }

    if keys.is_empty() {
        let out = vec![0u8; 20];
        io::stdout().write_all(&out).expect("write failed");
        return;
    }

    let filter = BinaryFuse32::try_from(&keys).expect("failed to build BinaryFuse32 filter");

    let mut descriptor = [0u8; BinaryFuse32::DESCRIPTOR_LEN];
    filter.dma_copy_descriptor_to(&mut descriptor);

    let fingerprints = filter.dma_fingerprints();

    let stdout = io::stdout();
    let mut out = stdout.lock();
    out.write_all(&descriptor).expect("write descriptor failed");
    out.write_all(fingerprints)
        .expect("write fingerprints failed");
    out.flush().expect("flush failed");
}
