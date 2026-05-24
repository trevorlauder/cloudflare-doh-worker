# Copyright 2025-2026 Trevor Lauder.
# SPDX-License-Identifier: MIT

"""BinaryFuse32 lookup and domain hashing for the blocklist filter."""

import hashlib
import struct
from typing import NamedTuple

_U64_MASK = (1 << 64) - 1
_U32_MASK = (1 << 32) - 1

_MIX_C1 = 0xFF51AFD7ED558CCD
_MIX_C2 = 0xC4CEB9FE1A85EC53


class BinaryFuse32Filter(NamedTuple):
    """Deserialized BinaryFuse32 filter from DMA-format bytes."""

    seed: int
    segment_length: int
    segment_length_mask: int
    segment_count_length: int
    fingerprints: bytes


_DESCRIPTOR_LEN = 20


def _domain_to_key(domain: str) -> int:
    """
    Hash a domain string to a u64 key using blake2b.

    Parameters:
    domain (str): The domain name to hash.

    Returns:
    int: An unsigned 64-bit integer key.
    """
    return int.from_bytes(
        hashlib.blake2b(domain.encode(), digest_size=8).digest(),
        "little",
    )


def load_filter(shard_bytes: bytes) -> BinaryFuse32Filter:
    """
    Deserialize a BinaryFuse32 filter from DMA-format bytes.

    The format is a 20-byte descriptor followed by u32 fingerprints in
    little-endian order, matching the xorf crate's DMA serialization.

    Parameters:
    shard_bytes (bytes): Raw bytes of a serialized BinaryFuse32 filter.

    Returns:
    BinaryFuse32Filter: Tuple of (seed, segment_length, segment_length_mask,
        segment_count_length, fingerprints).
    """
    seed, seg_len, seg_mask, seg_count_len = struct.unpack_from("<Q3I", shard_bytes, 0)

    return BinaryFuse32Filter(
        seed=seed,
        segment_length=seg_len,
        segment_length_mask=seg_mask,
        segment_count_length=seg_count_len,
        fingerprints=shard_bytes[_DESCRIPTOR_LEN:],
    )


_unpack_u32 = struct.Struct("<I").unpack_from


def check_filter(
    filter_obj: BinaryFuse32Filter,
    key: int,
) -> bool:
    """
    Check if a key is (possibly) in the BinaryFuse32 filter.

    Takes a pre-computed u64 key (from _domain_to_key), applies mix64, then
    XORs the three fingerprint entries. A result of zero indicates membership
    (with a theoretical false-positive rate of 1/2^32).

    Parameters:
    filter_obj (BinaryFuse32Filter): A deserialized filter from load_filter.
    key (int): A u64 key from _domain_to_key.

    Returns:
    bool: True if the key is (possibly) in the filter, False if definitely absent.
    """
    fingerprint_bytes = filter_obj.fingerprints
    if not fingerprint_bytes:
        return False

    seed = filter_obj.seed
    segment_length = filter_obj.segment_length
    segment_length_mask = filter_obj.segment_length_mask
    segment_count_length = filter_obj.segment_count_length

    mixed_hash = (key + seed) & _U64_MASK
    mixed_hash ^= mixed_hash >> 33
    mixed_hash = (mixed_hash * _MIX_C1) & _U64_MASK
    mixed_hash ^= mixed_hash >> 33
    mixed_hash = (mixed_hash * _MIX_C2) & _U64_MASK
    mixed_hash ^= mixed_hash >> 33

    fingerprint = (mixed_hash ^ (mixed_hash >> 32)) & _U32_MASK

    index_0 = ((mixed_hash * segment_count_length) >> 64) & _U32_MASK
    index_1 = (index_0 + segment_length) & _U32_MASK
    index_2 = (index_1 + segment_length) & _U32_MASK
    index_1 ^= ((mixed_hash >> 18) & _U32_MASK) & segment_length_mask
    index_2 ^= (mixed_hash & _U32_MASK) & segment_length_mask

    fingerprint ^= (
        _unpack_u32(fingerprint_bytes, index_0 * 4)[0]
        ^ _unpack_u32(fingerprint_bytes, index_1 * 4)[0]
        ^ _unpack_u32(fingerprint_bytes, index_2 * 4)[0]
    )

    return fingerprint == 0
