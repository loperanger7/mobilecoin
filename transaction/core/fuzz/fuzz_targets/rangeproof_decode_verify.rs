#![no_main]
//! RED-TEAM (double-spend / counterfeit audit, vector DS-6).
//!
//! The Bulletproofs range proof is what stops outputs with negative or
//! out-of-range values (i.e. counterfeiting, which is strictly worse than a
//! double-spend). `bulletproofs-og` is a MobileCoin fork, so its decode/verify
//! path is exactly the kind of code that should be fuzzed for panics on
//! attacker-controlled input.
//!
//! This target throws arbitrary bytes at the range-proof decode + verify seam:
//!   * arbitrary `RangeProof` bytes (`RangeProof::from_bytes`)
//!   * an arbitrary number (0..7) of arbitrary 32-byte commitments, which may or
//!     may not be valid Ristretto encodings
//!
//! The invariant: `check_range_proofs` must NEVER panic — it must cleanly
//! return Ok/Err for any input. (A panic in consensus validation aborts the
//! SGX enclave.) The empty-commitment case also exercises the F-2 fix in
//! `resize_slice_to_pow2`.
//!
//! Run:
//!   cargo +nightly-2024-10-11 fuzz run rangeproof_decode_verify
//!   cargo +nightly-2024-10-11 fuzz run rangeproof_decode_verify -- -max_total_time=60   # PR smoke

use libfuzzer_sys::fuzz_target;

use bulletproofs_og::RangeProof;
use curve25519_dalek::ristretto::CompressedRistretto;
use mc_crypto_ring_signature::generators;
use mc_transaction_core::range_proofs::check_range_proofs;
use rand_core::SeedableRng;
use rand_hc::Hc128Rng;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    // First byte picks how many commitments to build (0..=7). Including 0
    // deliberately exercises the empty-input path (F-2).
    let num_commitments = (data[0] % 8) as usize;
    let rest = &data[1..];

    // Carve out arbitrary 32-byte commitments (not necessarily decompressable).
    let mut commitments: Vec<CompressedRistretto> = Vec::with_capacity(num_commitments);
    let mut offset = 0usize;
    for _ in 0..num_commitments {
        if offset + 32 > rest.len() {
            break;
        }
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&rest[offset..offset + 32]);
        commitments.push(CompressedRistretto(bytes));
        offset += 32;
    }

    // Whatever is left is the candidate range-proof encoding.
    let proof_bytes = &rest[offset..];

    if let Ok(proof) = RangeProof::from_bytes(proof_bytes) {
        // Deterministic RNG; verification must be panic-free for ALL inputs.
        let mut rng = Hc128Rng::seed_from_u64(0);
        let _ = check_range_proofs(&proof, &commitments, &generators(0), &mut rng);
    }
});
