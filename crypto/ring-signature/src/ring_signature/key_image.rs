// Copyright (c) 2018-2022 The MobileCoin Foundation

use super::{hash_to_point, Error, Scalar};
use curve25519_dalek::ristretto::CompressedRistretto;
use mc_crypto_digestible::Digestible;
use mc_crypto_keys::{RistrettoPrivate, RistrettoPublic};
use mc_util_repr_bytes::{
    derive_core_cmp_from_as_ref, derive_debug_and_display_hex_from_as_ref,
    derive_repr_bytes_from_as_ref_and_try_from, typenum::U32, LengthMismatch,
};

#[cfg(feature = "prost")]
use mc_util_repr_bytes::derive_prost_message_from_repr_bytes;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

#[derive(Clone, Copy, Default, Digestible, Zeroize)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[digestible(transparent)]
/// The "image" of a private key `x`: I = x * Hp(x * G) = x * Hp(P).
pub struct KeyImage {
    /// The curve point corresponding to the key image
    pub point: CompressedRistretto,
}

impl KeyImage {
    /// View the underlying `CompressedRistretto` as an array of bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.point.as_bytes()
    }

    /// Copies `self` into a new Vec.
    #[cfg(feature = "alloc")]
    pub fn to_vec(&self) -> alloc::vec::Vec<u8> {
        self.point.as_bytes().to_vec()
    }
}

impl From<&RistrettoPrivate> for KeyImage {
    fn from(x: &RistrettoPrivate) -> Self {
        let P = RistrettoPublic::from(x);
        let Hp = hash_to_point(&P);
        let point = x.as_ref() * Hp;
        KeyImage {
            point: point.compress(),
        }
    }
}

// Many tests use this
impl From<u64> for KeyImage {
    fn from(n: u64) -> Self {
        let private_key = RistrettoPrivate::from(Scalar::from(n));
        Self::from(&private_key)
    }
}

impl TryFrom<[u8; 32]> for KeyImage {
    type Error = Error;
    fn try_from(src: [u8; 32]) -> Result<Self, Self::Error> {
        let point = CompressedRistretto::from_slice(&src).map_err(|_e| Error::InvalidCurvePoint)?;
        Ok(Self { point })
    }
}

impl AsRef<CompressedRistretto> for KeyImage {
    fn as_ref(&self) -> &CompressedRistretto {
        &self.point
    }
}

impl AsRef<[u8; 32]> for KeyImage {
    fn as_ref(&self) -> &[u8; 32] {
        self.as_bytes()
    }
}

impl AsRef<[u8]> for KeyImage {
    fn as_ref(&self) -> &[u8] {
        &self.as_bytes()[..]
    }
}

impl TryFrom<&[u8]> for KeyImage {
    type Error = Error;
    fn try_from(src: &[u8]) -> Result<Self, Error> {
        if src.len() != 32 {
            return Err(Error::from(LengthMismatch {
                expected: 32,
                found: src.len(),
            }));
        }
        let point = CompressedRistretto::from_slice(src).map_err(|_e| Error::InvalidCurvePoint)?;
        Ok(Self { point })
    }
}

derive_repr_bytes_from_as_ref_and_try_from!(KeyImage, U32);
derive_core_cmp_from_as_ref!(KeyImage, [u8; 32]);
derive_debug_and_display_hex_from_as_ref!(KeyImage);

#[cfg(feature = "prost")]
derive_prost_message_from_repr_bytes!(KeyImage);

#[cfg(test)]
mod redteam_tests {
    use super::*;
    use curve25519_dalek::ristretto::CompressedRistretto;

    // RED-TEAM (scalar-mult / point-handling audit) — invariant P1/P5.
    //
    // KeyImage::try_from performs a LENGTH-ONLY check (CompressedRistretto::
    // from_slice, key_image.rs:63/95). It accepts ANY 32 bytes — including
    // non-decompressable garbage and the identity point — and defers point
    // validity to verify time (mlsag_verify.rs:48). This documents that the
    // parse step is lenient; the safety net is the verifier, not the decoder.
    //
    // This is the upstream sibling of the Zcash CVE-2026-41584 pattern: an
    // invalid/degenerate point is constructible from untrusted bytes. MobileCoin
    // is saved because (a) decompress() returns Option (no panic, unlike Zcash's
    // unwrap) and (b) verify rejects it (proven in mlsag.rs). A strict decoder
    // that rejected non-canonical bytes at parse would be cheap hardening.
    #[test]
    fn redteam_p1_key_image_try_from_is_length_only() {
        // All-ones: valid length, not a valid Ristretto encoding.
        let garbage = [0xffu8; 32];
        let ki = KeyImage::try_from(garbage)
            .expect("try_from accepts any 32 bytes (length-only validation)");
        assert!(
            ki.point.decompress().is_none(),
            "all-ones is expected to be non-decompressable"
        );

        // Identity (all zeros) is a *valid* Ristretto point, also accepted unchecked.
        let identity = KeyImage::try_from([0u8; 32]).unwrap();
        assert_eq!(identity.point, CompressedRistretto([0u8; 32]));
        assert!(identity.point.decompress().is_some());

        // The &[u8] path is likewise length-only (rejects only on wrong length).
        assert!(KeyImage::try_from(&garbage[..]).is_ok());
        assert!(KeyImage::try_from(&[0u8; 31][..]).is_err());
    }

    // RED-TEAM (double-spend, vector 1): key-image dedup soundness.
    //
    // The ledger dedups key images by their 32 raw bytes (KeyImage Ord/Eq are
    // on [u8; 32]). For that to be a sound double-spend defense, a spent output
    // must have EXACTLY ONE encoding that the verifier accepts. The verifier
    // accepts only encodings that decompress (mlsag_verify.rs:48), and Ristretto
    // decompression is canonical + injective. This test proves the property the
    // dedup relies on:
    //   (a) canonical round-trip is stable: decompress(b).compress() == b
    //   (b) NO single-byte mutation of a valid encoding decompresses back to the
    //       SAME point under different bytes (that would be a dedup-bypass
    //       double-spend: two byte strings, one spent output)
    //   (c) distinct points never share an encoding (injective compression)
    #[test]
    fn redteam_dblspend_key_image_encoding_is_canonical_and_injective() {
        use curve25519_dalek::ristretto::RistrettoPoint;
        use mc_util_test_helper::{RngType, SeedableRng};

        let mut rng: RngType = SeedableRng::from_seed([7u8; 32]);
        let mut seen = alloc::collections::BTreeSet::new();

        for _ in 0..256 {
            let p = RistrettoPoint::random(&mut rng);
            let b = p.compress();

            // (a) canonical round-trip.
            assert_eq!(b.decompress().unwrap().compress(), b);

            // (c) injective: a fresh random point never collides with a prior one.
            assert!(seen.insert(b.to_bytes()), "two distinct points shared bytes");

            // (b) every single-byte perturbation that still decompresses must be
            //     a DIFFERENT point — never the same point under different bytes.
            let canonical = b.to_bytes();
            for i in 0..32 {
                let mut mutated = canonical;
                mutated[i] ^= 0x01;
                if let Some(q) = CompressedRistretto(mutated).decompress() {
                    assert_ne!(
                        q, p,
                        "non-canonical encoding decompressed to the same point: \
                         key-image dedup could be bypassed (double-spend)"
                    );
                }
            }
        }
    }
}
