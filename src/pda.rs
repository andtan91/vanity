//! PDA grinding: seed specs, message layout, midstate hashing.

use solana_pubkey::Pubkey;
use std::str::FromStr;

/// Solana limits: at most 16 seeds including the bump, each at most
/// 32 bytes. We append the bump ourselves, so users get 15.
pub const MAX_SEED_LEN: usize = 32;
pub const MAX_USER_SEEDS: usize = 15;
/// Number of ground (searched) bytes in the ground seed.
pub const GROUND_LEN: usize = 16;

/// One `--seed` argument: `str:`, `hex:`, `pubkey:`, `u64le:`, `u8:`.
/// Keeps the raw spec string for display.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SeedSpec {
    pub raw: String,
    pub bytes: Vec<u8>,
}

impl FromStr for SeedSpec {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, String> {
        let (kind, value) = s.split_once(':').ok_or(
            "--seed must be <kind>:<value> with kind one of \
             str, hex, pubkey, u64le, u8",
        )?;
        let bytes = match kind {
            "str" => value.as_bytes().to_vec(),
            "hex" => decode_hex(value)?,
            "pubkey" => Pubkey::from_str(value)
                .map_err(|e| format!("--seed pubkey: {e}"))?
                .to_bytes()
                .to_vec(),
            "u64le" => value
                .parse::<u64>()
                .map_err(|e| format!("--seed u64le: {e}"))?
                .to_le_bytes()
                .to_vec(),
            "u8" => vec![value
                .parse::<u8>()
                .map_err(|e| format!("--seed u8: {e}"))?],
            other => {
                return Err(format!(
                    "--seed kind '{other}' unknown; use \
                     str, hex, pubkey, u64le, or u8"
                ))
            }
        };
        if bytes.len() > MAX_SEED_LEN {
            return Err(format!(
                "--seed '{s}' is {} bytes; seeds are at most \
                 {MAX_SEED_LEN} bytes",
                bytes.len()
            ));
        }
        Ok(Self {
            raw: s.to_string(),
            bytes,
        })
    }
}

fn decode_hex(value: &str) -> Result<Vec<u8>, String> {
    if value.len() % 2 != 0 {
        return Err(format!(
            "--seed hex '{value}' has odd length"
        ));
    }
    (0..value.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&value[i..i + 2], 16).map_err(|_| {
                format!("--seed hex '{value}' is not valid hex")
            })
        })
        .collect()
}

/// Validate the grind layout and resolve the ground-seed index
/// (default: appended after the fixed seeds).
pub fn validate_layout(
    fixed: &[SeedSpec],
    grind_prefix: &str,
    grind_index: Option<usize>,
) -> Result<usize, String> {
    if !grind_prefix.is_ascii() {
        return Err(format!(
            "--grind-prefix '{grind_prefix}' must be ASCII"
        ));
    }
    if grind_prefix.len() + GROUND_LEN > MAX_SEED_LEN {
        return Err(format!(
            "--grind-prefix is {} bytes; prefix + {GROUND_LEN} \
             ground bytes must fit a {MAX_SEED_LEN}-byte seed",
            grind_prefix.len()
        ));
    }
    if fixed.len() + 1 > MAX_USER_SEEDS {
        return Err(format!(
            "{} fixed seeds + the ground seed exceeds \
             {MAX_USER_SEEDS} seeds (the bump is the 16th)",
            fixed.len()
        ));
    }
    let index = grind_index.unwrap_or(fixed.len());
    if index > fixed.len() {
        return Err(format!(
            "--grind-index {index} out of range; must be \
             0..={}",
            fixed.len()
        ));
    }
    Ok(index)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seed(s: &str) -> SeedSpec {
        s.parse().unwrap()
    }

    #[test]
    fn parses_str_seed() {
        let s = seed("str:theia_");
        assert_eq!(s.bytes, b"theia_");
        assert_eq!(s.raw, "str:theia_");
    }

    #[test]
    fn parses_hex_seed() {
        assert_eq!(seed("hex:00ffA5").bytes, vec![0x00, 0xff, 0xa5]);
    }

    #[test]
    fn parses_pubkey_seed() {
        let s = seed("pubkey:T1TANpTeScyeqVzzgNViGDNrkQ6qHz9KrSBS4aNXvGT");
        let pk =
            Pubkey::from_str("T1TANpTeScyeqVzzgNViGDNrkQ6qHz9KrSBS4aNXvGT")
                .unwrap();
        assert_eq!(s.bytes, pk.to_bytes().to_vec());
    }

    #[test]
    fn parses_u64le_seed() {
        assert_eq!(
            seed("u64le:258").bytes,
            vec![2, 1, 0, 0, 0, 0, 0, 0]
        );
    }

    #[test]
    fn parses_u8_seed() {
        assert_eq!(seed("u8:7").bytes, vec![7]);
    }

    #[test]
    fn rejects_odd_length_hex() {
        assert!("hex:abc".parse::<SeedSpec>().is_err());
    }

    #[test]
    fn rejects_non_hex_chars() {
        assert!("hex:zz".parse::<SeedSpec>().is_err());
    }

    #[test]
    fn rejects_u8_overflow() {
        assert!("u8:256".parse::<SeedSpec>().is_err());
    }

    #[test]
    fn rejects_unknown_kind() {
        assert!("base64:AAAA".parse::<SeedSpec>().is_err());
    }

    #[test]
    fn rejects_missing_colon() {
        assert!("theia".parse::<SeedSpec>().is_err());
    }

    #[test]
    fn rejects_seed_longer_than_32_bytes() {
        let long = format!("str:{}", "a".repeat(33));
        assert!(long.parse::<SeedSpec>().is_err());
        let ok = format!("str:{}", "a".repeat(32));
        assert!(ok.parse::<SeedSpec>().is_ok());
    }

    #[test]
    fn layout_default_index_is_after_fixed_seeds() {
        let fixed = [seed("str:pool"), seed("u8:1")];
        assert_eq!(validate_layout(&fixed, "theia_", None), Ok(2));
    }

    #[test]
    fn layout_explicit_index() {
        let fixed = [seed("str:pool")];
        assert_eq!(validate_layout(&fixed, "", Some(0)), Ok(0));
        assert_eq!(validate_layout(&fixed, "", Some(1)), Ok(1));
    }

    #[test]
    fn layout_rejects_index_out_of_range() {
        let fixed = [seed("str:pool")];
        let err = validate_layout(&fixed, "", Some(2)).unwrap_err();
        assert!(err.contains("--grind-index"), "{err}");
    }

    #[test]
    fn layout_rejects_long_grind_prefix() {
        // 16 ground chars + 17-byte prefix > 32-byte seed limit.
        let err = validate_layout(&[], &"a".repeat(17), None)
            .unwrap_err();
        assert!(err.contains("--grind-prefix"), "{err}");
        assert!(validate_layout(&[], &"a".repeat(16), None).is_ok());
    }

    #[test]
    fn layout_rejects_non_ascii_grind_prefix() {
        assert!(validate_layout(&[], "théia", None).is_err());
    }

    #[test]
    fn layout_rejects_too_many_seeds() {
        let fixed: Vec<SeedSpec> =
            (0..15).map(|_| seed("u8:0")).collect();
        // 15 fixed + ground = 16 user seeds; bump would be the 17th.
        assert!(validate_layout(&fixed, "", None).is_err());
        assert!(validate_layout(&fixed[..14], "", None).is_ok());
    }
}
