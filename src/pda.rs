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

/// Marker appended after the program id in the PDA preimage.
pub const PDA_MARKER: &[u8; 21] = b"ProgramDerivedAddress";
/// The only bump this grinder hashes with (canonical-first policy:
/// on-curve hits are discarded, never re-searched at lower bumps).
pub const BUMP: u8 = 255;

/// Fixed PDA preimage layout for one grind:
/// `seeds[..] ‖ [255] ‖ program_id ‖ b"ProgramDerivedAddress"`, with
/// the ground seed (`grind_prefix ‖ 16 alnum bytes`) at `ground_index`.
/// Precomputes a SHA-256 midstate over every whole 64-byte block
/// before the 16 ground bytes; per-attempt work is splicing those 16
/// bytes into the padded tail and compressing the remaining blocks.
pub struct PdaLayout {
    fixed: Vec<SeedSpec>,
    grind_prefix: Vec<u8>,
    ground_index: usize,
    template: PdaTemplate,
}

/// Per-thread spliceable hash state: midstate + padded tail blocks.
#[derive(Clone)]
pub struct PdaTemplate {
    midstate: [u32; 8],
    tail: Vec<u8>,
    splice_off: usize,
}

const SHA256_IV: [u32; 8] = [
    0x6a09_e667,
    0xbb67_ae85,
    0x3c6e_f372,
    0xa54f_f53a,
    0x510e_527f,
    0x9b05_688c,
    0x1f83_d9ab,
    0x5be0_cd19,
];

type Sha256Block =
    sha2::digest::generic_array::GenericArray<u8, sha2::digest::consts::U64>;

impl PdaLayout {
    pub fn new(
        fixed: &[SeedSpec],
        grind_prefix: &str,
        ground_index: usize,
        program_id: &Pubkey,
    ) -> Self {
        assert!(ground_index <= fixed.len(), "ground index");
        assert!(
            grind_prefix.len() + GROUND_LEN <= MAX_SEED_LEN,
            "ground seed too long"
        );

        let mut message = Vec::new();
        let mut ground_off = 0usize;
        for (i, s) in fixed
            .iter()
            .map(|s| s.bytes.as_slice())
            .take(ground_index)
            .chain([&[] as &[u8]]) // placeholder slot
            .chain(
                fixed
                    .iter()
                    .map(|s| s.bytes.as_slice())
                    .skip(ground_index),
            )
            .enumerate()
        {
            if i == ground_index {
                message.extend_from_slice(grind_prefix.as_bytes());
                ground_off = message.len();
                message.extend_from_slice(&[0u8; GROUND_LEN]);
            } else {
                message.extend_from_slice(s);
            }
        }
        message.push(BUMP);
        message.extend_from_slice(program_id.as_ref());
        message.extend_from_slice(PDA_MARKER);

        // Midstate over every whole block before the ground bytes.
        let prefix_blocks = ground_off / 64;
        let mut midstate = SHA256_IV;
        for block in message[..prefix_blocks * 64].chunks_exact(64) {
            sha2::compress256(
                &mut midstate,
                core::slice::from_ref(Sha256Block::from_slice(block)),
            );
        }

        // Tail = rest of the message plus standard SHA-256 padding.
        let mut tail = message[prefix_blocks * 64..].to_vec();
        let bit_len = (message.len() as u64) * 8;
        tail.push(0x80);
        while tail.len() % 64 != 56 {
            tail.push(0);
        }
        tail.extend_from_slice(&bit_len.to_be_bytes());

        Self {
            fixed: fixed.to_vec(),
            grind_prefix: grind_prefix.as_bytes().to_vec(),
            ground_index,
            template: PdaTemplate {
                midstate,
                tail,
                splice_off: ground_off - prefix_blocks * 64,
            },
        }
    }

    pub fn template(&self) -> PdaTemplate {
        self.template.clone()
    }

    /// Full seed list (bytes) with `grind_prefix ‖ ground` inserted,
    /// for `create_program_address` cross-checks and display.
    pub fn seeds_with_ground(
        &self,
        ground: &[u8; GROUND_LEN],
    ) -> Vec<Vec<u8>> {
        let mut seeds: Vec<Vec<u8>> = self
            .fixed
            .iter()
            .map(|s| s.bytes.clone())
            .collect();
        let mut ground_seed = self.grind_prefix.clone();
        ground_seed.extend_from_slice(ground);
        seeds.insert(self.ground_index, ground_seed);
        seeds
    }
}

impl PdaTemplate {
    /// Write the 16 ground bytes into the message tail.
    #[inline]
    pub fn splice(&mut self, ground: &[u8; GROUND_LEN]) {
        self.tail[self.splice_off..self.splice_off + GROUND_LEN]
            .copy_from_slice(ground);
    }

    /// SHA-256 of the full PDA preimage with the spliced ground bytes.
    #[inline]
    pub fn digest(&self) -> [u8; 32] {
        let mut state = self.midstate;
        for block in self.tail.chunks_exact(64) {
            sha2::compress256(
                &mut state,
                core::slice::from_ref(Sha256Block::from_slice(block)),
            );
        }
        let mut out = [0u8; 32];
        for (i, w) in state.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&w.to_be_bytes());
        }
        out
    }
}

/// Same 62-char alphabet as `grind`'s random seeds.
pub const ALNUM: &[u8; 62] =
    b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

/// Per-thread ground-seed stepper: a random base-62 odometer. No RNG
/// in the hot loop; a random start keeps seeds unpredictable across
/// runs and threads while the counter walk covers the space.
pub struct Odometer {
    idx: [u8; GROUND_LEN],
}

impl Odometer {
    pub fn random() -> Self {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        Self {
            idx: std::array::from_fn(|_| rng.gen_range(0..62)),
        }
    }

    /// Render the current position as 16 alnum bytes.
    #[inline]
    pub fn write(&self, out: &mut [u8; GROUND_LEN]) {
        for i in 0..GROUND_LEN {
            out[i] = ALNUM[self.idx[i] as usize];
        }
    }

    /// Advance one position (base-62, carries right to left).
    #[inline]
    pub fn step(&mut self) {
        for i in (0..GROUND_LEN).rev() {
            self.idx[i] += 1;
            if self.idx[i] == 62 {
                self.idx[i] = 0;
            } else {
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    const T1TAN: &str = "T1TANpTeScyeqVzzgNViGDNrkQ6qHz9KrSBS4aNXvGT";

    fn seed(s: &str) -> SeedSpec {
        s.parse().unwrap()
    }

    fn program() -> Pubkey {
        Pubkey::from_str(T1TAN).unwrap()
    }

    fn assert_matches_reference(
        fixed: &[SeedSpec],
        prefix: &str,
        index: usize,
        ground: &[u8; GROUND_LEN],
    ) {
        let prog = program();
        let layout = PdaLayout::new(fixed, prefix, index, &prog);
        let mut tpl = layout.template();
        tpl.splice(ground);

        let mut hasher = Sha256::new();
        for s in layout.seeds_with_ground(ground) {
            hasher.update(&s);
        }
        hasher.update([BUMP]);
        hasher.update(prog);
        hasher.update(PDA_MARKER);
        let want: [u8; 32] = hasher.finalize().into();
        assert_eq!(tpl.digest(), want);
    }

    #[test]
    fn template_ground_only() {
        assert_matches_reference(&[], "", 0, b"0123456789abcdef");
    }

    #[test]
    fn template_ground_with_prefix() {
        assert_matches_reference(
            &[],
            "theia_",
            0,
            b"ZZZZZZZZZZZZZZZZ",
        );
    }

    #[test]
    fn template_ground_first_middle_last() {
        let fixed = [seed(&format!("pubkey:{T1TAN}")), seed("u64le:7")];
        for index in 0..=2 {
            assert_matches_reference(
                &fixed,
                "v_",
                index,
                b"abcdefghij012345",
            );
        }
    }

    #[test]
    fn template_ground_straddles_block_boundary() {
        // 32 + 12 fixed bytes + 16-byte prefix puts the ground bytes
        // at message offset 60..76, across the first 64-byte block.
        let fixed = [
            seed(&format!("str:{}", "a".repeat(32))),
            seed(&format!("str:{}", "b".repeat(12))),
        ];
        assert_matches_reference(
            &fixed,
            &"p".repeat(16),
            2,
            b"qrstuvwxyz987654",
        );
    }

    #[test]
    fn template_long_tail_many_blocks() {
        // Ground seed first: the whole multi-block message is tail.
        let fixed: Vec<SeedSpec> = (0..8)
            .map(|_| seed(&format!("pubkey:{T1TAN}")))
            .collect();
        assert_matches_reference(
            &fixed,
            "",
            0,
            b"A1B2C3D4E5F6G7H8",
        );
    }

    #[test]
    fn template_resplice_overwrites() {
        let layout = PdaLayout::new(&[], "theia_", 0, &program());
        let mut tpl = layout.template();
        tpl.splice(b"0000000000000000");
        tpl.splice(b"06bd29104c000000");
        let mut hasher = Sha256::new();
        hasher.update(b"theia_06bd29104c000000");
        hasher.update([BUMP]);
        hasher.update(program());
        hasher.update(PDA_MARKER);
        let want: [u8; 32] = hasher.finalize().into();
        assert_eq!(tpl.digest(), want);
    }

    fn odo(idx: [u8; GROUND_LEN]) -> Odometer {
        Odometer { idx }
    }

    fn rendered(o: &Odometer) -> [u8; GROUND_LEN] {
        let mut out = [0u8; GROUND_LEN];
        o.write(&mut out);
        out
    }

    #[test]
    fn odometer_bytes_are_alnum() {
        let o = Odometer::random();
        for b in rendered(&o) {
            assert!(ALNUM.contains(&b), "{b} not alnum");
        }
    }

    #[test]
    fn odometer_step_increments_last_position() {
        let mut o = odo([0; GROUND_LEN]);
        assert_eq!(&rendered(&o), b"0000000000000000");
        o.step();
        assert_eq!(&rendered(&o), b"0000000000000001");
    }

    #[test]
    fn odometer_step_carries() {
        let mut idx = [0u8; GROUND_LEN];
        idx[15] = 61;
        let mut o = odo(idx);
        assert_eq!(&rendered(&o), b"000000000000000z");
        o.step();
        assert_eq!(&rendered(&o), b"0000000000000010");
    }

    #[test]
    fn odometer_full_wrap() {
        let mut o = odo([61; GROUND_LEN]);
        o.step();
        assert_eq!(&rendered(&o), b"0000000000000000");
    }

    #[test]
    fn odometer_random_instances_differ() {
        // 62^-16 collision odds; a failure here means a broken RNG.
        assert_ne!(
            rendered(&Odometer::random()),
            rendered(&Odometer::random())
        );
    }

    #[test]
    fn seeds_with_ground_inserts_at_index() {
        let fixed = [seed("str:pool"), seed("u8:3")];
        let layout = PdaLayout::new(&fixed, "x_", 1, &program());
        let seeds = layout.seeds_with_ground(b"0123456789abcdef");
        assert_eq!(
            seeds,
            vec![
                b"pool".to_vec(),
                b"x_0123456789abcdef".to_vec(),
                vec![3u8],
            ]
        );
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
