use super::*;

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn s_box_rows_are_permutations() {
    for s in S {
        for row in s.chunks(16) {
            let mut seen = [false; 16];
            for &v in row {
                assert!(!seen[v as usize]);
                seen[v as usize] = true;
            }
        }
    }
}

#[test]
fn des_known_answer() {
    // The classic worked example (key 133457799BBCDFF1); also what .NET's
    // DES gives.
    let key = unhex("133457799bbcdff1");
    let ct = des_encrypt_block(
        key[..].try_into().unwrap(),
        unhex("0123456789abcdef")[..].try_into().unwrap(),
    );
    assert_eq!(hex(&ct), "85e813540f0ab405");
    // SP 800-17 variable plaintext: key 0101..01, plaintext 8000..00.
    let ct = des_encrypt_block(&[1; 8], [0x80, 0, 0, 0, 0, 0, 0, 0]);
    assert_eq!(hex(&ct), "95f8a5e5dd31d900");
}

#[test]
fn des_decrypts_what_it_encrypts() {
    let d = Des::new(b"\x0e\x32\x92\x32\xea\x6d\x0d\x73");
    let x = 0x8787_8787_8787_8787u64;
    let c = d.block(x, false);
    assert_eq!(c, 0);
    assert_eq!(d.block(c, true), x);
}

/// Expected output from .NET's TripleDES (CBC, no padding) with the same
/// key, IV and plaintext.
const KEY: &str = "30557a9fc4e90e33587da2c7ec11365b80a5caef14395e83";
const IV: [u8; 8] = [0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF];
const CT: &str = "ec5e6519bc4475e99a12234cd449f98473c25c2c22bec16d8a39a01fe0c9b84e";

#[test]
fn triple_des_cbc_matches_dotnet() {
    let key: [u8; 24] = unhex(KEY).try_into().unwrap();
    let plain: Vec<u8> = (0..32).collect();
    let mut data = plain.clone();
    TripleDesCbc::new(&key, IV, false).process(&mut data);
    assert_eq!(hex(&data), CT);
    TripleDesCbc::new(&key, IV, true).process(&mut data);
    assert_eq!(data, plain);
}

#[test]
fn triple_des_chaining_runs_across_calls() {
    let key: [u8; 24] = unhex(KEY).try_into().unwrap();
    let mut enc = TripleDesCbc::new(&key, IV, false);
    let mut a: Vec<u8> = (0..8).collect();
    let mut b: Vec<u8> = (8..32).collect();
    enc.process(&mut a);
    enc.process(&mut b);
    assert_eq!(hex(&[a.clone(), b.clone()].concat()), CT);
    let mut dec = TripleDesCbc::new(&key, IV, true);
    dec.process(&mut a);
    dec.process(&mut b);
    assert_eq!([a, b].concat(), (0..32).collect::<Vec<u8>>());
}
