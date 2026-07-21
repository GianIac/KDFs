//! HMAC-based One-Step KDF tests.
#![allow(clippy::unwrap_used, reason = "tests")]

use digest::Digest;
use hex_literal::hex;
use hmac::{HmacReset, KeyInit};
use sha2::Sha256;

type HmacSha256 = HmacReset<Sha256>;

struct HmacFixture<'a> {
    secret: &'a [u8],
    salt: &'a [u8],
    other_info: &'a [u8],
    expected_key: &'a [u8],
}

fn test_hmac_key_derivation(fixtures: &[HmacFixture<'_>]) {
    for fixture in fixtures {
        let mut buf = [0u8; 256];

        for key_length in 1..=fixture.expected_key.len() {
            let key = &mut buf[..key_length];

            let aux = HmacSha256::new_from_slice(fixture.salt).unwrap();

            one_step_kdf::derive_key_into_with(
                aux,
                fixture.secret,
                fixture.other_info,
                key,
            )
            .unwrap();

            assert_eq!(&fixture.expected_key[..key_length], key);
        }
    }
}

#[test]
fn test_input_output_hmac_sha256() {
    let fixtures = [HmacFixture {
        secret: &[0u8; 32],
        salt: &[0u8; 64],
        other_info: &[],
        expected_key: &hex!(
            "ceb496ba22edd29dfc5fa4e2d58abcc3"
            "0b49af2d76d754b54b5c02cf0a2c02dc"
        ),
    }];

    test_hmac_key_derivation(&fixtures);
}

#[test]
fn test_hmac_sha256_multiple_blocks() {
    let secret = [0u8; 32];
    let salt = [0u8; 64];
    let other_info = [];

    let aux = HmacSha256::new_from_slice(&salt).unwrap();
    let mut key = [0u8; 64];

    one_step_kdf::derive_key_into_with(
        aux,
        &secret,
        &other_info,
        &mut key,
    )
    .unwrap();

    assert_eq!(
        key,
        hex!(
            // HMAC-SHA256(salt, 00000001 || secret)
            "ceb496ba22edd29dfc5fa4e2d58abcc3"
            "0b49af2d76d754b54b5c02cf0a2c02dc"

            // HMAC-SHA256(salt, 00000002 || secret)
            "142cd755e28b5aae1958ac736f2c3190"
            "75137e3fe4d94f64c6fc99cb31e2ad53"
        )
    );
}

#[test]
fn generic_aux_matches_digest_api() {
    let secret = b"secret";
    let other_info = b"shared-info";

    let mut through_wrapper = [0u8; 64];
    let mut through_aux = [0u8; 64];

    one_step_kdf::derive_key_into::<Sha256>(
        secret,
        other_info,
        &mut through_wrapper,
    )
    .unwrap();

    one_step_kdf::derive_key_into_with(
        Sha256::new(),
        secret,
        other_info,
        &mut through_aux,
    )
    .unwrap();

    assert_eq!(through_wrapper, through_aux);
}