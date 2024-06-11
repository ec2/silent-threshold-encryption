use std::path::PathBuf;

use ark_bls12_381::g2::Config as G2Config;
use ark_ec::hashing::curve_maps::wb::WBMap;
use ark_ec::hashing::map_to_curve_hasher::MapToCurveBasedHasher;
use ark_ec::hashing::HashToCurve as _;
use ark_ec::pairing::{Pairing, PairingOutput};
use ark_ff::field_hashers::{DefaultFieldHasher, HashToField};
use ark_serialize::CanonicalSerialize;
use ark_std::UniformRand;
use ark_std::{end_timer, start_timer, Zero};
use sha2::Sha256;
use silent_threshold::decryption::aggregate_partials;
use silent_threshold::{
    decryption::agg_dec,
    encryption::encrypt,
    kzg::KZG10,
    setup::{partial_decryption, AggregateKey, PublicKey, SecretKey},
};

type E = ark_bls12_381::Bls12_381;
type G2 = <E as Pairing>::G2;
type TargetField = <E as Pairing>::TargetField;

const DOMAIN: &[u8] = b"__DELOREAN_DOMAIN__";
fn main() {
    let mut rng = ark_std::test_rng();
    let n = 1 << 6; // actually n-1 total parties. one party is a dummy party that is always true
    let t: usize = 9;
    debug_assert!(t < n);

    let params = KZG10::<E>::setup(n, &mut rng).unwrap();

    let keygen_time = start_timer!(|| format!("Keygen with degree {} and threshold {}", n, t));
    let mut sk: Vec<SecretKey<E>> = Vec::new();
    let mut pk: Vec<PublicKey<E>> = Vec::new();

    // create the dummy party's keys
    sk.push(SecretKey::<E>::new(&mut rng));
    sk[0].nullify();
    pk.push(sk[0].get_pk(0, &params, n));

    for i in 1..n {
        sk.push(SecretKey::<E>::new(&mut rng));
        pk.push(sk[i].get_pk(i, &params, n))
    }
    end_timer!(keygen_time);

    let agg_key = AggregateKey::<E>::new(pk, &params);
    let mut agg_key_bytes = Vec::new();
    agg_key.serialize_uncompressed(&mut agg_key_bytes).unwrap();

    let msg = b"Hello world! I'm encrypting a message using timelock encryption.".to_vec();
    let tag = [2; 32];
    let g2_mapper =
        MapToCurveBasedHasher::<G2, DefaultFieldHasher<Sha256, 128>, WBMap<G2Config>>::new(DOMAIN)
            .expect("Failed to create G2 hasher");
    let hashed_tag = g2_mapper.hash(tag.as_slice()).expect("Failed to hash tag");
    // Encryption with armoring, making encrypted message ASCII printable
    let mut armored = silent_threshold::tage::ArmoredWriter::wrap_output(vec![]).unwrap();
    silent_threshold::age_encrypt(
        &mut armored,
        msg.as_slice(),
        [0; 32].as_slice(),
        &agg_key_bytes,
        tag,
        t,
        &params,
    )
    .unwrap();

    let encrypted = armored.finish().unwrap();
    let output_path: PathBuf = PathBuf::from("ciphertext.age");
    std::fs::write(&output_path, &encrypted).expect("failed to write output file");

    // compute partial decryptions
    let mut partial_decryptions: Vec<G2> = Vec::new();
    for i in 0..t + 1 {
        partial_decryptions.push(partial_decryption::<E>(hashed_tag.into(), sk[i].sk));
    }
    for _ in t + 1..n {
        partial_decryptions.push(G2::zero());
    }

    // compute the decryption key
    let mut selector: Vec<bool> = Vec::new();
    for _ in 0..t + 1 {
        selector.push(true);
    }
    for _ in t + 1..n {
        selector.push(false);
    }
    let agg_partials = aggregate_partials(&params, &partial_decryptions, &selector);

    // Decryption!!!!
    let mut decrypted = vec![];

    silent_threshold::age_decrypt(
        &mut decrypted,
        encrypted.as_slice(),
        [0; 32].as_slice(),
        [0; 32].as_slice(),
        params,
        selector,
        agg_key,
        agg_partials,
    )
    .unwrap();
    let decrypted = std::str::from_utf8(&decrypted).unwrap();

    println!("{decrypted}");
}
