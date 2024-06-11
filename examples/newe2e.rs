use ark_ec::pairing::{Pairing, PairingOutput};
use ark_ff::field_hashers::{DefaultFieldHasher, HashToField};
use ark_std::UniformRand;
use ark_std::{end_timer, start_timer, Zero};
use sha2::Sha256;
use silent_threshold::decryption::aggregate_partials;
use silent_threshold::{
    decryption::agg_dec,
    encryption::encrypt,
    kzg::KZG10,
    setup::{AggregateKey, PublicKey, SecretKey},
};
type E = ark_bls12_381::Bls12_381;
type G2 = <E as Pairing>::G2;
type TargetField = <E as Pairing>::TargetField;

const DOMAIN: &[u8] = b"__DELOREAN_DOMAIN__";
fn main() {
    let mut rng = ark_std::test_rng();
    let n = 1 << 7; // actually n-1 total parties. one party is a dummy party that is always true
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

    let msg = b"hello world this is the tag that i want to get signedeeeeeeeeeeeeeeeeee";

    let hasher = <DefaultFieldHasher<Sha256> as HashToField<TargetField>>::new(DOMAIN);

    let hashes: Vec<<E as Pairing>::TargetField> =
        hasher.hash_to_field(msg, 1).into_iter().collect();

    let msg_hash = hashes[0];

    let setup_time =
        start_timer!(|| format!("Encrypt::Setup with degree {} and threshold {}", n, t));

    let tag = G2::rand(&mut rng);

    let ct = encrypt::<E>(&agg_key, t, &params, tag, msg_hash);
    end_timer!(setup_time);

    // compute partial decryptions
    let mut partial_decryptions: Vec<G2> = Vec::new();
    for i in 0..t + 1 {
        partial_decryptions.push(sk[i].partial_decryption(&ct));
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

    let dec_key = agg_dec(agg_partials, &ct, &selector, &agg_key, &params);
    assert_eq!(dec_key, PairingOutput(msg_hash))
}
