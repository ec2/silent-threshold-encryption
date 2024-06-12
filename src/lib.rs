pub mod decryption;
pub mod encryption;
pub mod kzg;
pub mod setup;
pub mod tage;
pub mod utils;
use anyhow::anyhow;
use anyhow::Context;
use ark_bls12_381::g2::Config as G2Config;
use ark_ec::{
    hashing::{curve_maps::wb::WBMap, map_to_curve_hasher::MapToCurveBasedHasher, HashToCurve},
    pairing::Pairing,
};
use ark_ff::{field_hashers::DefaultFieldHasher, BigInteger, Field, PrimeField};
use ark_serialize::{CanonicalDeserialize as _, CanonicalSerialize as _};
use decryption::agg_dec;
use encryption::Ciphertext;
use kzg::UniversalParams;
use setup::AggregateKey;
use sha2::Sha256;
use std::io::{self, copy};
use std::iter;
use tage::{Identity, Recipient};

type E = ark_bls12_381::Bls12_381;
type G2 = <E as Pairing>::G2;
type TargetField = <E as Pairing>::TargetField;

const DOMAIN: &[u8] = b"__DELOREAN_DOMAIN__";

pub fn encrypt(
    src: &[u8],
    params: &UniversalParams<E>,
    threshold: usize,
    public_key_bytes: &[u8],
    tag: &[u8],
) -> anyhow::Result<Ciphertext<E>> {
    let message = src
        .try_into()
        .context("Message must be exactly 16 bytes long")?;
    let g2_mapper =
        MapToCurveBasedHasher::<G2, DefaultFieldHasher<Sha256, 128>, WBMap<G2Config>>::new(DOMAIN)
            .context("Failed to create G2 hasher")?;
    let hashed_tag = g2_mapper.hash(&tag).context("Failed to hash tag")?;
    // Map message to Gt (Fp12)
    let message_gt = TargetField::from(u128::from_le_bytes(message));
    // let get = message_f12.to_base_prime_field_elements();
    let apk: AggregateKey<E> = AggregateKey::<E>::deserialize_uncompressed(&public_key_bytes[..])
        .context("Failed to deserialize aggregate pk")?;

    let ct = encryption::encrypt(&apk, threshold, params, hashed_tag.into(), message_gt);

    Ok(ct)
}

pub fn decrypt(
    params: &UniversalParams<E>,
    aggregate_partials: G2,
    selector: &[bool],
    aggregate_pk: &AggregateKey<E>,
    ct: &Ciphertext<E>,
) -> anyhow::Result<Vec<u8>> {
    let dec_key = agg_dec(aggregate_partials, &ct, &selector, &aggregate_pk, &params);
    let dec_key_fp12 = dec_key.0;
    let dec_key_fp = dec_key_fp12
        .to_base_prime_field_elements()
        .collect::<Vec<_>>();
    // TODO: we might need to pad with 0s
    let mut msg = dec_key_fp[0].into_bigint().to_bytes_le();
    msg.truncate(16);
    Ok(msg)
}

pub fn e<W: io::Write, R: io::Read>(
    dst: W,
    mut src: R,
    public_key_bytes: &[u8],
    tag: &[u8],
    threshold: usize,
    params: &UniversalParams<E>,
) -> anyhow::Result<()> {
    let mut message = [0; 16];
    src.read(&mut message).context("IOError")?;

    let ct = encrypt(&message, &params, threshold, public_key_bytes, tag)?;

    ct.serialize_uncompressed(dst)
        .context("Failed to serialize ciphertext")?;

    Ok(())
}

pub fn d<W: io::Write, R: io::Read>(
    mut dst: W,
    mut src: R,

    params: &UniversalParams<E>,
    aggregate_partials: G2,
    selector: &[bool],
    aggregate_pk: &AggregateKey<E>,
) -> anyhow::Result<()> {
    let ct = Ciphertext::<E>::deserialize_uncompressed_unchecked(src)
        .context("Failed to deserialize ciphertext")?;

    let pt = decrypt(params, aggregate_partials, selector, aggregate_pk, &ct)?;

    dst.write_all(&pt)
        .context("failed to write to destination")?;
    Ok(())
}

pub fn age_encrypt<W: io::Write, R: io::Read>(
    dst: W,
    mut src: R,
    chain_hash: &[u8],
    public_key_bytes: &[u8],
    tag: [u8; 32],
    threshold: usize,
    params: &UniversalParams<E>,
) -> anyhow::Result<()> {
    let recipient = Recipient::new(chain_hash, public_key_bytes, tag, threshold, params.clone());
    let encryptor = age::Encryptor::with_recipients(vec![Box::new(recipient)])
        .expect("we provided a recipient");

    let mut writer = encryptor.wrap_output(dst)?;
    copy(&mut src, &mut writer)?;
    writer.finish()?;

    Ok(())
}
pub fn age_decrypt<W: io::Write, R: io::Read>(
    mut dst: W,
    src: R,
    chain_hash: &[u8],
    signature: &[u8],
    params: UniversalParams<E>,
    selector: Vec<bool>,
    aggregate_pk: AggregateKey<E>,
    aggregate_partials: G2,
) -> anyhow::Result<()> {
    let identity = Identity::new(
        chain_hash,
        signature,
        params,
        selector,
        aggregate_pk,
        aggregate_partials,
    );
    let src = age::armor::ArmoredReader::new(src);
    let decryptor = match age::Decryptor::new(src) {
        Ok(age::Decryptor::Recipients(d)) => d,
        Ok(age::Decryptor::Passphrase(_)) => return Err(anyhow!("invalid recipients")),
        Err(e) => return Err(anyhow!("failed to create decryptor")),
    };

    let mut reader = match decryptor.decrypt(iter::once(&identity as &dyn age::Identity)) {
        Ok(reader) => reader,
        Err(e) => return Err(anyhow!("FUG")),
    };
    copy(&mut reader, &mut dst)?;

    Ok(())
}
