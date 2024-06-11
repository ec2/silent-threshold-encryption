use std::sync::{Arc, Mutex};

use age::secrecy::{ExposeSecret, Zeroize};
use age_core::format::{FileKey, Stanza};
use ark_ec::pairing::Pairing;

pub const STANZA_TAG: &str = "tlock";

use std::io::{self, Write};

use thiserror::Error;

use crate::{kzg::UniversalParams, setup::AggregateKey};
type E = ark_bls12_381::Bls12_381;
type G2 = <E as Pairing>::G2;
type TargetField = <E as Pairing>::TargetField;
#[derive(Error, Debug)]
pub enum TLockAgeError {
    #[error(transparent)]
    Decrypt(#[from] age::DecryptError),
    #[error(transparent)]
    Encrypt(#[from] age::EncryptError),
    #[error("cannot parse header. partial information: round {round:?}, chain {chain:?}")]
    Header {
        round: Option<String>,
        chain: Option<String>,
    },
    #[error("recipient cannot be a passphrase")]
    InvalidRecipient,
    #[error(transparent)]
    IO(#[from] io::Error),
}

/// Writer that applies the age ASCII armor format.
pub struct ArmoredWriter<W: Write> {
    inner: age::armor::ArmoredWriter<W>,
}

impl<W: Write> ArmoredWriter<W> {
    /// Wraps the given output in an ArmoredWriter.
    pub fn wrap_output(w: W) -> anyhow::Result<Self> {
        let inner = age::armor::ArmoredWriter::wrap_output(w, age::armor::Format::AsciiArmor)
            .map_err(TLockAgeError::IO)?;
        Ok(Self { inner })
    }

    /// Writes the end marker of the age file, if armoring was enabled.
    ///
    /// You MUST call finish when you are done writing, in order to `finish` the armoring process. Failing to call `finish` will result in a truncated file that that will fail to decrypt.
    pub fn finish(self) -> io::Result<W> {
        self.inner.finish()
    }
}

impl<W: Write> Write for ArmoredWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

// Identity implements the age Identity interface. This is used to decrypt
// data with the age Decrypt API.
pub struct Identity {
    hash: Vec<u8>,
    signature: Vec<u8>,

    aggregate_partials: G2,
    params: UniversalParams<E>,
    selector: Vec<bool>,
    aggregate_pk: AggregateKey<E>,
}

impl Identity {
    pub fn new(
        hash: &[u8],
        signature: &[u8],
        params: UniversalParams<E>,
        selector: Vec<bool>,
        aggregate_pk: AggregateKey<E>,
        aggregate_partials: G2,
    ) -> Self {
        Self {
            hash: hash.to_vec(),
            signature: signature.to_vec(),
            params,
            selector,
            aggregate_pk,
            aggregate_partials,
        }
    }
}

impl age::Identity for Identity {
    // Unwrap is called by the age Decrypt API and is provided the DEK that was time
    // lock encrypted by the Wrap function via the Stanza. Inside of Unwrap we decrypt
    // the DEK and provide back to age.
    fn unwrap_stanza(&self, stanza: &Stanza) -> Option<Result<FileKey, age::DecryptError>> {
        if stanza.tag != STANZA_TAG {
            return None;
        }
        if stanza.args.len() != 2 {
            return Some(Err(age::DecryptError::InvalidHeader));
        }
        let args: [String; 2] = [stanza.args[0].clone(), stanza.args[1].clone()];

        let _tag = hex::decode(&args[0])
            .map_err(|_| age::DecryptError::InvalidHeader)
            .ok()?;

        if self.hash != hex::decode(&args[1]).ok()? {
            return Some(Err(age::DecryptError::InvalidHeader));
        }

        let dst = InMemoryWriter::new();
        let decryption = super::d(
            dst.to_owned(),
            stanza.body.as_slice(),
            &self.params,
            self.aggregate_partials,
            &self.selector,
            &self.aggregate_pk,
        );
        decryption
            .map_err(|_| age::DecryptError::DecryptionFailed)
            .ok()?;
        let mut dst = dst.memory();
        dst.resize(16, 0);
        let file_key: [u8; 16] = dst[..].try_into().ok()?;
        Some(Ok(file_key.into()))
    }
}

// Identity implements the age Identity interface. This is used to decrypt
// data with the age Decrypt API.
pub struct HeaderIdentity {
    hash: Mutex<Option<Vec<u8>>>,
    round: Mutex<Option<u64>>,
}

impl HeaderIdentity {
    pub fn new() -> Self {
        Self {
            hash: Mutex::new(None),
            round: Mutex::new(None),
        }
    }

    pub fn hash(&self) -> Option<Vec<u8>> {
        self.hash.lock().unwrap().clone()
    }

    pub fn round(&self) -> Option<u64> {
        *self.round.lock().unwrap()
    }
}

impl Default for HeaderIdentity {
    fn default() -> Self {
        Self::new()
    }
}

impl age::Identity for HeaderIdentity {
    // Unwrap is called by the age Decrypt API and is provided the DEK that was time
    // lock encrypted by the Wrap function via the Stanza. Inside of Unwrap we extract
    // tlock header and assign it to the identity.
    fn unwrap_stanza(&self, stanza: &Stanza) -> Option<Result<FileKey, age::DecryptError>> {
        if stanza.tag != STANZA_TAG {
            return None;
        }
        if stanza.args.len() != 2 {
            return Some(Err(age::DecryptError::InvalidHeader));
        }
        let args: [String; 2] = [stanza.args[0].clone(), stanza.args[1].clone()];

        let round = args[0]
            .parse::<u64>()
            .map_err(|_| age::DecryptError::InvalidHeader)
            .ok()?;
        let hash = hex::decode(&args[1])
            .map_err(|_| age::DecryptError::InvalidHeader)
            .ok()?;

        *self.round.lock().unwrap() = Some(round);
        *self.hash.lock().unwrap() = Some(hash);
        None
    }
}

/// Recipient implements the age Recipient interface. This is used to encrypt
/// data with the age Encrypt API.
pub struct Recipient {
    hash: Vec<u8>,
    public_key_bytes: Vec<u8>,
    tag: [u8; 32],
    threshold: usize,
    params: UniversalParams<E>,
}

impl Recipient {
    pub fn new(
        hash: &[u8],
        public_key_bytes: &[u8],
        tag: [u8; 32],
        threshold: usize,
        params: UniversalParams<E>,
    ) -> Self {
        Self {
            hash: hash.to_vec(),
            public_key_bytes: public_key_bytes.to_vec(),
            tag,
            threshold,
            params,
        }
    }
}

#[derive(Clone)]
struct InMemoryWriter {
    memory: Arc<Mutex<Vec<u8>>>,
}

impl InMemoryWriter {
    pub fn new() -> Self {
        Self {
            memory: Arc::new(Mutex::new(vec![])),
        }
    }

    pub fn memory(&self) -> Vec<u8> {
        self.memory.lock().unwrap().to_owned()
    }
}

impl io::Write for InMemoryWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.memory.lock().unwrap().extend(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.memory.lock().unwrap().to_owned().zeroize();
        Ok(())
    }
}

impl age::Recipient for Recipient {
    /// Wrap is called by the age Encrypt API and is provided the DEK generated by
    /// age that is used for encrypting/decrypting data. Inside of Wrap we encrypt
    /// the DEK using time lock encryption.
    fn wrap_file_key(&self, file_key: &FileKey) -> Result<Vec<Stanza>, age::EncryptError> {
        let src = file_key.expose_secret().as_slice();
        let dst = InMemoryWriter::new();
        let _ = super::e(
            dst.to_owned(),
            src,
            &self.public_key_bytes,
            &self.tag,
            self.threshold,
            &self.params,
        );

        Ok(vec![Stanza {
            tag: STANZA_TAG.to_string(),
            args: vec![hex::encode(self.tag), hex::encode(&self.hash)],
            body: dst.memory(),
        }])
    }
}
