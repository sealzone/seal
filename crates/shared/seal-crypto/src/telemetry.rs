//! Telemetry entries sealed to the tenant's readers (`TelemetryEntries::Sealed`): the enclave
//! seals each batch with `seal_entries`, readers holding a `TelemetryReaderKey` open it with
//! `open_entries`.
//!
//! Layout, for a batch `(tenant, stream, sequence, first_entry, count)`:
//! - `aad = canonical(&(tenant, stream, sequence, first_entry, count))` (`batch_aad`), `stream` a
//!   plain `[u8; 16]` and `count` a `u32`;
//! - `ciphertext = AES-256-GCM(batch key, nonce, canonical(entries), aad)` with a fresh random
//!   32-byte batch key and a random 12-byte nonce;
//! - per reader, the batch key HPKE-sealed to the reader's X25519 key (`hpke::seal`,
//!   `info = TELEMETRY_READER_INFO`, the same aad).
//!
//! The aad ties the ciphertext and every wrapped key to one batch of one stream. The rest of
//! the batch (`from`, `to`, `last`, the reader list) is covered by the enclave's signature over
//! the batch, which readers check before opening it.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use seal_proto::codec::{canonical, from_canonical};
use seal_proto::telemetry::{self as wire, TelemetryBatch, TelemetryEntries, TelemetryEntry, TELEMETRY_READER_INFO};
use seal_proto::{PublicKey, TenantId};
use zeroize::Zeroizing;

use crate::{CryptoError, Key32};

/// A telemetry reader's X25519 key (its public half goes in `TenantState::telemetry_readers`).
/// The 32-byte seed is the X25519 scalar. Zeroized on drop.
pub struct TelemetryReaderKey(x25519_dalek::StaticSecret);

impl TelemetryReaderKey {
    pub fn generate(rng: &mut impl rand::CryptoRng) -> Self {
        Self(x25519_dalek::StaticSecret::random_from_rng(rng))
    }
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self(x25519_dalek::StaticSecret::from(*seed))
    }
    /// The seed `from_seed` takes back, for storing the key.
    pub fn to_seed(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.0.to_bytes())
    }
    pub fn public_key(&self) -> PublicKey {
        PublicKey(x25519_dalek::PublicKey::from(&self.0).to_bytes())
    }
}

impl std::fmt::Debug for TelemetryReaderKey {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "TelemetryReaderKey(<redacted>)")
    }
}

/// `canonical(&(tenant, stream, sequence, first_entry, count))`.
pub fn batch_aad(tenant: &TenantId, stream: [u8; 16], sequence: u64, first_entry: u64, count: u32) -> Vec<u8> {
    canonical(&(tenant, stream, sequence, first_entry, count))
}

/// `TelemetryEntries::Sealed` for the batch `(tenant, stream, sequence, first_entry,
/// entries.len())`, its key wrapped once per reader in the order given. `Malformed` without
/// readers, for a reader key HPKE refuses, or for more than `u32::MAX` entries.
pub fn seal_entries(
    tenant: &TenantId,
    stream: [u8; 16],
    sequence: u64,
    first_entry: u64,
    entries: &[TelemetryEntry],
    readers: &[PublicKey],
    rng: &mut impl rand::CryptoRng,
) -> Result<TelemetryEntries, CryptoError> {
    if readers.is_empty() {
        return Err(CryptoError::Malformed("sealed telemetry needs at least one reader".into()));
    }
    let count =
        u32::try_from(entries.len()).map_err(|_| CryptoError::Malformed("too many telemetry entries".into()))?;
    let aad = batch_aad(tenant, stream, sequence, first_entry, count);
    let key = Key32::generate(rng);
    let mut nonce = [0u8; 12];
    rng.fill_bytes(&mut nonce);
    let plaintext = Zeroizing::new(canonical(&entries));
    let ciphertext = Aes256Gcm::new(key.expose().into())
        .encrypt(&Nonce::from(nonce), Payload { msg: &plaintext, aad: &aad })
        .map_err(|_| CryptoError::Malformed("telemetry entries too long to seal".into()))?;
    let readers = readers
        .iter()
        .map(|reader| {
            let (enc, wrapped_key) = crate::hpke::seal(reader, TELEMETRY_READER_INFO, &aad, key.expose(), rng)
                .map_err(|_| CryptoError::Malformed(format!("telemetry reader {reader}: not a usable X25519 key")))?;
            Ok(wire::TelemetryReaderKey { reader: *reader, enc, wrapped_key })
        })
        .collect::<Result<Vec<_>, CryptoError>>()?;
    Ok(TelemetryEntries::Sealed { readers, nonce, ciphertext })
}

/// The entries of a sealed `batch`, opened with `reader`. Check the batch's signature first:
/// this authenticates the entries against the batch's identity (the aad), not its other fields.
///
/// `Decrypt` when the batch has no slot for `reader`, or the wrapped key or ciphertext do not
/// open (wrong key, tampered, or moved to another batch). `Malformed` for a batch in clear, or
/// for opened entries that do not match the batch: not `count` of them, or one for another
/// tenant or dated outside `from..=to`.
pub fn open_entries(reader: &TelemetryReaderKey, batch: &TelemetryBatch) -> Result<Vec<TelemetryEntry>, CryptoError> {
    let TelemetryEntries::Sealed { readers, nonce, ciphertext } = &batch.entries else {
        return Err(CryptoError::Malformed("the batch's entries are in clear".into()));
    };
    let public = reader.public_key();
    let slot = readers.iter().find(|r| r.reader == public).ok_or(CryptoError::Decrypt)?;
    let aad = batch_aad(&batch.tenant, batch.stream, batch.sequence, batch.first_entry, batch.count);
    let key = crate::hpke::open(&reader.0, &slot.enc, &slot.wrapped_key, TELEMETRY_READER_INFO, &aad)?;
    let key: &[u8; 32] = key.expose().try_into().map_err(|_| CryptoError::Decrypt)?;
    let plaintext = Zeroizing::new(
        Aes256Gcm::new(key.into())
            .decrypt(&Nonce::from(*nonce), Payload { msg: ciphertext, aad: &aad })
            .map_err(|_| CryptoError::Decrypt)?,
    );
    let entries: Vec<TelemetryEntry> =
        from_canonical(&plaintext).map_err(|e| CryptoError::Malformed(format!("sealed telemetry entries: {e}")))?;
    if entries.len() != batch.count as usize {
        return Err(CryptoError::Malformed("the sealed entries do not match the batch's count".into()));
    }
    if entries.iter().any(|e| e.tenant != batch.tenant || e.at < batch.from || e.at > batch.to) {
        return Err(CryptoError::Malformed("a sealed entry is for another tenant or outside from..to".into()));
    }
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use seal_proto::identity::WorkloadIdentity;
    use seal_proto::telemetry::{Operation, TelemetryEvent};
    use seal_proto::{ErrorCode, KeyId};

    use super::*;

    fn rng() -> impl rand::CryptoRng {
        rand::rand_core::UnwrapErr(rand::rngs::SysRng)
    }

    fn tenant() -> TenantId {
        TenantId::new("acme").unwrap()
    }

    fn entry(at: u64) -> TelemetryEntry {
        TelemetryEntry {
            at,
            tenant: tenant(),
            identity: Some(WorkloadIdentity::AppKey { key_id: KeyId([0x11; 32]) }),
            event: TelemetryEvent::Refused { operation: Operation::Seal, code: ErrorCode::NotAllowed },
        }
    }

    /// A batch of `entries` sealed to `readers`, numbered (stream 1, sequence 2, first entry 30).
    fn batch(entries: &[TelemetryEntry], readers: &[PublicKey]) -> TelemetryBatch {
        let sealed = seal_entries(&tenant(), [1; 16], 2, 30, entries, readers, &mut rng()).unwrap();
        TelemetryBatch {
            tenant: tenant(),
            stream: [1; 16],
            sequence: 2,
            first_entry: 30,
            count: entries.len() as u32,
            from: entries.iter().map(|e| e.at).min().unwrap_or(0),
            to: entries.iter().map(|e| e.at).max().unwrap_or(0),
            entries: sealed,
            last: false,
        }
    }

    #[test]
    fn every_reader_opens_the_batch() {
        let readers: Vec<_> = (0..3).map(|_| TelemetryReaderKey::generate(&mut rng())).collect();
        let entries = [entry(100), entry(101)];
        let public: Vec<_> = readers.iter().map(|r| r.public_key()).collect();
        let b = batch(&entries, &public);
        let TelemetryEntries::Sealed { readers: slots, .. } = &b.entries else { panic!("sealed") };
        assert_eq!(slots.iter().map(|s| s.reader).collect::<Vec<_>>(), public);
        for reader in &readers {
            assert_eq!(open_entries(reader, &b).unwrap(), entries);
        }
        let empty = batch(&[], &[readers[0].public_key()]);
        assert_eq!(open_entries(&readers[0], &empty).unwrap(), []);
    }

    #[test]
    fn keys_round_trip_through_their_seed_and_redact() {
        let key = TelemetryReaderKey::generate(&mut rng());
        let again = TelemetryReaderKey::from_seed(&key.to_seed());
        assert_eq!(again.public_key(), key.public_key());
        assert_eq!(format!("{key:?}"), "TelemetryReaderKey(<redacted>)");
        assert_ne!(TelemetryReaderKey::generate(&mut rng()).public_key(), key.public_key());
    }

    #[test]
    fn wrong_keys_and_tampering_do_not_open() {
        let reader = TelemetryReaderKey::generate(&mut rng());
        let b = batch(&[entry(100)], &[reader.public_key()]);
        let stranger = TelemetryReaderKey::generate(&mut rng());
        assert_eq!(open_entries(&stranger, &b).unwrap_err(), CryptoError::Decrypt, "no slot");

        // The stranger's key in the reader's slot.
        let mut stolen = b.clone();
        let TelemetryEntries::Sealed { readers, .. } = &mut stolen.entries else { unreachable!() };
        readers[0].reader = stranger.public_key();
        assert_eq!(open_entries(&stranger, &stolen).unwrap_err(), CryptoError::Decrypt);

        let tampered = |f: &mut dyn FnMut(&mut TelemetryBatch)| {
            let mut t = b.clone();
            f(&mut t);
            open_entries(&reader, &t).unwrap_err()
        };
        let decrypt = CryptoError::Decrypt;
        assert_eq!(tampered(&mut |t| t.sequence += 1), decrypt, "another sequence");
        assert_eq!(tampered(&mut |t| t.stream[0] ^= 1), decrypt, "another stream");
        assert_eq!(tampered(&mut |t| t.first_entry += 1), decrypt, "another first entry");
        assert_eq!(tampered(&mut |t| t.tenant = TenantId::new("other").unwrap()), decrypt, "another tenant");
        assert_eq!(tampered(&mut |t| t.count += 1), decrypt, "another count");
        for which in 0..4 {
            let flipped = tampered(&mut |t| {
                let TelemetryEntries::Sealed { readers, nonce, ciphertext } = &mut t.entries else { unreachable!() };
                match which {
                    0 => ciphertext[0] ^= 1,
                    1 => nonce[0] ^= 1,
                    2 => readers[0].wrapped_key[0] ^= 1,
                    _ => readers[0].enc[0] ^= 1,
                }
            });
            assert_eq!(flipped, decrypt, "bit flip {which}");
        }

        let mut clear = b.clone();
        clear.entries = TelemetryEntries::Clear { entries: vec![entry(100)] };
        assert!(matches!(open_entries(&reader, &clear), Err(CryptoError::Malformed(_))));
    }

    /// Entries that open but do not match the signed metadata: what a buggy writer could produce.
    #[test]
    fn opened_entries_must_match_the_batch() {
        let reader = TelemetryReaderKey::generate(&mut rng());
        let readers = [reader.public_key()];
        let reseal = |b: &mut TelemetryBatch, entries: &[TelemetryEntry]| {
            let (tenant, stream, sequence, first_entry) = (&b.tenant, b.stream, b.sequence, b.first_entry);
            b.entries = seal_entries(tenant, stream, sequence, first_entry, entries, &readers, &mut rng()).unwrap();
        };
        let malformed = |b: &TelemetryBatch| matches!(open_entries(&reader, b), Err(CryptoError::Malformed(_)));

        // Sealed with one entry, labelled as two: the aad differs, so it does not even open.
        let mut miscounted = batch(&[entry(100)], &readers);
        miscounted.count = 2;
        assert_eq!(open_entries(&reader, &miscounted).unwrap_err(), CryptoError::Decrypt);

        // A count that matches the aad but not the entries (sealed under a forged count).
        let mut b = batch(&[entry(100)], &readers);
        let aad_two = batch_aad(&b.tenant, b.stream, b.sequence, b.first_entry, 2);
        b.count = 2;
        b.entries = forge(&aad_two, &[entry(100)], &readers);
        assert!(malformed(&b), "count mismatch");

        let mut b = batch(&[entry(100)], &readers);
        let mut other = entry(100);
        other.tenant = TenantId::new("other").unwrap();
        reseal(&mut b, &[other]);
        assert!(malformed(&b), "another tenant");

        let mut b = batch(&[entry(100)], &readers);
        reseal(&mut b, &[entry(99)]);
        assert!(malformed(&b), "before from");
    }

    /// `seal_entries`'s layout under an arbitrary aad.
    fn forge(aad: &[u8], entries: &[TelemetryEntry], readers: &[PublicKey]) -> TelemetryEntries {
        let key = Key32::generate(&mut rng());
        let ciphertext = Aes256Gcm::new(key.expose().into())
            .encrypt(&Nonce::from([0; 12]), Payload { msg: &canonical(&entries), aad })
            .unwrap();
        let readers = readers
            .iter()
            .map(|r| {
                let (enc, wrapped_key) =
                    crate::hpke::seal(r, TELEMETRY_READER_INFO, aad, key.expose(), &mut rng()).unwrap();
                wire::TelemetryReaderKey { reader: *r, enc, wrapped_key }
            })
            .collect();
        TelemetryEntries::Sealed { readers, nonce: [0; 12], ciphertext }
    }

    #[test]
    fn sealing_needs_usable_readers() {
        let e = [entry(1)];
        let seal = |readers: &[PublicKey]| seal_entries(&tenant(), [0; 16], 0, 0, &e, readers, &mut rng());
        assert!(matches!(seal(&[]), Err(CryptoError::Malformed(_))));
        assert!(matches!(seal(&[PublicKey([0; 32])]), Err(CryptoError::Malformed(_))), "low-order key");
    }
}
