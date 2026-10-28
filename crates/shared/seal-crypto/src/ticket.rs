//! Stateless proof tickets: any replica of a tenant and service key version can verify any
//! replica's ticket. `mac = HMAC-SHA256(key, canonical((tenant, value, expires_at)))`.
//! In those tuples `value` encodes as a CBOR array of 32 integers (a plain `[u8; 32]`).

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

use seal_proto::codec::canonical;
use seal_proto::freshness::{GuardianChallenge, ProofTicket, GUARDIAN_CHALLENGE_TTL_SECS, TICKET_TTL_SECS};
use seal_proto::{TenantId, TrustedTime, UnixTime};

use crate::{ChallengeKey, CryptoError, Key32, TicketKey};

fn mac(key: &Key32, msg: &[u8]) -> Hmac<Sha256> {
    let mut m = <Hmac<Sha256> as KeyInit>::new_from_slice(key.expose()).expect("HMAC takes any key length");
    m.update(msg);
    m
}

fn random32(rng: &mut impl rand::CryptoRng) -> [u8; 32] {
    let mut v = [0u8; 32];
    rng.fill_bytes(&mut v);
    v
}

fn check(key: &Key32, msg: &[u8], tag: &[u8; 32], expires_at: UnixTime, time: &TrustedTime) -> Result<(), CryptoError> {
    // Constant-time comparison (`Mac::verify_slice`), before the expiry check.
    let mac_ok = mac(key, msg).verify_slice(tag).is_ok();
    if mac_ok && time.latest() < expires_at {
        Ok(())
    } else {
        Err(CryptoError::InvalidTicket)
    }
}

impl TicketKey {
    fn message(tenant: &TenantId, value: &[u8; 32], expires_at: UnixTime) -> Vec<u8> {
        canonical(&(tenant, value, expires_at))
    }
    /// A new ticket for `tenant`, valid `TICKET_TTL_SECS` from `time.now`.
    pub fn issue(&self, tenant: &TenantId, time: &TrustedTime, rng: &mut impl rand::CryptoRng) -> ProofTicket {
        let value = random32(rng);
        let expires_at = time.now.saturating_add(TICKET_TTL_SECS);
        let mac = mac(&self.0, &Self::message(tenant, &value, expires_at)).finalize().into_bytes().into();
        ProofTicket { value, expires_at, mac }
    }
    /// MAC valid (constant time) and `time.latest() < expires_at`. Replay within the TTL is
    /// bounded by the proof's binding to purpose and blob, not prevented here.
    pub fn verify(&self, tenant: &TenantId, ticket: &ProofTicket, time: &TrustedTime) -> Result<(), CryptoError> {
        check(&self.0, &Self::message(tenant, &ticket.value, ticket.expires_at), &ticket.mac, ticket.expires_at, time)
    }
}

/// The guardian's challenges: `mac = HMAC-SHA256(key, canonical((value, expires_at)))`.
/// Any guardian instance of the platform verifies any instance's challenge.
impl ChallengeKey {
    fn message(value: &[u8; 32], expires_at: UnixTime) -> Vec<u8> {
        canonical(&(value, expires_at))
    }
    /// A new challenge valid `GUARDIAN_CHALLENGE_TTL_SECS` from `time.now`.
    pub fn issue(&self, time: &TrustedTime, rng: &mut impl rand::CryptoRng) -> GuardianChallenge {
        let value = random32(rng);
        let expires_at = time.now.saturating_add(GUARDIAN_CHALLENGE_TTL_SECS);
        let mac = mac(&self.0, &Self::message(&value, expires_at)).finalize().into_bytes().into();
        GuardianChallenge { value, expires_at, mac }
    }
    /// MAC valid (constant time) and `time.latest() < expires_at`.
    pub fn verify(&self, challenge: &GuardianChallenge, time: &TrustedTime) -> Result<(), CryptoError> {
        check(
            &self.0,
            &Self::message(&challenge.value, challenge.expires_at),
            &challenge.mac,
            challenge.expires_at,
            time,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rng() -> impl rand::CryptoRng {
        rand::rand_core::UnwrapErr(rand::rngs::SysRng)
    }
    fn tenant() -> TenantId {
        TenantId::new("acme").unwrap()
    }
    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    /// RFC 4231 test cases 1 and 2 (HMAC-SHA256).
    #[test]
    fn hmac_sha256_rfc4231() {
        let k = |b: &[u8]| <Hmac<Sha256> as KeyInit>::new_from_slice(b).unwrap();
        let mut m = k(&[0x0b; 20]);
        m.update(b"Hi There");
        assert_eq!(
            m.finalize().into_bytes().to_vec(),
            unhex("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")
        );
        let mut m = k(b"Jefe");
        m.update(b"what do ya want for nothing?");
        assert_eq!(
            m.finalize().into_bytes().to_vec(),
            unhex("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")
        );
        // Our 32-byte keys go through the same function.
        let key = Key32::from_bytes([0x0b; 32]);
        let mut m = k(&[0x0b; 32]);
        m.update(b"x");
        assert_eq!(mac(&key, b"x").finalize().into_bytes(), m.finalize().into_bytes());
    }

    #[test]
    fn tickets() {
        let key = TicketKey(Key32::from_bytes([1; 32]));
        let t0 = TrustedTime::exact(1_900_000_000);
        let ticket = key.issue(&tenant(), &t0, &mut rng());
        assert_eq!(ticket.expires_at, 1_900_000_000 + TICKET_TTL_SECS);
        key.verify(&tenant(), &ticket, &t0).unwrap();
        // Any replica with the same key verifies it.
        TicketKey(Key32::from_bytes([1; 32])).verify(&tenant(), &ticket, &t0).unwrap();

        let invalid = Err(CryptoError::InvalidTicket);
        assert_eq!(key.verify(&TenantId::new("bravo").unwrap(), &ticket, &t0), invalid);
        assert_eq!(TicketKey(Key32::from_bytes([2; 32])).verify(&tenant(), &ticket, &t0), invalid);
        for tamper in [
            |t: &mut ProofTicket| t.value[0] ^= 1,
            |t: &mut ProofTicket| t.mac[31] ^= 1,
            |t: &mut ProofTicket| t.expires_at += 1,
        ] {
            let mut t = ticket.clone();
            tamper(&mut t);
            assert_eq!(key.verify(&tenant(), &t, &t0), invalid);
        }
        // Expiry uses the latest possible time.
        let edge = ticket.expires_at;
        key.verify(&tenant(), &ticket, &TrustedTime::exact(edge - 1)).unwrap();
        assert_eq!(key.verify(&tenant(), &ticket, &TrustedTime::exact(edge)), invalid);
        assert_eq!(key.verify(&tenant(), &ticket, &TrustedTime { now: edge - 10, radius: 10 }), invalid);
        key.verify(&tenant(), &ticket, &TrustedTime { now: edge - 10, radius: 9 }).unwrap();
    }

    #[test]
    fn guardian_challenges() {
        let key = ChallengeKey(Key32::from_bytes([3; 32]));
        let t0 = TrustedTime::exact(1_900_000_000);
        let c = key.issue(&t0, &mut rng());
        assert_eq!(c.expires_at, 1_900_000_000 + GUARDIAN_CHALLENGE_TTL_SECS);
        key.verify(&c, &t0).unwrap();
        assert_ne!(c.value, key.issue(&t0, &mut rng()).value);
        let invalid = Err(CryptoError::InvalidTicket);
        assert_eq!(ChallengeKey(Key32::from_bytes([4; 32])).verify(&c, &t0), invalid);
        let mut t = c.clone();
        t.value[5] ^= 1;
        assert_eq!(key.verify(&t, &t0), invalid);
        let mut t = c.clone();
        t.expires_at -= 1;
        assert_eq!(key.verify(&t, &t0), invalid);
        assert_eq!(key.verify(&c, &TrustedTime::exact(c.expires_at)), invalid);
        assert_eq!(key.verify(&c, &TrustedTime { now: c.expires_at - 1, radius: 1 }), invalid);
        // A ticket MAC is never a challenge MAC: the messages differ in shape.
        let tk = TicketKey(Key32::from_bytes([3; 32]));
        let ticket = tk.issue(&tenant(), &t0, &mut rng());
        let as_challenge = GuardianChallenge { value: ticket.value, expires_at: ticket.expires_at, mac: ticket.mac };
        assert_eq!(key.verify(&as_challenge, &t0), invalid);
    }
}
