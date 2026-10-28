//! JWS verification (RFC 7515 compact serialization) for OIDC ID tokens: RS256 and ES256 only.
//!
//! The caller fixes the algorithm per issuer and passes it in; a token whose `alg` header
//! differs is refused, and a key verifies only the algorithm of its own type (RSA → RS256,
//! P-256 → ES256), so algorithm confusion is ruled out by construction. Further rules:
//! - exactly three base64url parts without padding; a header that is a JSON object;
//! - the header's `kid` equals the key's `kid` (both absent counts as equal);
//! - `typ`, when present, is `JWT` (case-insensitive, with or without `application/`);
//! - a `crit` header is refused: no extension is understood;
//! - RS256 keys have a modulus of at least 2048 bits, and the signature is exactly as long as
//!   the modulus; ES256 signatures are `R || S`, 64 bytes.
//!
//! Only signatures are checked here. Claims (`iss`, `aud`, `exp`, …) are the caller's.

use p256::ecdsa::signature::Verifier as _;
use rsa::traits::PublicKeyParts as _;
use serde::Deserialize;

use seal_proto::codec::from_b64url;

use crate::CryptoError;

/// Longest token accepted, in bytes.
pub const MAX_TOKEN_LEN: usize = 16 * 1024;
/// Smallest RSA modulus accepted, in bits.
pub const MIN_RSA_BITS: usize = 2048;

/// The two signature algorithms Seal verifies.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum JwsAlg {
    /// RSASSA-PKCS1-v1_5 with SHA-256.
    Rs256,
    /// ECDSA on P-256 with SHA-256.
    Es256,
}

impl JwsAlg {
    /// The `alg` header value.
    pub fn name(self) -> &'static str {
        match self {
            JwsAlg::Rs256 => "RS256",
            JwsAlg::Es256 => "ES256",
        }
    }
}

#[derive(Clone, Debug)]
enum PublicJwk {
    Rsa(rsa::RsaPublicKey),
    P256(p256::ecdsa::VerifyingKey),
}

/// A public verification key, as a JWK set carries it.
#[derive(Clone, Debug)]
pub struct Jwk {
    kid: Option<String>,
    key: PublicJwk,
}

fn malformed(what: &str) -> CryptoError {
    CryptoError::Malformed(format!("jwk: {what}"))
}

fn b64(field: &str, value: &str) -> Result<Vec<u8>, CryptoError> {
    from_b64url(value).map_err(|_| malformed(&format!("{field} is not base64url")))
}

/// The JWK members this module reads; others are ignored.
#[derive(Deserialize)]
struct RawJwk {
    kty: String,
    kid: Option<String>,
    #[serde(rename = "use")]
    use_: Option<String>,
    alg: Option<String>,
    crv: Option<String>,
    n: Option<String>,
    e: Option<String>,
    x: Option<String>,
    y: Option<String>,
}

impl Jwk {
    /// An RSA key from its big-endian modulus and exponent.
    pub fn rsa(kid: Option<String>, n: &[u8], e: &[u8]) -> Result<Self, CryptoError> {
        let strip = |b: &[u8]| -> Vec<u8> {
            let start = b.iter().position(|&x| x != 0).unwrap_or(b.len());
            b[start..].to_vec()
        };
        let (n, e) = (strip(n), strip(e));
        if n.is_empty() || e.is_empty() {
            return Err(malformed("empty RSA component"));
        }
        let uint = |b: &[u8]| {
            let bits = u32::try_from(b.len() * 8).map_err(|_| malformed("RSA component too large"))?;
            rsa::BoxedUint::from_be_slice(b, bits).map_err(|_| malformed("RSA component"))
        };
        let key = rsa::RsaPublicKey::new(uint(&n)?, uint(&e)?).map_err(|_| malformed("invalid RSA key"))?;
        if (key.n().bits() as usize) < MIN_RSA_BITS {
            return Err(malformed("RSA modulus below 2048 bits"));
        }
        Ok(Self { kid, key: PublicJwk::Rsa(key) })
    }

    /// A P-256 key from its affine coordinates.
    pub fn p256(kid: Option<String>, x: &[u8], y: &[u8]) -> Result<Self, CryptoError> {
        if x.len() != 32 || y.len() != 32 {
            return Err(malformed("P-256 coordinates must be 32 bytes"));
        }
        let sec1 = [&[0x04][..], x, y].concat();
        let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(&sec1).map_err(|_| malformed("invalid P-256 point"))?;
        Ok(Self { kid, key: PublicJwk::P256(key) })
    }

    /// One member of a JWK set. Errors on keys this module cannot use: other key types or
    /// curves, `use` other than `sig`, or an `alg` that disagrees with the key type.
    pub fn from_json(value: &serde_json::Value) -> Result<Self, CryptoError> {
        let raw: RawJwk = serde_json::from_value(value.clone()).map_err(|_| malformed("not a JWK"))?;
        if raw.use_.as_deref().is_some_and(|u| u != "sig") {
            return Err(malformed("not a signing key"));
        }
        let jwk = match (raw.kty.as_str(), raw.n, raw.e, raw.crv.as_deref(), raw.x, raw.y) {
            ("RSA", Some(n), Some(e), _, _, _) => Self::rsa(raw.kid, &b64("n", &n)?, &b64("e", &e)?)?,
            ("EC", _, _, Some("P-256"), Some(x), Some(y)) => Self::p256(raw.kid, &b64("x", &x)?, &b64("y", &y)?)?,
            _ => return Err(malformed("unsupported key type")),
        };
        if raw.alg.as_deref().is_some_and(|a| a != jwk.alg().name()) {
            return Err(malformed("alg disagrees with the key type"));
        }
        Ok(jwk)
    }

    pub fn kid(&self) -> Option<&str> {
        self.kid.as_deref()
    }

    /// The only algorithm this key verifies.
    pub fn alg(&self) -> JwsAlg {
        match self.key {
            PublicJwk::Rsa(_) => JwsAlg::Rs256,
            PublicJwk::P256(_) => JwsAlg::Es256,
        }
    }
}

/// The usable keys of a JWK set document (`{"keys": [...]}`). Keys this module cannot use
/// are skipped, so an issuer that also publishes, say, encryption keys still works.
#[derive(Clone, Debug, Default)]
pub struct JwkSet {
    keys: Vec<Jwk>,
}

impl JwkSet {
    pub fn from_json(bytes: &[u8]) -> Result<Self, CryptoError> {
        #[derive(Deserialize)]
        struct Doc {
            keys: Vec<serde_json::Value>,
        }
        let doc: Doc = serde_json::from_slice(bytes).map_err(|_| malformed("not a JWK set"))?;
        Ok(Self { keys: doc.keys.iter().filter_map(|k| Jwk::from_json(k).ok()).collect() })
    }

    pub fn keys(&self) -> &[Jwk] {
        &self.keys
    }

    /// The key a token names: by `kid`, or the only key of the set when the token names none.
    pub fn find(&self, kid: Option<&str>) -> Option<&Jwk> {
        match kid {
            Some(kid) => {
                let mut matching = self.keys.iter().filter(|k| k.kid() == Some(kid));
                let key = matching.next()?;
                // Two keys under one kid: refuse to guess.
                matching.next().is_none().then_some(key)
            }
            None => match self.keys.as_slice() {
                [only] if only.kid.is_none() => Some(only),
                _ => None,
            },
        }
    }
}

/// The protected header members this module reads.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub struct JwsHeader {
    pub alg: String,
    pub kid: Option<String>,
    pub typ: Option<String>,
    #[serde(default)]
    crit: Option<serde_json::Value>,
}

struct Parts<'t> {
    header: JwsHeader,
    signing_input: &'t str,
    payload: &'t str,
    signature: Vec<u8>,
}

fn split(token: &str) -> Result<Parts<'_>, CryptoError> {
    let bad = |what: &str| CryptoError::Malformed(format!("jws: {what}"));
    if token.len() > MAX_TOKEN_LEN {
        return Err(bad("token too long"));
    }
    let mut parts = token.split('.');
    let (Some(header), Some(payload), Some(signature), None) = (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(bad("expected three parts"));
    };
    let header_json = from_b64url(header).map_err(|_| bad("header is not base64url"))?;
    let header: JwsHeader = serde_json::from_slice(&header_json).map_err(|_| bad("header is not a JSON object"))?;
    let signature = from_b64url(signature).map_err(|_| bad("signature is not base64url"))?;
    let signing_input = &token[..token.rfind('.').expect("three parts")];
    Ok(Parts { header, signing_input, payload, signature })
}

/// The token's protected header, unverified: for choosing the key only.
pub fn peek_header(token: &str) -> Result<JwsHeader, CryptoError> {
    split(token).map(|p| p.header)
}

/// The token's payload, unverified: for routing (which issuer) only, never for decisions.
pub fn peek_payload(token: &str) -> Result<Vec<u8>, CryptoError> {
    let parts = split(token)?;
    from_b64url(parts.payload).map_err(|_| CryptoError::Malformed("jws: payload is not base64url".into()))
}

/// Verifies `token` with `key` under exactly `alg` (the module rules above) and returns the
/// payload bytes. `BadSignature` for a wrong algorithm, key id, type or signature.
pub fn verify(token: &str, key: &Jwk, alg: JwsAlg) -> Result<Vec<u8>, CryptoError> {
    let parts = split(token)?;
    let h = &parts.header;
    if h.alg != alg.name() || key.alg() != alg || h.kid != key.kid || h.crit.is_some() {
        return Err(CryptoError::BadSignature);
    }
    if let Some(typ) = &h.typ {
        let typ = typ.to_ascii_lowercase();
        if typ != "jwt" && typ != "application/jwt" {
            return Err(CryptoError::BadSignature);
        }
    }
    let input = parts.signing_input.as_bytes();
    match &key.key {
        PublicJwk::Rsa(rsa_key) => {
            if parts.signature.len() != rsa_key.size() {
                return Err(CryptoError::BadSignature);
            }
            let sig = rsa::pkcs1v15::Signature::try_from(parts.signature.as_slice())
                .map_err(|_| CryptoError::BadSignature)?;
            rsa::pkcs1v15::VerifyingKey::<sha2::Sha256>::new(rsa_key.clone())
                .verify(input, &sig)
                .map_err(|_| CryptoError::BadSignature)?;
        }
        PublicJwk::P256(ec_key) => {
            let sig = p256::ecdsa::Signature::from_slice(&parts.signature).map_err(|_| CryptoError::BadSignature)?;
            ec_key.verify(input, &sig).map_err(|_| CryptoError::BadSignature)?;
        }
    }
    from_b64url(parts.payload).map_err(|_| CryptoError::Malformed("jws: payload is not base64url".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use seal_proto::codec::b64url;

    // RFC 7515 Appendix A.2: the RSA key (n, e) and the complete RS256 JWS.
    const A2_N: &str = "ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSHSXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ";
    const A2_D: &str = "Eq5xpGnNCivDflJsRQBXHx1hdR1k6Ulwe2JZD50LpXyWPEAeP88vLNO97IjlA7_GQ5sLKMgvfTeXZx9SE-7YwVol2NXOoAJe46sui395IW_GO-pWJ1O0BkTGoVEn2bKVRUCgu-GjBVaYLU6f3l9kJfFNS3E0QbVdxzubSu3Mkqzjkn439X0M_V51gfpRLI9JYanrC4D4qAdGcopV_0ZHHzQlBjudU2QvXt4ehNYTCBr6XCLQUShb1juUO1ZdiYoFaFQT5Tw8bGUl_x_jTj3ccPDVZFD9pIuhLhBOneufuBiB4cS98l2SR_RQyGWSeWjnczT0QU91p1DhOVRuOopznQ";
    const A2_P: &str = "4BzEEOtIpmVdVEZNCqS7baC4crd0pqnRH_5IB3jw3bcxGn6QLvnEtfdUdiYrqBdss1l58BQ3KhooKeQTa9AB0Hw_Py5PJdTJNPY8cQn7ouZ2KKDcmnPGBY5t7yLc1QlQ5xHdwW1VhvKn-nXqhJTBgIPgtldC-KDV5z-y2XDwGUc";
    const A2_Q: &str = "uQPEfgmVtjL0Uyyx88GZFF1fOunH3-7cepKmtH4pxhtCoHqpWmT8YAmZxaewHgHAjLYsp1ZSe7zFYHj7C6ul7TjeLQeZD_YwD66t62wDmpe_HlB-TnBA-njbglfIsRLtXlnDzQkv5dTltRJ11BKBBypeeF6689rjcJIDEz9RWdc";
    const A2_JWS: &str = concat!(
        "eyJhbGciOiJSUzI1NiJ9",
        ".",
        "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt",
        "cGxlLmNvbS9pc19yb290Ijp0cnVlfQ",
        ".",
        "cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7",
        "AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4",
        "BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K",
        "0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqv",
        "hJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrB",
        "p0igcN_IoypGlUPQGe77Rw",
    );
    // RFC 7515 Appendix A.3: the P-256 key (x, y, d) and the complete ES256 JWS.
    const A3_X: &str = "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU";
    const A3_Y: &str = "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0";
    const A3_D: &str = "jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI";
    const A3_JWS: &str = concat!(
        "eyJhbGciOiJFUzI1NiJ9",
        ".",
        "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt",
        "cGxlLmNvbS9pc19yb290Ijp0cnVlfQ",
        ".",
        "DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSA",
        "pmWQxfKTUJqPP3-Kg6NU1Q",
    );
    const PAYLOAD: &[u8] = b"{\"iss\":\"joe\",\r\n \"exp\":1300819380,\r\n \"http://example.com/is_root\":true}";

    fn d(s: &str) -> Vec<u8> {
        from_b64url(s).unwrap()
    }
    fn rsa_key(kid: Option<&str>) -> Jwk {
        Jwk::rsa(kid.map(Into::into), &d(A2_N), &d("AQAB")).unwrap()
    }
    fn ec_key(kid: Option<&str>) -> Jwk {
        Jwk::p256(kid.map(Into::into), &d(A3_X), &d(A3_Y)).unwrap()
    }
    fn rsa_signer() -> rsa::pkcs1v15::SigningKey<sha2::Sha256> {
        let uint = |s: &str| rsa::BoxedUint::from_be_slice(&d(s), 2048).unwrap();
        let key =
            rsa::RsaPrivateKey::from_components(uint(A2_N), uint("AQAB"), uint(A2_D), vec![uint(A2_P), uint(A2_Q)])
                .unwrap();
        rsa::pkcs1v15::SigningKey::new(key)
    }
    fn ec_signer() -> p256::ecdsa::SigningKey {
        p256::ecdsa::SigningKey::from_slice(&d(A3_D)).unwrap()
    }
    /// A token over `header` and `payload`, signed with the RFC keys.
    fn token(header: &str, payload: &[u8], alg: JwsAlg) -> String {
        use p256::ecdsa::signature::Signer as _;
        let input = format!("{}.{}", b64url(header.as_bytes()), b64url(payload));
        let sig = match alg {
            JwsAlg::Rs256 => Box::<[u8]>::from(rsa_signer().sign(input.as_bytes())).to_vec(),
            JwsAlg::Es256 => {
                let s: p256::ecdsa::Signature = ec_signer().sign(input.as_bytes());
                s.to_bytes().to_vec()
            }
        };
        format!("{input}.{}", b64url(&sig))
    }

    #[test]
    fn rfc7515_a2_rs256() {
        assert_eq!(verify(A2_JWS, &rsa_key(None), JwsAlg::Rs256).unwrap(), PAYLOAD);
        // Our signer reproduces the RFC's deterministic signature exactly.
        assert_eq!(token("{\"alg\":\"RS256\"}", PAYLOAD, JwsAlg::Rs256), A2_JWS);
    }

    #[test]
    fn rfc7515_a3_es256() {
        assert_eq!(verify(A3_JWS, &ec_key(None), JwsAlg::Es256).unwrap(), PAYLOAD);
    }

    #[test]
    fn tampering_is_refused() {
        let flip = |s: &str, i: usize| {
            let mut b = s.as_bytes().to_vec();
            b[i] = if b[i] == b'A' { b'B' } else { b'A' };
            String::from_utf8(b).unwrap()
        };
        // A payload byte, a signature byte.
        for t in [flip(A2_JWS, 30), flip(A2_JWS, A2_JWS.len() - 5)] {
            assert!(verify(&t, &rsa_key(None), JwsAlg::Rs256).is_err());
        }
        for t in [flip(A3_JWS, 30), flip(A3_JWS, A3_JWS.len() - 5)] {
            assert!(verify(&t, &ec_key(None), JwsAlg::Es256).is_err());
        }
        // Structure.
        for t in ["", "a.b", "a.b.c.d", &format!("{A2_JWS}="), &format!("{A2_JWS}.")] {
            assert!(verify(t, &rsa_key(None), JwsAlg::Rs256).is_err(), "{t}");
        }
    }

    #[test]
    fn wrong_alg_is_refused() {
        let bad = Err(CryptoError::BadSignature);
        // The caller's fixed algorithm wins over the header and the key.
        assert_eq!(verify(A2_JWS, &rsa_key(None), JwsAlg::Es256), bad);
        assert_eq!(verify(A3_JWS, &ec_key(None), JwsAlg::Rs256), bad);
        // A key verifies only its own algorithm.
        assert_eq!(verify(A3_JWS, &rsa_key(None), JwsAlg::Es256), bad);
        assert_eq!(verify(A2_JWS, &ec_key(None), JwsAlg::Rs256), bad);
        // `none`, HS256 and case variants never pass.
        for alg in ["none", "HS256", "rs256", "PS256"] {
            let header = format!("{{\"alg\":\"{alg}\"}}");
            let t = format!("{}.{}.{}", b64url(header.as_bytes()), b64url(PAYLOAD), A2_JWS.rsplit('.').next().unwrap());
            assert_eq!(verify(&t, &rsa_key(None), JwsAlg::Rs256), bad, "{alg}");
            let unsigned = format!("{}.{}.", b64url(header.as_bytes()), b64url(PAYLOAD));
            assert!(verify(&unsigned, &rsa_key(None), JwsAlg::Rs256).is_err(), "{alg}");
        }
    }

    #[test]
    fn wrong_kid_is_refused() {
        let bad = Err(CryptoError::BadSignature);
        let t = token("{\"alg\":\"RS256\",\"kid\":\"k1\"}", PAYLOAD, JwsAlg::Rs256);
        assert_eq!(verify(&t, &rsa_key(Some("k1")), JwsAlg::Rs256).unwrap(), PAYLOAD);
        assert_eq!(verify(&t, &rsa_key(Some("k2")), JwsAlg::Rs256), bad);
        assert_eq!(verify(&t, &rsa_key(None), JwsAlg::Rs256), bad);
        // A key with a kid does not verify a token that names none.
        assert_eq!(verify(A2_JWS, &rsa_key(Some("k1")), JwsAlg::Rs256), bad);
        let t = token("{\"alg\":\"ES256\",\"kid\":\"e1\"}", PAYLOAD, JwsAlg::Es256);
        assert_eq!(verify(&t, &ec_key(Some("e1")), JwsAlg::Es256).unwrap(), PAYLOAD);
        assert_eq!(verify(&t, &ec_key(Some("e2")), JwsAlg::Es256), bad);
    }

    #[test]
    fn typ_and_crit() {
        for typ in ["JWT", "jwt", "application/jwt"] {
            let t = token(&format!("{{\"alg\":\"RS256\",\"typ\":\"{typ}\"}}"), PAYLOAD, JwsAlg::Rs256);
            assert!(verify(&t, &rsa_key(None), JwsAlg::Rs256).is_ok(), "{typ}");
        }
        for typ in ["at+jwt", "JOSE", "secevent+jwt", ""] {
            let t = token(&format!("{{\"alg\":\"RS256\",\"typ\":\"{typ}\"}}"), PAYLOAD, JwsAlg::Rs256);
            assert_eq!(verify(&t, &rsa_key(None), JwsAlg::Rs256), Err(CryptoError::BadSignature), "{typ}");
        }
        let t = token("{\"alg\":\"RS256\",\"crit\":[\"exp\"],\"exp\":1}", PAYLOAD, JwsAlg::Rs256);
        assert_eq!(verify(&t, &rsa_key(None), JwsAlg::Rs256), Err(CryptoError::BadSignature));
        // A duplicated header member is malformed, not first- or last-wins.
        let t = token("{\"alg\":\"RS256\",\"alg\":\"RS256\"}", PAYLOAD, JwsAlg::Rs256);
        assert!(matches!(verify(&t, &rsa_key(None), JwsAlg::Rs256), Err(CryptoError::Malformed(_))));
        // The header must be an object.
        let t = token("[\"RS256\"]", PAYLOAD, JwsAlg::Rs256);
        assert!(matches!(verify(&t, &rsa_key(None), JwsAlg::Rs256), Err(CryptoError::Malformed(_))));
    }

    #[test]
    fn jwk_sets() {
        let doc = serde_json::json!({"keys": [
            {"kty": "RSA", "kid": "r", "use": "sig", "alg": "RS256", "n": A2_N, "e": "AQAB"},
            {"kty": "EC", "kid": "e", "crv": "P-256", "x": A3_X, "y": A3_Y},
            {"kty": "RSA", "kid": "enc", "use": "enc", "n": A2_N, "e": "AQAB"},
            {"kty": "RSA", "kid": "mislabelled", "alg": "ES256", "n": A2_N, "e": "AQAB"},
            {"kty": "EC", "kid": "p384", "crv": "P-384", "x": A3_X, "y": A3_Y},
            {"kty": "oct", "kid": "hmac", "k": "AAAA"},
            {"kty": "RSA", "kid": "short", "n": "AQAB", "e": "AQAB"},
            {"kty": "RSA", "kid": "dup", "n": A2_N, "e": "AQAB"},
            {"kty": "EC", "kid": "dup", "crv": "P-256", "x": A3_X, "y": A3_Y},
        ]});
        let set = JwkSet::from_json(doc.to_string().as_bytes()).unwrap();
        let kids: Vec<_> = set.keys().iter().map(|k| k.kid().unwrap()).collect();
        assert_eq!(kids, ["r", "e", "dup", "dup"]);
        assert_eq!(set.find(Some("r")).unwrap().alg(), JwsAlg::Rs256);
        assert_eq!(set.find(Some("e")).unwrap().alg(), JwsAlg::Es256);
        assert!(set.find(Some("enc")).is_none());
        assert!(set.find(Some("dup")).is_none());
        assert!(set.find(None).is_none());
        let one =
            JwkSet::from_json(format!("{{\"keys\":[{{\"kty\":\"RSA\",\"n\":\"{A2_N}\",\"e\":\"AQAB\"}}]}}").as_bytes())
                .unwrap();
        assert!(verify(A2_JWS, one.find(None).unwrap(), JwsAlg::Rs256).is_ok());
        assert!(JwkSet::from_json(b"[]").is_err());
        // An off-curve point is refused.
        let mut y = d(A3_Y);
        y[31] ^= 1;
        assert!(Jwk::p256(None, &d(A3_X), &y).is_err());
    }

    #[test]
    fn peeking_does_not_verify() {
        let t = token("{\"alg\":\"RS256\",\"kid\":\"k1\",\"typ\":\"JWT\"}", PAYLOAD, JwsAlg::Rs256);
        let h = peek_header(&t).unwrap();
        assert_eq!((h.alg.as_str(), h.kid.as_deref(), h.typ.as_deref()), ("RS256", Some("k1"), Some("JWT")));
        assert_eq!(peek_payload(&t).unwrap(), PAYLOAD);
    }
}
