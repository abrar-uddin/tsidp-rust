//! RS256 signing key management.
//!
//! The on-disk format is identical to the Go tsidp's `oidc-key.json`:
//! `{"kid": <u64>, "key": "-----BEGIN RSA PRIVATE KEY-----..."}` so a
//! migrated deployment keeps its JWKS and existing tokens stay verifiable.

use jsonwebtoken::{Algorithm, EncodingKey, Header};
use pkcs1::{DecodeRsaPrivateKey, EncodeRsaPrivateKey, LineEnding};
use rsa::RsaPrivateKey;
use rsa::traits::PublicKeyParts;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use crate::util::{b64url, random_u64};

#[derive(Serialize, Deserialize)]
struct KeyFile {
    kid: u64,
    key: String,
}

#[derive(Clone)]
pub struct SigningKey {
    pub kid: u64,
    private_pem: String,
    encoding: EncodingKey,
    n_b64: String,
    e_b64: String,
}

impl std::fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SigningKey")
            .field("kid", &self.kid)
            .finish_non_exhaustive()
    }
}

impl SigningKey {
    pub fn generate() -> anyhow::Result<Self> {
        let mut rng = rand::thread_rng();
        let key = RsaPrivateKey::new(&mut rng, 2048)?;
        Self::from_private(random_u64(), key)
    }

    fn from_private(kid: u64, key: RsaPrivateKey) -> anyhow::Result<Self> {
        let pem = key.to_pkcs1_pem(LineEnding::LF)?.to_string();
        let encoding = EncodingKey::from_rsa_pem(pem.as_bytes())?;
        let public = key.to_public_key();
        Ok(SigningKey {
            kid,
            n_b64: b64url(&public.n().to_bytes_be()),
            e_b64: b64url(&public.e().to_bytes_be()),
            private_pem: pem,
            encoding,
        })
    }

    pub fn from_json(bytes: &[u8]) -> anyhow::Result<Self> {
        let f: KeyFile = serde_json::from_slice(bytes)?;
        let key = RsaPrivateKey::from_pkcs1_pem(&f.key)?;
        Self::from_private(f.kid, key)
    }

    pub fn to_json(&self) -> anyhow::Result<Vec<u8>> {
        Ok(serde_json::to_vec(&KeyFile {
            kid: self.kid,
            key: self.private_pem.clone(),
        })?)
    }

    pub fn kid_string(&self) -> String {
        self.kid.to_string()
    }

    /// The public JWK for the JWKS endpoint.
    pub fn jwk(&self) -> Value {
        json!({
            "use": "sig",
            "kty": "RSA",
            "kid": self.kid_string(),
            "alg": "RS256",
            "n": self.n_b64,
            "e": self.e_b64,
        })
    }

    /// Base64url modulus and exponent, handy for building a `DecodingKey` in tests.
    pub fn public_components(&self) -> (&str, &str) {
        (&self.n_b64, &self.e_b64)
    }

    /// Sign a claim set as a compact JWS. `typ` is `JWT` for ID tokens and
    /// `at+jwt` (RFC 9068) for JWT access tokens.
    pub fn sign(&self, claims: &Map<String, Value>, typ: &str) -> anyhow::Result<String> {
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(self.kid_string());
        header.typ = Some(typ.to_string());
        Ok(jsonwebtoken::encode(&header, claims, &self.encoding)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{DecodingKey, Validation};

    #[test]
    fn roundtrip_json_and_sign() {
        let k = SigningKey::generate().unwrap();
        let bytes = k.to_json().unwrap();
        let k2 = SigningKey::from_json(&bytes).unwrap();
        assert_eq!(k.kid, k2.kid);
        assert_eq!(k.jwk(), k2.jwk());

        let mut claims = Map::new();
        claims.insert("sub".into(), json!("userid:1"));
        claims.insert("iss".into(), json!("https://idp.example.ts.net"));
        claims.insert("aud".into(), json!(["client"]));
        claims.insert("exp".into(), json!(crate::util::now_unix() + 60));
        let tok = k.sign(&claims, "JWT").unwrap();

        let (n, e) = k2.public_components();
        let dk = DecodingKey::from_rsa_components(n, e).unwrap();
        let mut v = Validation::new(Algorithm::RS256);
        v.set_audience(&["client"]);
        v.set_issuer(&["https://idp.example.ts.net"]);
        let data = jsonwebtoken::decode::<Map<String, Value>>(&tok, &dk, &v).unwrap();
        assert_eq!(data.claims["sub"], json!("userid:1"));
        assert_eq!(data.header.kid.as_deref(), Some(k.kid_string().as_str()));
    }

    #[test]
    fn reads_go_format() {
        // A Go-written file: kid as a JSON number and a PKCS#1 PEM.
        let k = SigningKey::generate().unwrap();
        let v: Value = serde_json::from_slice(&k.to_json().unwrap()).unwrap();
        assert!(v["kid"].is_u64());
        assert!(
            v["key"]
                .as_str()
                .unwrap()
                .starts_with("-----BEGIN RSA PRIVATE KEY-----")
        );
    }
}
