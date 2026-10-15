//! In-memory store for authorization codes, access tokens and refresh tokens.
//!
//! Everything here is keyed by the random token string. Codes expire after
//! `code_ttl` (the Go implementation never set an expiry and its cleanup task
//! deleted every pending code, issue #193), access tokens after
//! `access_token_ttl` and refresh tokens after `refresh_token_ttl`.

use parking_lot::Mutex;
use serde::Serialize;
use std::collections::HashMap;
use std::sync::Arc;

use crate::clients::Client;
use crate::identity::Identity;
use crate::util::now_unix;

/// RFC 8693 §4.1 `act` claim.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct ActorClaim {
    pub sub: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub client_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub act: Option<Box<ActorClaim>>,
}

/// Everything we know about a grant, shared by the code, the access token
/// and the refresh token derived from it.
#[derive(Debug, Clone)]
pub struct AuthRequest {
    /// Random id shared by every code, access token and refresh token that
    /// descends from one authorization (RFC 6819 §5.2.2.3 refresh token
    /// rotation with reuse detection: a replayed refresh token revokes the
    /// whole family).
    pub family: String,
    pub client_id: String,
    /// Snapshot of the client at authorization time (secret, auth method).
    pub client: Option<Arc<Client>>,
    pub nonce: String,
    pub redirect_uri: String,
    pub scopes: Vec<String>,
    /// RFC 8707 resource indicators granted.
    pub resources: Vec<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub identity: Arc<Identity>,
    /// Unix seconds.
    pub valid_till: i64,
    pub issued_at: i64,
    pub not_before: i64,
    pub jti: String,
    /// Issuer the tokens were minted with (set at issuance; empty for codes).
    pub issuer: String,
    pub is_exchanged: bool,
    pub original_client_id: String,
    pub exchanged_by: String,
    pub audiences: Vec<String>,
    pub actor: Option<ActorClaim>,
}

impl AuthRequest {
    pub fn is_expired(&self, now: i64) -> bool {
        now >= self.valid_till
    }
}

#[derive(Default)]
struct Inner {
    codes: HashMap<String, AuthRequest>,
    access: HashMap<String, Arc<AuthRequest>>,
    refresh: HashMap<String, Arc<AuthRequest>>,
    /// Refresh tokens already redeemed: token -> (family, original expiry).
    /// Kept until the original token would have expired so a replay can be
    /// told apart from a token that never existed.
    used_refresh: HashMap<String, (String, i64)>,
}

#[derive(Default)]
pub struct TokenStore {
    inner: Mutex<Inner>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefreshError {
    /// Unknown or expired.
    Invalid,
    /// Already redeemed once; the family has been revoked.
    Reused,
}

fn revoke_family_locked(g: &mut Inner, family: &str) -> usize {
    let before = g.codes.len() + g.access.len() + g.refresh.len();
    g.codes.retain(|_, ar| ar.family != family);
    g.access.retain(|_, ar| ar.family != family);
    g.refresh.retain(|_, ar| ar.family != family);
    before - (g.codes.len() + g.access.len() + g.refresh.len())
}

impl TokenStore {
    pub fn put_code(&self, code: String, ar: AuthRequest) {
        self.inner.lock().codes.insert(code, ar);
    }

    /// Redeem a code: it is removed whether or not it is still valid.
    pub fn take_code(&self, code: &str) -> Option<AuthRequest> {
        let ar = self.inner.lock().codes.remove(code)?;
        if ar.is_expired(now_unix()) {
            return None;
        }
        Some(ar)
    }

    pub fn put_access(&self, token: String, ar: Arc<AuthRequest>) {
        self.inner.lock().access.insert(token, ar);
    }

    pub fn put_refresh(&self, token: String, ar: Arc<AuthRequest>) {
        self.inner.lock().refresh.insert(token, ar);
    }

    /// Look up an access token, dropping it if expired.
    pub fn get_access(&self, token: &str) -> Option<Arc<AuthRequest>> {
        let mut g = self.inner.lock();
        let ar = g.access.get(token)?.clone();
        if ar.is_expired(now_unix()) {
            g.access.remove(token);
            return None;
        }
        Some(ar)
    }

    /// Refresh tokens are single use: taken on first use whether valid or not.
    /// Presenting one a second time is treated as theft: every token in the
    /// same family is revoked and `Err(RefreshReuse)` is returned.
    pub fn take_refresh(&self, token: &str) -> Result<Arc<AuthRequest>, RefreshError> {
        let mut g = self.inner.lock();
        let now = now_unix();
        match g.refresh.remove(token) {
            Some(ar) => {
                g.used_refresh
                    .insert(token.to_string(), (ar.family.clone(), ar.valid_till));
                if ar.is_expired(now) {
                    Err(RefreshError::Invalid)
                } else {
                    Ok(ar)
                }
            }
            None => match g.used_refresh.remove(token) {
                Some((family, exp)) if exp > now => {
                    let n = revoke_family_locked(&mut g, &family);
                    tracing::warn!(
                        family,
                        revoked = n,
                        "refresh token replayed; revoked every token derived from the same authorization"
                    );
                    Err(RefreshError::Reused)
                }
                _ => Err(RefreshError::Invalid),
            },
        }
    }

    /// Drop everything issued to a client (used when the client is deleted).
    pub fn revoke_client(&self, client_id: &str) {
        let mut g = self.inner.lock();
        g.codes.retain(|_, ar| ar.client_id != client_id);
        g.access.retain(|_, ar| ar.client_id != client_id);
        g.refresh.retain(|_, ar| ar.client_id != client_id);
    }

    /// Remove expired entries. Returns how many were dropped.
    pub fn cleanup(&self) -> usize {
        let now = now_unix();
        let mut g = self.inner.lock();
        let before = g.codes.len() + g.access.len() + g.refresh.len() + g.used_refresh.len();
        g.codes.retain(|_, ar| !ar.is_expired(now));
        g.access.retain(|_, ar| !ar.is_expired(now));
        g.refresh.retain(|_, ar| !ar.is_expired(now));
        g.used_refresh.retain(|_, (_, exp)| *exp > now);
        before - (g.codes.len() + g.access.len() + g.refresh.len() + g.used_refresh.len())
    }

    pub fn counts(&self) -> (usize, usize, usize) {
        let g = self.inner.lock();
        (g.codes.len(), g.access.len(), g.refresh.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(super) fn ar(valid_till: i64) -> AuthRequest {
        AuthRequest {
            family: "fam".into(),
            client_id: "c".into(),
            client: None,
            nonce: String::new(),
            redirect_uri: String::new(),
            scopes: vec![],
            resources: vec![],
            code_challenge: None,
            code_challenge_method: None,
            identity: Arc::new(Identity::dev("a@b")),
            valid_till,
            issued_at: 0,
            not_before: 0,
            jti: String::new(),
            issuer: String::new(),
            is_exchanged: false,
            original_client_id: String::new(),
            exchanged_by: String::new(),
            audiences: vec![],
            actor: None,
        }
    }

    #[test]
    fn codes_are_single_use_and_expire() {
        let s = TokenStore::default();
        s.put_code("live".into(), ar(now_unix() + 300));
        s.put_code("dead".into(), ar(now_unix() - 1));
        assert!(s.take_code("dead").is_none());
        assert!(s.take_code("live").is_some());
        assert!(s.take_code("live").is_none());
    }

    #[test]
    fn cleanup_keeps_fresh_codes() {
        let s = TokenStore::default();
        s.put_code("fresh".into(), ar(now_unix() + 300));
        s.put_access("old".into(), Arc::new(ar(now_unix() - 5)));
        assert_eq!(s.cleanup(), 1);
        assert_eq!(s.counts(), (1, 0, 0));
    }

    #[test]
    fn refresh_single_use_and_reuse_revokes_family() {
        let s = TokenStore::default();
        s.put_refresh("r".into(), Arc::new(ar(now_unix() + 300)));
        s.put_access("a".into(), Arc::new(ar(now_unix() + 300)));
        let mut other = ar(now_unix() + 300);
        other.family = "other".into();
        s.put_access("b".into(), Arc::new(other));
        assert!(s.take_refresh("r").is_ok());
        assert_eq!(s.take_refresh("r").err(), Some(RefreshError::Reused));
        assert!(s.get_access("a").is_none(), "same family revoked");
        assert!(s.get_access("b").is_some(), "other family untouched");
        assert_eq!(s.take_refresh("r").err(), Some(RefreshError::Invalid));
        assert_eq!(s.take_refresh("never").err(), Some(RefreshError::Invalid));
        s.put_refresh("dead".into(), Arc::new(ar(now_unix() - 1)));
        assert_eq!(s.take_refresh("dead").err(), Some(RefreshError::Invalid));
        assert_eq!(s.cleanup(), 1, "expired used-refresh tombstone pruned");
    }
}

#[cfg(test)]
mod more_tests {
    use super::*;

    #[test]
    fn revoke_client_and_access_expiry() {
        let s = TokenStore::default();
        let mut a = tests::ar(now_unix() + 60);
        a.client_id = "a".into();
        let mut b = tests::ar(now_unix() + 60);
        b.client_id = "b".into();
        s.put_code("ca".into(), a.clone());
        s.put_access("aa".into(), Arc::new(a.clone()));
        s.put_refresh("ra".into(), Arc::new(a));
        s.put_access("ab".into(), Arc::new(b));
        s.revoke_client("a");
        assert_eq!(s.counts(), (0, 1, 0));
        assert!(s.get_access("ab").is_some());
        s.put_access("old".into(), Arc::new(tests::ar(now_unix() - 1)));
        assert!(s.get_access("old").is_none());
        assert_eq!(s.counts().1, 1, "expired token removed on lookup");
        let act = ActorClaim {
            sub: "s".into(),
            client_id: String::new(),
            act: None,
        };
        assert_eq!(
            serde_json::to_value(&act).unwrap(),
            serde_json::json!({"sub": "s"})
        );
    }
}
