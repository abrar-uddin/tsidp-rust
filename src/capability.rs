//! The `tailscale.com/cap/tsidp` application capability grant.
//!
//! Grants are written in the tailnet policy file and delivered to tsidp by
//! tailscaled in the WhoIs response for the calling node. tsidp is deny by
//! default: anything not granted here is refused.

use serde::Deserialize;
use serde_json::{Map, Value};
use std::collections::{BTreeSet, HashMap};

pub const CAP_NAME: &str = "tailscale.com/cap/tsidp";

/// One rule inside the grant. Unknown fields are ignored so the schema can
/// grow without breaking older servers.
#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
#[serde(default)]
pub struct CapRule {
    /// Also include `extraClaims` in the /userinfo response.
    #[serde(rename = "includeInUserInfo")]
    pub include_in_user_info: bool,
    /// Extra claims merged into the ID token (scalars and arrays only).
    #[serde(rename = "extraClaims")]
    pub extra_claims: Map<String, Value>,
    /// STS / resource indicators: users this rule applies to (`*` wildcard).
    pub users: Vec<String>,
    /// STS / resource indicators: audiences the users may obtain tokens for.
    pub resources: Vec<String>,
    /// Allow access to the admin UI and the /clients API.
    pub allow_admin_ui: bool,
    /// Allow RFC 7591 dynamic client registration.
    pub allow_dcr: bool,
    /// Groups to add to the `groups` claim for matching users.
    pub groups: Vec<String>,
}

/// Capabilities accumulated across all rules granted to a caller.
#[derive(Debug, Clone, Default)]
pub struct AccessRules {
    pub allow_admin_ui: bool,
    pub allow_dcr: bool,
    pub rules: Vec<CapRule>,
}

impl AccessRules {
    pub fn from_rules(rules: Vec<CapRule>) -> Self {
        let allow_admin_ui = rules.iter().any(|r| r.allow_admin_ui);
        let allow_dcr = rules.iter().any(|r| r.allow_dcr);
        AccessRules {
            allow_admin_ui,
            allow_dcr,
            rules,
        }
    }

    pub fn admin() -> Self {
        AccessRules {
            allow_admin_ui: true,
            allow_dcr: true,
            rules: Vec::new(),
        }
    }
}

/// Parse all `tailscale.com/cap/tsidp` values out of a WhoIs cap map.
/// A malformed rule is skipped with a warning rather than failing the login.
pub fn parse_cap_rules(cap_map: Option<&HashMap<String, Vec<Value>>>) -> Vec<CapRule> {
    let Some(values) = cap_map.and_then(|m| m.get(CAP_NAME)) else {
        return Vec::new();
    };
    values
        .iter()
        .filter_map(|v| match serde_json::from_value::<CapRule>(v.clone()) {
            Ok(r) => Some(r),
            Err(e) => {
                tracing::warn!(error = %e, value = %v, "ignoring malformed tsidp capability rule");
                None
            }
        })
        .collect()
}

/// Does `user` (a login name) match a rule's `users` list?
pub fn user_matches(rule: &CapRule, login_name: &str) -> bool {
    rule.users.iter().any(|u| u == "*" || u == login_name)
}

/// RFC 8707 / RFC 8693: filter `requested` resources down to those the user
/// is granted. Empty result means nothing was allowed.
pub fn allowed_resources(rules: &[CapRule], login_name: &str, requested: &[String]) -> Vec<String> {
    requested
        .iter()
        .filter(|res| {
            rules
                .iter()
                .filter(|r| user_matches(r, login_name))
                .any(|r| {
                    r.resources
                        .iter()
                        .any(|allowed| allowed == "*" || allowed == *res)
                })
        })
        .cloned()
        .collect()
}

/// Union of the `groups` lists from every rule that applies to the user.
pub fn granted_groups(rules: &[CapRule], login_name: &str) -> Vec<String> {
    let mut set = BTreeSet::new();
    for r in rules {
        // A rule with no `users` list applies to the node it was granted to.
        if r.users.is_empty() || user_matches(r, login_name) {
            for g in &r.groups {
                set.insert(g.clone());
            }
        }
    }
    set.into_iter().collect()
}

/// Merge `extraClaims` from all rules into one map.
///
/// Values for the same claim are deduplicated. If any rule provides the
/// claim as an array the result is an array; otherwise the first scalar
/// wins. Objects are not supported and are skipped with a warning.
pub fn flatten_extra_claims(rules: &[CapRule]) -> Map<String, Value> {
    #[derive(Default)]
    struct Acc {
        is_array: bool,
        scalar: Option<Value>,
        values: Vec<Value>,
        seen: BTreeSet<String>,
    }
    let mut acc: std::collections::BTreeMap<String, Acc> = Default::default();

    for rule in rules {
        for (claim, raw) in &rule.extra_claims {
            let entry = acc.entry(claim.clone()).or_default();
            match raw {
                Value::Array(items) => {
                    entry.is_array = true;
                    for item in items {
                        add_value(entry_values(entry), item, claim);
                    }
                }
                Value::Object(_) | Value::Null => {
                    tracing::warn!(claim, value = %raw, "unsupported extraClaims value type; skipping");
                }
                scalar => {
                    if entry.scalar.is_none() {
                        entry.scalar = Some(scalar.clone());
                    }
                    add_value(entry_values(entry), scalar, claim);
                }
            }
        }
    }

    fn entry_values(a: &mut Acc) -> (&mut Vec<Value>, &mut BTreeSet<String>) {
        (&mut a.values, &mut a.seen)
    }

    fn add_value((values, seen): (&mut Vec<Value>, &mut BTreeSet<String>), v: &Value, claim: &str) {
        match v {
            Value::Object(_) | Value::Null => {
                tracing::warn!(claim, value = %v, "unsupported extraClaims array element; skipping");
            }
            Value::Array(inner) => {
                for i in inner {
                    add_value((values, seen), i, claim);
                }
            }
            other => {
                let key = other.to_string();
                if seen.insert(key) {
                    values.push(other.clone());
                }
            }
        }
    }

    let mut out = Map::new();
    for (claim, a) in acc {
        if a.is_array {
            out.insert(claim, Value::Array(a.values));
        } else if let Some(s) = a.scalar {
            out.insert(claim, s);
        }
    }
    out
}

/// Claims tsidp sets itself; a grant may not override them.
pub const PROTECTED_CLAIMS: &[&str] = &[
    "sub",
    "aud",
    "exp",
    "iat",
    "iss",
    "jti",
    "nbf",
    "username",
    "email",
    "key",
    "addresses",
    "nid",
    "node",
    "tailnet",
    "tags",
    "user",
    "uid",
    "nonce",
    "azp",
    "act",
    "preferred_username",
    "picture",
    "name",
];

/// Merge extra claims into `claims`, skipping (with a warning) any that would
/// overwrite a protected claim. Unlike the Go implementation this never fails
/// the token request because of a policy typo.
pub fn apply_extra_claims(claims: &mut Map<String, Value>, rules: &[CapRule]) {
    for (k, v) in flatten_extra_claims(rules) {
        if PROTECTED_CLAIMS.contains(&k.as_str()) {
            tracing::warn!(claim = %k, "extraClaims tried to overwrite a protected claim; ignored");
            continue;
        }
        claims.insert(k, v);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn rules(v: Value) -> Vec<CapRule> {
        let mut m = HashMap::new();
        m.insert(CAP_NAME.to_string(), v.as_array().unwrap().clone());
        parse_cap_rules(Some(&m))
    }

    #[test]
    fn parses_readme_example() {
        let r = rules(json!([{
            "allow_admin_ui": true, "allow_dcr": true, "users": ["*"], "resources": ["*"],
            "extraClaims": {"bools": true, "strings": "x", "numbers": 180, "array1": [1,2,3], "array2": ["one","two"]},
            "includeInUserInfo": true, "unknown_future_field": 1
        }]));
        assert_eq!(r.len(), 1);
        let a = AccessRules::from_rules(r.clone());
        assert!(a.allow_admin_ui && a.allow_dcr);
        let flat = flatten_extra_claims(&r);
        assert_eq!(flat["bools"], json!(true));
        assert_eq!(flat["numbers"], json!(180));
        assert_eq!(flat["array1"], json!([1, 2, 3]));
        assert_eq!(flat["array2"], json!(["one", "two"]));
    }

    #[test]
    fn malformed_rule_is_skipped() {
        let r = rules(json!([{"allow_admin_ui": "yes"}, {"allow_dcr": true}]));
        assert_eq!(r.len(), 1);
        assert!(r[0].allow_dcr);
    }

    #[test]
    fn arrays_merge_and_dedupe_across_rules() {
        let r = rules(
            json!([{"extraClaims": {"roles": ["a", "b"]}}, {"extraClaims": {"roles": ["b", "c"]}}, {"extraClaims": {"roles": "d"}}]),
        );
        let flat = flatten_extra_claims(&r);
        assert_eq!(flat["roles"], json!(["a", "b", "c", "d"]));
    }

    #[test]
    fn protected_claims_not_overwritten() {
        let r = rules(json!([{"extraClaims": {"sub": "evil", "email_verified": true}}]));
        let mut claims = Map::new();
        claims.insert("sub".into(), json!("userid:1"));
        apply_extra_claims(&mut claims, &r);
        assert_eq!(claims["sub"], json!("userid:1"));
        assert_eq!(claims["email_verified"], json!(true));
    }

    #[test]
    fn resources_and_groups() {
        let r = rules(json!([
            {"users": ["alice@example.com"], "resources": ["https://api.example.com"], "groups": ["admins"]},
            {"users": ["*"], "resources": ["https://shared.example.com"], "groups": ["everyone"]}
        ]));
        let req = vec![
            "https://api.example.com".to_string(),
            "https://shared.example.com".to_string(),
            "https://nope".to_string(),
        ];
        assert_eq!(allowed_resources(&r, "alice@example.com", &req).len(), 2);
        assert_eq!(
            allowed_resources(&r, "bob@example.com", &req),
            vec!["https://shared.example.com".to_string()]
        );
        assert_eq!(
            granted_groups(&r, "alice@example.com"),
            vec!["admins".to_string(), "everyone".to_string()]
        );
        assert_eq!(
            granted_groups(&r, "bob@example.com"),
            vec!["everyone".to_string()]
        );
    }
}
