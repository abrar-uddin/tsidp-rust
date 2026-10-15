//! Minimal Prometheus text-format metrics without external dependencies.

use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Default)]
pub struct Metrics {
    pub auth_codes_issued: AtomicU64,
    pub tokens_issued: AtomicU64,
    pub refresh_grants: AtomicU64,
    pub token_exchanges: AtomicU64,
    pub introspections: AtomicU64,
    pub userinfo_requests: AtomicU64,
    pub client_registrations: AtomicU64,
    pub oauth_errors: AtomicU64,
    pub whois_failures: AtomicU64,
    pub localapi_errors: AtomicU64,
    pub denied_requests: AtomicU64,
}

impl Metrics {
    fn inc(counter: &AtomicU64) {
        counter.fetch_add(1, Ordering::Relaxed);
    }
    pub fn inc_codes(&self) {
        Self::inc(&self.auth_codes_issued)
    }
    pub fn inc_tokens(&self) {
        Self::inc(&self.tokens_issued)
    }
    pub fn inc_refresh(&self) {
        Self::inc(&self.refresh_grants)
    }
    pub fn inc_exchanges(&self) {
        Self::inc(&self.token_exchanges)
    }
    pub fn inc_introspections(&self) {
        Self::inc(&self.introspections)
    }
    pub fn inc_userinfo(&self) {
        Self::inc(&self.userinfo_requests)
    }
    pub fn inc_registrations(&self) {
        Self::inc(&self.client_registrations)
    }
    pub fn inc_oauth_errors(&self) {
        Self::inc(&self.oauth_errors)
    }
    pub fn whois_failed(&self) {
        Self::inc(&self.whois_failures)
    }
    pub fn localapi_failed(&self) {
        Self::inc(&self.localapi_errors)
    }
    pub fn denied(&self) {
        Self::inc(&self.denied_requests)
    }

    /// Render in Prometheus exposition format. Gauges for live token counts
    /// and readiness are passed in by the caller.
    pub fn render(
        &self,
        active_tokens: (usize, usize, usize),
        ready: bool,
        info: &[(&str, &str)],
    ) -> String {
        let mut out = String::with_capacity(2048);
        let mut counter = |name: &str, help: &str, v: &AtomicU64| {
            out.push_str(&format!(
                "# HELP {name} {help}\n# TYPE {name} counter\n{name} {}\n",
                v.load(Ordering::Relaxed)
            ));
        };
        counter(
            "tsidp_auth_codes_issued_total",
            "Authorization codes issued.",
            &self.auth_codes_issued,
        );
        counter(
            "tsidp_tokens_issued_total",
            "Token responses issued (code + refresh grants).",
            &self.tokens_issued,
        );
        counter(
            "tsidp_refresh_grants_total",
            "Successful refresh_token grants.",
            &self.refresh_grants,
        );
        counter(
            "tsidp_token_exchanges_total",
            "Successful RFC 8693 token exchanges.",
            &self.token_exchanges,
        );
        counter(
            "tsidp_introspections_total",
            "Introspection requests.",
            &self.introspections,
        );
        counter(
            "tsidp_userinfo_requests_total",
            "Userinfo requests.",
            &self.userinfo_requests,
        );
        counter(
            "tsidp_client_registrations_total",
            "Clients created via DCR, API or UI.",
            &self.client_registrations,
        );
        counter(
            "tsidp_oauth_errors_total",
            "OAuth error responses returned.",
            &self.oauth_errors,
        );
        counter(
            "tsidp_whois_failures_total",
            "LocalAPI whois lookups that failed.",
            &self.whois_failures,
        );
        counter(
            "tsidp_localapi_errors_total",
            "LocalAPI calls that failed.",
            &self.localapi_errors,
        );
        counter(
            "tsidp_denied_requests_total",
            "Requests denied by capability or listener policy.",
            &self.denied_requests,
        );

        let (codes, access, refresh) = active_tokens;
        out.push_str("# HELP tsidp_active_tokens Live entries in the in-memory token store.\n# TYPE tsidp_active_tokens gauge\n");
        out.push_str(&format!("tsidp_active_tokens{{kind=\"code\"}} {codes}\n"));
        out.push_str(&format!(
            "tsidp_active_tokens{{kind=\"access\"}} {access}\n"
        ));
        out.push_str(&format!(
            "tsidp_active_tokens{{kind=\"refresh\"}} {refresh}\n"
        ));
        out.push_str("# HELP tsidp_ready 1 when the issuer is known and tailscaled is Running.\n# TYPE tsidp_ready gauge\n");
        out.push_str(&format!("tsidp_ready {}\n", if ready { 1 } else { 0 }));
        out.push_str("# HELP tsidp_build_info Build information.\n# TYPE tsidp_build_info gauge\n");
        let labels: Vec<String> = info
            .iter()
            .map(|(k, v)| format!("{k}=\"{}\"", v.replace('"', "'")))
            .collect();
        out.push_str(&format!("tsidp_build_info{{{}}} 1\n", labels.join(",")));
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_prometheus_text() {
        let m = Metrics::default();
        m.inc_codes();
        m.inc_codes();
        m.inc_tokens();
        m.inc_refresh();
        m.inc_exchanges();
        m.inc_introspections();
        m.inc_userinfo();
        m.inc_registrations();
        m.inc_oauth_errors();
        m.whois_failed();
        m.localapi_failed();
        m.denied();
        let out = m.render(
            (1, 2, 3),
            false,
            &[("version", "v\"1"), ("issuer", "https://x")],
        );
        assert!(out.contains(
            "# TYPE tsidp_auth_codes_issued_total counter\ntsidp_auth_codes_issued_total 2\n"
        ));
        for name in [
            "tsidp_tokens_issued_total 1",
            "tsidp_refresh_grants_total 1",
            "tsidp_token_exchanges_total 1",
            "tsidp_introspections_total 1",
            "tsidp_userinfo_requests_total 1",
            "tsidp_client_registrations_total 1",
            "tsidp_oauth_errors_total 1",
            "tsidp_whois_failures_total 1",
            "tsidp_localapi_errors_total 1",
            "tsidp_denied_requests_total 1",
            "tsidp_active_tokens{kind=\"code\"} 1",
            "tsidp_active_tokens{kind=\"access\"} 2",
            "tsidp_active_tokens{kind=\"refresh\"} 3",
            "tsidp_ready 0",
        ] {
            assert!(
                out.contains(&format!("{name}\n")),
                "missing {name} in\n{out}"
            );
        }
        assert!(
            out.contains("tsidp_build_info{version=\"v'1\",issuer=\"https://x\"} 1"),
            "quotes escaped"
        );
    }
}
