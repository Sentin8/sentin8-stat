// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Stat
// SPDX-License-Identifier: Apache-2.0

//! # stat-client
//!
//! Rust client for the Sentin8 Stat analytics & telemetry service.
//!
//! Used by Sentin8 services (BFF server-side tagging) and third-party Rust
//! backends to send events to Stat. The client never stores a static
//! credential: it obtains a fresh Auth M2M token (scope `sentin8:stat:measure`)
//! from the provided `sentin8_m2m::TokenSource` on each request.
//!
#![deny(missing_docs)]


use sentin8_middleware::http_client::Sentin8HttpClient;
use serde::Serialize;
use thiserror::Error;
use uuid::Uuid;

/// Errors returned by the Stat client.
#[derive(Debug, Error)]
pub enum StatError {
    /// An HTTP request failed (transport error or non-success status).
    #[error("Stat HTTP error: {0}")]
    Http(String),
    /// A response body could not be decoded.
    #[error("Stat response decode error: {0}")]
    Decode(String),
    /// The M2M token could not be obtained.
    #[error("M2M token error: {0}")]
    Token(String),
}

/// The Stat client — **certificate-presenting** (, auth DESIGN
/// §4.3f): every call presents the workload's Acme-issued client
/// certificate in the TLS handshake; Stat's TLS layer authenticates it
/// and the registry map authorizes the scopes. No bearer token exists
/// on this path. Cheap to clone.
#[derive(Clone)]
pub struct Client {
    base_url: String,
    property_id: Uuid,
    http: Sentin8HttpClient,
}

impl Client {
    /// Build a certificate-presenting Stat client. The transport
    /// presents `cert_path`/`key_path` (the workload's Acme-issued
    /// identity) on every call and trusts only `ca_cert_path`.
    ///
    /// # Errors
    /// [`StatError::Http`] when the mTLS transport cannot be built from
    /// the identity paths — a missing certificate identity is a
    /// provisioning state, surfaced loud.
    pub fn with_workload_identity(
        base_url: impl Into<String>,
        property_id: Uuid,
        ca_cert_path: &str,
        cert_path: &str,
        key_path: &str,
    ) -> Result<Self, StatError> {
        let mtls =
            sentin8_middleware::mtls::MtlsConfig::new(ca_cert_path, cert_path, key_path);
        let http = sentin8_middleware::mtls::build_mtls_client(&mtls)
            .map(Sentin8HttpClient::from_client)
            .map_err(|e| StatError::Http(e.to_string()))?;
        Ok(Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            property_id,
            http,
        })
    }

    /// Test-only plain-HTTP constructor — talks to a local test server
    /// with no TLS/identity.
    #[cfg(test)]
    pub fn plain(base_url: impl Into<String>, property_id: Uuid) -> Self {
        Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            property_id,
            http: Sentin8HttpClient::new(),
        }
    }

    /// Plain-HTTP DEV FALLBACK constructor — no TLS identity (Stat
    /// rejects it loudly at the authorization gate). Use ONLY for the
    /// fail-soft boot/test path when the workload certificate cannot be
    /// minted yet; never for production paths.
    pub fn new_dev_plain(base_url: impl Into<String>, property_id: Uuid) -> Self {
        Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            property_id,
            http: Sentin8HttpClient::new(),
        }
    }

    /// Wrap a pre-built cert-presenting transport (— for
    /// callers that hold a shared per-process transport (app's telemetry
    /// listener constructs a client per event against one transport).
    pub fn from_transport(
        base_url: impl Into<String>,
        property_id: Uuid,
        http: Sentin8HttpClient,
    ) -> Self {
        Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            property_id,
            http,
        }
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }

    /// `POST /v1/m/collect` — send a batch of event envelopes.
    pub async fn collect(&self, events: &[EventEnvelope]) -> Result<(), StatError> {
        let body = serde_json::to_value(events).map_err(|e| StatError::Decode(e.to_string()))?;
        self.post("/v1/m/collect", body).await
    }

    /// `POST /v1/m/pageview` — page-view shorthand.
    pub async fn pageview(
        &self,
        client_id: &str,
        url: &str,
        title: Option<&str>,
        props: Option<serde_json::Value>,
    ) -> Result<(), StatError> {
        let body = serde_json::json!({
            "property_id": self.property_id,
            "client_id": client_id,
            "url": url,
            "title": title,
            "props": props.unwrap_or(serde_json::Value::Null),
        });
        self.post("/v1/m/pageview", body).await
    }

    /// `POST /v1/m/event` — named-event shorthand.
    pub async fn event(
        &self,
        client_id: &str,
        name: &str,
        props: Option<serde_json::Value>,
    ) -> Result<(), StatError> {
        let body = serde_json::json!({
            "property_id": self.property_id,
            "client_id": client_id,
            "name": name,
            "props": props.unwrap_or(serde_json::Value::Null),
        });
        self.post("/v1/m/event", body).await
    }

    /// `POST /v1/m/conversion` — conversion shorthand.
    pub async fn conversion(
        &self,
        client_id: &str,
        id: &str,
        value: Option<f64>,
        currency: Option<&str>,
    ) -> Result<(), StatError> {
        let body = serde_json::json!({
            "property_id": self.property_id,
            "client_id": client_id,
            "conversions": [{ "id": id, "value": value, "currency": currency }],
            "props": serde_json::Value::Null,
        });
        self.post("/v1/m/conversion", body).await
    }

    /// `POST /v1/m/metric` — server-telemetry shorthand.
    ///
    /// `name` is the metric batch source label (e.g. `auth.daily_snapshot`);
    /// `metrics` is the numeric map (e.g. `{"users.count": 42}`);
    /// `dim_tags` is optional dimension props (e.g. `{"token_tp":"m2m"}`).
    pub async fn metric(
        &self,
        name: &str,
        metrics: serde_json::Value,
        dim_tags: Option<serde_json::Value>,
    ) -> Result<(), StatError> {
        let body = serde_json::json!({
            "property_id": self.property_id,
            "name": name,
            "metrics": metrics,
            "dim_tags": dim_tags.unwrap_or(serde_json::Value::Null),
        });
        self.post("/v1/m/metric", body).await
    }

    async fn post(&self, path: &str, body: serde_json::Value) -> Result<(), StatError> {
        let resp = self
            .http
            .post(self.url(path))
            .json(&body)
            .send()
            .await
            .map_err(|e| StatError::Http(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(StatError::Http(format!("status {}", resp.status())));
        }
        Ok(())
    }

    /// Fire-and-forget variant of [`metric`].
    ///
    /// Spawns the HTTP POST on the tokio runtime and returns immediately.
    /// Use this for server-telemetry metrics where the caller must not block
    /// on Stat (e.g. a request handler emitting a per-request counter). The
    /// spawned task logs failures via `tracing` but never propagates errors
    /// to the caller — this is the definition of fire-and-forget.
    ///
    /// The caller does not need to be `#[tokio::main]` — `tokio::spawn`
    /// works from any async context that is already running on the tokio
    /// runtime (which is the case for every Sentin8 service's axum handler).
    pub fn metric_fire_and_forget(
        &self,
        name: &str,
        metrics: serde_json::Value,
        dim_tags: Option<serde_json::Value>,
    ) {
        let client = self.clone();
        let name = name.to_string();
        tokio::spawn(async move {
            if let Err(e) = client.metric(&name, metrics, dim_tags).await {
                tracing::warn!(error = %e, metric = %name, "stat fire-and-forget metric failed");
            }
        });
    }

    /// Fire-and-forget variant of [`collect`].
    ///
    /// Spawns the HTTP POST and returns immediately. For batch event
    /// ingestion where the caller does not want to wait for Stat.
    pub fn collect_fire_and_forget(&self, events: Vec<EventEnvelope>) {
        let client = self.clone();
        tokio::spawn(async move {
            if let Err(e) = client.collect(&events).await {
                tracing::warn!(error = %e, "stat fire-and-forget collect failed");
            }
        });
    }

    /// Fire-and-forget variant of [`event`].
    ///
    /// Spawns the HTTP POST and returns immediately. For named events
    /// emitted from request handlers that must not block on Stat.
    pub fn event_fire_and_forget(
        &self,
        client_id: &str,
        name: &str,
        props: Option<serde_json::Value>,
    ) {
        let client = self.clone();
        let client_id = client_id.to_string();
        let name = name.to_string();
        tokio::spawn(async move {
            if let Err(e) = client.event(&client_id, &name, props).await {
                tracing::warn!(error = %e, event = %name, "stat fire-and-forget event failed");
            }
        });
    }
}

/// A single event envelope, as sent to `/v1/m/collect`.
#[derive(Debug, Clone, Serialize)]
pub struct EventEnvelope {
    /// Unique event id.
    pub event_id: Uuid,
    /// Anonymous client/device id.
    pub client_id: String,
    /// Property the event reports against.
    pub property_id: Uuid,
    /// Server-emitter slug path: when set, stat's ingest resolves slug →
    /// property server-side; `property_id` stays the wire field for web
    /// SDKs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub property_slug: Option<String>,
    /// Emitter type (`web` | `server` | …).
    pub client_type: String,
    /// Event class (`pageview` | `event` | …).
    pub event_type: String,
    /// Specific event name.
    pub event_name: String,
    /// Event timestamp (UTC).
    pub timestamp: chrono::DateTime<chrono::Utc>,
    /// Authenticated subject id, when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject_id: Option<String>,
    /// Page URL for web events.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub page_url: Option<String>,
    /// Page title for web events.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub page_title: Option<String>,
    /// Referrer for web events.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub referrer: Option<String>,
    /// Conversions carried by this event.
    #[serde(default)]
    pub conversions: Vec<Conversion>,
    /// Engagement time in milliseconds.
    #[serde(default)]
    pub engagement_time_ms: i64,
    /// Numeric metric map for server telemetry.
    #[serde(default)]
    pub metrics: serde_json::Value,
    /// Arbitrary event properties.
    #[serde(default)]
    pub props: serde_json::Value,
}

/// A conversion event carried by an envelope.
#[derive(Debug, Clone, Serialize)]
pub struct Conversion {
    /// Conversion id.
    pub id: String,
    /// Monetary value, when applicable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<f64>,
    /// ISO currency code for the value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub currency: Option<String>,
}

impl EventEnvelope {
    /// Build a pageview envelope.
    pub fn pageview(
        property_id: Uuid,
        client_id: impl Into<String>,
        url: impl Into<String>,
    ) -> Self {
        Self {
            event_id: Uuid::new_v4(),
            client_id: client_id.into(),
            property_id,
            property_slug: None,
            client_type: "web".into(),
            event_type: "pageview".into(),
            event_name: "pageview".into(),
            timestamp: chrono::Utc::now(),
            subject_id: None,
            page_url: Some(url.into()),
            page_title: None,
            referrer: None,
            conversions: vec![],
            engagement_time_ms: 0,
            metrics: serde_json::Value::Null,
            props: serde_json::Value::Null,
        }
    }

    /// Build a named-event envelope.
    pub fn event(property_id: Uuid, client_id: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            event_id: Uuid::new_v4(),
            client_id: client_id.into(),
            property_id,
            property_slug: None,
            client_type: "web".into(),
            event_type: "event".into(),
            event_name: name.into(),
            timestamp: chrono::Utc::now(),
            subject_id: None,
            page_url: None,
            page_title: None,
            referrer: None,
            conversions: vec![],
            engagement_time_ms: 0,
            metrics: serde_json::Value::Null,
            props: serde_json::Value::Null,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Install the Graviola PQ crypto provider once — reqwest panics with
    /// "No provider set" when a client is built without one.
    fn install_provider() {
        use std::sync::Once;
        static ONCE: Once = Once::new();
        ONCE.call_once(|| {
            let _ = sentin8_tls::crypto::sentin8_pq_provider().install_default();
        });
    }

    #[test]
    fn event_envelope_pageview() {
        install_provider();
        let prop = Uuid::new_v4();
        let ev = EventEnvelope::pageview(prop, "client-1", "/home");
        assert_eq!(ev.property_id, prop);
        assert_eq!(ev.client_id, "client-1");
        assert_eq!(ev.event_type, "pageview");
        assert_eq!(ev.page_url.as_deref(), Some("/home"));
    }

    #[test]
    fn event_envelope_event() {
        install_provider();
        let prop = Uuid::new_v4();
        let ev = EventEnvelope::event(prop, "client-1", "button_click");
        assert_eq!(ev.event_type, "event");
        assert_eq!(ev.event_name, "button_click");
    }

    #[test]
    fn conversion_new() {
        install_provider();
        let conv = Conversion {
            id: "conv-1".into(),
            value: Some(99.99),
            currency: Some("USD".into()),
        };
        assert_eq!(conv.id, "conv-1");
        assert_eq!(conv.value, Some(99.99));
        assert_eq!(conv.currency.as_deref(), Some("USD"));
    }

    #[test]
    fn event_envelope_has_unique_event_id() {
        install_provider();
        let prop = Uuid::new_v4();
        let ev1 = EventEnvelope::pageview(prop, "c1", "/a");
        let ev2 = EventEnvelope::pageview(prop, "c1", "/b");
        assert_ne!(ev1.event_id, ev2.event_id);
    }
}
