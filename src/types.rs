// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Stat
// SPDX-License-Identifier: Apache-2.0

//! Stat shared types - event envelope, property, session, funnel, account,
//! aggregate rows, ingest request, conversion, metric aggregate.
//!
//! Wire types - metric envelopes, properties, dimensions.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Full event envelope as sent by SDKs / servers. Mirrors the JSON shape in
/// the design doc , extended with the optional `metrics` field for
/// server telemetry events.
#[derive(Debug, Clone, Serialize, Deserialize)]
/// The eventenvelope type.
pub struct EventEnvelope {
    /// event identifier.
    pub event_id: Uuid,
    /// client identifier.
    pub client_id: String,
    /// property identifier.
    pub property_id: Uuid,
    /// Server-emitter slug path : when set, the ingest layer
    /// resolves slug → property server-side (env-scoped) and overwrites
    /// `property_id`. `property_id` stays the wire field for web SDKs.
    #[serde(default)]
    /// The property slug.
    pub property_slug: Option<String>,
    /// `web` | `server` | `mobile`.
    /// The client type.
    pub client_type: String,
    /// `pageview` | `screenview` | `event` | `conversion` | `metric` | `custom`.
    /// The event type.
    pub event_type: String,
    /// The event name.
    pub event_name: String,
    /// The timestamp.
    pub timestamp: chrono::DateTime<chrono::Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// subject identifier.
    pub subject_id: Option<String>,
    #[serde(default)]
    /// The event category.
    pub event_category: Option<String>,
    #[serde(default)]
    /// The page URL.
    pub page_url: Option<String>,
    #[serde(default)]
    /// The page title.
    pub page_title: Option<String>,
    #[serde(default)]
    /// The referrer.
    pub referrer: Option<String>,
    #[serde(default)]
    /// The screen name.
    pub screen_name: Option<String>,
    #[serde(default)]
    /// The app version.
    pub app_version: Option<String>,
    /// Geo/device context - usually populated by the pipeline enrichment stage,
    /// but SDKs may send hints.
    #[serde(default)]
    /// The geo.
    pub geo: Option<GeoHint>,
    #[serde(default)]
    /// The device.
    pub device: Option<DeviceHint>,
    #[serde(default)]
    /// The traffic source.
    pub traffic_source: Option<TrafficSource>,
    #[serde(default)]
    /// The conversions.
    pub conversions: Vec<Conversion>,
    #[serde(default)]
    /// The engagement time ms.
    pub engagement_time_ms: i64,
    /// Numeric telemetry values. Present when `event_type == "metric"`.
    #[serde(default)]
    /// The metrics.
    pub metrics: serde_json::Value,
    /// Arbitrary flat JSON object (max 64 keys, max 4 KiB). PII deny-list
    /// applied at ingest.
    #[serde(default)]
    /// The props.
    pub props: serde_json::Value,
    /// Set at ingest when the PII deny-list stripped at least one key
    /// from `props` - dashboards distinguish cleaned payloads (stat DESIGN
    /// §4, cross-cutting CC-7 doc alignment).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    /// Whether PII was stripped.
    pub props_pii_stripped: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
/// The geohint type.
pub struct GeoHint {
    /// The ip.
    pub ip: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
/// The devicehint type.
pub struct DeviceHint {
    /// The user agent.
    pub user_agent: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
/// The trafficsource type.
pub struct TrafficSource {
    #[serde(skip_serializing_if = "Option::is_none")]
    /// The utm source.
    pub utm_source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// The utm medium.
    pub utm_medium: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// The utm campaign.
    pub utm_campaign: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// The conversion type.
pub struct Conversion {
    /// Identifier.
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// The value.
    pub value: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// The currency.
    pub currency: Option<String>,
}

/// `POST /v1/m/collect` body - either a single envelope or an array.
/// Ingest request body - one envelope or a batch.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum CollectBody {
    /// A single envelope.
    Single(Box<EventEnvelope>),
    /// A batch of envelopes.
    Batch(Vec<EventEnvelope>),
}

/// Shorthand request bodies.

#[derive(Debug, Clone, Deserialize, utoipa::ToSchema)]
/// Request body for pageview.
pub struct PageviewRequest {
    /// property identifier.
    pub property_id: Uuid,
    /// client identifier.
    pub client_id: String,
    /// The URL.
    pub url: String,
    #[serde(default)]
    /// The title.
    pub title: Option<String>,
    #[serde(default)]
    /// The referrer.
    pub referrer: Option<String>,
    #[serde(default)]
    /// subject identifier.
    pub subject_id: Option<String>,
    #[serde(default)]
    /// The props.
    pub props: serde_json::Value,
}

#[derive(Debug, Clone, Deserialize)]
/// Request body for event.
pub struct EventRequest {
    /// property identifier.
    pub property_id: Uuid,
    /// client identifier.
    pub client_id: String,
    /// The name.
    pub name: String,
    #[serde(default)]
    /// The category.
    pub category: Option<String>,
    #[serde(default)]
    /// subject identifier.
    pub subject_id: Option<String>,
    #[serde(default)]
    /// The props.
    pub props: serde_json::Value,
}

#[derive(Debug, Clone, Deserialize)]
/// Request body for conversionshorthand.
pub struct ConversionShorthandRequest {
    /// property identifier.
    pub property_id: Uuid,
    /// client identifier.
    pub client_id: String,
    /// The conversions.
    pub conversions: Vec<Conversion>,
    #[serde(default)]
    /// subject identifier.
    pub subject_id: Option<String>,
    #[serde(default)]
    /// The props.
    pub props: serde_json::Value,
}

#[derive(Debug, Clone, Deserialize)]
/// Request body for metric.
pub struct MetricRequest {
    /// property identifier.
    pub property_id: Uuid,
    /// Metric batch source label, e.g. `auth.daily_snapshot`.
    /// The name.
    pub name: String,
    /// Numeric map, e.g. `{"users.count": 42}`.
    /// The metrics.
    pub metrics: serde_json::Value,
    /// Optional dimension tags, e.g. `{"token_tp":"m2m"}`.
    #[serde(default)]
    /// The dim tags.
    pub dim_tags: serde_json::Value,
}

// ── Admin API types ──────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
/// The property type.
pub struct Property {
    /// Identifier.
    pub id: Uuid,
    /// env identifier.
    pub env_id: Uuid,
    /// account identifier.
    pub account_id: Option<Uuid>,
    /// The name.
    pub name: String,
    /// The slug.
    pub slug: String,
    /// The timezone.
    pub timezone: String,
    /// The session timeout minutes.
    pub session_timeout_minutes: i32,
    /// The retention days.
    pub retention_days: i32,
    /// The bot filter enabled.
    pub bot_filter_enabled: bool,
    /// The pii deny list.
    pub pii_deny_list: serde_json::Value,
    /// The status.
    pub status: String,
    /// created time.
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// updated time.
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Deserialize, utoipa::ToSchema)]
/// Request body for createproperty.
pub struct CreatePropertyRequest {
    /// The name.
    pub name: String,
    /// The slug.
    pub slug: String,
    #[serde(default)]
    /// account identifier.
    pub account_id: Option<Uuid>,
}

#[derive(Debug, Clone, Deserialize, utoipa::ToSchema)]
/// Request body for updateproperty.
pub struct UpdatePropertyRequest {
    /// The name.
    pub name: Option<String>,
    /// The timezone.
    pub timezone: Option<String>,
    /// The status.
    pub status: Option<String>,
}

#[derive(Debug, Clone, Deserialize, utoipa::ToSchema)]
/// Request body for retention.
pub struct RetentionRequest {
    /// The retention days.
    pub retention_days: i32,
}

#[derive(Debug, Clone, Deserialize, utoipa::ToSchema)]
/// The settingsupdate type.
pub struct SettingsUpdate {
    /// The session timeout minutes.
    pub session_timeout_minutes: Option<i32>,
    /// The timezone.
    pub timezone: Option<String>,
    /// The bot filter enabled.
    pub bot_filter_enabled: Option<bool>,
    /// The pii deny list.
    pub pii_deny_list: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
/// The account type.
pub struct Account {
    /// Identifier.
    pub id: Uuid,
    /// env identifier.
    pub env_id: Uuid,
    /// The name.
    pub name: String,
    /// created time.
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Deserialize, utoipa::ToSchema)]
/// Request body for createaccount.
pub struct CreateAccountRequest {
    /// The name.
    pub name: String,
}

// ── Data API types ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, utoipa::ToSchema)]
/// The metricpoint type.
pub struct MetricPoint {
    /// The day.
    pub day: chrono::NaiveDate,
    /// The metric name.
    pub metric_name: String,
    /// The value.
    pub value: f64,
}

#[derive(Debug, Clone, Serialize)]
/// The aggregaterow type.
pub struct AggregateRow {
    /// The day.
    pub day: chrono::NaiveDate,
    /// The dimensions.
    pub dimensions: serde_json::Value,
    /// The metrics.
    pub metrics: serde_json::Value,
}

/// Per-service traffic summary row - one row per `from_service → to_service`
/// pair, aggregated from TLS's `tls.traffic.*` metrics.
/// Returned by `GET /v1/data/traffic`.
#[derive(Debug, Clone, Serialize)]
/// The trafficsummary type.
pub struct TrafficSummary {
    /// The calling service (e.g. `bff`).
    /// The from.
    pub from: String,
    /// The target service (e.g. `auth`).
    /// The to.
    pub to: String,
    /// Total request count in the period.
    /// The count count.
    pub count: f64,
    /// Average latency in ms.
    /// The latency ms.
    pub latency_ms: f64,
    /// Number of error responses (status ≥ 500).
    /// The errors.
    pub errors: f64,
}

#[derive(Debug, Clone, Serialize, utoipa::ToSchema)]
/// The funnel type.
pub struct Funnel {
    /// Identifier.
    pub id: Uuid,
    /// property identifier.
    pub property_id: Uuid,
    /// The name.
    pub name: String,
    /// The steps.
    pub steps: serde_json::Value,
}

#[derive(Debug, Clone, Deserialize, utoipa::ToSchema)]
/// Request body for createfunnel.
pub struct CreateFunnelRequest {
    /// property identifier.
    pub property_id: Uuid,
    /// The name.
    pub name: String,
    /// The steps.
    pub steps: serde_json::Value,
}

/// Default PII deny-list keys. Applied to `props` at ingest.
/// The pii deny list constant.
pub const PII_DENY_LIST: &[&str] = &[
    "email",
    "phone",
    "pan",
    "pin",
    "cvv",
    "ssn",
    "password",
    "token",
    "secret",
    "apikey",
    "api_key",
    "iban",
    "account_number",
    "card_number",
];

/// Strip PII deny-list keys from a JSON object. Returns the cleaned object and
/// whether any keys were stripped (so the event can be flagged).
/// Strip pii.
pub fn strip_pii(props: &serde_json::Value) -> (serde_json::Value, bool) {
    let Some(obj) = props.as_object() else {
        return (props.clone(), false);
    };
    let mut stripped = false;
    let mut cleaned = serde_json::Map::with_capacity(obj.len());
    for (k, v) in obj {
        let lower = k.to_lowercase();
        if PII_DENY_LIST.contains(&lower.as_str()) {
            stripped = true;
            continue;
        }
        cleaned.insert(k.clone(), v.clone());
    }
    (serde_json::Value::Object(cleaned), stripped)
}
