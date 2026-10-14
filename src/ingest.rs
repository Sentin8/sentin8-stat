// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Stat
// SPDX-License-Identifier: Apache-2.0

//! Stat ingest layer — collect, pixel fallback, shorthand endpoints, M2M
//! auth, rate limiting, PII stripping, dedupe, Bus enqueue.

use axum::{
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::Response,
    Json,
};
use glide::AsyncCommands;
use serde::Deserialize;
use uuid::Uuid;

use crate::auth;
use crate::handlers::AppState;
use crate::store;
use crate::types::{self, CollectBody, EventEnvelope};

/// PII-stripped + validated envelope ready for insert.
fn clean(envelope: &mut EventEnvelope) -> Result<(), (StatusCode, String)> {
    if envelope.event_id == Uuid::nil() {
        envelope.event_id = Uuid::new_v4();
    }
    if envelope.client_id.trim().is_empty() {
        return Err((StatusCode::BAD_REQUEST, "client_id is required".into()));
    }
    if envelope.property_id == Uuid::nil() {
        return Err((StatusCode::BAD_REQUEST, "property_id is required".into()));
    }
    if !matches!(envelope.client_type.as_str(), "web" | "server" | "mobile") {
        return Err((
            StatusCode::BAD_REQUEST,
            "client_type must be web|server|mobile".into(),
        ));
    }
    if !matches!(
        envelope.event_type.as_str(),
        "pageview" | "screenview" | "event" | "conversion" | "metric" | "custom"
    ) {
        return Err((StatusCode::BAD_REQUEST, "invalid event_type".into()));
    }
    // Normalize props to an object if absent.
    if !envelope.props.is_object() {
        envelope.props = serde_json::Value::Object(serde_json::Map::new());
    }
    // Strip PII deny-list keys; the flag is persisted with the event so
    // dashboards can distinguish cleaned payloads (stat DESIGN §4).
    let (cleaned, stripped) = types::strip_pii(&envelope.props);
    envelope.props = cleaned;
    envelope.props_pii_stripped = stripped;
    // Drop non-numeric metric values.
    if envelope.event_type == "metric" {
        if let Some(obj) = envelope.metrics.as_object() {
            let mut filtered = serde_json::Map::new();
            for (k, v) in obj {
                if v.is_number() {
                    filtered.insert(k.clone(), v.clone());
                }
            }
            envelope.metrics = serde_json::Value::Object(filtered);
        } else {
            envelope.metrics = serde_json::Value::Object(serde_json::Map::new());
        }
    }
    Ok(())
}

/// Resolve the env binding for a property (public lookup).
async fn resolve_property(
    state: &AppState,
    property_id: Uuid,
) -> Result<Uuid, (StatusCode, String)> {
    store::resolve_property(&state.pool, property_id)
        .await?
        .ok_or((
            StatusCode::NOT_FOUND,
            "property not found or archived".into(),
        ))
}

/// : when the envelope carries `property_slug`, resolve it
/// server-side and overwrite `property_id` (server telemetry path —
/// emitters never need a UUID lookup at boot). `property_id`-only callers
/// (web SDK) are unchanged. A slug with no active property row → 404,
/// exactly like an unknown property id.
async fn apply_slug(
    state: &AppState,
    envelope: &mut EventEnvelope,
) -> Result<(), (StatusCode, String)> {
    if let Some(slug) = envelope.property_slug.as_deref().map(str::trim) {
        if !slug.is_empty() {
            let (pid, _env) = store::resolve_property_slug(&state.pool, slug)
                .await?
                .ok_or((
                    StatusCode::NOT_FOUND,
                    format!("property slug not found: {slug}"),
                ))?;
            envelope.property_id = pid;
        }
    }
    Ok(())
}

/// Check the rate limit for a key in Valkey. Returns `true` if allowed.
async fn rate_limit(state: &AppState, key: &str, limit: u32) -> bool {
    let conn = state.valkey.clone();
    let bucket = format!("stat:rl:{key}");
    let minute = chrono::Utc::now().format("%Y%m%d%H%M").to_string();
    let valkey_key = format!("{bucket}:{minute}");
    let count: i64 = conn.incr(&valkey_key, 1).await.unwrap_or(0);
    if count == 1 {
        let _: Result<(), _> = conn.expire(&valkey_key, 120i64).await;
    }
    count <= limit as i64
}

/// Enqueue an event id onto Bus `stat-events` stream (best-effort).
async fn enqueue(
    state: &AppState,
    env_id: Uuid,
    event_id: Uuid,
    publisher_id_token: Option<String>,
    publisher_subject: Option<String>,
) {
    let client = state.bus_client.clone();
    let req = sentin8::bus::contracts::ProduceRequest {
        stream_family: state.config.stream_family.clone(),
        env_id: None,
        event_type: "sentin8:stat:event:ingested".into(),
        payload: serde_json::json!({ "event_id": event_id }),
        correlation_id: None,
        idempotency_key: None,
        publisher_id_token,
        publisher_subject,
    };
    if let Err(e) = client.produce(&req).await {
        tracing::warn!(error = %e, "failed to enqueue stat event");
    }
    let _ = env_id;
}

/// Common ingest path: validate, resolve property, write raw event, enqueue.
async fn ingest_one(
    state: &AppState,
    headers: &HeaderMap,
    mut envelope: EventEnvelope,
) -> Result<(), (StatusCode, String)> {
    clean(&mut envelope)?;
    apply_slug(state, &mut envelope).await?;

    // Auth: M2M token (server/mobile) OR user token (web) OR unauthenticated.
    let auth_ctx = auth::verify_token_opt(&state.config, headers).await?;
    // ── Sentin8:Policy : evaluate authenticated callers only —
    // the unauthenticated ingest path is unchanged (existing policy).
    if let Some(a) = &auth_ctx {
        crate::policy::require_policy(
            &state.policy,
            a,
            &headers,
            sentin8::shield::EvalTarget::new("sentin8:stat:measure"),
        )
        .await?;
    }
    let env_id = resolve_property(state, envelope.property_id).await?;

    // Rate limit.
    let limit = match envelope.client_type.as_str() {
        "web" => state.config.web_rate_limit_per_minute,
        _ => state.config.server_rate_limit_per_minute,
    };
    let rl_key = match &auth_ctx {
        Some(a) => format!("m2m:{}", a.claims.sub),
        None => format!("client:{}", envelope.client_id),
    };
    if !rate_limit(state, &rl_key, limit).await {
        // Retry-After (stat DESIGN §4): the bucket window is one minute —
        // consumers back off deterministically instead of hammering.
        // The shared `(StatusCode, String)` error carries the 60s bucket
        // window in the message; a full header-carrying response type is
        // the ingest-layer follow-up (stat DESIGN §4).
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            "rate limit exceeded; retry-after: 60".to_string(),
        ));
    }

    // If a token is present, attach the subject id (identity stitching hint).
    if let Some(a) = auth_ctx.as_ref() {
        if envelope.subject_id.is_none() {
            envelope.subject_id = a.subject_id();
        }
    }

    store::insert_event(&state.pool, env_id, &envelope).await?;
    let publisher_id_token = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .map(|s| s.to_string());
    let publisher_subject = auth_ctx.as_ref().map(|a| a.claims.sub.clone());
    enqueue(
        state,
        env_id,
        envelope.event_id,
        publisher_id_token,
        publisher_subject,
    )
    .await;
    Ok(())
}

/// `POST /v1/m/collect` — batch ingest (max 100 events / 1 MiB).
/// Handle collect.
pub async fn collect(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<StatusCode, (StatusCode, String)> {
    if body.len() > state.config.collect_body_max_bytes {
        return Err((StatusCode::PAYLOAD_TOO_LARGE, "body too large".into()));
    }
    let parsed: CollectBody = serde_json::from_slice(&body)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("invalid JSON: {e}")))?;
    let envelopes: Vec<EventEnvelope> = match parsed {
        CollectBody::Single(e) => vec![*e],
        CollectBody::Batch(v) => v,
    };
    if envelopes.is_empty() {
        return Ok(StatusCode::NO_CONTENT);
    }
    if envelopes.len() > state.config.collect_batch_max {
        return Err((
            StatusCode::PAYLOAD_TOO_LARGE,
            format!("batch exceeds {} events", state.config.collect_batch_max),
        ));
    }
    for envelope in envelopes {
        ingest_one(&state, &headers, envelope).await?;
    }
    Ok(StatusCode::NO_CONTENT)
}

/// `GET /v1/m/collect` — pixel fallback. Query-string encoded single event,
/// returns a 1x1 transparent GIF.
#[derive(Debug, Deserialize)]
/// The pixelquery type.
pub struct PixelQuery {
    /// property identifier.
    pub property_id: Uuid,
    /// client identifier.
    pub client_id: String,
    #[serde(default = "default_event_type")]
    /// The event type.
    pub event_type: String,
    #[serde(default)]
    /// The event name.
    pub event_name: Option<String>,
    #[serde(default)]
    /// The URL.
    pub url: Option<String>,
    #[serde(default)]
    /// The title.
    pub title: Option<String>,
}

fn default_event_type() -> String {
    "pageview".into()
}

/// 1x1 transparent GIF (43 bytes).
const PIXEL_GIF: &[u8] = &[
    0x47, 0x49, 0x46, 0x38, 0x39, 0x61, 0x01, 0x00, 0x01, 0x00, 0x80, 0x00, 0x00, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0x21, 0xf9, 0x04, 0x01, 0x00, 0x00, 0x00, 0x00, 0x2c, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x01, 0x00, 0x00, 0x02, 0x01, 0x44, 0x00, 0x3b,
];

/// Handle pixel.
pub async fn pixel(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<PixelQuery>,
) -> Result<Response, (StatusCode, String)> {
    let envelope = EventEnvelope {
        event_id: Uuid::new_v4(),
        client_id: q.client_id,
        property_id: q.property_id,
        property_slug: None,
        client_type: "web".into(),
        event_type: q.event_type,
        event_name: q.event_name.unwrap_or_else(|| "pixel".into()),
        timestamp: chrono::Utc::now(),
        subject_id: None,
        event_category: None,
        page_url: q.url,
        page_title: q.title,
        referrer: None,
        screen_name: None,
        app_version: None,
        geo: None,
        device: None,
        traffic_source: None,
        conversions: vec![],
        engagement_time_ms: 0,
        metrics: serde_json::Value::Null,
        props: serde_json::Value::Object(serde_json::Map::new()),
        props_pii_stripped: false,
    };
    // Best-effort ingest — pixel must return 200 even if ingest fails.
    let _ = ingest_one(&state, &headers, envelope).await;
    let resp = Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "image/gif")
        .header("cache-control", "no-store")
        .body(axum::body::Body::from(PIXEL_GIF))
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("response build failed: {e}"),
            )
        })?;
    Ok(resp)
}

// ── Shorthand endpoints ──────────────────────────────────────────────────

/// `POST /v1/m/pageview`
/// Handle pageview.
pub async fn pageview(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<types::PageviewRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    let envelope = EventEnvelope {
        event_id: Uuid::new_v4(),
        client_id: req.client_id,
        property_id: req.property_id,
        property_slug: None,
        client_type: "web".into(),
        event_type: "pageview".into(),
        event_name: "pageview".into(),
        timestamp: chrono::Utc::now(),
        subject_id: req.subject_id,
        event_category: None,
        page_url: Some(req.url),
        page_title: req.title,
        referrer: req.referrer,
        screen_name: None,
        app_version: None,
        geo: None,
        device: None,
        traffic_source: None,
        conversions: vec![],
        engagement_time_ms: 0,
        metrics: serde_json::Value::Null,
        props: req.props,
        props_pii_stripped: false,
    };
    ingest_one(&state, &headers, envelope).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `POST /v1/m/event`
/// Handle event.
pub async fn event(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<types::EventRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    let envelope = EventEnvelope {
        event_id: Uuid::new_v4(),
        client_id: req.client_id,
        property_id: req.property_id,
        property_slug: None,
        client_type: "web".into(),
        event_type: "event".into(),
        event_name: req.name,
        timestamp: chrono::Utc::now(),
        subject_id: req.subject_id,
        event_category: req.category,
        page_url: None,
        page_title: None,
        referrer: None,
        screen_name: None,
        app_version: None,
        geo: None,
        device: None,
        traffic_source: None,
        conversions: vec![],
        engagement_time_ms: 0,
        metrics: serde_json::Value::Null,
        props: req.props,
        props_pii_stripped: false,
    };
    ingest_one(&state, &headers, envelope).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `POST /v1/m/conversion`
/// Handle conversion.
pub async fn conversion(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<types::ConversionShorthandRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    let envelope = EventEnvelope {
        event_id: Uuid::new_v4(),
        client_id: req.client_id,
        property_id: req.property_id,
        property_slug: None,
        client_type: "web".into(),
        event_type: "conversion".into(),
        event_name: "conversion".into(),
        timestamp: chrono::Utc::now(),
        subject_id: req.subject_id,
        event_category: None,
        page_url: None,
        page_title: None,
        referrer: None,
        screen_name: None,
        app_version: None,
        geo: None,
        device: None,
        traffic_source: None,
        conversions: req.conversions,
        engagement_time_ms: 0,
        metrics: serde_json::Value::Null,
        props: req.props,
        props_pii_stripped: false,
    };
    ingest_one(&state, &headers, envelope).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `POST /v1/m/metric` — server-only telemetry (requires `sentin8:stat:measure`).
/// Handle metric.
pub async fn metric(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<types::MetricRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    // M2M token required.
    let _a = auth::require_measure(&state.config, &headers).await?;
    let envelope = EventEnvelope {
        event_id: Uuid::new_v4(),
        client_id: "server".into(),
        property_id: req.property_id,
        property_slug: None,
        client_type: "server".into(),
        event_type: "metric".into(),
        event_name: req.name,
        timestamp: chrono::Utc::now(),
        subject_id: None,
        event_category: None,
        page_url: None,
        page_title: None,
        referrer: None,
        screen_name: None,
        app_version: None,
        geo: None,
        device: None,
        traffic_source: None,
        conversions: vec![],
        engagement_time_ms: 0,
        metrics: req.metrics,
        props: req.dim_tags,
        props_pii_stripped: false,
    };
    ingest_one(&state, &headers, envelope).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `POST /v1/m/batch` — server-side batch (M2M required, higher limits).
/// Handle batch.
pub async fn batch(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<StatusCode, (StatusCode, String)> {
    let _a = auth::require_measure(&state.config, &headers).await?;
    // 2x the standard batch limit for server batches.
    let max = state.config.collect_batch_max * 2;
    let max_bytes = state.config.collect_body_max_bytes * 4;
    if body.len() > max_bytes {
        return Err((StatusCode::PAYLOAD_TOO_LARGE, "body too large".into()));
    }
    let parsed: CollectBody = serde_json::from_slice(&body)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("invalid JSON: {e}")))?;
    let envelopes: Vec<EventEnvelope> = match parsed {
        CollectBody::Single(e) => vec![*e],
        CollectBody::Batch(v) => v,
    };
    if envelopes.len() > max {
        return Err((
            StatusCode::PAYLOAD_TOO_LARGE,
            format!("batch exceeds {max} events"),
        ));
    }
    for envelope in envelopes {
        ingest_one(&state, &headers, envelope).await?;
    }
    Ok(StatusCode::NO_CONTENT)
}
