// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Stat
// SPDX-License-Identifier: Apache-2.0

//! Stat Data API - reports, metrics time-series, sessions, funnels,
//! retention, realtime, and the aggregate-query DSL.
//!
//! Requires the `sentin8:stat:data:read` scope.

use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use serde::Deserialize;
use uuid::Uuid;

use crate::auth;
use crate::handlers::AppState;
use crate::store;
use crate::types;

fn auth_scope(a: &auth::AuthContext) -> String {
    a.claims.scope.clone()
}

/// Resolve `property_id` - if the caller didn't supply one, use the first
/// active property for the org/env.
async fn resolve_property_id(
    state: &AppState,
    a: &auth::AuthContext,
    property_id: Option<Uuid>,
) -> Result<Uuid, (StatusCode, String)> {
    if let Some(id) = property_id {
        return Ok(id);
    }
    let props = store::list_properties(
        &state.pool,
        a.env_id(),
        &a.claims.sub,
        &auth_scope(a),
        a.is_platform_admin(),
    )
    .await?;
    props.first().map(|p| p.id).ok_or((
        StatusCode::NOT_FOUND,
        "no properties found for this org/env".into(),
    ))
}

#[derive(Debug, Deserialize, utoipa::IntoParams, utoipa::ToSchema)]
/// The reportquery type.
pub struct ReportQuery {
    #[serde(default)]
    /// property identifier.
    pub property_id: Option<Uuid>,
    #[serde(default)]
    /// The from.
    pub from: Option<chrono::NaiveDate>,
    #[serde(default)]
    /// The to.
    pub to: Option<chrono::NaiveDate>,
}

fn date_range(
    q: &ReportQuery,
) -> Result<(chrono::NaiveDate, chrono::NaiveDate), (StatusCode, String)> {
    let to = q.to.unwrap_or_else(|| chrono::Utc::now().date_naive());
    let from = q.from.unwrap_or(to - chrono::Duration::days(30));
    if from > to {
        return Err((StatusCode::BAD_REQUEST, "from must be <= to".into()));
    }
    Ok((from, to))
}

/// `GET /v1/data/reports` - list available report templates.
/// List reports.
#[utoipa::path(
    get,
    path = "/v1/data/reports",
    params(ReportQuery),
    responses(
        (status = 200, description = "Saved reports for this property", body = Vec<serde_json::Value>),
        (status = 403, description = "Missing stat:data:read scope"),
    ),
    security(("sentin8:stat:data:read" = [])),
    tag = "data",
)]
pub async fn list_reports(
    State(_state): State<AppState>,
    _headers: HeaderMap,
) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "reports": [
            "events-over-time",
            "top-pages",
            "traffic-sources",
            "conversions",
            "retention",
            "funnel",
            "metrics-over-time"
        ]
    }))
}

/// `GET /v1/data/reports/{report_id}` - run a pre-canned report.
/// Run report.
#[utoipa::path(
    get,
    path = "/v1/data/reports/{report_id}",
    params(("report_id" = String, Path, description = "Report id")),
    responses(
        (status = 200, description = "The report's result rows", body = serde_json::Value),
        (status = 403, description = "Missing stat:data:read scope"),
        (status = 404, description = "Unknown report"),
    ),
    security(("sentin8:stat:data:read" = [])),
    tag = "data",
)]
pub async fn run_report(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(report_id): Path<String>,
    Query(q): Query<ReportQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let a = auth::require_data_read(&state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:stat:data:read"),
    )
    .await?;
    let (from, to) = date_range(&q)?;
    let property_id = resolve_property_id(&state, &a, q.property_id).await?;
    let table = match report_id.as_str() {
        "events-over-time" => "sentin8_stat_aggregate_events_daily",
        "sessions" => "sentin8_stat_aggregate_sessions_daily",
        "conversions" => "sentin8_stat_aggregate_conversions_daily",
        "traffic-sources" => "sentin8_stat_aggregate_traffic_source_daily",
        "geo" => "sentin8_stat_aggregate_geo_daily",
        "device" => "sentin8_stat_aggregate_device_daily",
        "engagement" => "sentin8_stat_aggregate_engagement_daily",
        _ => return Err((StatusCode::NOT_FOUND, "unknown report".into())),
    };
    let rows = store::read_aggregate(
        &state.pool,
        a.env_id(),
        &a.claims.sub,
        &auth_scope(&a),
        a.is_platform_admin(),
        table,
        property_id,
        from,
        to,
    )
    .await?;
    Ok(Json(
        serde_json::json!({ "report": report_id, "rows": rows }),
    ))
}

#[derive(Debug, Deserialize)]
/// The metricsquery type.
pub struct MetricsQuery {
    #[serde(default)]
    /// property identifier.
    pub property_id: Option<Uuid>,
    /// The metric.
    pub metric: String,
    #[serde(default)]
    /// The from.
    pub from: Option<chrono::NaiveDate>,
    #[serde(default)]
    /// The to.
    pub to: Option<chrono::NaiveDate>,
}

/// `GET /v1/data/metrics` - server-telemetry time-series from
/// `sentin8_stat_aggregate_metrics_daily`.
/// Handle metrics.
#[utoipa::path(
    get,
    path = "/v1/data/metrics",
    params(ReportQuery),
    responses(
        (status = 200, description = "Aggregated metrics", body = Vec<serde_json::Value>),
        (status = 403, description = "Missing stat:data:read scope"),
    ),
    security(("sentin8:stat:data:read" = [])),
    tag = "data",
)]
pub async fn metrics(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<MetricsQuery>,
) -> Result<Json<Vec<types::MetricPoint>>, (StatusCode, String)> {
    let a = auth::require_data_read(&state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:stat:data:read"),
    )
    .await?;
    let to = q.to.unwrap_or_else(|| chrono::Utc::now().date_naive());
    let from = q.from.unwrap_or(to - chrono::Duration::days(30));
    let property_id = resolve_property_id(&state, &a, q.property_id).await?;
    let points = store::read_metrics_daily(
        &state.pool,
        a.env_id(),
        &a.claims.sub,
        &auth_scope(&a),
        a.is_platform_admin(),
        property_id,
        &q.metric,
        from,
        to,
    )
    .await?;
    Ok(Json(points))
}

/// `GET /v1/data/traffic` - TLS inter-service traffic matrix.
///
/// Returns per-`(from_service, to_service)` summary rows (count, average
/// latency, errors) aggregated from the `tls.traffic.*` metrics that
/// TLS flushes every 10 seconds. Used by Dash's `MetricsTable` widget
/// for system/org/env metrics.
/// Handle traffic.
#[utoipa::path(
    get,
    path = "/v1/data/traffic",
    params(ReportQuery),
    responses(
        (status = 200, description = "Traffic summaries", body = Vec<serde_json::Value>),
        (status = 403, description = "Missing stat:data:read scope"),
    ),
    security(("sentin8:stat:data:read" = [])),
    tag = "data",
)]
pub async fn traffic(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<ReportQuery>,
) -> Result<Json<Vec<types::TrafficSummary>>, (StatusCode, String)> {
    let a = auth::require_data_read(&state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:stat:data:read"),
    )
    .await?;
    let (from, to) = date_range(&q)?;
    let property_id = resolve_property_id(&state, &a, q.property_id).await?;
    let rows = store::read_traffic_summary(
        &state.pool,
        a.env_id(),
        &a.claims.sub,
        &auth_scope(&a),
        a.is_platform_admin(),
        property_id,
        from,
        to,
    )
    .await?;
    Ok(Json(rows))
}

/// `GET /v1/data/sessions` - session breakdown.
/// Handle sessions.
#[utoipa::path(
    get,
    path = "/v1/data/sessions",
    params(ReportQuery),
    responses(
        (status = 200, description = "Session rows", body = Vec<serde_json::Value>),
        (status = 403, description = "Missing stat:data:read scope"),
    ),
    security(("sentin8:stat:data:read" = [])),
    tag = "data",
)]
pub async fn sessions(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<ReportQuery>,
) -> Result<Json<Vec<types::AggregateRow>>, (StatusCode, String)> {
    let a = auth::require_data_read(&state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:stat:data:read"),
    )
    .await?;
    let (from, to) = date_range(&q)?;
    let property_id = resolve_property_id(&state, &a, q.property_id).await?;
    let rows = store::read_aggregate(
        &state.pool,
        a.env_id(),
        &a.claims.sub,
        &auth_scope(&a),
        a.is_platform_admin(),
        "sentin8_stat_aggregate_sessions_daily",
        property_id,
        from,
        to,
    )
    .await?;
    Ok(Json(rows))
}

/// `POST /v1/data/funnels` - define a funnel.
/// Create funnel.
#[utoipa::path(
    post,
    path = "/v1/data/funnels",
    request_body = types::CreateFunnelRequest,
    responses(
        (status = 200, description = "Funnel created", body = types::Funnel),
        (status = 403, description = "Missing stat:data:write scope"),
    ),
    security(("sentin8:stat:data:write" = [])),
    tag = "data",
)]
pub async fn create_funnel(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<types::CreateFunnelRequest>,
) -> Result<Json<types::Funnel>, (StatusCode, String)> {
    let a = auth::require_data_read(&state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:stat:data:read"),
    )
    .await?;
    let funnel = store::create_funnel(
        &state.pool,
        a.env_id(),
        &a.claims.sub,
        &auth_scope(&a),
        a.is_platform_admin(),
        &req,
    )
    .await?;
    emit_event(
        &state.pool,
        a.env_id(),
        "sentin8:stat:funnel:created",
        serde_json::to_value(&funnel).unwrap_or_default(),
    )
    .await;
    Ok(Json(funnel))
}

/// `GET /v1/data/funnels/{id}` - funnel report.
/// Fetch funnel.
#[utoipa::path(
    get,
    path = "/v1/data/funnels/{id}",
    params(("id" = String, Path, description = "Funnel id")),
    responses(
        (status = 200, description = "Funnel steps + drop-off", body = serde_json::Value),
        (status = 403, description = "Missing stat:data:read scope"),
        (status = 404, description = "Unknown funnel"),
    ),
    security(("sentin8:stat:data:read" = [])),
    tag = "data",
)]
pub async fn get_funnel(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<types::Funnel>, (StatusCode, String)> {
    let a = auth::require_data_read(&state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:stat:data:read"),
    )
    .await?;
    let funnel = store::get_funnel(
        &state.pool,
        a.env_id(),
        &a.claims.sub,
        &auth_scope(&a),
        a.is_platform_admin(),
        id,
    )
    .await?;
    Ok(Json(funnel))
}

#[derive(Debug, Deserialize)]
/// The retentionquery type.
pub struct RetentionQuery {
    #[serde(default)]
    /// property identifier.
    pub property_id: Option<Uuid>,
    #[serde(default)]
    /// The from.
    pub from: Option<chrono::NaiveDate>,
    #[serde(default)]
    /// The to.
    pub to: Option<chrono::NaiveDate>,
}

/// `GET /v1/data/retention` - cohort retention (reads sessions aggregate).
/// Handle retention.
#[utoipa::path(
    get,
    path = "/v1/data/retention",
    params(ReportQuery),
    responses(
        (status = 200, description = "Retention cohorts", body = serde_json::Value),
        (status = 403, description = "Missing stat:data:read scope"),
    ),
    security(("sentin8:stat:data:read" = [])),
    tag = "data",
)]
pub async fn retention(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<RetentionQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let a = auth::require_data_read(&state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:stat:data:read"),
    )
    .await?;
    let to = q.to.unwrap_or_else(|| chrono::Utc::now().date_naive());
    let from = q.from.unwrap_or(to - chrono::Duration::days(30));
    let property_id = resolve_property_id(&state, &a, q.property_id).await?;
    let rows = store::read_aggregate(
        &state.pool,
        a.env_id(),
        &a.claims.sub,
        &auth_scope(&a),
        a.is_platform_admin(),
        "sentin8_stat_aggregate_sessions_daily",
        property_id,
        from,
        to,
    )
    .await?;
    Ok(Json(serde_json::json!({ "cohort": rows })))
}

/// `GET /v1/data/realtime` - real-time active users (last 5 min, in-memory).
///
/// Uses a Valkey sorted-set counter keyed by minute.
/// Handle realtime.
#[utoipa::path(
    get,
    path = "/v1/data/realtime",
    responses(
        (status = 200, description = "Realtime counters (active sessions, recent events)", body = serde_json::Value),
        (status = 403, description = "Missing stat:data:read scope"),
    ),
    security(("sentin8:stat:data:read" = [])),
    tag = "data",
)]
pub async fn realtime(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<ReportQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let a = auth::require_data_read(&state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:stat:data:read"),
    )
    .await?;
    let property_id = resolve_property_id(&state, &a, q.property_id).await?;
    let now = chrono::Utc::now().timestamp();
    let cutoff = now - 300; // 5 minutes ago
    let conn = state.valkey.clone();
    let key = format!("stat:realtime:{}", property_id);
    use glide::AsyncCommands as _;
    let count: Result<i64, _> = conn.zcount(key, cutoff, now).await;
    let active = count.unwrap_or(0);
    Ok(Json(
        serde_json::json!({ "property_id": property_id, "active_users": active }),
    ))
}

#[derive(Debug, Deserialize)]
/// The querydsl type.
pub struct QueryDsl {
    /// property identifier.
    pub property_id: Uuid,
    /// The table.
    pub table: String,
    #[serde(default)]
    /// The from.
    pub from: Option<chrono::NaiveDate>,
    #[serde(default)]
    /// The to.
    pub to: Option<chrono::NaiveDate>,
}

const ALLOWED_TABLES: &[&str] = &[
    "sentin8_stat_aggregate_events_daily",
    "sentin8_stat_aggregate_sessions_daily",
    "sentin8_stat_aggregate_conversions_daily",
    "sentin8_stat_aggregate_engagement_daily",
    "sentin8_stat_aggregate_geo_daily",
    "sentin8_stat_aggregate_device_daily",
    "sentin8_stat_aggregate_traffic_source_daily",
    "sentin8_stat_aggregate_metrics_daily",
];

/// `POST /v1/data/query` - arbitrary aggregate query (JSON DSL, aggregates only).
/// Handle query.
#[utoipa::path(
    post,
    path = "/v1/data/query",
    request_body = serde_json::Value,
    responses(
        (status = 200, description = "Query result rows", body = serde_json::Value),
        (status = 400, description = "Invalid query"),
        (status = 403, description = "Missing stat:data:read scope"),
    ),
    security(("sentin8:stat:data:read" = [])),
    tag = "data",
)]
pub async fn query(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<QueryDsl>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let a = auth::require_data_read(&state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:stat:data:read"),
    )
    .await?;
    if !ALLOWED_TABLES.contains(&req.table.as_str()) {
        return Err((
            StatusCode::BAD_REQUEST,
            "QueryRequiresRawScan: only aggregate tables are allowed".into(),
        ));
    }
    let to = req.to.unwrap_or_else(|| chrono::Utc::now().date_naive());
    let from = req.from.unwrap_or(to - chrono::Duration::days(30));
    if req.table == "sentin8_stat_aggregate_metrics_daily" {
        let rows = store::read_aggregate(
            &state.pool,
            a.env_id(),
            &a.claims.sub,
            &auth_scope(&a),
            a.is_platform_admin(),
            &req.table,
            req.property_id,
            from,
            to,
        )
        .await?;
        return Ok(Json(serde_json::json!({ "rows": rows })));
    }
    let rows = store::read_aggregate(
        &state.pool,
        a.env_id(),
        &a.claims.sub,
        &auth_scope(&a),
        a.is_platform_admin(),
        &req.table,
        req.property_id,
        from,
        to,
    )
    .await?;
    Ok(Json(serde_json::json!({ "rows": rows })))
}

/// Append an event to the service's local `stat.outbox` for Bus relay
/// (DBX §6.7: local outbox + produce API). The outbox is FORCE-RLS'd, so we
/// acquire a connection, set the tenant context, then INSERT on that same
/// connection. The post-commit relay (shell step 8b) pushes the row to Bus
/// `POST /v1/produce` with stat's M2M token.
async fn emit_event(
    pool: &sqlx::PgPool,
    env_id: uuid::Uuid,
    event_type: &str,
    payload: serde_json::Value,
) {
    let mut conn = match pool.acquire().await {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(error = %e, event_type = %event_type, "stat: failed to acquire connection for outbox event");
            return;
        }
    };
    let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
        .bind(env_id)
        .execute(&mut *conn)
        .await;
    let _ = sentin8::bus::outbox::insert_outbox_row(
        &mut *conn, env_id, "stat", event_type, &payload,
    )
    .await
    .map_err(|e| {
        tracing::warn!(error = %e, event_type = %event_type, "stat: failed to emit outbox event");
        e
    });
}
