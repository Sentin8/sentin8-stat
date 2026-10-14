// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Stat
// SPDX-License-Identifier: Apache-2.0

//! Stat Admin API — properties, accounts, settings, retention.
//!
//! Stories Requires `sentin8:stat:admin` scope.

use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use serde::Deserialize;
use serde::Serialize;
use sqlx::Row;
use uuid::Uuid;

use crate::admin_ui::TargetEnvQuery;
use crate::auth;
use crate::handlers::AppState;
use crate::store;
use crate::types;

fn auth_scope(a: &auth::AuthContext) -> String {
    a.claims.scope.clone()
}

fn err_db(e: sqlx::Error) -> (StatusCode, String) {
    (StatusCode::INTERNAL_SERVER_ERROR, format!("db error: {e}"))
}

/// Resolve the tenant env an admin operation targets.
///
/// Fix A: `target_env_id` is REQUIRED on admin
/// endpoints — no fallback to the token's `env_id` (the CLI's token carries
/// the system env, so a silent fallback leaks cross-tenant data and, in the
/// delegated-token path, silently misroutes CRUD to the wrong env). 400 when
/// missing/unparsable.
fn target_env(q: &TargetEnvQuery) -> Result<Uuid, (StatusCode, String)> {
    q.target_env_id
        .as_deref()
        .and_then(|s| Uuid::parse_str(s).ok())
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "missing target_env_id".into()))
}

/// `POST /v1/admin/properties`
#[utoipa::path(
    post,
    operation_id = "property.create",
    path = "/v1/admin/properties",
    request_body = types::CreatePropertyRequest,
    responses(
        (status = 200, description = "Property created", body = types::Property),
        (status = 403, description = "Missing stat:admin scope"),
    ),
    security(("sentin8:stat:admin" = [])),
    tag = "stat",
)]
pub async fn create_property(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<TargetEnvQuery>,
    Json(req): Json<types::CreatePropertyRequest>,
) -> Result<Json<types::Property>, (StatusCode, String)> {
    let a = auth::require_admin(&state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:stat:data:read"),
    )
    .await?;
    let env_id = target_env(&q)?;
    let prop = store::create_property(
        &state.pool,
        env_id,
        &a.claims.sub,
        &auth_scope(&a),
        a.is_platform_admin(),
        &req,
    )
    .await?;
    emit_audit(&state, &a, "create", "property", &prop.id.to_string()).await;
    emit_event(
        &state.pool,
        env_id,
        "sentin8:stat:property:created",
        serde_json::to_value(&prop).unwrap_or_default(),
    )
    .await;
    Ok(Json(prop))
}

/// `GET /v1/admin/properties`
#[utoipa::path(
    get,
    operation_id = "property.list",
    path = "/v1/admin/properties",
    responses(
        (status = 200, description = "List of properties", body = [types::Property]),
        (status = 403, description = "Missing stat:admin scope"),
    ),
    security(("sentin8:stat:admin" = [])),
    tag = "stat",
)]
pub async fn list_properties(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<TargetEnvQuery>,
) -> Result<Json<Vec<types::Property>>, (StatusCode, String)> {
    let a = auth::require_admin(&state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:stat:data:read"),
    )
    .await?;
    let env_id = target_env(&q)?;
    let props = store::list_properties(
        &state.pool,
        env_id,
        &a.claims.sub,
        &auth_scope(&a),
        a.is_platform_admin(),
    )
    .await?;
    Ok(Json(props))
}

/// `GET /v1/admin/properties/{id}`
#[utoipa::path(
    get,
    operation_id = "property.get",
    path = "/v1/admin/properties/{id}",
    params(("id" = Uuid, Path, description = "Property ID")),
    responses(
        (status = 200, description = "Property", body = types::Property),
        (status = 404, description = "Property not found"),
        (status = 403, description = "Missing stat:admin scope"),
    ),
    security(("sentin8:stat:admin" = [])),
    tag = "stat",
)]
pub async fn get_property(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<TargetEnvQuery>,
    Path(id): Path<Uuid>,
) -> Result<Json<types::Property>, (StatusCode, String)> {
    let a = auth::require_admin(&state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:stat:data:read"),
    )
    .await?;
    let env_id = target_env(&q)?;
    let prop = store::get_property(
        &state.pool,
        env_id,
        &a.claims.sub,
        &auth_scope(&a),
        a.is_platform_admin(),
        id,
    )
    .await?;
    Ok(Json(prop))
}

/// `PUT /v1/admin/properties/{id}`
#[utoipa::path(
    put,
    operation_id = "property.update",
    path = "/v1/admin/properties/{id}",
    params(("id" = Uuid, Path, description = "Property ID")),
    request_body = types::UpdatePropertyRequest,
    responses(
        (status = 200, description = "Property updated", body = types::Property),
        (status = 404, description = "Property not found"),
        (status = 403, description = "Missing stat:admin scope"),
    ),
    security(("sentin8:stat:admin" = [])),
    tag = "stat",
)]
pub async fn update_property(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<TargetEnvQuery>,
    Path(id): Path<Uuid>,
    Json(req): Json<types::UpdatePropertyRequest>,
) -> Result<Json<types::Property>, (StatusCode, String)> {
    let a = auth::require_admin(&state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:stat:data:read"),
    )
    .await?;
    let env_id = target_env(&q)?;
    let prop = store::update_property(
        &state.pool,
        env_id,
        &a.claims.sub,
        &auth_scope(&a),
        a.is_platform_admin(),
        id,
        &req,
    )
    .await?;
    emit_audit(&state, &a, "update", "property", &id.to_string()).await;
    emit_event(
        &state.pool,
        env_id,
        "sentin8:stat:property:updated",
        serde_json::to_value(&prop).unwrap_or_default(),
    )
    .await;
    Ok(Json(prop))
}

/// `DELETE /v1/admin/properties/{id}`
#[utoipa::path(
    delete,
    operation_id = "property.delete",
    path = "/v1/admin/properties/{id}",
    params(("id" = Uuid, Path, description = "Property ID")),
    responses(
        (status = 204, description = "Property deleted"),
        (status = 404, description = "Property not found"),
        (status = 403, description = "Missing stat:admin scope"),
    ),
    security(("sentin8:stat:admin" = [])),
    tag = "stat",
)]
pub async fn delete_property(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<TargetEnvQuery>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, (StatusCode, String)> {
    let a = auth::require_admin(&state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:stat:data:read"),
    )
    .await?;
    let env_id = target_env(&q)?;
    store::delete_property(
        &state.pool,
        env_id,
        &a.claims.sub,
        &auth_scope(&a),
        a.is_platform_admin(),
        id,
    )
    .await?;
    emit_audit(&state, &a, "delete", "property", &id.to_string()).await;
    emit_event(
        &state.pool,
        env_id,
        "sentin8:stat:property:deleted",
        serde_json::json!({ "id": id }),
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

/// `PUT /v1/admin/properties/{id}/retention`
#[utoipa::path(
    put,
    operation_id = "retention.set",
    path = "/v1/admin/properties/{id}/retention",
    params(("id" = Uuid, Path, description = "Property ID")),
    request_body = types::RetentionRequest,
    responses(
        (status = 204, description = "Retention set"),
        (status = 403, description = "Missing stat:admin scope"),
    ),
    security(("sentin8:stat:admin" = [])),
    tag = "stat",
)]
pub async fn set_retention(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<TargetEnvQuery>,
    Path(id): Path<Uuid>,
    Json(req): Json<types::RetentionRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    let a = auth::require_admin(&state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:stat:data:read"),
    )
    .await?;
    let env_id = target_env(&q)?;
    store::set_retention(
        &state.pool,
        env_id,
        &a.claims.sub,
        &auth_scope(&a),
        a.is_platform_admin(),
        id,
        &req,
    )
    .await?;
    emit_audit(&state, &a, "update", "retention", &id.to_string()).await;
    Ok(StatusCode::NO_CONTENT)
}

/// `GET /v1/admin/properties/{id}/settings`
#[utoipa::path(
    get,
    operation_id = "setting.get",
    path = "/v1/admin/properties/{id}/settings",
    params(("id" = Uuid, Path, description = "Property ID")),
    responses(
        (status = 200, description = "Property settings"),
        (status = 403, description = "Missing stat:admin scope"),
    ),
    security(("sentin8:stat:admin" = [])),
    tag = "stat",
)]
pub async fn get_settings(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<TargetEnvQuery>,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let a = auth::require_admin(&state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:stat:data:read"),
    )
    .await?;
    let env_id = target_env(&q)?;
    let prop = store::get_property(
        &state.pool,
        env_id,
        &a.claims.sub,
        &auth_scope(&a),
        a.is_platform_admin(),
        id,
    )
    .await?;
    Ok(Json(serde_json::json!({
        "session_timeout_minutes": prop.session_timeout_minutes,
        "timezone": prop.timezone,
        "bot_filter_enabled": prop.bot_filter_enabled,
        "pii_deny_list": prop.pii_deny_list,
    })))
}

/// `PUT /v1/admin/properties/{id}/settings`
#[utoipa::path(
    put,
    operation_id = "setting.update",
    path = "/v1/admin/properties/{id}/settings",
    params(("id" = Uuid, Path, description = "Property ID")),
    request_body = types::SettingsUpdate,
    responses(
        (status = 204, description = "Settings updated"),
        (status = 403, description = "Missing stat:admin scope"),
    ),
    security(("sentin8:stat:admin" = [])),
    tag = "stat",
)]
pub async fn update_settings(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<TargetEnvQuery>,
    Path(id): Path<Uuid>,
    Json(req): Json<types::SettingsUpdate>,
) -> Result<StatusCode, (StatusCode, String)> {
    let a = auth::require_admin(&state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:stat:data:read"),
    )
    .await?;
    let env_id = target_env(&q)?;
    store::update_settings(
        &state.pool,
        env_id,
        &a.claims.sub,
        &auth_scope(&a),
        a.is_platform_admin(),
        id,
        &req,
    )
    .await?;
    emit_audit(&state, &a, "update", "settings", &id.to_string()).await;
    Ok(StatusCode::NO_CONTENT)
}

// ── Reaggregate (stat README §7) ───────────────────────────────────────

/// Request body for `POST /v1/admin/properties/{id}/reaggregate` — the
/// raw-events window to rebuild. Both fields accept RFC 3339 timestamps;
/// omitted fields default per `parse_reaggregate_window` (full omission =
/// last 30 days).
#[derive(Debug, Clone, Default, Deserialize, utoipa::ToSchema)]
/// The reaggregaterequest type.
pub struct ReaggregateRequest {
    #[serde(default)]
    /// Inclusive window start (RFC 3339).
    pub from: Option<String>,
    #[serde(default)]
    /// Inclusive window end (RFC 3339).
    pub to: Option<String>,
}

/// A per-property custom alert rule (`stat.alert_rules`, stat README §7).
#[derive(Debug, Clone, Serialize, utoipa::ToSchema)]
/// The alertrule type.
pub struct AlertRule {
    /// Identifier.
    pub id: Uuid,
    /// env identifier.
    pub env_id: Uuid,
    /// Watched property identifier.
    pub property_id: Uuid,
    /// Display name.
    pub name: String,
    /// Rule type — `threshold` (metric value vs threshold) or `anomaly`
    /// (moving-average deviation factor over the window).
    pub rule_type: String,
    /// Metric vocabulary key (`events.count`, `conversions.count`,
    /// `metric:{name}`).
    pub metric_name: String,
    /// Comparator — `gt` | `gte` | `lt` | `lte`.
    pub comparator: String,
    /// Comparison threshold (metric value or deviation factor).
    pub threshold: f64,
    /// Moving-average lookback in hours (`anomaly` rules).
    pub window_hours: i32,
    /// Noise floor — the rule never evaluates below it.
    pub min_sample: i32,
    /// Whether the rule evaluates.
    pub enabled: bool,
    /// created time.
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// updated time.
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

/// Request body for `POST /v1/admin/properties/{id}/alert-rules`.
#[derive(Debug, Clone, Deserialize, utoipa::ToSchema)]
/// Request body for createalertrule.
pub struct CreateAlertRuleRequest {
    /// Display name.
    pub name: String,
    /// `threshold` or `anomaly`.
    pub rule_type: String,
    /// Metric vocabulary key (`events.count`, `conversions.count`,
    /// `metric:{name}`).
    pub metric_name: String,
    /// `gt` | `gte` | `lt` | `lte`.
    pub comparator: String,
    /// Comparison threshold (metric value, or deviation factor for
    /// `anomaly` — e.g. `3.0` = current exceeds 3× the baseline).
    pub threshold: f64,
    #[serde(default = "default_window_hours")]
    /// Moving-average lookback in hours (`anomaly` rules).
    pub window_hours: i32,
    #[serde(default = "default_min_sample")]
    /// Noise floor — the rule never evaluates below it.
    pub min_sample: i32,
    #[serde(default = "default_enabled")]
    /// Whether the rule evaluates.
    pub enabled: bool,
}

/// Default anomaly lookback (`stat.alert_rules.window_hours`).
fn default_window_hours() -> i32 {
    24
}

/// Default noise floor (`stat.alert_rules.min_sample`).
fn default_min_sample() -> i32 {
    10
}

/// Default enabled (`stat.alert_rules.enabled`).
fn default_enabled() -> bool {
    true
}

/// Validate a create-alert-rule request against the known rule types,
/// comparators, and metric vocabulary — 400 message on the first unknown
/// field (stat DESIGN §4: rules are validated against the aggregates at
/// create time so the evaluator never encounters an unmapped metric).
fn validate_alert_rule(req: &CreateAlertRuleRequest) -> Result<(), (StatusCode, String)> {
    if req.name.trim().is_empty() {
        return Err((StatusCode::BAD_REQUEST, "name must not be empty".into()));
    }
    if req.rule_type != "threshold" && req.rule_type != "anomaly" {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "unknown rule_type {:?} (expected 'threshold' or 'anomaly')",
                req.rule_type
            ),
        ));
    }
    if !matches!(req.comparator.as_str(), "gt" | "gte" | "lt" | "lte") {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "unknown comparator {:?} (expected gt, gte, lt, or lte)",
                req.comparator
            ),
        ));
    }
    if crate::worker::alerts::metric_source(&req.metric_name).is_none() {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "unknown metric_name {:?} (expected 'events.count', \
                 'conversions.count', or 'metric:<name>')",
                req.metric_name
            ),
        ));
    }
    if !req.threshold.is_finite() || req.threshold.is_nan() {
        return Err((StatusCode::BAD_REQUEST, "threshold must be finite".into()));
    }
    if req.window_hours < 1 {
        return Err((StatusCode::BAD_REQUEST, "window_hours must be >= 1".into()));
    }
    if req.min_sample < 0 {
        return Err((StatusCode::BAD_REQUEST, "min_sample must be >= 0".into()));
    }
    Ok(())
}

fn row_to_alert_rule(r: sqlx::postgres::PgRow) -> AlertRule {
    AlertRule {
        id: r.get("id"),
        env_id: r.get("env_id"),
        property_id: r.get("property_id"),
        name: r.get("name"),
        rule_type: r.get("rule_type"),
        metric_name: r.get("metric_name"),
        comparator: r.get("comparator"),
        threshold: r.get("threshold"),
        window_hours: r.get("window_hours"),
        min_sample: r.get("min_sample"),
        enabled: r.get("enabled"),
        created_at: r.get("created_at"),
        updated_at: r.get("updated_at"),
    }
}

/// `POST /v1/admin/properties/{id}/reaggregate`
///
/// Delete and rebuild the property's day-granularity `metrics` rollups over
/// a raw-events window (stat README §7). v1 reaggregates from `stat.events`
/// ONLY — a window reaching past the property's retention horizon is a 400
/// (the spilled raw data lives in Storage archives; per stat DESIGN §4.3.6
/// the archive spill is the source-of-truth boundary and the Storage-archive
/// replay path is out of scope for this endpoint). The recomputation shares the
/// background rollup's SQL via
/// `crate::worker::rollups::reaggregate_property`.
#[utoipa::path(
    post,
    operation_id = "property.reaggregate",
    path = "/v1/admin/properties/{id}/reaggregate",
    params(
        ("id" = Uuid, Path, description = "Property ID"),
        ("target_env_id" = String, Query, description = "Target env (required)"),
    ),
    request_body = ReaggregateRequest,
    responses(
        (status = 200, description = "Rollups rebuilt over the window"),
        (status = 400, description = "Invalid window, window beyond the retention horizon, or property not in env"),
        (status = 404, description = "Property not found"),
        (status = 403, description = "Missing stat:admin scope"),
    ),
    security(("sentin8:stat:admin" = [])),
    tag = "stat",
)]
pub async fn reaggregate(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<TargetEnvQuery>,
    Path(id): Path<Uuid>,
    Json(req): Json<ReaggregateRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let a = auth::require_admin(&state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:stat:data:read"),
    )
    .await?;
    let env_id = target_env(&q)?;

    let window =
        crate::worker::rollups::parse_reaggregate_window(req.from.as_deref(), req.to.as_deref())
            .map_err(|e| (StatusCode::BAD_REQUEST, e))?;

    // Property existence + env scoping + retention read — one
    // context-set transaction, mirroring the store's read pattern so the
    // horizon check runs on the property's own retention setting.
    let retention_days = {
        let mut conn = state.pool.begin().await.map_err(err_db)?;
        crate::store::set_rls(
            &mut conn,
            env_id,
            &a.claims.sub,
            &a.claims.token_tp,
            &auth_scope(&a),
            a.is_platform_admin(),
        )
        .await?;
        let row = sqlx::query("SELECT retention_days FROM properties WHERE id = $1")
            .bind(id)
            .fetch_optional(&mut *conn)
            .await
            .map_err(err_db)?
            .ok_or((StatusCode::NOT_FOUND, "property not found".into()))?;
        let days: i32 = row.get("retention_days");
        conn.commit().await.map_err(err_db)?;
        days
    };

    crate::worker::rollups::check_window_horizon(&window, retention_days, chrono::Utc::now())
        .map_err(|e| (StatusCode::BAD_REQUEST, e))?;

    let recomputed = crate::worker::rollups::reaggregate_property(&state.pool, id, &window)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;

    emit_audit_details(
        &state,
        &a,
        "reaggregate",
        serde_json::json!({
            "action": "reaggregate",
            "resource_type": "property",
            "resource_id": id,
            "actor": a.claims.sub,
            "from": window.from.to_rfc3339(),
            "to": window.to.to_rfc3339(),
            "from_day": window.from_day.to_string(),
            "to_day": window.to_day.to_string(),
            "recomputed": recomputed,
        }),
    )
    .await;

    Ok(Json(serde_json::json!({
        "property_id": id,
        "from": window.from.to_rfc3339(),
        "to": window.to.to_rfc3339(),
        "recomputed": recomputed,
    })))
}

/// `GET /v1/admin/accounts`
#[utoipa::path(
    get,
    operation_id = "account.list",
    path = "/v1/admin/accounts",
    responses(
        (status = 200, description = "List of accounts", body = [types::Account]),
        (status = 403, description = "Missing stat:admin scope"),
    ),
    security(("sentin8:stat:admin" = [])),
    tag = "stat",
)]
pub async fn list_accounts(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<TargetEnvQuery>,
) -> Result<Json<Vec<types::Account>>, (StatusCode, String)> {
    let a = auth::require_admin(&state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:stat:data:read"),
    )
    .await?;
    let env_id = target_env(&q)?;
    let accounts = store::list_accounts(
        &state.pool,
        env_id,
        &a.claims.sub,
        &auth_scope(&a),
        a.is_platform_admin(),
    )
    .await?;
    Ok(Json(accounts))
}

/// `POST /v1/admin/accounts`
#[utoipa::path(
    post,
    operation_id = "account.create",
    path = "/v1/admin/accounts",
    request_body = types::CreateAccountRequest,
    responses(
        (status = 200, description = "Account created", body = types::Account),
        (status = 403, description = "Missing stat:admin scope"),
    ),
    security(("sentin8:stat:admin" = [])),
    tag = "stat",
)]
pub async fn create_account(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<TargetEnvQuery>,
    Json(req): Json<types::CreateAccountRequest>,
) -> Result<Json<types::Account>, (StatusCode, String)> {
    let a = auth::require_admin(&state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:stat:data:read"),
    )
    .await?;
    let env_id = target_env(&q)?;
    let account = store::create_account(
        &state.pool,
        env_id,
        &a.claims.sub,
        &auth_scope(&a),
        a.is_platform_admin(),
        &req,
    )
    .await?;
    emit_event(
        &state.pool,
        env_id,
        "sentin8:stat:account:created",
        serde_json::to_value(&account).unwrap_or_default(),
    )
    .await;
    emit_audit(&state, &a, "create", "account", &account.id.to_string()).await;
    Ok(Json(account))
}

// ── Alert rules (stat README §7, stat DESIGN §3/§4) ────────────────────

const ALERT_RULE_SELECT: &str = "id, env_id, property_id, name, rule_type, metric_name, comparator, threshold, window_hours, min_sample, enabled, created_at, updated_at";

/// `POST /v1/admin/properties/{id}/alert-rules`
///
/// Create a per-property custom alert rule (stat README §7). The request
/// is validated against the known rule types, comparators, and metric
/// vocabulary (400 on unknown); the property must exist in the target
/// env (404). The INSERT runs in one explicit transaction with the RLS
/// context set on the same connection (stat DESIGN §5).
#[utoipa::path(
    post,
    operation_id = "alert_rule.create",
    path = "/v1/admin/properties/{id}/alert-rules",
    params(
        ("id" = Uuid, Path, description = "Property ID"),
        ("target_env_id" = String, Query, description = "Target env (required)"),
    ),
    request_body = CreateAlertRuleRequest,
    responses(
        (status = 200, description = "Rule created", body = AlertRule),
        (status = 400, description = "Unknown rule_type, comparator, or metric_name; invalid threshold/window"),
        (status = 404, description = "Property not found in env"),
        (status = 403, description = "Missing stat:admin scope"),
    ),
    security(("sentin8:stat:admin" = [])),
    tag = "stat",
)]
pub async fn create_alert_rule(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<TargetEnvQuery>,
    Path(id): Path<Uuid>,
    Json(req): Json<CreateAlertRuleRequest>,
) -> Result<Json<AlertRule>, (StatusCode, String)> {
    let a = auth::require_admin(&state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:stat:data:read"),
    )
    .await?;
    let env_id = target_env(&q)?;
    validate_alert_rule(&req)?;

    let mut conn = state.pool.begin().await.map_err(err_db)?;
    store::set_rls(
        &mut conn,
        env_id,
        &a.claims.sub,
        &a.claims.token_tp,
        &auth_scope(&a),
        a.is_platform_admin(),
    )
    .await?;
    let row = sqlx::query(&format!(
        r#"INSERT INTO alert_rules
               (env_id, property_id, name, rule_type, metric_name,
                comparator, threshold, window_hours, min_sample, enabled)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
           RETURNING {ALERT_RULE_SELECT}"#
    ))
    .bind(env_id)
    .bind(id)
    .bind(req.name.trim())
    .bind(&req.rule_type)
    .bind(&req.metric_name)
    .bind(&req.comparator)
    .bind(req.threshold)
    .bind(req.window_hours)
    .bind(req.min_sample)
    .bind(req.enabled)
    .fetch_one(&mut *conn)
    .await
    .map_err(|e| {
        // FK to properties — the property does not exist in this env.
        if e.to_string().contains("foreign key") {
            (StatusCode::NOT_FOUND, "property not found".into())
        } else {
            err_db(e)
        }
    })?;
    conn.commit().await.map_err(err_db)?;
    let rule = row_to_alert_rule(row);
    emit_audit(&state, &a, "create", "alert_rule", &rule.id.to_string()).await;
    emit_event(
        &state.pool,
        env_id,
        "sentin8:stat:alert_rule:created",
        serde_json::to_value(&rule).unwrap_or_default(),
    )
    .await;
    Ok(Json(rule))
}

/// `GET /v1/admin/properties/{id}/alert-rules`
#[utoipa::path(
    get,
    operation_id = "alert_rule.list",
    path = "/v1/admin/properties/{id}/alert-rules",
    params(
        ("id" = Uuid, Path, description = "Property ID"),
        ("target_env_id" = String, Query, description = "Target env (required)"),
    ),
    responses(
        (status = 200, description = "Rules for the property", body = [AlertRule]),
        (status = 403, description = "Missing stat:admin scope"),
    ),
    security(("sentin8:stat:admin" = [])),
    tag = "stat",
)]
pub async fn list_alert_rules(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<TargetEnvQuery>,
    Path(id): Path<Uuid>,
) -> Result<Json<Vec<AlertRule>>, (StatusCode, String)> {
    let a = auth::require_admin(&state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:stat:data:read"),
    )
    .await?;
    let env_id = target_env(&q)?;

    let mut conn = state.pool.begin().await.map_err(err_db)?;
    store::set_rls(
        &mut conn,
        env_id,
        &a.claims.sub,
        &a.claims.token_tp,
        &auth_scope(&a),
        a.is_platform_admin(),
    )
    .await?;
    let rows = sqlx::query(&format!(
        "SELECT {ALERT_RULE_SELECT} FROM alert_rules \
         WHERE env_id = $1 AND property_id = $2 ORDER BY created_at DESC"
    ))
    .bind(env_id)
    .bind(id)
    .fetch_all(&mut *conn)
    .await
    .map_err(err_db)?;
    conn.commit().await.map_err(err_db)?;
    Ok(Json(rows.into_iter().map(row_to_alert_rule).collect()))
}

/// `DELETE /v1/admin/properties/{id}/alert-rules/{rule_id}`
#[utoipa::path(
    delete,
    operation_id = "alert_rule.delete",
    path = "/v1/admin/properties/{id}/alert-rules/{rule_id}",
    params(
        ("id" = Uuid, Path, description = "Property ID"),
        ("rule_id" = Uuid, Path, description = "Alert rule ID"),
        ("target_env_id" = String, Query, description = "Target env (required)"),
    ),
    responses(
        (status = 204, description = "Rule deleted"),
        (status = 404, description = "Rule not found"),
        (status = 403, description = "Missing stat:admin scope"),
    ),
    security(("sentin8:stat:admin" = [])),
    tag = "stat",
)]
pub async fn delete_alert_rule(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<TargetEnvQuery>,
    Path((id, rule_id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, (StatusCode, String)> {
    let a = auth::require_admin(&state.config, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:stat:data:read"),
    )
    .await?;
    let env_id = target_env(&q)?;

    let mut conn = state.pool.begin().await.map_err(err_db)?;
    store::set_rls(
        &mut conn,
        env_id,
        &a.claims.sub,
        &a.claims.token_tp,
        &auth_scope(&a),
        a.is_platform_admin(),
    )
    .await?;
    let res =
        sqlx::query("DELETE FROM alert_rules WHERE id = $1 AND property_id = $2 AND env_id = $3")
            .bind(rule_id)
            .bind(id)
            .bind(env_id)
            .execute(&mut *conn)
            .await
            .map_err(err_db)?;
    conn.commit().await.map_err(err_db)?;
    if res.rows_affected() == 0 {
        return Err((StatusCode::NOT_FOUND, "alert rule not found".into()));
    }
    emit_audit(&state, &a, "delete", "alert_rule", &rule_id.to_string()).await;
    emit_event(
        &state.pool,
        env_id,
        "sentin8:stat:alert_rule:deleted",
        serde_json::json!({ "id": rule_id, "property_id": id }),
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

/// Emit an audit event for Admin API calls.
async fn emit_audit(
    state: &AppState,
    a: &auth::AuthContext,
    action: &str,
    resource: &str,
    id: &str,
) {
    emit_audit_details(
        state,
        a,
        action,
        serde_json::json!({
            "action": action,
            "resource_type": resource,
            "resource_id": id,
            "actor": a.claims.sub,
        }),
    )
    .await;
}

/// Emit an audit journal row with caller-provided `details` — the
/// reaggregate write records the rebuilt window (stat DESIGN §5
/// "Audit journaling": admin writes land in `audit_journal`, best-effort).
async fn emit_audit_details(
    state: &AppState,
    a: &auth::AuthContext,
    action: &str,
    details: serde_json::Value,
) {
    let _ = sqlx::query(
        r#"INSERT INTO audit_journal (id, env_id, action, details)
           VALUES ($1, $2, $3, $4)"#,
    )
    .bind(uuid::Uuid::new_v4())
    .bind(a.env_id())
    .bind(action)
    .bind(details)
    .execute(&state.pool)
    .await;
}

/// Append an event to the service's local `stat.outbox` for Bus relay
/// (DBX §6.7: local outbox + produce API). The outbox is FORCE-RLS'd, and
/// `set_config(..., true)` is TRANSACTION-local — so the context set and
/// the INSERT share ONE explicit transaction (a bare `pool.acquire()` runs
/// each statement in its own autocommit transaction and the context
/// evaporates before the INSERT — stat DESIGN §5).
async fn emit_event(
    pool: &sqlx::PgPool,
    env_id: uuid::Uuid,
    event_type: &str,
    payload: serde_json::Value,
) {
    let mut tx = match pool.begin().await {
        Ok(t) => t,
        Err(e) => {
            tracing::warn!(error = %e, event_type = %event_type, "stat: failed to begin tx for outbox event");
            return;
        }
    };
    let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
        .bind(env_id)
        .execute(&mut *tx)
        .await;
    let _ = sentin8::bus::outbox::insert_outbox_row(
        &mut *tx,
        env_id,
        "stat",
        event_type,
        &payload,
    )
    .await
    .map_err(|e| {
        tracing::warn!(error = %e, event_type = %event_type, "stat: failed to emit outbox event");
        e
    });
    if let Err(e) = tx.commit().await {
        tracing::warn!(error = %e, event_type = %event_type, "stat: failed to commit outbox event tx");
    }
}
