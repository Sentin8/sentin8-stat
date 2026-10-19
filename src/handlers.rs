// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Stat
// SPDX-License-Identifier: Apache-2.0

//! Shared handler state + health endpoint for Stat.

use std::sync::Arc;

use axum::{extract::State, Json};

use crate::config::StatConfig;

#[derive(Clone)]
/// app state.
pub struct AppState {
    /// The config.
    pub config: Arc<StatConfig>,
    /// The pool.
    pub pool: sqlx::PgPool,
    /// The Valkey GLIDE client.
    pub valkey: glide::GlideClient,
    /// DCR-registered M2M-backed Bus client (built once at startup).
    /// The bus client.
    pub bus_client: sentin8::bus::client::BusClient,
    /// Shield engine ( - ): additional gate after scope.
    /// The policy.
    pub policy: Arc<crate::policy::Engine>,
    /// Shared Sentin8:Policy admin surface ( - one
    /// implementation for every service; mounted in server::routes).
    /// The admin.
    pub admin: sentin8::shield::admin::SharedAdminState,
}

/// Handle health.
#[utoipa::path(
    get,
    path = "/v1/health",
    responses(
        (status = 200, description = "Liveness (version, build, active connections)", body = sentin8::middleware::health::LiveHealth),
    ),
    security(),
    tag = "meta",
)]
pub async fn health(State(_state): State<AppState>) -> Json<serde_json::Value> {
    let mut payload = serde_json::json!({ "status": "ok", "service": "stat", "version": sentin8::build_info::id(), "build": sentin8::build_info::build_hash() });
    if let Some(n) = sentin8::middleware::traffic_counter::process_active_connections() {
        payload["active_connections"] = serde_json::json!(n);
    }
    Json(payload)
}

/// Handle readiness.
#[utoipa::path(
    get,
    path = "/v1/readiness",
    responses(
        (status = 200, description = "Readiness (PG reachable + writer workers)", body = ReadinessResponse),
        (status = 503, description = "Not ready"),
    ),
    security(),
    tag = "meta",
)]
pub async fn readiness(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, (axum::http::StatusCode, String)> {
    let pg_ok = sqlx::query("SELECT 1").execute(&state.pool).await.is_ok();
    if !pg_ok {
        return Err((
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            "database unavailable".into(),
        ));
    }
    Ok(Json(serde_json::json!({
        "status": "ready",
        "checks": { "postgres": "ok" },
    })))
}

/// The `GET /v1/readiness` payload (PG + writer workers).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct ReadinessResponse {
    /// `ready`/`degraded`.
    pub status: String,
    /// Per-dependency check results.
    pub checks: std::collections::BTreeMap<String, String>,
}
