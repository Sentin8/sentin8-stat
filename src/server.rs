// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Stat
// SPDX-License-Identifier: Apache-2.0

//! Axum server setup for Stat.

use axum::routing::{get, post};

use crate::admin_api;
use crate::data_api;
use crate::handlers::{self, AppState};
use crate::ingest;

/// Build state.
pub async fn build_state(
    core: sentin8::shell::ServiceCore,
) -> anyhow::Result<crate::handlers::AppState> {
    let config = crate::config::StatConfig::from_env();
    let valkey = sentin8::middleware::valkey_client(&config.valkey_url, "sentin8:stat").await?;

    // Build the M2M-backed Bus client at startup via DCR (RFC 7591).
    let bus_client = sentin8::bus::client::BusClient::for_workload(
        &config.sentin8_bus_url,
        &config.sentin8_auth_issuer,
        "stat",
    )
    .await
    .expect("stat bus client certificate");

    // ── Sentin8:Policy (— shell-owned boot): consume the
    // engine the shell booted in step 8 — no second engine, consumer, or
    // DCR registration here.
    let policy_engine = core.admin.policy.clone();

    let state = AppState {
        config: std::sync::Arc::new(config.clone()),
        pool: core.pool.clone(),
        valkey,
        bus_client,
        policy: policy_engine.clone(),
        admin: sentin8::shield::admin::SharedAdminState {
            service: "sentin8:stat".to_string(),
            pool: core.pool.clone(),
            policy: policy_engine.clone(),
            auth_client: std::sync::Arc::new(config.auth_client.clone()),
        },
    };

    // Embedded pipeline worker (stat DESIGN.md §2): spawn the Bus SSE
    // consumer, DB fallback poll, rollup loop, alert evaluator, Valkey
    // subscriber, and archive sweep as background tasks. Fail-open: a
    // worker task's failure never affects the ingest/read planes — the
    // 30s DB fallback poll and idempotent loops self-heal.
    crate::worker::spawn(core.pool.clone(), &config, state.bus_client.clone()).await;

    Ok(state)
}

/// Add this service's routes onto the shell-provided router. The shell
/// owns the boot sequence, state binding, OpenAPI merge and the standard
/// middleware stack; this adds ONLY routes (including the service's own
/// `/v1/health` — custom payload).
/// Handle routes.
pub fn routes(
    router: axum::Router<crate::handlers::AppState>,
) -> axum::Router<crate::handlers::AppState> {
    router
        // ── Operational ──────────────────────────────────────────────────
        .route("/v1/health", get(handlers::health))
        // ── Admin UI (RFW) ─────────────────────────────────────────────────
        .route("/v1/admin/ui/{*page}", get(crate::admin_ui::get_admin_ui))
        .route("/v1/admin/{resource}", get(crate::admin_ui::get_admin_data))
        .route("/v1/readiness", get(handlers::readiness))
        // ── Measurement API (/v1/m/*) ───────────────────────────────────
        .route("/v1/m/collect", get(ingest::pixel).post(ingest::collect))
        .route("/v1/m/pageview", post(ingest::pageview))
        .route("/v1/m/event", post(ingest::event))
        .route("/v1/m/conversion", post(ingest::conversion))
        .route("/v1/m/metric", post(ingest::metric))
        .route("/v1/m/batch", post(ingest::batch))
        // ── Data API (/v1/data/*) ──────────────────────────────────────
        .route("/v1/data/reports", get(data_api::list_reports))
        .route("/v1/data/reports/{report_id}", get(data_api::run_report))
        .route("/v1/data/metrics", get(data_api::metrics))
        .route("/v1/data/traffic", get(data_api::traffic))
        .route("/v1/data/sessions", get(data_api::sessions))
        .route("/v1/data/funnels", post(data_api::create_funnel))
        .route("/v1/data/funnels/{id}", get(data_api::get_funnel))
        .route("/v1/data/retention", get(data_api::retention))
        .route("/v1/data/realtime", get(data_api::realtime))
        .route("/v1/data/query", post(data_api::query))
        // ── Admin API (/v1/admin/*) ────────────────────────────────────
        .route(
            "/v1/admin/properties",
            post(admin_api::create_property).get(admin_api::list_properties),
        )
        .route(
            "/v1/admin/properties/{id}",
            get(admin_api::get_property)
                .put(admin_api::update_property)
                .delete(admin_api::delete_property),
        )
        // POST alias for RFW row_action_post (renderer only supports POST)
        .route(
            "/v1/admin/properties/{id}/delete",
            post(admin_api::delete_property),
        )
        .route(
            "/v1/admin/properties/{id}/retention",
            axum::routing::put(admin_api::set_retention),
        )
        .route(
            "/v1/admin/properties/{id}/settings",
            get(admin_api::get_settings).put(admin_api::update_settings),
        )
        .route(
            "/v1/admin/properties/{id}/reaggregate",
            post(admin_api::reaggregate),
        )
        .route(
            "/v1/admin/properties/{id}/alert-rules",
            post(admin_api::create_alert_rule).get(admin_api::list_alert_rules),
        )
        .route(
            "/v1/admin/properties/{id}/alert-rules/{rule_id}",
            axum::routing::delete(admin_api::delete_alert_rule),
        )
        .route(
            "/v1/admin/accounts",
            get(admin_api::list_accounts).post(admin_api::create_account),
        )
        // Traffic counter — counts every inbound request (excludes health checks).
        // ── Sentin8:Policy admin API ( — shared implementation,
        // one surface per service; handlers are generic over this AppState).
        .route(
            "/v1/admin/policy-sets",
            get(sentin8::shield::admin::list_policy_sets::<handlers::AppState>),
        )
        .route(
            "/v1/admin/policy-sets/{name}",
            get(sentin8::shield::admin::get_policy_set::<handlers::AppState>)
                .put(sentin8::shield::admin::put_policy_set::<handlers::AppState>)
                .delete(sentin8::shield::admin::delete_policy_set::<handlers::AppState>),
        )
        .route(
            "/v1/admin/policy-sets/{name}/test",
            post(sentin8::shield::admin::test_policy_set::<handlers::AppState>),
        )
        .route(
            "/v1/admin/policy-sets/enforce",
            post(sentin8::shield::admin::admin_enforce_policy_set::<handlers::AppState>),
        )
        .route(
            "/v1/admin/policy-sets/shadow",
            post(sentin8::shield::admin::admin_shadow_policy_set::<handlers::AppState>),
        )
        .route(
            "/v1/admin/policy-sets/disable",
            post(sentin8::shield::admin::admin_disable_policy_set::<handlers::AppState>),
        )
        .route(
            "/v1/admin/relations",
            get(sentin8::shield::admin::list_relations::<handlers::AppState>)
                .put(sentin8::shield::admin::put_relation::<handlers::AppState>)
                .delete(sentin8::shield::admin::delete_relation::<handlers::AppState>),
        )
        .route(
            "/v1/admin/relations/check",
            get(sentin8::shield::admin::check_relation::<handlers::AppState>),
        )
        .route(
            "/v1/admin/attributes",
            get(sentin8::shield::admin::list_attributes::<handlers::AppState>)
                .put(sentin8::shield::admin::put_attribute::<handlers::AppState>)
                .delete(sentin8::shield::admin::delete_attribute::<handlers::AppState>),
        )
}

/// Shared policy-admin surface accessor — the shared
/// handlers extract this service's admin state via [`HasPolicyAdmin`].
impl sentin8::shield::admin::HasPolicyAdmin for AppState {
    fn policy_admin(&self) -> &sentin8::shield::admin::SharedAdminState {
        &self.admin
    }
}
