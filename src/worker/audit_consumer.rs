// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Stat
// SPDX-License-Identifier: Apache-2.0

//! Audit-volume consumer — SSE subscription to `sentin8:sys:audit:recorded`
//! (stat DESIGN.md §2, STATW-2).
//!
//! Sys's `POST /v1/audit` ingest API fans out one
//! `sentin8:sys:audit:recorded` event per ingested audit record on the
//! `sys` stream family (local outbox → shell relay → Bus). This module
//! consumes that stream as consumer group `stat-audit` and increments the
//! per-service audit-volume counter into `aggregate_metrics_daily`
//! (`audit.events`, dimensions `{service, severity}`), so audit volume is
//! queryable through the standard metrics pipeline (rollups + DSL).
//!
//! The event payload identifies the emitting service; the matching
//! platform-telemetry property is resolved by slug (each service's
//! property slug equals its name — see the properties seed in
//! `sql/init.sql`). Events whose service has no property are counted
//! against the `sys` property (the platform plane).
//!
//! Delivery is Bus at-least-once; ACK advances the consumer group. A
//! redelivered event may double-increment within the same day bucket —
//! accepted for volume analytics.

use std::sync::Arc;

use futures_util::StreamExt;
use sqlx::Row;

use sentin8::bus::client::BusClient;

/// Bus stream family the audit fan-out lands on (sys outbox family).
const AUDIT_STREAM_FAMILY: &str = "sys";
/// Consumer group for this consumer (declared as the `stat-audit` M2M
/// workload in `registration.rs`).
const AUDIT_CONSUMER_GROUP: &str = "stat-audit";
/// Reconnect delay when the Bus SSE connection drops.
const RECONNECT_DELAY: std::time::Duration = std::time::Duration::from_secs(2);
/// Fallback property slug when the emitting service has no telemetry
/// property (the platform plane).
const FALLBACK_SLUG: &str = "sys";

/// Spawn the audit-volume consumer loop. Called once at service state
/// build; runs until process shutdown, sharing the service's capped pool.
pub fn spawn(pool: sqlx::PgPool, bus: BusClient) {
    tokio::spawn(async move {
        audit_consume_loop(Arc::new(AuditConsumerState { pool, bus })).await;
    });
}

struct AuditConsumerState {
    pool: sqlx::PgPool,
    bus: BusClient,
}

/// SSE consume loop — same shape as the ingest plane's `sse_consume_loop`:
/// one long-lived Server-Sent Events connection to Bus, each `data:` line
/// a JSON `ConsumeMessage`, ACK via the HTTP ack endpoint, reconnect with
/// a 2s backoff.
async fn audit_consume_loop(state: Arc<AuditConsumerState>) {
    tracing::info!(
        stream_family = AUDIT_STREAM_FAMILY,
        consumer_group = AUDIT_CONSUMER_GROUP,
        "stat: audit-volume consumer starting"
    );

    loop {
        let resp = match state
            .bus
            .sse_consume(AUDIT_STREAM_FAMILY, AUDIT_CONSUMER_GROUP)
            .await
        {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(error = %e, "stat: audit sse_consume failed; retrying in 2s");
                tokio::time::sleep(RECONNECT_DELAY).await;
                continue;
            }
        };

        tracing::info!(
            stream_family = AUDIT_STREAM_FAMILY,
            "stat: audit-volume consumer connected"
        );

        let mut buffer = String::new();
        let mut stream = resp.bytes_stream();

        let mut stream_error = false;
        while let Some(chunk_result) = stream.next().await {
            let chunk = match chunk_result {
                Ok(c) => c,
                Err(e) => {
                    tracing::warn!(error = %e, "stat: audit SSE stream error");
                    stream_error = true;
                    break;
                }
            };
            buffer.push_str(&String::from_utf8_lossy(&chunk));

            while let Some(pos) = buffer.find("\n\n") {
                let event_text = buffer[..pos].to_string();
                buffer = buffer[pos + 2..].to_string();

                let mut data_line = String::new();
                for line in event_text.lines() {
                    if let Some(d) = line.strip_prefix("data: ") {
                        data_line = d.to_string();
                    }
                }
                if data_line.is_empty() {
                    continue;
                }

                let msg: serde_json::Value = match serde_json::from_str(&data_line) {
                    Ok(v) => v,
                    Err(_) => continue,
                };

                let message_id = msg["message_id"].as_str().unwrap_or("").to_string();
                let payload = msg
                    .get("payload")
                    .cloned()
                    .unwrap_or_else(|| serde_json::json!({}));

                match record_audit_event(&state, &payload).await {
                    Ok(()) => {
                        let _ = state
                            .bus
                            .ack(AUDIT_STREAM_FAMILY, AUDIT_CONSUMER_GROUP, &message_id)
                            .await;
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "stat: audit event processing failed — NOT acked (bus redelivery retries)");
                        // No ACK on failure: Bus at-least-once redelivers the
                        // message to the group instead of silently dropping
                        // the sample. A poison message is bounded by the
                        // relay's retry budget semantics (worker DESIGN §2).
                    }
                }
            }
        }

        let _ = stream_error;
        tracing::warn!("stat: audit SSE disconnected; reconnecting in 2s");
        tokio::time::sleep(RECONNECT_DELAY).await;
    }
}

/// Increment the `audit.events` counter for the emitting service.
///
/// The payload carries `service` (stamped by the producer), `severity`, and
/// the tenant `env_id`. The property is resolved by slug — the payload's
/// service name is the colon `vertical:service` form while property slugs
/// are bare (stat DESIGN §2), so the vertical prefix is stripped (payload
/// completeness is the producer's contract; the consumer tolerates both
/// shapes). The whole flow runs in ONE explicit transaction with the
/// context set on the same connection: `set_config(..., true)` is
/// transaction-local, so an autocommit context-set evaporates before the
/// next statement and FORCE-RLS filters every row (stat DESIGN §5).
async fn record_audit_event(
    state: &AuditConsumerState,
    payload: &serde_json::Value,
) -> Result<(), String> {
    let service_raw = payload["service"].as_str().unwrap_or(FALLBACK_SLUG);
    // Colon service_type (`sentin8:sys`) → bare property slug (`sys`).
    let service = service_raw.rsplit(':').next().unwrap_or(service_raw);
    let severity = payload["severity"].as_str().unwrap_or("info");
    let env_id = payload["env_id"]
        .as_str()
        .and_then(|v| uuid::Uuid::parse_str(v).ok());

    // ONE explicit transaction: context-set (system env, the slug plane is
    // platform-wide) → property resolve (target slug, fallback `sys`) →
    // context re-scope to the property's env → upsert → commit.
    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|e| format!("begin tx: {e}"))?;
    let _ = sqlx::query("SELECT sentin8_set_tenant_context($1, '', '', '', false, false)")
        .bind(sentin8::config::SYSTEM_ENV_ID)
        .execute(&mut *tx)
        .await;

    let (property_id, property_env_id) = {
        let row = sqlx::query(
            "SELECT id, env_id FROM properties WHERE slug = $1 AND status = 'active' LIMIT 1",
        )
        .bind(service)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| format!("resolve property: {e}"))?;
        match row {
            Some(r) => (
                r.get::<uuid::Uuid, _>("id"),
                r.get::<uuid::Uuid, _>("env_id"),
            ),
            None => {
                // No property for this service — fall back to the sys
                // property; if even that is missing (pre-seed boot), skip.
                let row = sqlx::query(
                    "SELECT id, env_id FROM properties WHERE slug = $1 AND status = 'active' LIMIT 1",
                )
                .bind(FALLBACK_SLUG)
                .fetch_optional(&mut *tx)
                .await
                .map_err(|e| format!("resolve fallback property: {e}"))?;
                row.map(|r| {
                    (
                        r.get::<uuid::Uuid, _>("id"),
                        r.get::<uuid::Uuid, _>("env_id"),
                    )
                })
                .ok_or_else(|| "no telemetry property (sys) found".to_string())?
            }
        }
    };

    // The increment rides the property's env context (RLS).
    let _ = sqlx::query("SELECT sentin8_set_tenant_context($1, '', '', '', false, false)")
        .bind(property_env_id)
        .execute(&mut *tx)
        .await;

    let day = chrono::Utc::now().date_naive();
    let dims = serde_json::json!({
        "service": service,
        "severity": severity,
        // Tenant env from the payload (payload completeness — the consumer
        // never calls back). Absent → the property's own env.
        "env_id": env_id.map(|v| v.to_string()).unwrap_or_default(),
    });
    let dims_json = serde_json::to_string(&dims).unwrap_or_else(|_| "{}".into());
    // Same non-crypto dimension hash as the pipeline's `sha256_hash`
    // (pipeline.rs) — deterministic bucket key, not a security boundary.
    let dims_hash = {
        let mut h: u128 = 0x6a09e667f3bcc908;
        for b in dims_json.as_bytes() {
            h = h.wrapping_mul(0x100000001b3).wrapping_add(*b as u128);
        }
        format!("{:x}", h)
    };

    sqlx::query(
        r#"INSERT INTO aggregate_metrics_daily
           (env_id, property_id, day, metric_name, dimensions,
            dimensions_hash, value_type, value)
           VALUES ($1, $2, $3, $4, $5, $6, 'counter', 1)
           ON CONFLICT (property_id, day, metric_name, dimensions_hash)
           DO UPDATE SET value = aggregate_metrics_daily.value + 1,
                         updated_at = now()"#,
    )
    .bind(property_env_id)
    .bind(property_id)
    .bind(day)
    .bind("audit.events")
    .bind(&dims)
    .bind(&dims_hash)
    .execute(&mut *tx)
    .await
    .map_err(|e| format!("audit volume increment: {e}"))?;

    tx.commit().await.map_err(|e| format!("commit tx: {e}"))?;
    Ok(())
}
