// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Stat
// SPDX-License-Identifier: Apache-2.0

//! The embedded analytics pipeline worker (design stat DESIGN.md §2).
//!
//! Background tasks spawned at service state build: a Bus SSE consumer
//! runs the 7-stage pipeline over `stat-events`, a 30s DB fallback poll
//! catches anything the Bus missed, and the rollup / alert / Valkey
//! subscriber / archive-sweep loops run on their own cadences.

pub mod alerts;
pub mod audit_consumer;
pub mod pipeline;
pub mod rollups;
pub mod telemetry_sub;
pub mod valkey_sub;

use std::sync::Arc;

use futures_util::StreamExt;
use sentin8::bus::client::BusClient;
use tokio::time::Duration;
use uuid::Uuid;

use crate::config::StatConfig;

/// Reconnect delay when the Bus SSE connection drops.
const RECONNECT_DELAY: Duration = Duration::from_secs(2);
/// DB fallback poll interval - safety net for unprocessed events.
const DB_FALLBACK_INTERVAL: Duration = Duration::from_secs(30);
/// Archive sweep cadence (stat design §4.3.6): hourly.
const ARCHIVE_SWEEP_INTERVAL_SECS: u64 = 3600;
/// Bus stream family the ingest plane enqueues onto.
const INGEST_STREAM_FAMILY: &str = "stat-events";
/// Consumer group for the embedded pipeline.
const CONSUMER_GROUP: &str = "stat";
/// Max events per DB fallback pass.
const CONSUME_BATCH: u32 = 25;
/// Max retries before a message is moved to the DLQ.
const MAX_RETRIES: u32 = 3;

/// Spawn every worker task. Called once at service state build - the
/// tasks run until process shutdown and share the service's capped pool.
pub async fn spawn(pool: sqlx::PgPool, config: &StatConfig, bus: BusClient) {
    // Curated alert evaluator - every 60s, reads aggregate_*_daily
    // and produces `sentin8:stat:alert:event_spike` /
    // `sentin8:stat:alert:conversion_drop` events via Bus HTTP API
    // (fire-and-forget).
    {
        let alert_pool = pool.clone();
        let bus_url = config.sentin8_bus_url.clone();
        let issuer = config.sentin8_auth_issuer.clone();
        tokio::spawn(async move {
            let bus = sentin8::bus::client::BusClient::for_workload(&bus_url, &issuer, "stat")
                .await
                .expect("stat bus client certificate");
            alerts::run_alert_evaluator(alert_pool, bus).await;
        });
    }

    // Multi-granularity rollup - every 60s, aggregates
    // aggregate_metrics_daily into rollups at minute, hour, day, week,
    // month, year granularities, then publishes a
    // `stat:rollups:*` snapshot to Valkey so Dash's MetricsTable gets
    // live updates via BFF's pub/sub (no HTTP polling).
    {
        let rollup_pool = pool.clone();
        let rollup_bus_url = config.sentin8_bus_url.clone();
        let rollup_issuer = config.sentin8_auth_issuer.clone();
        tokio::spawn(async move {
            let bus = sentin8::bus::client::BusClient::for_workload(
                &rollup_bus_url,
                &rollup_issuer,
                "stat",
            )
            .await
            .expect("stat bus client certificate");
            rollups::run_rollup_loop(rollup_pool, bus).await;
        });
    }

    // Valkey pub/sub subscriber - subscribes to `stat:metrics:tls` and
    // `stat:metrics:log`, aggregates into minute/hour/day rollups, and
    // publishes back to `stat:rollups:{granularity}` channels.
    {
        let valkey_url = config.valkey_url.clone();
        tokio::spawn(async move {
            if let Err(e) = valkey_sub::run_valkey_subscriber(valkey_url).await {
                tracing::error!(error = %e, "stat: Valkey subscriber loop exited");
            }
        });
    }

    // MemBus telemetry ingest (SDD §2.3): subscribes to the
    // `stat.telemetry` Pub/Sub family - shield decision frames and
    // service metric frames - decodes, resolves the emitter slug, and
    // inserts on the store path. Ephemeral class: no ack/retry/DLQ; a
    // stat outage drops frames by contract (non-important updates).
    {
        let telemetry_pool = pool.clone();
        let valkey_url = config.valkey_url.clone();
        tokio::spawn(async move {
            if let Err(e) =
                telemetry_sub::run_telemetry_subscriber(telemetry_pool, valkey_url).await
            {
                tracing::error!(error = %e, "stat: telemetry subscriber loop exited");
            }
        });
    }

    // Archive sweep (stat design §4.3.6): hourly spill of expired raw
    // events to Storage (`stat-archive/...`), then deletion. Retention is
    // each property's retention_days; a failed pass leaves rows queued.
    {
        let archive_pool = pool.clone();
        let storage_url = config.sentin8_storage_url.clone();
        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(std::time::Duration::from_secs(ARCHIVE_SWEEP_INTERVAL_SECS));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                interval.tick().await;
                match pipeline::run_archive_sweep(&archive_pool, &storage_url).await {
                    Ok(summary) if summary.total_archived > 0 => {
                        tracing::info!(
                            archived = summary.total_archived,
                            deleted = summary.total_deleted,
                            "archive sweep completed"
                        );
                    }
                    Ok(_) => {}
                    Err(e) => {
                        tracing::warn!(error = %e, "archive sweep failed - rows stay queued");
                    }
                }
            }
        });
    }

    // Audit-volume consumer (STATW-2): SSE subscription to
    // `sentin8:sys:audit:recorded` (family `sys`, group `stat-audit`)
    // feeding the per-service audit-volume aggregate.
    {
        let audit_pool = pool.clone();
        let audit_bus_url = config.sentin8_bus_url.clone();
        let audit_issuer = config.sentin8_auth_issuer.clone();
        tokio::spawn(async move {
            let bus = sentin8::bus::client::BusClient::for_workload(
                &audit_bus_url,
                &audit_issuer,
                "stat-audit",
            )
            .await
            .expect("stat-audit bus client certificate");
            audit_consumer::spawn(audit_pool, bus);
        });
    }

    // SSE consumer task - single Server-Sent Events connection to Bus
    // (no HTTP polling). One connection per stream family is enough;
    // Bus pushes messages as they arrive.
    let state = Arc::new(WorkerState { pool, bus });
    tokio::spawn(sse_consume_loop(state.clone()));

    // DB fallback poll - safety net for unprocessed events (every 30s).
    // If the Bus enqueue in the ingest path fails (network issue, Bus
    // restart, etc.), events still get processed via this periodic scan.
    let db_state = state.clone();
    tokio::spawn(db_fallback_loop(db_state));
}

struct WorkerState {
    pool: sqlx::PgPool,
    bus: BusClient,
}

/// SSE consumer loop - connect to Bus via Server-Sent Events, receive
/// pushed messages, process each event, and ACK via the HTTP ack
/// endpoint. No HTTP polling. Reconnects on disconnect with a 2s
/// backoff.
async fn sse_consume_loop(state: Arc<WorkerState>) {
    tracing::info!(
        stream_family = INGEST_STREAM_FAMILY,
        consumer_group = CONSUMER_GROUP,
        "stat: bus SSE consumer starting"
    );

    loop {
        let resp = match state
            .bus
            .sse_consume(INGEST_STREAM_FAMILY, CONSUMER_GROUP)
            .await
        {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(error = %e, "stat: sse_consume failed; retrying in 2s");
                tokio::time::sleep(RECONNECT_DELAY).await;
                continue;
            }
        };

        tracing::info!(
            stream_family = INGEST_STREAM_FAMILY,
            "stat: bus SSE connected"
        );

        let mut buffer = String::new();
        let mut stream = resp.bytes_stream();

        let mut stream_error = false;
        while let Some(chunk_result) = stream.next().await {
            let chunk = match chunk_result {
                Ok(c) => c,
                Err(e) => {
                    tracing::warn!(error = %e, "stat: bus SSE stream error");
                    stream_error = true;
                    break;
                }
            };
            buffer.push_str(&String::from_utf8_lossy(&chunk));

            // Process complete events (separated by \n\n)
            while let Some(pos) = buffer.find("\n\n") {
                let event_text = buffer[..pos].to_string();
                buffer = buffer[pos + 2..].to_string();

                let mut data_line = String::new();
                for line in event_text.lines() {
                    if let Some(d) = line.strip_prefix("data: ") {
                        data_line = d.to_string();
                    }
                    // `id:` lines and `:` comments (heartbeats) are skipped -
                    // ACKs use message_id from the JSON data.
                }

                if data_line.is_empty() {
                    continue;
                }

                let msg: serde_json::Value = match serde_json::from_str(&data_line) {
                    Ok(v) => v,
                    Err(_) => continue,
                };

                let message_id = msg["message_id"].as_str().unwrap_or("").to_string();

                // Extract the event_id from the payload (falls back to message_id).
                let event_id: String = msg["payload"]
                    .get("event_id")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
                    .unwrap_or(message_id.clone());
                let event_uuid = match Uuid::parse_str(&event_id) {
                    Ok(u) => u,
                    Err(_) => {
                        tracing::warn!(
                            event_id = %event_id,
                            "invalid event_id UUID, skipping"
                        );
                        // ACK to advance the cursor even on skip.
                        let _ = state
                            .bus
                            .ack(INGEST_STREAM_FAMILY, CONSUMER_GROUP, &message_id)
                            .await;
                        continue;
                    }
                };

                match process_one(&state, event_uuid).await {
                    Ok(()) => {
                        let _ = state
                            .bus
                            .ack(INGEST_STREAM_FAMILY, CONSUMER_GROUP, &message_id)
                            .await;
                    }
                    Err(e) => {
                        tracing::warn!(
                            error = %e,
                            event_id = %event_id,
                            "process failed"
                        );
                        // Nack via HTTP so Bus tracks retries / DLQ.
                        let _ = nack_with_retry(&state, &message_id).await;
                        // ACK to move on (DLQ handles poison messages).
                        let _ = state
                            .bus
                            .ack(INGEST_STREAM_FAMILY, CONSUMER_GROUP, &message_id)
                            .await;
                    }
                }
            }
        }

        if !stream_error {
            tracing::info!(
                stream_family = INGEST_STREAM_FAMILY,
                "stat: bus SSE stream ended; reconnecting in 2s"
            );
        }
        tokio::time::sleep(RECONNECT_DELAY).await;
    }
}

/// DB fallback poll - every 30s, scan for unprocessed events as a safety
/// net in case the Bus enqueue in the ingest path fails (network issue,
/// Bus restart, etc.). This runs alongside the SSE consumer.
async fn db_fallback_loop(state: Arc<WorkerState>) {
    loop {
        tokio::time::sleep(DB_FALLBACK_INTERVAL).await;
        if let Ok(rows) = sqlx::query_scalar::<_, uuid::Uuid>(
            r#"SELECT id FROM events
               WHERE processed = false
               ORDER BY created_at
               LIMIT $1"#,
        )
        .bind(CONSUME_BATCH as i64)
        .fetch_all(&state.pool)
        .await
        {
            for event_uuid in rows {
                match process_one(&state, event_uuid).await {
                    Ok(()) => {
                        tracing::info!(event_id = %event_uuid, "processed via DB fallback")
                    }
                    Err(e) => tracing::warn!(
                        error = %e,
                        event_id = %event_uuid,
                        "DB fallback process failed"
                    ),
                }
            }
        }
    }
}

/// Process one event through the pipeline.
async fn process_one(state: &WorkerState, event_id: Uuid) -> Result<(), String> {
    let mut event = pipeline::EventRecord::load(&state.pool, event_id)
        .await
        .map_err(|e| format!("load: {e}"))?
        .ok_or_else(|| "event not found".to_string())?;
    pipeline::run_pipeline(&state.pool, &mut event).await
}

/// Nack with retry - after max retries, the Bus DLQ handles poison messages.
async fn nack_with_retry(state: &WorkerState, message_id: &str) -> Result<(), String> {
    // The Bus nack endpoint tracks retries server-side; after max_retries it
    // moves the message to the DLQ. We call nack with the retry count.
    for _ in 0..MAX_RETRIES {
        let res = state
            .bus
            .nack(INGEST_STREAM_FAMILY, CONSUMER_GROUP, message_id, Some(1))
            .await;
        if res.is_ok() {
            return Ok(());
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
    Err(format!(
        "nack failed after {MAX_RETRIES} retries for {message_id}"
    ))
}
