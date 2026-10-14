// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Stat
// SPDX-License-Identifier: Apache-2.0

//! Valkey pub/sub subscriber for real-time metrics from tls and log.
//!
//! Subscribes to:
//!   - `stat:metrics:tls` — traffic metrics (count, latency, errors per from→to)
//!   - `stat:metrics:log` — log error/warning counts per service
//!
//! Aggregates incoming metrics into per-minute, per-hour, per-day windows
//! in memory, then publishes rollups to Valkey channels every 10 seconds:
//!   - `stat:rollups:minute` — 60-second window (drained at the minute
//!                              boundary, snapshotted otherwise)
//!   - `stat:rollups:hour`   — rolling 1-hour window (snapshot each
//!                              publish, drained at the hour boundary)
//!   - `stat:rollups:day`    — rolling 24-hour window (snapshot each
//!                              publish, drained at 00:00 UTC)
//!
//! All three channels publish every 10 seconds so consumers get near-real-
//! time visibility into every granularity. The minute buffer is drained
//! when its 60s window elapses; the hour/day buffers are only drained at
//! their window boundary so their published `value` is a true rolling
//! aggregate over the full window.
//!
//! Consumers (e.g. Dash via BFF, Captain) can subscribe to these rollup
//! channels for live aggregated metrics without querying PostgreSQL.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};

/// Incoming metrics message from tls or log.
#[derive(Debug, Deserialize)]
struct MetricsMessage {
    ts: String,
    source: String,
    #[allow(dead_code)]
    window: String,
    #[serde(default)]
    org_id: Option<String>,
    #[serde(default)]
    env_id: Option<String>,
    metrics: serde_json::Value,
}

/// Aggregated metric published in rollups.
#[derive(Debug, Clone, Serialize)]
struct AggregatedMetric {
    source: String,
    org_id: String,
    env_id: String,
    metric: String,
    value: f64,
    count: u64,
    ts: String,
}

/// In-memory aggregation buffer. Keyed by (source, org_id, env_id, metric_name).
type AggKey = (String, String, String, String);
type AggBuffer = Arc<Mutex<HashMap<AggKey, (f64, u64, String)>>>;

/// Run the Valkey subscriber loop. Subscribes to `stat:metrics:tls` and
/// `stat:metrics:log`, aggregates into minute/hour/day buffers, and
/// publishes all three rollups every 10 seconds. The minute buffer is
/// drained at its 60s window boundary; the hour/day buffers snapshot each
/// tick and drain only at their window boundary (top of the hour /
/// 00:00 UTC).
pub async fn run_valkey_subscriber(valkey_url: String) -> anyhow::Result<()> {
    let conn = sentin8::middleware::valkey_client(&valkey_url, "sentin8:stat").await?;

    // Aggregation buffers for each granularity.
    let minute_buf: AggBuffer = Arc::new(Mutex::new(HashMap::new()));
    let hour_buf: AggBuffer = Arc::new(Mutex::new(HashMap::new()));
    let day_buf: AggBuffer = Arc::new(Mutex::new(HashMap::new()));

    // Spawn the rollup publishers. All publish every 10s; each drains its
    // buffer only when its window elapses (minute=60s, hour=3600s,
    // day=00:00 UTC).
    spawn_rollup_publisher(
        conn.clone(),
        "minute",
        Duration::from_secs(10),
        ResetWindow::Every(60),
        minute_buf.clone(),
    );
    spawn_rollup_publisher(
        conn.clone(),
        "hour",
        Duration::from_secs(10),
        ResetWindow::Every(3600),
        hour_buf.clone(),
    );
    spawn_rollup_publisher(
        conn.clone(),
        "day",
        Duration::from_secs(10),
        ResetWindow::Midnight,
        day_buf.clone(),
    );

    // Main message loop — receive metrics and accumulate into all buffers.
    // GLIDE pubsub: ONE pubsub-enabled client subscribes once; the inner
    // loop drains messages WITHOUT tearing the subscription down. Only a
    // terminal channel end (connection closed, Valkey restart) breaks the
    // inner loop, and the outer `loop` re-establishes the subscription —
    // connect-time subscriptions survive glide-core's automatic
    // reconnects in between (group DESIGN.md §3.1).
    'outer: loop {
        let pubsub_client =
            match sentin8::middleware::valkey_client_pubsub(&valkey_url, "sentin8:stat").await {
                Ok(c) => c,
                Err(e) => {
                    tracing::warn!(error = %e, "stat: Valkey pubsub connect failed; retrying in 3s");
                    tokio::time::sleep(Duration::from_secs(3)).await;
                    continue;
                }
            };
        use glide::PubSubCommands as _;
        if let Err(e) = pubsub_client
            .subscribe(&["stat:metrics:tls", "stat:metrics:log"])
            .await
        {
            tracing::warn!(error = %e, "stat: subscribe to metrics channels failed");
            tokio::time::sleep(Duration::from_secs(3)).await;
            continue;
        }

        tracing::info!("stat: subscribed to stat:metrics:tls and stat:metrics:log");

        // Inner receive loop — ONE subscription, many messages. Recreating
        // the client per message was the ~2/s connection churn (a client
        // create + drop per metric frame).
        loop {
        let payload: String = match pubsub_client.get_pubsub_message().await {
            Ok(msg) => String::from_utf8_lossy(&msg.payload).into_owned(),
            Err(_) => {
                tracing::warn!("stat: metrics channel ended — reconnecting");
                tokio::time::sleep(Duration::from_secs(3)).await;
                continue 'outer;
            }
        };

            let parsed: MetricsMessage = match serde_json::from_str(&payload) {
                Ok(m) => m,
                Err(e) => {
                    tracing::debug!(error = %e, "stat: failed to parse metrics message");
                    continue;
                }
            };

            let org_id = parsed.org_id.unwrap_or_default();
            let env_id = parsed.env_id.unwrap_or_default();
            let source = parsed.source.clone();
            let ts = parsed.ts.clone();

            // Flatten the metrics JSON into individual (name, value) pairs.
            if let Some(obj) = parsed.metrics.as_object() {
                for (name, val) in obj {
                    let value = val.as_f64().unwrap_or(0.0);
                    let key = (source.clone(), org_id.clone(), env_id.clone(), name.clone());

                    // Accumulate into all granularity buffers.
                    // For counters (count, errors), we sum. For gauges (latency_ms),
                    // we take the latest value and track count for averaging.
                    let is_counter = name.ends_with(".count")
                        || name.ends_with(".errors")
                        || name.contains(".errors.")
                        || name.contains(".warnings.");
                    for buf in [&minute_buf, &hour_buf, &day_buf].iter() {
                        let mut b = buf.lock();
                        let entry = b.entry(key.clone()).or_insert((0.0, 0, ts.clone()));
                        if is_counter {
                            entry.0 += value;
                            entry.1 += 1;
                        } else {
                            entry.0 = value;
                            entry.1 += 1;
                        }
                        entry.2 = ts.clone();
                    }
                }
            }
        } // inner receive loop
    }
}

/// When a rollup buffer should be drained (cleared) after publishing.
enum ResetWindow {
    /// Drain every N seconds (e.g. minute = 60s).
    Every(u64),
    /// Drain at 00:00 UTC each day (the day rollup is a true 24h window).
    Midnight,
}

impl ResetWindow {
    /// Returns `true` if the buffer should be drained now, given the time
    /// of the last drain.
    fn should_reset(&self, last_drain: &chrono::DateTime<chrono::Utc>) -> bool {
        match self {
            ResetWindow::Every(secs) => {
                (chrono::Utc::now() - *last_drain).num_seconds() >= *secs as i64
            }
            ResetWindow::Midnight => last_drain.date_naive() != chrono::Utc::now().date_naive(),
        }
    }
}

/// Spawn a periodic rollup publisher. Publishes every `interval` seconds
/// (all granularities publish every 60s for near-real-time visibility).
/// The buffer is snapshotted (published without clearing) on every tick
/// and drained (cleared) only when `reset` says the window has elapsed,
/// so the published `value` is a true rolling aggregate over the full
/// granularity window.
fn spawn_rollup_publisher(
    conn: glide::GlideClient,
    granularity: &'static str,
    interval: Duration,
    reset: ResetWindow,
    buf: AggBuffer,
) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.tick().await; // skip first tick
        let mut last_drain = chrono::Utc::now();
        loop {
            ticker.tick().await;
            let drain = reset.should_reset(&last_drain);
            publish_rollups(&conn, granularity, &buf, drain).await;
            if drain {
                last_drain = chrono::Utc::now();
            }
        }
    });
}

/// Publish the aggregated metrics. When `drain` is `true` the buffer is
/// cleared after snapshotting (the window has elapsed); when `false` the
/// buffer is left intact so the next publish is a rolling aggregate over
/// the same window.
async fn publish_rollups(
    conn: &glide::GlideClient,
    granularity: &str,
    buf: &AggBuffer,
    drain: bool,
) {
    let items: Vec<AggregatedMetric> = {
        let mut b = buf.lock();
        if drain {
            b.drain()
                .map(
                    |((source, org_id, env_id, metric), (value, count, ts))| AggregatedMetric {
                        source,
                        org_id,
                        env_id,
                        metric,
                        value,
                        count,
                        ts,
                    },
                )
                .collect()
        } else {
            // Snapshot only — clone the aggregated values without clearing
            // the buffer, so the next publish is a rolling aggregate.
            b.iter()
                .map(
                    |((source, org_id, env_id, metric), (value, count, ts))| AggregatedMetric {
                        source: source.clone(),
                        org_id: org_id.clone(),
                        env_id: env_id.clone(),
                        metric: metric.clone(),
                        value: *value,
                        count: *count,
                        ts: ts.clone(),
                    },
                )
                .collect()
        }
    };

    if items.is_empty() {
        return;
    }

    let channel = format!("stat:rollups:{granularity}");
    let payload = serde_json::json!({
        "granularity": granularity,
        "ts": chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
        "metrics": items,
    });
    let payload_str = serde_json::to_string(&payload).unwrap_or_default();

    use glide::AsyncCommands as _;
    let _: Result<usize, _> = conn
        .publish::<_, _, usize>(&channel, payload_str.as_str())
        .await;

    tracing::debug!(granularity, count = items.len(), drain, "published rollup");
}
