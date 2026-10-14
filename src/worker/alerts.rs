// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Stat
// SPDX-License-Identifier: Apache-2.0

//! Stat curated alert evaluation — emits `stat.alert.*` events via
//! Bus HTTP API (fire-and-forget) when thresholds are crossed.
//!
//! A periodic background task (every 60s) reads the
//! `sentin8_stat_aggregate_events_daily` and `sentin8_stat_aggregate_conversions_daily`
//! tables and evaluates:
//!
//! - **Event volume spike**: event count for today exceeds the 7-day
//!   average by more than 3x (configurable threshold).
//! - **Conversion rate drop**: conversion count drops below 50% of the
//!   7-day average.
//!
//! Alerts are sent via `BusClient::produce()` — fire-and-forget, NOT
//! written to `inbox`. If a produce call fails, the alert is lost
//! (best-effort) — the next evaluation cycle re-detects and retries.
//!
//! Alongside the curated rules, each pass evaluates the per-property
//! custom rules in `stat.alert_rules` (stat README §7, stat DESIGN §2/§3):
//! `threshold` rules compare today's aggregate value against a threshold
//! via a comparator, `anomaly` rules compare the moving-average deviation
//! factor over the past `window_hours` of daily buckets. Custom-rule
//! fires ride the same alert → Post path with the same envelope plus
//! `rule_id` + `rule_type`.

use sentin8::bus::client::BusClient;
use sentin8::bus::contracts::ProduceRequest;
use sqlx::Row;

/// Default thresholds.
const SPIKE_MULTIPLIER: f64 = 3.0;
const CONVERSION_DROP_RATIO: f64 = 0.5;
const MIN_EVENT_VOLUME: i64 = 100;
const EVAL_INTERVAL_SECS: u64 = 60;

/// Run the alert evaluation loop forever.
pub async fn run_alert_evaluator(pool: sqlx::PgPool, bus: BusClient) {
    tracing::info!(
        "stat alert evaluator started ({}s interval)",
        EVAL_INTERVAL_SECS
    );
    let mut ticker = tokio::time::interval(std::time::Duration::from_secs(EVAL_INTERVAL_SECS));

    loop {
        ticker.tick().await;
        if let Err(e) = evaluate_event_spikes(&pool, &bus).await {
            tracing::debug!(error = %e, "stat event-spike eval failed");
        }
        if let Err(e) = evaluate_conversion_drops(&pool, &bus).await {
            tracing::debug!(error = %e, "stat conversion-drop eval failed");
        }
        if let Err(e) = evaluate_custom_rules(&pool, &bus).await {
            tracing::debug!(error = %e, "stat custom-rule eval failed");
        }
    }
}

/// Event volume spike: today's count vs 7-day average.
async fn evaluate_event_spikes(pool: &sqlx::PgPool, bus: &BusClient) -> Result<(), sqlx::Error> {
    let today = chrono::Utc::now().date_naive();
    let week_ago = today - chrono::Duration::days(7);

    let rows = sqlx::query(
        r#"SELECT a.env_id, a.property_id,
                  (a.metrics->>'count')::float8 as today_count,
                  COALESCE(avg((w.metrics->>'count')::float8), 0) as avg_count
             FROM aggregate_events_daily a
        LEFT JOIN aggregate_events_daily w
               ON w.property_id = a.property_id
              AND w.env_id = a.env_id
              AND w.day >= $2 AND w.day < $1
            WHERE a.day = $1
              AND (a.metrics->>'count')::float8 >= $3
            GROUP BY a.env_id, a.property_id, today_count"#,
    )
    .bind(today)
    .bind(week_ago)
    .bind(MIN_EVENT_VOLUME as f64)
    .fetch_all(pool)
    .await?;

    for row in rows {
        let env_id: uuid::Uuid = row.get("env_id");
        let property_id: uuid::Uuid = row.get("property_id");
        let today_count: f64 = row.get("today_count");
        let avg_count: f64 = row.get("avg_count");

        if avg_count > 0.0 && today_count > avg_count * SPIKE_MULTIPLIER {
            let payload = serde_json::json!({
                "property_id": property_id,
                "env_id": env_id,
                "today_count": today_count as i64,
                "avg_count": avg_count as i64,
                "spike_multiplier": SPIKE_MULTIPLIER,
                "dedup_key": format!("event_spike:{}:{}", property_id, today),
                "severity": "info",
                "title": format!("Event volume spike: {:.0} events (avg {:.0})", today_count, avg_count),
                "body": format!(
                    "Property {} received {:.0} events today, {:.1}x the 7-day average of {:.0}",
                    property_id, today_count, today_count / avg_count, avg_count
                ),
            });
            fire_and_forget(bus, "sentin8:stat:alert:event_spike", payload).await;
        }
    }
    Ok(())
}

/// Conversion rate drop: today's conversions vs 7-day average.
async fn evaluate_conversion_drops(
    pool: &sqlx::PgPool,
    bus: &BusClient,
) -> Result<(), sqlx::Error> {
    let today = chrono::Utc::now().date_naive();
    let week_ago = today - chrono::Duration::days(7);

    let rows = sqlx::query(
        r#"SELECT a.env_id, a.property_id,
                  (a.metrics->>'count')::float8 as today_conv,
                  COALESCE(avg((w.metrics->>'count')::float8), 0) as avg_conv
             FROM aggregate_conversions_daily a
        LEFT JOIN aggregate_conversions_daily w
               ON w.property_id = a.property_id
              AND w.env_id = a.env_id
              AND w.day >= $2 AND w.day < $1
            WHERE a.day = $1
            GROUP BY a.env_id, a.property_id, today_conv"#,
    )
    .bind(today)
    .bind(week_ago)
    .fetch_all(pool)
    .await?;

    for row in rows {
        let env_id: uuid::Uuid = row.get("env_id");
        let property_id: uuid::Uuid = row.get("property_id");
        let today_conv: f64 = row.get("today_conv");
        let avg_conv: f64 = row.get("avg_conv");

        if avg_conv > 0.0 && today_conv < avg_conv * CONVERSION_DROP_RATIO {
            let payload = serde_json::json!({
                "property_id": property_id,
                "env_id": env_id,
                "today_conversions": today_conv as i64,
                "avg_conversions": avg_conv as i64,
                "drop_ratio": CONVERSION_DROP_RATIO,
                "dedup_key": format!("conversion_drop:{}:{}", property_id, today),
                "severity": "warning",
                "title": format!("Conversion drop: {:.0} today (avg {:.0})", today_conv, avg_conv),
                "body": format!(
                    "Property {} conversions at {:.0} today, {:.0}% of the 7-day average of {:.0}",
                    property_id, today_conv, (today_conv / avg_conv) * 100.0, avg_conv
                ),
            });
            fire_and_forget(bus, "sentin8:stat:alert:conversion_drop", payload).await;
        }
    }
    Ok(())
}

// ── Custom per-property alert rules (stat README §7, DESIGN §2/§3) ──────
//
// Rows of `stat.alert_rules` evaluated each pass alongside the curated
// spike/drop rules. Two rule types over the daily aggregates:
//
// - `threshold` — today's metric value vs `threshold` via `comparator`.
// - `anomaly` — the moving-average deviation factor
//   (`anomaly_deviation(current, avg)`) over the past
//   `ceil(window_hours / 24)` daily buckets vs `threshold` via
//   `comparator` (e.g. `gt 3.0` = current exceeds 3× the baseline).
//
// `min_sample` is the current-bucket noise floor (mirrors the curated
// spike rule's `MIN_EVENT_VOLUME`): a rule never evaluates below it.
// Fires ride the same alert → Post path as the curated rules — same
// envelope (property/env, dedup_key, severity, title, body) plus
// `rule_id` + `rule_type`, deduped per rule per day bucket in the
// payload key (the curated rules' dedupe contract).

/// A per-property custom alert rule row (`stat.alert_rules`).
#[derive(Debug, Clone)]
pub struct AlertRule {
    /// Rule identifier.
    pub id: uuid::Uuid,
    /// Owning env.
    pub env_id: uuid::Uuid,
    /// Watched property.
    pub property_id: uuid::Uuid,
    /// Display name.
    pub name: String,
    /// `threshold` or `anomaly`.
    pub rule_type: String,
    /// Metric vocabulary key (`events.count`, `conversions.count`,
    /// `metric:{name}`).
    pub metric_name: String,
    /// `gt` | `gte` | `lt` | `lte`.
    pub comparator: String,
    /// Comparison threshold — metric value for `threshold`, deviation
    /// factor for `anomaly`.
    pub threshold: f64,
    /// Moving-average lookback in hours (`anomaly`); whole days cover
    /// `ceil(window_hours / 24)` daily buckets.
    pub window_hours: i32,
    /// Current-bucket noise floor — the rule never evaluates below it.
    pub min_sample: i32,
}

/// Resolution of a metric vocabulary key to its aggregate source — the
/// allowlist is the ONLY path a rule's metric reaches SQL (create-time
/// validation 400s unknown keys, so the `format!` interpolation in the
/// query builders below never sees caller input outside it).
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct MetricSource {
    /// Aggregate table (allowlisted name).
    pub table: &'static str,
    /// Value SQL expression (allowlisted).
    pub expr: &'static str,
    /// For `metric:{name}` sources: the aggregate's `metric_name` filter;
    /// `None` for the whole-table event/conversion counters.
    pub aggregate_metric: Option<String>,
}

/// Map a metric vocabulary key to its aggregate source.
pub(crate) fn metric_source(metric_name: &str) -> Option<MetricSource> {
    match metric_name {
        "events.count" => Some(MetricSource {
            table: "aggregate_events_daily",
            expr: "(metrics->>'count')::float8",
            aggregate_metric: None,
        }),
        "conversions.count" => Some(MetricSource {
            table: "aggregate_conversions_daily",
            expr: "(metrics->>'count')::float8",
            aggregate_metric: None,
        }),
        other => other
            .strip_prefix("metric:")
            .filter(|name| !name.is_empty())
            .map(|name| MetricSource {
                table: "aggregate_metrics_daily",
                expr: "value",
                aggregate_metric: Some(name.to_string()),
            }),
    }
}

/// Evaluate `comparator(value, threshold)` — the pure comparator behind
/// both rule types (`threshold` compares the metric value, `anomaly`
/// compares the deviation factor). Unknown comparators never fire (the
/// CHECK constraint and create-time validation admit only the four).
pub fn evaluate_comparator(value: f64, comparator: &str, threshold: f64) -> bool {
    match comparator {
        "gt" => value > threshold,
        "gte" => value >= threshold,
        "lt" => value < threshold,
        "lte" => value <= threshold,
        _ => false,
    }
}

/// Deviation factor of the current bucket vs the moving average —
/// `current / avg` when the baseline is positive, `INFINITY` when the
/// baseline is flat-zero and the current value is not (unbounded upward
/// deviation), `1.0` when both are zero (no deviation).
pub fn anomaly_deviation(current: f64, avg: f64) -> f64 {
    if avg > 0.0 {
        current / avg
    } else if current > 0.0 {
        f64::INFINITY
    } else {
        1.0
    }
}

/// Event type for custom-rule fires
/// (`vertical:service:resource:operation`).
const RULE_TRIGGERED_EVENT: &str = "sentin8:stat:alert:rule_triggered";

/// One custom-rule pass: discover the envs with enabled rules (bare read —
/// the rollup pass's owner-read posture; only env ids are touched), then
/// evaluate each env under its own context-set transaction.
async fn evaluate_custom_rules(pool: &sqlx::PgPool, bus: &BusClient) -> Result<(), sqlx::Error> {
    let today = chrono::Utc::now().date_naive();
    for env_id in rule_envs(pool).await? {
        match evaluate_env_rules(pool, env_id, today).await {
            Ok(fired) => {
                for payload in fired {
                    fire_and_forget(bus, RULE_TRIGGERED_EVENT, payload).await;
                }
            }
            Err(e) => {
                tracing::debug!(error = %e, "stat custom-rule eval failed for one env");
            }
        }
    }
    Ok(())
}

/// Distinct envs holding at least one enabled rule — bare pool read (env
/// ids only; the per-env rule/aggregate reads below are context-scoped).
async fn rule_envs(pool: &sqlx::PgPool) -> Result<Vec<uuid::Uuid>, sqlx::Error> {
    let rows = sqlx::query(
        r#"SELECT DISTINCT p.env_id
             FROM properties p
             JOIN alert_rules r ON r.property_id = p.id AND r.enabled"#,
    )
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(|r| r.get("env_id")).collect())
}

/// Evaluate one env's enabled rules — ONE explicit transaction:
/// context-set (the audit-consumer pattern; `set_config(..., true)` is
/// transaction-local, stat DESIGN §5) → load the rules (explicit
/// `env_id` clause + property JOIN as defense-in-depth) → per-rule
/// aggregate reads on the same connection → collect fires → commit.
/// Producing happens after the caller's commit so network I/O never
/// holds a pool connection.
async fn evaluate_env_rules(
    pool: &sqlx::PgPool,
    env_id: uuid::Uuid,
    today: chrono::NaiveDate,
) -> Result<Vec<serde_json::Value>, sqlx::Error> {
    let mut tx = pool.begin().await?;
    let _ = sqlx::query("SELECT sentin8_set_tenant_context($1, '', '', '', false, false)")
        .bind(env_id)
        .execute(&mut *tx)
        .await;

    let rows = sqlx::query(
        r#"SELECT r.id, r.env_id, r.property_id, r.name, r.rule_type,
                  r.metric_name, r.comparator, r.threshold, r.window_hours, r.min_sample
             FROM alert_rules r
             JOIN properties p ON p.id = r.property_id AND p.env_id = r.env_id
            WHERE r.enabled AND r.env_id = $1"#,
    )
    .bind(env_id)
    .fetch_all(&mut *tx)
    .await?;

    let mut fired = Vec::new();
    for row in rows {
        let rule = AlertRule {
            id: row.get("id"),
            env_id: row.get("env_id"),
            property_id: row.get("property_id"),
            name: row.get("name"),
            rule_type: row.get("rule_type"),
            metric_name: row.get("metric_name"),
            comparator: row.get("comparator"),
            threshold: row.get("threshold"),
            window_hours: row.get("window_hours"),
            min_sample: row.get("min_sample"),
        };
        // Unknown metric keys are rejected at create time — skip
        // defensively rather than fail the whole pass.
        let Some(src) = metric_source(&rule.metric_name) else {
            continue;
        };
        let current = metric_bucket_value(&mut *tx, &src, rule.property_id, today).await?;
        if current < rule.min_sample as f64 {
            continue; // below the noise floor — no evaluation
        }

        let (fire, baseline, deviation_factor) = if rule.rule_type == "anomaly" {
            // Daily buckets: the window covers ceil(window_hours / 24)
            // whole days, ending at today (excluded — that's the current
            // bucket).
            let window_days = ((rule.window_hours.max(1) as i64) + 23) / 24;
            let history = metric_history(
                &mut *tx,
                &src,
                rule.property_id,
                today - chrono::Duration::days(window_days),
                today,
            )
            .await?;
            if history.is_empty() {
                continue; // no baseline buckets yet — nothing to deviate from
            }
            let avg = history.iter().sum::<f64>() / history.len() as f64;
            let d = anomaly_deviation(current, avg);
            (
                evaluate_comparator(d, &rule.comparator, rule.threshold),
                avg,
                Some(d),
            )
        } else if rule.rule_type == "threshold" {
            (
                evaluate_comparator(current, &rule.comparator, rule.threshold),
                0.0,
                None,
            )
        } else {
            continue; // CHECK constraint admits only the two types
        };

        if fire {
            fired.push(rule_payload(
                &rule,
                today,
                current,
                baseline,
                deviation_factor,
            ));
        }
    }

    tx.commit().await?;
    Ok(fired)
}

/// Build the single-day SUM query for one metric source. Table and value
/// expression come from the static allowlist (`MetricSource`); the
/// optional aggregate-metric filter is a bound parameter (last bind).
fn metric_day_sql(src: &MetricSource) -> String {
    match src.aggregate_metric {
        Some(_) => format!(
            "SELECT COALESCE(SUM({e}), 0) AS v FROM {t} \
             WHERE property_id = $1 AND day = $2 AND metric_name = $3",
            e = src.expr,
            t = src.table
        ),
        None => format!(
            "SELECT COALESCE(SUM({e}), 0) AS v FROM {t} \
             WHERE property_id = $1 AND day = $2",
            e = src.expr,
            t = src.table
        ),
    }
}

/// Build the per-day-history SUM query for one metric source (window
/// `[from, to)`), same allowlist discipline as [`metric_day_sql`].
fn metric_history_sql(src: &MetricSource) -> String {
    match src.aggregate_metric {
        Some(_) => format!(
            "SELECT day, COALESCE(SUM({e}), 0) AS v FROM {t} \
             WHERE property_id = $1 AND day >= $2 AND day < $3 \
             AND metric_name = $4 GROUP BY day ORDER BY day",
            e = src.expr,
            t = src.table
        ),
        None => format!(
            "SELECT day, COALESCE(SUM({e}), 0) AS v FROM {t} \
             WHERE property_id = $1 AND day >= $2 AND day < $3 \
             GROUP BY day ORDER BY day",
            e = src.expr,
            t = src.table
        ),
    }
}

/// SUM of one metric source's value for a single day bucket.
async fn metric_bucket_value(
    tx: &mut sqlx::PgConnection,
    src: &MetricSource,
    property_id: uuid::Uuid,
    day: chrono::NaiveDate,
) -> Result<f64, sqlx::Error> {
    let sql = metric_day_sql(src);
    let mut q = sqlx::query(&sql).bind(property_id).bind(day);
    if let Some(name) = src.aggregate_metric.as_deref() {
        q = q.bind(name);
    }
    let row = q.fetch_one(&mut *tx).await?;
    Ok(row.get("v"))
}

/// Per-day SUMs of one metric source over `[from_day, to_day)` — only
/// buckets with at least one aggregate row are returned (the
/// moving-average baseline is taken over non-empty buckets).
async fn metric_history(
    tx: &mut sqlx::PgConnection,
    src: &MetricSource,
    property_id: uuid::Uuid,
    from_day: chrono::NaiveDate,
    to_day: chrono::NaiveDate,
) -> Result<Vec<f64>, sqlx::Error> {
    let sql = metric_history_sql(src);
    let mut q = sqlx::query(&sql)
        .bind(property_id)
        .bind(from_day)
        .bind(to_day);
    if let Some(name) = src.aggregate_metric.as_deref() {
        q = q.bind(name);
    }
    let rows = q.fetch_all(&mut *tx).await?;
    Ok(rows.into_iter().map(|r| r.get("v")).collect())
}

/// Build the fire payload — the curated rules' envelope (property/env,
/// dedup_key, severity, title, body) plus the rule context (`rule_id`,
/// `rule_type`, metric, comparator, threshold, current, baseline).
fn rule_payload(
    rule: &AlertRule,
    today: chrono::NaiveDate,
    current: f64,
    baseline: f64,
    deviation: Option<f64>,
) -> serde_json::Value {
    // Upward comparators inform (info), downward comparators warn — the
    // curated rules' severity split (spike=info, drop=warning).
    let severity = if rule.comparator.starts_with("lt") {
        "warning"
    } else {
        "info"
    };
    let (title, body) = match deviation {
        Some(d) => (
            format!(
                "{}: {} at {:.2}x of the {}h average",
                rule.name, rule.metric_name, d, rule.window_hours
            ),
            format!(
                "Property {} metric {} is {} today vs moving average {:.2} \
                 over the past {}h (deviation {:.2}x, threshold {} {})",
                rule.property_id,
                rule.metric_name,
                current,
                baseline,
                rule.window_hours,
                d,
                rule.comparator,
                rule.threshold
            ),
        ),
        None => (
            format!(
                "{}: {} {} {}",
                rule.name, rule.metric_name, rule.comparator, rule.threshold
            ),
            format!(
                "Property {} metric {} is {} today (threshold {} {})",
                rule.property_id, rule.metric_name, current, rule.comparator, rule.threshold
            ),
        ),
    };
    serde_json::json!({
        "property_id": rule.property_id,
        "env_id": rule.env_id,
        "rule_id": rule.id,
        "rule_name": rule.name,
        "rule_type": rule.rule_type,
        "metric_name": rule.metric_name,
        "comparator": rule.comparator,
        "threshold": rule.threshold,
        "current_value": current,
        "baseline_value": if deviation.is_some() { serde_json::json!(baseline) } else { serde_json::Value::Null },
        "deviation_factor": deviation,
        "window_hours": rule.window_hours,
        "dedup_key": format!("rule:{}:{}", rule.id, today),
        "severity": severity,
        "title": title,
        "body": body,
    })
}

/// Fire-and-forget produce to Bus.
async fn fire_and_forget(bus: &BusClient, event_type: &str, payload: serde_json::Value) {
    // The embedded worker produces on behalf of the service itself
    // of the service itself (M2M token), not the original user.
    let req = ProduceRequest {
        stream_family: "stat-pipeline".into(),
        env_id: None,
        event_type: event_type.into(),
        payload,
        correlation_id: None,
        idempotency_key: None,
        publisher_id_token: None, // Worker M2M token — set if available
        publisher_subject: Some("sentin8:stat".into()),
    };
    if let Err(e) = bus.produce(&req).await {
        tracing::debug!(error = %e, event_type = %event_type, "stat: alert produce failed (fire-and-forget)");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn comparator_covers_all_four_operators() {
        assert!(evaluate_comparator(5.0, "gt", 4.0));
        assert!(!evaluate_comparator(4.0, "gt", 4.0), "gt is strict");
        assert!(evaluate_comparator(4.0, "gte", 4.0));
        assert!(evaluate_comparator(3.0, "lt", 4.0));
        assert!(!evaluate_comparator(4.0, "lt", 4.0), "lt is strict");
        assert!(evaluate_comparator(4.0, "lte", 4.0));
    }

    #[test]
    fn comparator_unknown_operator_never_fires() {
        assert!(!evaluate_comparator(100.0, "eq", 100.0));
        assert!(!evaluate_comparator(100.0, "", 0.0));
    }

    #[test]
    fn deviation_is_current_over_average() {
        assert_eq!(anomaly_deviation(300.0, 100.0), 3.0);
        assert!((anomaly_deviation(50.0, 200.0) - 0.25).abs() < 1e-9);
    }

    #[test]
    fn deviation_flat_zero_baseline_is_infinite_only_when_current_positive() {
        assert_eq!(anomaly_deviation(10.0, 0.0), f64::INFINITY);
        assert_eq!(anomaly_deviation(0.0, 0.0), 1.0, "both zero = no deviation");
    }

    #[test]
    fn metric_source_maps_the_vocabulary() {
        let events = metric_source("events.count").expect("events.count known");
        assert_eq!(events.table, "aggregate_events_daily");
        assert_eq!(events.aggregate_metric, None);

        let conversions = metric_source("conversions.count").expect("conversions.count known");
        assert_eq!(conversions.table, "aggregate_conversions_daily");
        assert_eq!(conversions.aggregate_metric, None);

        let custom = metric_source("metric:auth.errors").expect("metric: prefix known");
        assert_eq!(custom.table, "aggregate_metrics_daily");
        assert_eq!(custom.aggregate_metric.as_deref(), Some("auth.errors"));

        assert!(
            metric_source("metric:").is_none(),
            "empty aggregate metric rejected"
        );
        assert!(
            metric_source("bogus.metric").is_none(),
            "unknown key rejected"
        );
    }

    #[test]
    fn anomaly_rule_semantics_end_to_end() {
        // Spike-style anomaly: current exceeds 3× the moving average.
        let spike = anomaly_deviation(400.0, 100.0);
        assert!(evaluate_comparator(spike, "gt", 3.0));
        assert!(!evaluate_comparator(spike, "lt", 0.5));
        // Drop-style anomaly: current falls below half the average.
        let drop = anomaly_deviation(40.0, 100.0);
        assert!(evaluate_comparator(drop, "lt", 0.5));
        assert!(!evaluate_comparator(drop, "gt", 3.0));
        // A fresh metric from a flat-zero baseline deviates infinitely —
        // gated in practice by the min_sample noise floor.
        assert!(evaluate_comparator(anomaly_deviation(25.0, 0.0), "gt", 3.0));
    }
}
