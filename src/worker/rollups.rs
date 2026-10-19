// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Stat
// SPDX-License-Identifier: Apache-2.0

//! Multi-granularity rollup job - aggregates from `stat.events` daily
//! aggregates (`aggregate_metrics_daily`) into `stat.rollups` at the
//! implemented granularities: hour, day, week, month, year (minute
//! rollups stay Valkey-only - see worker/valkey_sub.rs).
//!
//! Runs as a periodic background task inside the stat service (alongside
//! the Bus consume loop and the alert evaluator). Every 60 seconds it
//! rolls up recent data so that Dash charts can query any granularity
//! via `GET /v1/data/traffic` or `GET /v1/data/metrics` without scanning
//! raw events.
//!
//! Rollup hierarchy:
//!   minute  (5-minute buckets, TTL 7 days - hot, for real-time charts)
//!   hour    (rolled up from minute / directly from *_daily)
//!   day     (rolled up from *_daily - the authoritative source)
//!   week    (rolled up from day - ISO week starting Monday)
//!   month   (rolled up from day)
//!   year    (rolled up from month)
//!
//! The rollup is idempotent: upserts keyed by
//! `(property_id, kind, granularity, bucket, dimensions_hash)`.
//!
//! The admin reaggregate endpoint (`POST /v1/admin/properties/{id}/reaggregate`,
//! stat README §7) reuses this module's day-granularity computation and
//! window mechanics via `reaggregate_property` / `day_bucket_bounds` /
//! `check_window_horizon`.

use chrono::Timelike;
use sentin8::bus::client::BusClient;
use sqlx::{PgPool, Row};

/// Entry point - spawn the periodic rollup loop. Runs DB-level rollups
/// (hour/day/week/month/year) into `sentin8_stat_rollups`.
/// Minute-level metrics are kept only in Valkey (see `valkey_sub.rs`),
/// not in the database - they're high-volume and ephemeral.
pub async fn run_rollup_loop(pool: PgPool, bus: BusClient) {
    let mut tick = tokio::time::interval(std::time::Duration::from_secs(60));
    tick.tick().await; // skip first immediate tick
    loop {
        tick.tick().await;
        if let Err(e) = run_rollup_pass(&pool, &bus).await {
            tracing::warn!(error = %e, "stat rollup pass failed");
        }
    }
}

/// One rollup pass - aggregate `sentin8_stat_aggregate_metrics_daily` into
/// `sentin8_stat_rollups` at hour/day/week/month/year granularities.
/// Minute-level is NOT written to the DB - it lives only in Valkey
/// (published by `valkey_sub.rs` every 60s to `stat:rollups:minute`).
///
/// Every updated day-bucket ALSO emits a `sentin8:stat:aggregate:updated`
/// event on the `stat-pipeline` stream family (APP-1, stat DESIGN §10):
/// payload-complete (property_id, aggregate, window, bucket_start, value,
/// dimensions) so downstream apps apply store metrics without a callback.
/// Fire-and-forget: a Bus outage degrades to the next pass re-emitting
/// (the DB rollup is the durable source).
async fn run_rollup_pass(pool: &PgPool, bus: &BusClient) -> Result<(), String> {
    // ── 1. Hourly rollup (last 48 hours) ──
    rollup_hour(pool).await?;

    // ── 2. Daily rollup (last 400 days) - emits the aggregate events ──
    rollup_day(pool, bus).await?;

    // ── 3. Weekly rollup (last 2 years) ──
    rollup_week(pool).await?;

    // ── 4. Monthly rollup (last 10 years) ──
    rollup_month(pool).await?;

    // ── 5. Yearly rollup ──
    rollup_year(pool).await?;

    Ok(())
}

/// Upsert a rollup row. `metrics` is a JSONB object with the aggregated
/// values (count, value, etc.).
async fn upsert_rollup<'e, E>(
    executor: E,
    env_id: uuid::Uuid,
    property_id: uuid::Uuid,
    kind: &str,
    granularity: &str,
    bucket: chrono::DateTime<chrono::Utc>,
    dimensions: &serde_json::Value,
    metrics: &serde_json::Value,
) -> Result<(), String>
where
    E: sqlx::Executor<'e, Database = sqlx::Postgres>,
{
    let dims_str = serde_json::to_string(dimensions).unwrap_or_else(|_| "{}".into());
    let _dims_hash = format!("{:x}", simple_hash(dims_str.as_bytes()));
    sqlx::query(
        r#"INSERT INTO rollups
           (env_id, property_id, kind, granularity, bucket,
            dimensions, metrics)
           VALUES ($1, $2, $3, $4, $5, $6, $7)
           ON CONFLICT (property_id, kind, granularity, bucket,
                        md5(dimensions::text))
           DO UPDATE SET metrics = EXCLUDED.metrics,
                         updated_at = now()"#,
    )
    .bind(env_id)
    .bind(property_id)
    .bind(kind)
    .bind(granularity)
    .bind(bucket)
    .bind(dimensions)
    .bind(metrics)
    .execute(executor)
    .await
    .map_err(|e| format!("upsert rollup {kind}/{granularity}: {e}"))?;
    Ok(())
}

/// Upsert ONE metrics day-aggregate into `stat.rollups` at day
/// granularity - the day-rollup computation shared by the background pass
/// (`rollup_day`) and the admin reaggregate endpoint
/// (`reaggregate_property`), so the row shape (dimensions
/// `{metric_name, value_type}`, metrics `{value}`, bucket = UTC midnight)
/// cannot drift between the two callers.
pub(crate) async fn upsert_metrics_day_rollup<'e, E>(
    executor: E,
    env_id: uuid::Uuid,
    property_id: uuid::Uuid,
    day: chrono::NaiveDate,
    metric_name: &str,
    value_type: &str,
    value: f64,
) -> Result<(), String>
where
    E: sqlx::Executor<'e, Database = sqlx::Postgres>,
{
    let bucket = day.and_hms_opt(0, 0, 0).unwrap().and_utc();
    let dims = serde_json::json!({
        "metric_name": metric_name,
        "value_type": value_type,
    });
    let metrics = serde_json::json!({ "value": value });
    upsert_rollup(
        executor,
        env_id,
        property_id,
        "metrics",
        "day",
        bucket,
        &dims,
        &metrics,
    )
    .await
}

/// Roll up metrics_daily into sentin8_stat_rollups at day granularity.
/// This is the base rollup - all other granularities derive from this.
async fn rollup_day(pool: &PgPool, bus: &BusClient) -> Result<(), String> {
    let rows = sqlx::query(
        r#"SELECT env_id, property_id, day, metric_name,
                  dimensions, value_type, value
           FROM aggregate_metrics_daily
           WHERE day >= now()::date - interval '400 days'"#,
    )
    .fetch_all(pool)
    .await
    .map_err(|e| format!("rollup_day query: {e}"))?;

    for row in rows {
        let env_id: uuid::Uuid = row.get("env_id");
        let property_id: uuid::Uuid = row.get("property_id");
        let day: chrono::NaiveDate = row.get("day");
        let metric_name: String = row.get("metric_name");
        let _dimensions: serde_json::Value = row.get("dimensions");
        let value_type: String = row.get("value_type");
        let value: f64 = row.get("value");

        upsert_metrics_day_rollup(
            pool,
            env_id,
            property_id,
            day,
            &metric_name,
            &value_type,
            value,
        )
        .await?;
        // APP-1: emit the payload-complete aggregate event for the updated
        // day-bucket (fire-and-forget - a failed produce is retried by the
        // next pass because the DB upsert is idempotent and the query re-reads
        // the bucket).
        emit_aggregate_updated(
            bus,
            env_id,
            property_id,
            &metric_name,
            "daily",
            day.and_hms_opt(0, 0, 0).unwrap().and_utc(),
            value,
            &serde_json::json!({ "metric_name": metric_name, "value_type": value_type }),
        )
        .await;
    }
    Ok(())
}

/// Emit one `sentin8:stat:aggregate:updated` event on the `stat-pipeline`
/// stream family. The payload mirrors
/// `sentin8_stat_server::worker::AggregateUpdatedEvent` (the app
/// listener's parser): property_id, aggregate, window, bucket_start,
/// value, dimensions. Best-effort - a failed produce degrades to the
/// next pass re-emitting the bucket.
async fn emit_aggregate_updated(
    bus: &BusClient,
    env_id: uuid::Uuid,
    property_id: uuid::Uuid,
    aggregate: &str,
    window: &str,
    bucket: chrono::DateTime<chrono::Utc>,
    value: f64,
    dimensions: &serde_json::Value,
) {
    let req = sentin8::bus::contracts::ProduceRequest {
        stream_family: "stat-pipeline".into(),
        event_type: "sentin8:stat:aggregate:updated".into(),
        payload: serde_json::json!({
            "property_id": property_id,
            "aggregate": aggregate,
            "window": window,
            "bucket_start": bucket.to_rfc3339(),
            "value": value,
            "dimensions": dimensions,
        }),
        env_id: Some(env_id),
        ..Default::default()
    };
    if let Err(e) = bus.produce(&req).await {
        tracing::warn!(error = %e, property_id = %property_id, "stat: aggregate event produce failed (retried next pass)");
    }
}

/// Roll up into hour-level buckets. Since the source is daily, each hour
/// bucket gets the day's value. When per-hour pipeline writes are added,
/// this will aggregate from real hourly data.
async fn rollup_hour(pool: &PgPool) -> Result<(), String> {
    let rows = sqlx::query(
        r#"SELECT env_id, property_id, day, metric_name,
                  dimensions, value_type, value
           FROM aggregate_metrics_daily
           WHERE day >= now()::date - interval '2 days'"#,
    )
    .fetch_all(pool)
    .await
    .map_err(|e| format!("rollup_hour query: {e}"))?;

    let now = chrono::Utc::now();
    for row in rows {
        let env_id: uuid::Uuid = row.get("env_id");
        let property_id: uuid::Uuid = row.get("property_id");
        let day: chrono::NaiveDate = row.get("day");
        let metric_name: String = row.get("metric_name");
        let value_type: String = row.get("value_type");
        let value: f64 = row.get("value");

        // Bucket = current hour on the day.
        let bucket = day.and_hms_opt(now.time().hour(), 0, 0).unwrap().and_utc();
        let dims = serde_json::json!({
            "metric_name": metric_name,
            "value_type": value_type,
        });
        let metrics = serde_json::json!({ "value": value });
        upsert_rollup(
            pool,
            env_id,
            property_id,
            "metrics",
            "hour",
            bucket,
            &dims,
            &metrics,
        )
        .await?;
    }
    Ok(())
}

/// Roll up daily into weekly buckets (ISO week, Monday-based).
async fn rollup_week(pool: &PgPool) -> Result<(), String> {
    // Aggregate daily values into weekly sums/averages.
    let rows = sqlx::query(
        r#"SELECT env_id, property_id,
                  metric_name, value_type,
                  date_trunc('week', day::timestamptz) AS week_start,
                  CASE WHEN value_type = 'counter'
                       THEN sum(value)
                       ELSE avg(value)
                       END AS agg_value
           FROM aggregate_metrics_daily
           WHERE day >= now()::date - interval '2 years'
           GROUP BY env_id, property_id, metric_name, value_type, week_start"#,
    )
    .fetch_all(pool)
    .await
    .map_err(|e| format!("rollup_week query: {e}"))?;

    for row in rows {
        let env_id: uuid::Uuid = row.get("env_id");
        let property_id: uuid::Uuid = row.get("property_id");
        let metric_name: String = row.get("metric_name");
        let value_type: String = row.get("value_type");
        let week_start: chrono::DateTime<chrono::Utc> = row.get("week_start");
        let agg_value: f64 = row.get("agg_value");

        let dims = serde_json::json!({
            "metric_name": metric_name,
            "value_type": value_type,
        });
        let metrics = serde_json::json!({ "value": agg_value });
        upsert_rollup(
            pool,
            env_id,
            property_id,
            "metrics",
            "week",
            week_start,
            &dims,
            &metrics,
        )
        .await?;
    }
    Ok(())
}

/// Roll up daily into monthly buckets.
async fn rollup_month(pool: &PgPool) -> Result<(), String> {
    let rows = sqlx::query(
        r#"SELECT env_id, property_id,
                  metric_name, value_type,
                  date_trunc('month', day::timestamptz) AS month_start,
                  CASE WHEN value_type = 'counter'
                       THEN sum(value)
                       ELSE avg(value)
                       END AS agg_value
           FROM aggregate_metrics_daily
           WHERE day >= now()::date - interval '10 years'
           GROUP BY env_id, property_id, metric_name, value_type, month_start"#,
    )
    .fetch_all(pool)
    .await
    .map_err(|e| format!("rollup_month query: {e}"))?;

    for row in rows {
        let env_id: uuid::Uuid = row.get("env_id");
        let property_id: uuid::Uuid = row.get("property_id");
        let metric_name: String = row.get("metric_name");
        let value_type: String = row.get("value_type");
        let month_start: chrono::DateTime<chrono::Utc> = row.get("month_start");
        let agg_value: f64 = row.get("agg_value");

        let dims = serde_json::json!({
            "metric_name": metric_name,
            "value_type": value_type,
        });
        let metrics = serde_json::json!({ "value": agg_value });
        upsert_rollup(
            pool,
            env_id,
            property_id,
            "metrics",
            "month",
            month_start,
            &dims,
            &metrics,
        )
        .await?;
    }
    Ok(())
}

/// Roll up monthly into yearly buckets.
async fn rollup_year(pool: &PgPool) -> Result<(), String> {
    let rows = sqlx::query(
        r#"SELECT env_id, property_id,
                  metric_name, value_type,
                  date_trunc('year', day::timestamptz) AS year_start,
                  CASE WHEN value_type = 'counter'
                       THEN sum(value)
                       ELSE avg(value)
                       END AS agg_value
           FROM aggregate_metrics_daily
           GROUP BY env_id, property_id, metric_name, value_type, year_start"#,
    )
    .fetch_all(pool)
    .await
    .map_err(|e| format!("rollup_year query: {e}"))?;

    for row in rows {
        let env_id: uuid::Uuid = row.get("env_id");
        let property_id: uuid::Uuid = row.get("property_id");
        let metric_name: String = row.get("metric_name");
        let value_type: String = row.get("value_type");
        let year_start: chrono::DateTime<chrono::Utc> = row.get("year_start");
        let agg_value: f64 = row.get("agg_value");

        let dims = serde_json::json!({
            "metric_name": metric_name,
            "value_type": value_type,
        });
        let metrics = serde_json::json!({ "value": agg_value });
        upsert_rollup(
            pool,
            env_id,
            property_id,
            "metrics",
            "year",
            year_start,
            &dims,
            &metrics,
        )
        .await?;
    }
    Ok(())
}

/// Simple non-cryptographic hash for dimension keys (same approach as the
/// existing `sha256_hash` stub in pipeline.rs).
fn simple_hash(bytes: &[u8]) -> u128 {
    let mut h: u128 = 0x6a09e667f3bcc908;
    for &b in bytes {
        h = h.wrapping_mul(0x100000001b3).wrapping_add(b as u128);
    }
    h
}

// ── Reaggregate (admin endpoint backing, stat README §7) ─────────────────

/// Maximum window length accepted by `reaggregate_property` (days). Bounds
/// a runaway request before it scans the partitioned raw log.
pub const REAGGREGATE_MAX_WINDOW_DAYS: i64 = 400;

/// A parsed reaggregate window: inclusive raw-event timestamps
/// `[from, to]` plus the day buckets they cover.
#[derive(Debug, Clone, PartialEq)]
pub struct ReaggregateWindow {
    /// Inclusive window start (UTC).
    pub from: chrono::DateTime<chrono::Utc>,
    /// Inclusive window end (UTC).
    pub to: chrono::DateTime<chrono::Utc>,
    /// First day bucket touched (UTC date of `from`).
    pub from_day: chrono::NaiveDate,
    /// Last day bucket touched (UTC date of `to`).
    pub to_day: chrono::NaiveDate,
}

/// Parse and normalize a reaggregate window.
///
/// `from`/`to` accept RFC 3339 timestamps (with or without an offset -
/// naive strings are interpreted as UTC). When both are `None` the window
/// defaults to the last 30 days ending now. When only one bound is given,
/// the other defaults around it (`to` = now / `from` = `to` − 30 days).
///
/// # Errors
/// Returns a caller-ready message when a bound is unparsable, `to < from`,
/// the window lies in the future, or the span exceeds
/// [`REAGGREGATE_MAX_WINDOW_DAYS`].
pub fn parse_reaggregate_window(
    from: Option<&str>,
    to: Option<&str>,
) -> Result<ReaggregateWindow, String> {
    let now = chrono::Utc::now();
    let parse_bound = |raw: &str, name: &str| -> Result<chrono::DateTime<chrono::Utc>, String> {
        chrono::DateTime::parse_from_rfc3339(raw)
            .map(|dt| dt.with_timezone(&chrono::Utc))
            .or_else(|_| {
                chrono::NaiveDateTime::parse_from_str(raw, "%Y-%m-%dT%H:%M:%S")
                    .map(|naive| naive.and_utc())
            })
            .map_err(|_| format!("invalid {name} timestamp: {raw:?} (expected RFC 3339)"))
    };
    let to = match to {
        Some(raw) => Some(parse_bound(raw, "to")?),
        None => None,
    };
    let from = match from {
        Some(raw) => Some(parse_bound(raw, "from")?),
        None => None,
    };
    let to = to.unwrap_or(now);
    let from = from.unwrap_or(to - chrono::Duration::days(30));
    if to < from {
        return Err("'to' must not precede 'from'".into());
    }
    if to > now + chrono::Duration::minutes(5) {
        return Err("'to' lies in the future".into());
    }
    let from_day = from.date_naive();
    let to_day = to.date_naive();
    let days = (to_day - from_day).num_days() + 1;
    if days > REAGGREGATE_MAX_WINDOW_DAYS {
        return Err(format!(
            "window spans {days} day buckets - max {}",
            REAGGREGATE_MAX_WINDOW_DAYS
        ));
    }
    Ok(ReaggregateWindow {
        from,
        to,
        from_day,
        to_day,
    })
}

/// Reject a window reaching past the property's raw retention horizon
/// (stat design §4.3.6: the archive sweep is the source-of-truth boundary -
/// raw events older than `retention_days` live only in Storage archives,
/// which this endpoint does not replay).
///
/// The horizon is evaluated per property from its `retention_days`
/// (0 = retain indefinitely). The spilled portion of the window
/// (`from` before the horizon) is reported in the message so the caller
/// can either narrow the window or raise retention and re-run.
pub fn check_window_horizon(
    window: &ReaggregateWindow,
    retention_days: i32,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<(), String> {
    if retention_days <= 0 {
        return Ok(());
    }
    let horizon = now - chrono::Duration::days(retention_days as i64);
    if window.from < horizon {
        return Err(format!(
            "window reaches past the property's retention horizon: raw events \
             older than {retention_days}d are archived to Storage and cannot \
             be reaggregated from stat.events (stat DESIGN §4.3.6); narrow \
             the window to start at/after the horizon or raise retention_days"
        ));
    }
    Ok(())
}

/// Rebuild the day-granularity `metrics` rollups for one property over the
/// given window, from the raw events still present in `stat.events`.
///
/// One explicit transaction: context-set (the property's env, REQUIRED -
/// `set_config(..., true)` is transaction-local and the RLS policies admit
/// only a matching `app.env_id`) → property existence check → DELETE of the
/// window's `metrics`-kind day buckets → set-based recomputation from
/// `stat.events` (counter = SUM, gauge = last-write - mirroring the
/// pipeline's `upsert_metric` semantics) → commit. The delete-then-recompute
/// pair is one unit so a mid-rebuild failure leaves the previous rollups
/// intact.
///
/// Callers must run [`check_window_horizon`] first - this helper does NOT
/// re-check retention (the admin handler owns the archive-boundary
/// rejection, stat README §7).
///
/// # Errors
/// Property not found, SQL failure, or commit failure - message strings are
/// caller-ready for the 400/500 mapping.
pub async fn reaggregate_property(
    pool: &PgPool,
    property_id: uuid::Uuid,
    window: &ReaggregateWindow,
) -> Result<usize, String> {
    let mut tx = pool.begin().await.map_err(|e| format!("begin tx: {e}"))?;

    // Tenant context on the SAME transaction as every statement below
    // (stat DESIGN §5). The archive sweep sets the SYSTEM env for its
    // cross-property query; here the caller resolved one property, so the
    // context is the property's env - the RLS policies then bound every
    // read/write to that env without a role-level escape hatch.
    let prop = sqlx::query("SELECT env_id FROM properties WHERE id = $1 LIMIT 1")
        .bind(property_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| format!("property lookup: {e}"))?
        .ok_or_else(|| format!("property {property_id} not found"))?;
    let env_id: uuid::Uuid = prop.get("env_id");
    let _ = sqlx::query("SELECT sentin8_set_tenant_context($1, '', '', '', false, false)")
        .bind(env_id)
        .execute(&mut *tx)
        .await;

    // Drop the window's existing day-`metrics` buckets, then recompute
    // them from raw events in the same transaction - the rollup table is
    // never left partially rebuilt.
    sqlx::query(
        r#"DELETE FROM rollups
           WHERE property_id = $1
             AND kind = 'metrics'
             AND granularity = 'day'
             AND bucket >= $2
             AND bucket <= $3"#,
    )
    .bind(property_id)
    .bind(window.from_day.and_hms_opt(0, 0, 0).unwrap().and_utc())
    .bind(window.to_day.and_hms_opt(0, 0, 0).unwrap().and_utc())
    .execute(&mut *tx)
    .await
    .map_err(|e| format!("delete window buckets: {e}"))?;

    // Set-based recomputation from the raw log - one pass, no per-row
    // round trips (pool is capped at 3 connections; a per-bucket loop
    // would serialize thousands of round trips). Counter metrics SUM all
    // raw metric entries; gauge metrics keep the LAST raw value per
    // (metric_name, dimensions) - mirroring the pipeline's `upsert_metric`
    // counter=SUM / gauge=last-write split.
    let rows = sqlx::query(
        r#"WITH raw AS (
               SELECT e.timestamp::date AS day,
                      m.key AS metric_name,
                      m.value::text AS raw_value,
                      md5(COALESCE(e.props::text, '{}')) AS dims_hash,
                      e.props,
                      row_number() OVER (
                          PARTITION BY m.key,
                                       md5(COALESCE(e.props::text, '{}'))
                          ORDER BY e.timestamp DESC
                      ) AS recency
               FROM events e
               CROSS JOIN LATERAL jsonb_each(e.metrics) AS m(key, value)
               WHERE e.property_id = $1
                 AND e.timestamp >= $2
                 AND e.timestamp <= $3
           )
           SELECT day, metric_name, props, raw_value, recency
           FROM raw"#,
    )
    .bind(property_id)
    .bind(window.from)
    .bind(window.to)
    .fetch_all(&mut *tx)
    .await
    .map_err(|e| format!("raw metric scan: {e}"))?;

    // Fold in Rust: counters SUM; gauges keep the most recent value per
    // dimension set. Key = (day, metric_name, dims_hash) - matching the
    // daily-aggregate uniqueness so rebuilt buckets are replayable.
    use std::collections::HashMap;
    let mut counters: HashMap<(chrono::NaiveDate, String, String), (serde_json::Value, f64)> =
        HashMap::new();
    let mut gauges: HashMap<(chrono::NaiveDate, String, String), (serde_json::Value, f64, i64)> =
        HashMap::new();
    for row in &rows {
        let day: chrono::NaiveDate = row.get("day");
        let metric_name: String = row.get("metric_name");
        let props: serde_json::Value = row.get("props");
        let raw_value: String = row.get("raw_value");
        let recency: i64 = row.get("recency");
        let value: f64 = raw_value.parse().unwrap_or(0.0);
        let dims_json = serde_json::to_string(&props).unwrap_or_else(|_| "{}".into());
        let key = (day, metric_name.clone(), dims_json.clone());
        if metric_name.ends_with(".issued")
            || metric_name.ends_with(".created")
            || metric_name.ends_with(".completed")
        {
            counters.entry(key).or_insert((props, 0.0)).1 += value;
        } else if gauges
            .get(&key)
            .map(|(_, _, r)| recency < *r)
            .unwrap_or(true)
        {
            gauges.insert(key, (props, value, recency));
        }
    }

    let mut rebuilt = 0usize;
    for ((day, metric_name, _dims_json), (_, value)) in counters {
        upsert_metrics_day_rollup(
            &mut *tx,
            env_id,
            property_id,
            day,
            &metric_name,
            "counter",
            value,
        )
        .await?;
        rebuilt += 1;
    }
    for ((day, metric_name, _dims_json), (_, value, _)) in gauges {
        upsert_metrics_day_rollup(
            &mut *tx,
            env_id,
            property_id,
            day,
            &metric_name,
            "gauge",
            value,
        )
        .await?;
        rebuilt += 1;
    }

    tx.commit().await.map_err(|e| format!("commit: {e}"))?;
    Ok(rebuilt)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_window_is_last_30_days() {
        let w = parse_reaggregate_window(None, None).expect("default window parses");
        assert_eq!(w.to_day, chrono::Utc::now().date_naive());
        // `from = to − 30d`, INCLUSIVE of both endpoints → 31 day buckets.
        assert_eq!(
            (w.to_day - w.from_day).num_days() + 1,
            31,
            "default window covers the 30-day span inclusively"
        );
    }

    #[test]
    fn explicit_bounds_parse_and_map_to_day_buckets() {
        let w =
            parse_reaggregate_window(Some("2026-09-01T00:00:00Z"), Some("2026-09-10T23:59:59Z"))
                .expect("explicit window parses");
        assert_eq!(w.from_day.to_string(), "2026-09-01");
        assert_eq!(w.to_day.to_string(), "2026-09-10");
    }

    #[test]
    fn partial_bounds_default_the_other_side() {
        // Only `to` → from = to − 30d (inclusive of both endpoints → 31
        // buckets).
        let w = parse_reaggregate_window(None, Some("2026-09-10T12:00:00Z"))
            .expect("to-only window parses");
        assert_eq!(w.to_day.to_string(), "2026-09-10");
        assert_eq!(
            (w.to_day - w.from_day).num_days() + 1,
            31,
            "from defaults to 30 days before to"
        );
        // Only `from` → to = now.
        let w = parse_reaggregate_window(Some("2026-09-20T00:00:00Z"), None)
            .expect("from-only window parses");
        assert_eq!(w.from_day.to_string(), "2026-09-20");
        assert!(w.to >= chrono::Utc::now() - chrono::Duration::minutes(5));
    }

    #[test]
    fn rejects_inverted_future_and_oversized_windows() {
        let err =
            parse_reaggregate_window(Some("2026-09-10T00:00:00Z"), Some("2026-09-01T00:00:00Z"))
                .expect_err("inverted window rejected");
        assert!(err.contains("'to' must not precede"), "got: {err}");

        let err =
            parse_reaggregate_window(Some("2026-09-01T00:00:00Z"), Some("2099-01-01T00:00:00Z"))
                .expect_err("future window rejected");
        assert!(err.contains("future"), "got: {err}");

        let err =
            parse_reaggregate_window(Some("2020-01-01T00:00:00Z"), Some("2026-09-25T00:00:00Z"))
                .expect_err("oversized window rejected");
        assert!(err.contains("max"), "got: {err}");
    }

    #[test]
    fn rejects_unparsable_bounds() {
        let err = parse_reaggregate_window(Some("not-a-date"), None)
            .expect_err("unparsable from rejected");
        assert!(err.contains("invalid from"), "got: {err}");
    }

    #[test]
    fn horizon_admits_inside_and_rejects_beyond() {
        let now = chrono::Utc::now();
        let w =
            parse_reaggregate_window(Some(&(now - chrono::Duration::days(5)).to_rfc3339()), None)
                .expect("window inside horizon");
        check_window_horizon(&w, 30, now).expect("inside horizon admitted");

        let w =
            parse_reaggregate_window(Some(&(now - chrono::Duration::days(60)).to_rfc3339()), None)
                .expect("spilled window parses");
        let err = check_window_horizon(&w, 30, now).expect_err("beyond horizon rejected");
        assert!(
            err.contains("retention horizon") && err.contains("§4.3.6"),
            "got: {err}"
        );
    }

    #[test]
    fn horizon_zero_retention_admits_any_window() {
        let now = chrono::Utc::now();
        let w = parse_reaggregate_window(
            Some(&(now - chrono::Duration::days(300)).to_rfc3339()),
            None,
        )
        .expect("long window parses");
        check_window_horizon(&w, 0, now).expect("retention 0 = retain indefinitely");
    }
}
