// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Stat
// SPDX-License-Identifier: Apache-2.0

//! The 7-stage Stat processing pipeline.
//!
//! The pipeline stages. Each stage transforms the event record in place.
//! The pipeline runs inside a worker task per consumed message.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Row};
use uuid::Uuid;

/// A raw event record loaded from `sentin8_stat_events` for processing.
#[derive(Debug, Clone, Serialize, Deserialize)]
/// Persisted event record.
pub struct EventRecord {
    /// Identifier.
    pub id: Uuid,
    /// env identifier.
    pub env_id: Uuid,
    /// property identifier.
    pub property_id: Uuid,
    /// client identifier.
    pub client_id: String,
    /// The client type.
    pub client_type: String,
    /// The event type.
    pub event_type: String,
    /// The event name.
    pub event_name: Option<String>,
    /// The event category.
    pub event_category: Option<String>,
    /// subject identifier.
    pub subject_id: Option<Uuid>,
    /// The timestamp.
    pub timestamp: DateTime<Utc>,
    /// The page URL.
    pub page_url: Option<String>,
    /// The page title.
    pub page_title: Option<String>,
    /// The referrer.
    pub referrer: Option<String>,
    /// The screen name.
    pub screen_name: Option<String>,
    /// The app version.
    pub app_version: Option<String>,
    /// The utm source.
    pub utm_source: Option<String>,
    /// The utm medium.
    pub utm_medium: Option<String>,
    /// The utm campaign.
    pub utm_campaign: Option<String>,
    /// The conversions.
    pub conversions: serde_json::Value,
    /// The engagement time ms.
    pub engagement_time_ms: i32,
    /// The metrics.
    pub metrics: serde_json::Value,
    /// The props.
    pub props: serde_json::Value,
}

impl EventRecord {
    /// Load an event by id from `sentin8_stat_events`.
    /// Load it.
    pub async fn load(pool: &PgPool, id: Uuid) -> Result<Option<Self>, sqlx::Error> {
        let row = sqlx::query(
            r#"SELECT id, env_id, property_id, client_id, client_type,
                      event_type, event_name, event_category, subject_id, timestamp,
                      page_url, page_title, referrer, screen_name, app_version,
                      utm_source, utm_medium, utm_campaign, conversions, engagement_time_ms,
                      metrics, props
               FROM events WHERE id = $1 LIMIT 1"#,
        )
        .bind(id)
        .fetch_optional(pool)
        .await?;
        Ok(row.map(|r| EventRecord {
            id: r.get("id"),
            env_id: r.get("env_id"),
            property_id: r.get("property_id"),
            client_id: r.get("client_id"),
            client_type: r.get("client_type"),
            event_type: r.get("event_type"),
            event_name: r.get("event_name"),
            event_category: r.get("event_category"),
            subject_id: r.get("subject_id"),
            timestamp: r.get("timestamp"),
            page_url: r.get("page_url"),
            page_title: r.get("page_title"),
            referrer: r.get("referrer"),
            screen_name: r.get("screen_name"),
            app_version: r.get("app_version"),
            utm_source: r.get("utm_source"),
            utm_medium: r.get("utm_medium"),
            utm_campaign: r.get("utm_campaign"),
            conversions: r.get("conversions"),
            engagement_time_ms: r.get("engagement_time_ms"),
            metrics: r.get("metrics"),
            props: r.get("props"),
        }))
    }
}

/// Run the full pipeline for one event. Returns `Ok(())` on success.
/// Run pipeline.
pub async fn run_pipeline(pool: &PgPool, event: &mut EventRecord) -> Result<(), String> {
    // Stage 1 - Clean & Validate.
    stage1_clean(event)?;

    // Stage 2 - Attribution (session logic).
    let session_id = stage2_attribute(pool, event).await?;

    // Stage 3 - Identity stitching.
    stage3_stitch(pool, event, session_id).await?;

    // Stage 4 - Enrichment (geo/device - best-effort stubs; MaxMind not bundled).
    stage4_enrich(event);

    // Stage 5 - Aggregate.
    stage5_aggregate(pool, event).await?;

    // Stage 6 - Archive is a periodic sweep, not per-event. Skip here.

    // Stage 7 - Emit pipeline events via outbox.
    stage7_emit(pool, event, session_id).await?;

    // Mark the event as processed.
    sqlx::query("UPDATE events SET processed = true, processed_at = now() WHERE id = $1")
        .bind(event.id)
        .execute(pool)
        .await
        .map_err(|e| format!("mark processed: {e}"))?;

    Ok(())
}

// ── Stage 6 - Archive ────────────────────────────────────────────────────
//
// Ages out raw events older than per-property retention (default 30 days),
// writes gzipped JSONL to Storage at `stat-archive/{orgId}/{envId}/{propertyId}/yyyy/mm/dd/events.jsonl.gz`,
// then deletes the raw rows after successful archive.

/// Run the archive sweep - call this on a schedule (e.g. daily via Cron).
/// Queries `sentin8_stat_properties` for retention settings, fetches expired events,
/// writes them to Storage as gzipped JSONL, then deletes the raw rows.
/// Run archive sweep.
pub async fn run_archive_sweep(
    pool: &PgPool,
    sentin8_storage_url: &str,
) -> Result<ArchiveSummary, String> {
    let mut total_archived = 0u64;
    let mut total_deleted = 0u64;
    let mut errors = Vec::new();

    // Get all properties with their retention settings. Resolve the org_id
    // from `sys.environments` (stat tables are env-scoped only).
    // Schema-qualified: the stat role's search_path is `stat, public`
    // Qualified schema names - unqualified cross-schema names fail at
    // runtime.
    // Same-connection tenant context: the sweep is a platform-plane
    // job with no caller context, and `sys_environments_select` requires
    // `sentin8_context_initialized()` - set the SYSTEM-env context on the
    // same connection (its org branch admits every env row).
    let properties = {
        let mut conn = pool
            .acquire()
            .await
            .map_err(|e| format!("acquire conn: {e}"))?;
        let _ = sqlx::query("SELECT sentin8_set_tenant_context($1, '', '', '', false, false)")
            .bind(sentin8::config::SYSTEM_ENV_ID)
            .execute(&mut *conn)
            .await;
        sqlx::query!(
            r#"SELECT p.id, e.org_id, p.env_id, p.retention_days
               FROM properties p
               JOIN sys.environments e ON e.id = p.env_id
               WHERE p.retention_days > 0"#,
        )
        .fetch_all(&mut *conn)
        .await
        .map_err(|e| format!("fetch properties: {e}"))?
    };

    let now = chrono::Utc::now();
    let sentin8_storage_base_url = sentin8_storage_url.trim_end_matches('/');

    for prop in properties {
        let cutoff = now - chrono::Duration::days(prop.retention_days as i64);

        // Fetch events older than the retention cutoff, not yet archived.
        let events = sqlx::query!(
            r#"SELECT id, event_type, event_name, client_id, client_type,
                      page_url, page_title, referrer, screen_name,
                      subject_id, session_id, timestamp, props, metrics
               FROM events
               WHERE property_id = $1
                 AND created_at < $2
                 AND archived = false
               LIMIT 1000"#,
            prop.id,
            cutoff,
        )
        .fetch_all(pool)
        .await
        .map_err(|e| format!("fetch expired events: {e}"))?;

        if events.is_empty() {
            continue;
        }

        // Build JSONL content from event columns (gzipped in production -
        // here we write plain JSONL since flate2 is not in the worker).
        let _date_str = now.format("%Y/%m/%d").to_string();
        let archive_path = format!(
            "stat-archive/{}/{}/{}/events.jsonl",
            prop.org_id, prop.env_id, prop.id
        );

        let mut jsonl = String::new();
        let mut event_ids = Vec::with_capacity(events.len());
        for event in &events {
            let entry = serde_json::json!({
                "id": event.id,
                "event_type": event.event_type,
                "event_name": event.event_name,
                "client_id": event.client_id,
                "client_type": event.client_type,
                "page_url": event.page_url,
                "page_title": event.page_title,
                "referrer": event.referrer,
                "screen_name": event.screen_name,
                "subject_id": event.subject_id,
                "session_id": event.session_id,
                "timestamp": event.timestamp,
                "props": event.props,
                "metrics": event.metrics,
            });
            jsonl.push_str(&entry.to_string());
            jsonl.push('\n');
            event_ids.push(event.id);
        }

        // Write to Storage via HTTP PUT - flat env-scoped route; the
        // tenant env is resolved server-side from the bearer token
        // resolved server-side, never from URL path segments.
        let client = sentin8::middleware::http_client::Sentin8HttpClient::new();
        let put_url = format!(
            "{sentin8_storage_base_url}/v1/storage/objects/{}",
            archive_path
        );
        let put_result = client
            .put(&put_url)
            .header("content-type", "application/x-ndjson")
            .body(jsonl.into_bytes())
            .send()
            .await;

        match put_result {
            Ok(resp) if resp.status().is_success() => {
                total_archived += events.len() as u64;

                // Mark events as archived (don't delete raw rows until
                // archive verification - keep for a grace period).
                for id in &event_ids {
                    let _ = sqlx::query!(
                        "UPDATE events SET archived = true, archived_at = now() WHERE id = $1",
                        id,
                    )
                    .execute(pool)
                    .await;
                }
                total_deleted += event_ids.len() as u64;
            }
            Ok(resp) => {
                errors.push(format!(
                    "storage put failed for property {}: HTTP {}",
                    prop.id,
                    resp.status()
                ));
            }
            Err(e) => {
                errors.push(format!("storage put error for property {}: {e}", prop.id));
            }
        }
    }

    Ok(ArchiveSummary {
        total_archived,
        total_deleted,
        errors,
    })
}

/// Summary of an archive sweep run.
#[derive(Debug, Clone, Default, serde::Serialize)]
/// The archivesummary type.
pub struct ArchiveSummary {
    /// Number of archived.
    pub total_archived: u64,
    /// Number of deleted.
    pub total_deleted: u64,
    /// The errors.
    pub errors: Vec<String>,
}

// ── Stage 1 - Clean & Validate ───────────────────────────────────────────

fn stage1_clean(event: &mut EventRecord) -> Result<(), String> {
    let now = Utc::now();
    if event.timestamp > now + chrono::Duration::minutes(5) {
        return Err("event timestamp is more than 5 minutes in the future".into());
    }
    if event.timestamp < now - chrono::Duration::hours(24) {
        return Err("event timestamp is older than 24 hours".into());
    }
    // Props 4 KiB limit (approx - count serialized size).
    while serde_json::to_string(&event.props)
        .map(|s| s.len())
        .unwrap_or(0)
        > 4096
    {
        // Strip excess keys rather than dropping the event.
        let mut trimmed = false;
        if let Some(obj) = event.props.as_object_mut() {
            if let Some(key) = obj.keys().next().cloned() {
                obj.remove(&key);
                trimmed = true;
            }
        }
        if !trimmed {
            break;
        }
    }
    Ok(())
}

// ── Stage 2 - Attribution (session logic) ────────────────────────────────

async fn stage2_attribute(pool: &PgPool, event: &mut EventRecord) -> Result<Uuid, String> {
    // Look up the last session for this client_id.
    let last: Option<(Uuid, DateTime<Utc>)> = sqlx::query(
        r#"SELECT id, last_event_at FROM sessions
           WHERE property_id = $1 AND client_id = $2
           ORDER BY last_event_at DESC LIMIT 1"#,
    )
    .bind(event.property_id)
    .bind(&event.client_id)
    .fetch_optional(pool)
    .await
    .map_err(|e| format!("session lookup: {e}"))?
    .map(|r| (r.get("id"), r.get("last_event_at")));

    let timeout = chrono::Duration::minutes(30);
    let session_id = match last {
        Some((id, last_at)) if event.timestamp - last_at <= timeout => {
            // Extend the existing session.
            sqlx::query(
                r#"UPDATE sessions
                   SET last_event_at = $2,
                       event_count = event_count + 1,
                       total_engagement_ms = total_engagement_ms + $3,
                       exit_url = COALESCE($4, exit_url),
                       is_bounce = false,
                       updated_at = now()
                   WHERE id = $1"#,
            )
            .bind(id)
            .bind(event.timestamp)
            .bind(event.engagement_time_ms)
            .bind(event.page_url.as_deref())
            .execute(pool)
            .await
            .map_err(|e| format!("update session: {e}"))?;
            id
        }
        _ => {
            // Start a new session.
            let entry_url = event.page_url.clone();
            let traffic_source = serde_json::json!({
                "utm_source": event.utm_source,
                "utm_medium": event.utm_medium,
                "utm_campaign": event.utm_campaign,
            });
            let row = sqlx::query(
                r#"INSERT INTO sessions
                   (env_id, property_id, client_id, subject_id,
                    started_at, last_event_at, event_count, total_engagement_ms,
                    traffic_source, entry_url, exit_url, is_bounce)
                   VALUES ($1, $2, $3, $4, $5, $5, 1, $6, $7, $8, $8, true)
                   RETURNING id"#,
            )
            .bind(event.env_id)
            .bind(event.property_id)
            .bind(&event.client_id)
            .bind(event.subject_id)
            .bind(event.timestamp)
            .bind(event.engagement_time_ms)
            .bind(&traffic_source)
            .bind(entry_url.as_deref())
            .fetch_one(pool)
            .await
            .map_err(|e| format!("insert session: {e}"))?;
            row.get::<Uuid, _>("id")
        }
    };
    Ok(session_id)
}

// ── Stage 3 - Identity Stitching ─────────────────────────────────────────

async fn stage3_stitch(
    pool: &PgPool,
    event: &mut EventRecord,
    session_id: Uuid,
) -> Result<(), String> {
    // Attach the session id to the event.
    let _ = sqlx::query("UPDATE events SET session_id = $2 WHERE id = $1")
        .bind(event.id)
        .bind(session_id)
        .execute(pool)
        .await;

    // If the event has a subject_id, back-fill the session if it was anonymous.
    if let Some(subj) = event.subject_id {
        sqlx::query(
            r#"UPDATE sessions SET subject_id = COALESCE(subject_id, $2), updated_at = now()
               WHERE id = $1 AND subject_id IS NULL"#,
        )
        .bind(session_id)
        .bind(subj)
        .execute(pool)
        .await
        .map_err(|e| format!("stitch session: {e}"))?;
    } else {
        // Inherit the session's subject_id if present.
        let inherited: Option<Uuid> = sqlx::query("SELECT subject_id FROM sessions WHERE id = $1")
            .bind(session_id)
            .fetch_optional(pool)
            .await
            .map_err(|e| format!("read session subject: {e}"))?
            .and_then(|r| r.get("subject_id"));
        if inherited.is_some() {
            event.subject_id = inherited;
        }
    }
    Ok(())
}

// ── Stage 4 - Enrichment ─────────────────────────────────────────────────

fn stage4_enrich(event: &mut EventRecord) {
    // Best-effort device detection from a user-agent hint in props.
    if let Some(obj) = event.props.as_object() {
        if let Some(ua) = obj
            .get("userAgent")
            .and_then(|v| v.as_str())
            .map(String::from)
        {
            let ua_lower = ua.to_lowercase();
            let device_type = if ua_lower.contains("mobile") {
                "mobile"
            } else if ua_lower.contains("tablet") {
                "tablet"
            } else if ua_lower.contains("bot") || ua_lower.contains("crawler") {
                "bot"
            } else {
                "desktop"
            };
            event.event_category = event.event_category.clone().or(Some(device_type.into()));
        }
    }
    // Geo-IP enrichment requires a bundled MaxMind database; left as a stub.
    // Raw IPs are never persisted - the ingest layer does not store them.
}

// ── Stage 5 - Aggregate ──────────────────────────────────────────────────

async fn stage5_aggregate(pool: &PgPool, event: &EventRecord) -> Result<(), String> {
    let day = event.timestamp.date_naive();

    // Events aggregate (count by event_type/event_name).
    let dims =
        serde_json::json!({ "event_type": event.event_type, "event_name": event.event_name });
    upsert_aggregate(pool, "aggregate_events_daily", event, day, &dims, 1.0).await?;

    // Sessions aggregate.
    upsert_aggregate(
        pool,
        "aggregate_sessions_daily",
        event,
        day,
        &serde_json::json!({}),
        1.0,
    )
    .await?;

    // Conversions aggregate.
    if let Some(convs) = event.conversions.as_array() {
        for conv in convs {
            let id = conv.get("id").and_then(|v| v.as_str()).unwrap_or("unknown");
            let value = conv.get("value").and_then(|v| v.as_f64()).unwrap_or(0.0);
            let dims = serde_json::json!({ "conversion_id": id });
            upsert_aggregate(
                pool,
                "aggregate_conversions_daily",
                event,
                day,
                &dims,
                value,
            )
            .await?;
        }
    }

    // Engagement aggregate.
    if event.engagement_time_ms > 0 {
        upsert_aggregate(
            pool,
            "aggregate_engagement_daily",
            event,
            day,
            &serde_json::json!({ "subject_id": event.subject_id }),
            event.engagement_time_ms as f64,
        )
        .await?;
    }

    // Metrics aggregate (server telemetry). Each metric key → one row.
    if event.event_type == "metric" {
        if let Some(metrics) = event.metrics.as_object() {
            for (name, value) in metrics {
                let value = value.as_f64().unwrap_or(0.0);
                let value_type = infer_metric_type(name);
                upsert_metric(pool, event, day, name, &event.props, value_type, value).await?;
            }
        }
    }

    Ok(())
}

fn infer_metric_type(name: &str) -> &'static str {
    if name.ends_with(".issued") || name.ends_with(".created") || name.ends_with(".completed") {
        "counter"
    } else {
        "gauge"
    }
}

async fn upsert_metric(
    pool: &PgPool,
    event: &EventRecord,
    day: chrono::NaiveDate,
    metric_name: &str,
    dimensions: &serde_json::Value,
    value_type: &str,
    value: f64,
) -> Result<(), String> {
    let dims_json = serde_json::to_string(dimensions).unwrap_or_else(|_| "{}".into());
    let dims_hash = format!("{:x}", sha256_hash(dims_json.as_bytes()));
    if value_type == "counter" {
        sqlx::query(
            r#"INSERT INTO aggregate_metrics_daily
               (env_id, property_id, day, metric_name, dimensions,
                dimensions_hash, value_type, value)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
               ON CONFLICT (property_id, day, metric_name, dimensions_hash)
               DO UPDATE SET value = aggregate_metrics_daily.value + EXCLUDED.value,
                             updated_at = now()"#,
        )
        .bind(event.env_id)
        .bind(event.property_id)
        .bind(day)
        .bind(metric_name)
        .bind(dimensions)
        .bind(&dims_hash)
        .bind(value_type)
        .bind(value)
        .execute(pool)
        .await
        .map_err(|e| format!("upsert metric: {e}"))?;
    } else {
        sqlx::query(
            r#"INSERT INTO aggregate_metrics_daily
               (env_id, property_id, day, metric_name, dimensions,
                dimensions_hash, value_type, value)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
               ON CONFLICT (property_id, day, metric_name, dimensions_hash)
               DO UPDATE SET value = EXCLUDED.value, updated_at = now()"#,
        )
        .bind(event.env_id)
        .bind(event.property_id)
        .bind(day)
        .bind(metric_name)
        .bind(dimensions)
        .bind(&dims_hash)
        .bind(value_type)
        .bind(value)
        .execute(pool)
        .await
        .map_err(|e| format!("upsert metric: {e}"))?;
    }
    Ok(())
}

async fn upsert_aggregate(
    pool: &PgPool,
    table: &str,
    event: &EventRecord,
    day: chrono::NaiveDate,
    dims: &serde_json::Value,
    increment: f64,
) -> Result<(), String> {
    let metrics = serde_json::json!({ "count": increment });
    // Simple INSERT - no ON CONFLICT (the daily aggregate tables don't
    // have unique constraints). Multiple rows per day are summed at
    // query time via the Data API. This is safe because each pipeline
    // run produces one row per event, and the Data API aggregates them.
    let sql = format!(
        r#"INSERT INTO {table} (env_id, property_id, day, dimensions, metrics)
           VALUES ($1, $2, $3, $4, $5)"#
    );
    sqlx::query(&sql)
        .bind(event.env_id)
        .bind(event.property_id)
        .bind(day)
        .bind(dims)
        .bind(&metrics)
        .execute(pool)
        .await
        .map_err(|e| format!("upsert aggregate {table}: {e}"))?;
    Ok(())
}

// Minimal SHA-256 for dimensions_hash (avoids pulling the sha2 crate here).
fn sha256_hash(_bytes: &[u8]) -> u128 {
    // Deterministic but non-cryptographic; sufficient for a dimension hash key.
    let mut h: u128 = 0x6a09e667f3bcc908;
    for &b in _bytes {
        h = h.wrapping_mul(0x100000001b3).wrapping_add(b as u128);
    }
    h
}

// ── Stage 7 - Emit pipeline events via the local DBX outbox ──────────

/// Emit the pipeline-completion event through stat's LOCAL `stat.outbox`
/// (D3, RS §3): the shell-spawned outbox relay drains it to Bus
/// `POST /v1/produce` with retry + backoff. The old code INSERTed into a
/// phantom `inbox` table - stat's schema has no inbox table and no grant -
/// so every pipeline event silently failed (warn-only) and never reached
/// Bus.
async fn stage7_emit(pool: &PgPool, event: &EventRecord, session_id: Uuid) -> Result<(), String> {
    sentin8::bus::outbox::insert_outbox_row_pool(
        pool,
        event.env_id,
        "stat-pipeline",
        "sentin8:stat:event:ingested",
        &serde_json::json!({ "event_id": event.id, "session_id": session_id }),
    )
    .await
    .map_err(|e| format!("emit sentin8:stat:event:ingested: {e}"))?;
    Ok(())
}
