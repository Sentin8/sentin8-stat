// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Stat
// SPDX-License-Identifier: Apache-2.0

//! PostgreSQL store for Stat — properties, funnels, accounts, events,
//! sessions, and the aggregate tables.
//!
//! RLS is enforced at the database level; this store sets the tenant
//! context via `sentin8_set_tenant_context` before reads/writes.

use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::types::{
    Account, CreateAccountRequest, CreateFunnelRequest, CreatePropertyRequest, Funnel, Property,
    RetentionRequest, SettingsUpdate, UpdatePropertyRequest,
};

fn err_db(e: sqlx::Error) -> (axum::http::StatusCode, String) {
    (
        axum::http::StatusCode::INTERNAL_SERVER_ERROR,
        format!("db error: {e}"),
    )
}

/// Set the RLS tenant context for the current transaction.
pub(crate) async fn set_rls(
    conn: &mut sqlx::PgConnection,
    env_id: Uuid,
    subject: &str,
    subject_type: &str,
    scopes: &str,
    is_admin: bool,
) -> Result<(), (axum::http::StatusCode, String)> {
    sqlx::query("SELECT sentin8_set_tenant_context($1, $2, $3, $4, $5, false)")
        .bind(env_id)
        .bind(subject)
        .bind(subject_type)
        .bind(scopes)
        .bind(is_admin)
        .execute(conn)
        .await
        .map_err(err_db)?;
    Ok(())
}

// ── Properties ───────────────────────────────────────────────────────────

/// Create property.
pub async fn create_property(
    pool: &PgPool,
    env_id: Uuid,
    subject: &str,
    scopes: &str,
    is_admin: bool,
    req: &CreatePropertyRequest,
) -> Result<Property, (axum::http::StatusCode, String)> {
    let mut conn = pool.begin().await.map_err(err_db)?;
    set_rls(&mut conn, env_id, subject, "machine", scopes, is_admin).await?;
    let row = sqlx::query(
        r#"INSERT INTO properties (env_id, account_id, name, slug)
           VALUES ($1, $2, $3, $4)
           RETURNING id, env_id, account_id, name, slug, timezone,
                     session_timeout_minutes, retention_days, bot_filter_enabled, pii_deny_list,
                     status, created_at, updated_at"#,
    )
    .bind(env_id)
    .bind(req.account_id)
    .bind(&req.name)
    .bind(&req.slug)
    .fetch_one(&mut *conn)
    .await
    .map_err(|e| {
        if e.to_string().contains("duplicate") || e.to_string().contains("unique") {
            (
                axum::http::StatusCode::CONFLICT,
                format!("property slug already exists: {e}"),
            )
        } else {
            err_db(e)
        }
    })?;
    conn.commit().await.map_err(err_db)?;
    Ok(row_to_property(row))
}

/// List properties.
pub async fn list_properties(
    pool: &PgPool,
    env_id: Uuid,
    subject: &str,
    scopes: &str,
    is_admin: bool,
) -> Result<Vec<Property>, (axum::http::StatusCode, String)> {
    let mut conn = pool.begin().await.map_err(err_db)?;
    set_rls(&mut conn, env_id, subject, "machine", scopes, is_admin).await?;
    let rows = sqlx::query(
        r#"SELECT id, env_id, account_id, name, slug, timezone,
                  session_timeout_minutes, retention_days, bot_filter_enabled, pii_deny_list,
                  status, created_at, updated_at
           FROM properties
           WHERE env_id = $1 AND status <> 'archived'
           ORDER BY created_at DESC"#,
    )
    .bind(env_id)
    .fetch_all(&mut *conn)
    .await
    .map_err(err_db)?;
    Ok(rows.into_iter().map(row_to_property).collect())
}

/// Fetch property.
pub async fn get_property(
    pool: &PgPool,
    env_id: Uuid,
    subject: &str,
    scopes: &str,
    is_admin: bool,
    id: Uuid,
) -> Result<Property, (axum::http::StatusCode, String)> {
    let mut conn = pool.begin().await.map_err(err_db)?;
    set_rls(&mut conn, env_id, subject, "machine", scopes, is_admin).await?;
    let row = sqlx::query(
        r#"SELECT id, env_id, account_id, name, slug, timezone,
                  session_timeout_minutes, retention_days, bot_filter_enabled, pii_deny_list,
                  status, created_at, updated_at
           FROM properties WHERE id = $1"#,
    )
    .bind(id)
    .fetch_optional(&mut *conn)
    .await
    .map_err(err_db)?
    .ok_or((
        axum::http::StatusCode::NOT_FOUND,
        "property not found".into(),
    ))?;
    Ok(row_to_property(row))
}

/// Update property.
pub async fn update_property(
    pool: &PgPool,
    env_id: Uuid,
    subject: &str,
    scopes: &str,
    is_admin: bool,
    id: Uuid,
    req: &UpdatePropertyRequest,
) -> Result<Property, (axum::http::StatusCode, String)> {
    let mut conn = pool.begin().await.map_err(err_db)?;
    set_rls(&mut conn, env_id, subject, "machine", scopes, is_admin).await?;
    let row = sqlx::query(
        r#"UPDATE properties
           SET name = COALESCE($2, name),
               timezone = COALESCE($3, timezone),
               status = COALESCE($4, status),
               updated_at = now()
           WHERE id = $1
           RETURNING id, env_id, account_id, name, slug, timezone,
                     session_timeout_minutes, retention_days, bot_filter_enabled, pii_deny_list,
                     status, created_at, updated_at"#,
    )
    .bind(id)
    .bind(req.name.as_deref())
    .bind(req.timezone.as_deref())
    .bind(req.status.as_deref())
    .fetch_optional(&mut *conn)
    .await
    .map_err(err_db)?
    .ok_or((
        axum::http::StatusCode::NOT_FOUND,
        "property not found".into(),
    ))?;
    conn.commit().await.map_err(err_db)?;
    Ok(row_to_property(row))
}

/// Delete property.
pub async fn delete_property(
    pool: &PgPool,
    env_id: Uuid,
    subject: &str,
    scopes: &str,
    is_admin: bool,
    id: Uuid,
) -> Result<(), (axum::http::StatusCode, String)> {
    let mut conn = pool.begin().await.map_err(err_db)?;
    set_rls(&mut conn, env_id, subject, "machine", scopes, is_admin).await?;
    let res =
        sqlx::query("UPDATE properties SET status = 'archived', updated_at = now() WHERE id = $1")
            .bind(id)
            .execute(&mut *conn)
            .await
            .map_err(err_db)?;
    if res.rows_affected() == 0 {
        return Err((
            axum::http::StatusCode::NOT_FOUND,
            "property not found".into(),
        ));
    }
    conn.commit().await.map_err(err_db)?;
    Ok(())
}

/// Handle set retention.
pub async fn set_retention(
    pool: &PgPool,
    env_id: Uuid,
    subject: &str,
    scopes: &str,
    is_admin: bool,
    id: Uuid,
    req: &RetentionRequest,
) -> Result<(), (axum::http::StatusCode, String)> {
    let mut conn = pool.begin().await.map_err(err_db)?;
    set_rls(&mut conn, env_id, subject, "machine", scopes, is_admin).await?;
    let res =
        sqlx::query("UPDATE properties SET retention_days = $2, updated_at = now() WHERE id = $1")
            .bind(id)
            .bind(req.retention_days)
            .execute(&mut *conn)
            .await
            .map_err(err_db)?;
    if res.rows_affected() == 0 {
        return Err((
            axum::http::StatusCode::NOT_FOUND,
            "property not found".into(),
        ));
    }
    conn.commit().await.map_err(err_db)?;
    Ok(())
}

/// Update settings.
pub async fn update_settings(
    pool: &PgPool,
    env_id: Uuid,
    subject: &str,
    scopes: &str,
    is_admin: bool,
    id: Uuid,
    req: &SettingsUpdate,
) -> Result<(), (axum::http::StatusCode, String)> {
    let mut conn = pool.begin().await.map_err(err_db)?;
    set_rls(&mut conn, env_id, subject, "machine", scopes, is_admin).await?;
    let res = sqlx::query(
        r#"UPDATE properties
           SET session_timeout_minutes = COALESCE($2, session_timeout_minutes),
               timezone = COALESCE($3, timezone),
               bot_filter_enabled = COALESCE($4, bot_filter_enabled),
               pii_deny_list = COALESCE($5, pii_deny_list),
               updated_at = now()
           WHERE id = $1"#,
    )
    .bind(id)
    .bind(req.session_timeout_minutes)
    .bind(req.timezone.as_deref())
    .bind(req.bot_filter_enabled)
    .bind(req.pii_deny_list.as_ref())
    .execute(&mut *conn)
    .await
    .map_err(err_db)?;
    if res.rows_affected() == 0 {
        return Err((
            axum::http::StatusCode::NOT_FOUND,
            "property not found".into(),
        ));
    }
    conn.commit().await.map_err(err_db)?;
    Ok(())
}

fn row_to_property(r: sqlx::postgres::PgRow) -> Property {
    Property {
        id: r.get("id"),
        env_id: r.get("env_id"),
        account_id: r.get("account_id"),
        name: r.get("name"),
        slug: r.get("slug"),
        timezone: r.get("timezone"),
        session_timeout_minutes: r.get("session_timeout_minutes"),
        retention_days: r.get("retention_days"),
        bot_filter_enabled: r.get("bot_filter_enabled"),
        pii_deny_list: r.get("pii_deny_list"),
        status: r.get("status"),
        created_at: r.get("created_at"),
        updated_at: r.get("updated_at"),
    }
}

// ── Accounts ─────────────────────────────────────────────────────────────

/// List accounts.
pub async fn list_accounts(
    pool: &PgPool,
    env_id: Uuid,
    subject: &str,
    scopes: &str,
    is_admin: bool,
) -> Result<Vec<Account>, (axum::http::StatusCode, String)> {
    let mut conn = pool.begin().await.map_err(err_db)?;
    set_rls(&mut conn, env_id, subject, "machine", scopes, is_admin).await?;
    let rows = sqlx::query(
        "SELECT id, env_id, name, created_at FROM accounts WHERE env_id = $1 ORDER BY created_at DESC",
    )

    .bind(env_id)
    .fetch_all(&mut *conn)
    .await
    .map_err(err_db)?;
    Ok(rows
        .into_iter()
        .map(|r| Account {
            id: r.get("id"),
            env_id: r.get("env_id"),
            name: r.get("name"),
            created_at: r.get("created_at"),
        })
        .collect())
}

/// Create account.
pub async fn create_account(
    pool: &PgPool,
    env_id: Uuid,
    subject: &str,
    scopes: &str,
    is_admin: bool,
    req: &CreateAccountRequest,
) -> Result<Account, (axum::http::StatusCode, String)> {
    let mut conn = pool.begin().await.map_err(err_db)?;
    set_rls(&mut conn, env_id, subject, "machine", scopes, is_admin).await?;
    let row = sqlx::query(
        r#"INSERT INTO accounts (env_id, name)
           VALUES ($1, $2)
           RETURNING id, env_id, name, created_at"#,
    )
    .bind(env_id)
    .bind(&req.name)
    .fetch_one(&mut *conn)
    .await
    .map_err(err_db)?;
    conn.commit().await.map_err(err_db)?;
    Ok(Account {
        id: row.get("id"),
        env_id: row.get("env_id"),
        name: row.get("name"),
        created_at: row.get("created_at"),
    })
}

// ── Funnels (Data API) ───────────────────────────────────────────────────

/// Create funnel.
pub async fn create_funnel(
    pool: &PgPool,
    env_id: Uuid,
    subject: &str,
    scopes: &str,
    is_admin: bool,
    req: &CreateFunnelRequest,
) -> Result<Funnel, (axum::http::StatusCode, String)> {
    let mut conn = pool.begin().await.map_err(err_db)?;
    set_rls(&mut conn, env_id, subject, "machine", scopes, is_admin).await?;
    let row = sqlx::query(
        r#"INSERT INTO funnels (env_id, property_id, name, steps)
           VALUES ($1, $2, $3, $4)
           RETURNING id, property_id, name, steps"#,
    )
    .bind(env_id)
    .bind(req.property_id)
    .bind(&req.name)
    .bind(&req.steps)
    .fetch_one(&mut *conn)
    .await
    .map_err(err_db)?;
    conn.commit().await.map_err(err_db)?;
    Ok(Funnel {
        id: row.get("id"),
        property_id: row.get("property_id"),
        name: row.get("name"),
        steps: row.get("steps"),
    })
}

/// Fetch funnel.
pub async fn get_funnel(
    pool: &PgPool,
    env_id: Uuid,
    subject: &str,
    scopes: &str,
    is_admin: bool,
    id: Uuid,
) -> Result<Funnel, (axum::http::StatusCode, String)> {
    let mut conn = pool.begin().await.map_err(err_db)?;
    set_rls(&mut conn, env_id, subject, "machine", scopes, is_admin).await?;
    let row = sqlx::query("SELECT id, property_id, name, steps FROM funnels WHERE id = $1")
        .bind(id)
        .fetch_optional(&mut *conn)
        .await
        .map_err(err_db)?
        .ok_or((axum::http::StatusCode::NOT_FOUND, "funnel not found".into()))?;
    Ok(Funnel {
        id: row.get("id"),
        property_id: row.get("property_id"),
        name: row.get("name"),
        steps: row.get("steps"),
    })
}

// ── Property resolution (unauthenticated web ingest) ─────────────────────

/// Look up a property by id and return its `env_id` binding.
/// Returns `None` if the property does not exist or is archived.
/// Resolve property.
pub async fn resolve_property(
    pool: &PgPool,
    property_id: Uuid,
) -> Result<Option<Uuid>, (axum::http::StatusCode, String)> {
    // Bypass RLS for the public lookup — the propertyId is a public identifier.
    let row = sqlx::query("SELECT env_id FROM properties WHERE id = $1 AND status = 'active'")
        .bind(property_id)
        .fetch_optional(pool)
        .await
        .map_err(err_db)?;
    Ok(row.map(|r| r.get("env_id")))
}

/// Resolve a property slug to `(property_id, env_id)` (server
/// telemetry path). Slugs are unique per env; the platform seed keeps them
/// globally unique per service short name. Same public-lookup bypass as
/// `resolve_property` (the slug is a public identifier).
/// Resolve property slug.
///
/// RLS: `stat.properties` is FORCE-RLS'd — the lookup MUST run inside a
/// transaction with the SYSTEM env context set (the telemetry ingest path
/// has no tenant context of its own; the platform seed's properties live
/// in the system env). Without it the query sees zero rows and every
/// shield decision frame drops with "property slug not found".
pub async fn resolve_property_slug(
    pool: &PgPool,
    slug: &str,
) -> Result<Option<(Uuid, Uuid)>, (axum::http::StatusCode, String)> {
    let mut conn = pool.begin().await.map_err(err_db)?;
    let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
        .bind(sentin8::config::SYSTEM_ENV_ID)
        .execute(&mut *conn)
        .await;
    let row = sqlx::query(
        "SELECT id, env_id FROM properties WHERE slug = $1 AND status = 'active' LIMIT 1",
    )
    .bind(slug)
    .fetch_optional(&mut *conn)
    .await
    .map_err(err_db)?;
    conn.rollback().await.map_err(err_db)?;
    Ok(row.map(|r| (r.get("id"), r.get("env_id"))))
}

// ── Events write ─────────────────────────────────────────────────────────

/// Insert a raw event into `sentin8_stat_events`. RLS context must be set first.
/// Handle insert event.
pub async fn insert_event(
    pool: &PgPool,
    env_id: Uuid,
    e: &crate::types::EventEnvelope,
) -> Result<(), (axum::http::StatusCode, String)> {
    let mut conn = pool.begin().await.map_err(err_db)?;
    set_rls(
        &mut conn,
        env_id,
        "stat-ingest",
        "machine",
        "sentin8:stat:measure",
        true,
    )
    .await?;
    sqlx::query(
        r#"INSERT INTO events
           (id, env_id, property_id, client_id, client_type,
            event_type, event_name, event_category, subject_id, timestamp,
            page_url, page_title, referrer, screen_name, app_version,
            utm_source, utm_medium, utm_campaign, conversions, engagement_time_ms,
            metrics, props, props_pii_stripped, processed)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16,
                   $17, $18, $19, $20, $21, $22, $23, false)
           ON CONFLICT (id, timestamp) DO NOTHING"#,
    )
    .bind(e.event_id)
    .bind(env_id)
    .bind(e.property_id)
    .bind(&e.client_id)
    .bind(&e.client_type)
    .bind(&e.event_type)
    .bind(&e.event_name)
    .bind(e.event_category.as_deref())
    .bind(
        e.subject_id
            .as_deref()
            .and_then(|s| Uuid::parse_str(s).ok()),
    )
    .bind(e.timestamp)
    .bind(e.page_url.as_deref())
    .bind(e.page_title.as_deref())
    .bind(e.referrer.as_deref())
    .bind(e.screen_name.as_deref())
    .bind(e.app_version.as_deref())
    .bind(
        e.traffic_source
            .as_ref()
            .and_then(|t| t.utm_source.as_deref()),
    )
    .bind(
        e.traffic_source
            .as_ref()
            .and_then(|t| t.utm_medium.as_deref()),
    )
    .bind(
        e.traffic_source
            .as_ref()
            .and_then(|t| t.utm_campaign.as_deref()),
    )
    .bind(serde_json::to_value(&e.conversions).unwrap_or(serde_json::Value::Array(vec![])))
    .bind(e.engagement_time_ms)
    .bind(&e.metrics)
    .bind(&e.props)
    .bind(e.props_pii_stripped)
    .execute(&mut *conn)
    .await
    .map_err(err_db)?;
    conn.commit().await.map_err(err_db)?;
    Ok(())
}

// ── Traffic summary (TLS traffic matrix) ──────────────────────────────

/// Read the TLS traffic matrix from `sentin8_stat_aggregate_metrics_daily`.
/// Queries all `tls.traffic.*.count`, `.latency_ms`, `.errors` metric
/// names for the given property and date range, then groups them into
/// per-`(from, to)` summary rows.
/// Read traffic summary.
pub async fn read_traffic_summary(
    pool: &PgPool,
    env_id: Uuid,
    subject: &str,
    scopes: &str,
    is_admin: bool,
    property_id: Uuid,
    from: chrono::NaiveDate,
    to: chrono::NaiveDate,
) -> Result<Vec<crate::types::TrafficSummary>, (axum::http::StatusCode, String)> {
    let mut conn = pool.begin().await.map_err(err_db)?;
    set_rls(&mut conn, env_id, subject, "machine", scopes, is_admin).await?;
    // Fetch all tls.traffic.* metric rows for this property/date range.
    // metric_name looks like: tls.traffic.{from}→{to}.count
    let rows = sqlx::query(
        r#"SELECT metric_name, value
           FROM aggregate_metrics_daily
           WHERE property_id = $1
             AND metric_name LIKE 'tls.traffic.%'
             AND day BETWEEN $2 AND $3
           ORDER BY metric_name, day"#,
    )
    .bind(property_id)
    .bind(from)
    .bind(to)
    .fetch_all(&mut *conn)
    .await
    .map_err(err_db)?;

    // Group by (from, to) pair. The metric name encodes the pair:
    // tls.traffic.{from}→{to}.{count|latency_ms|errors}
    // We take the latest day's value for each metric (the query is
    // ordered by day ascending, so later rows overwrite earlier ones).
    use std::collections::HashMap;
    let mut pairs: HashMap<(String, String), [f64; 3]> = HashMap::new();
    for row in rows {
        let name: String = row.get("metric_name");
        let value: f64 = row.get("value");
        // Parse: tls.traffic.{from}→{to}.{suffix}
        let rest = name.strip_prefix("tls.traffic.");
        if let Some(rest) = rest {
            // The suffix is the last `.` segment; the pair is everything before it.
            if let Some(dot_pos) = rest.rfind('.') {
                let pair_str = &rest[..dot_pos];
                let suffix = &rest[dot_pos + 1..];
                // Split the pair on `→`.
                if let Some(arrow_pos) = pair_str.find('→') {
                    let from = pair_str[..arrow_pos].to_string();
                    let to = pair_str[arrow_pos + 3..].to_string(); // skip `→` (3 bytes)
                    let entry = pairs.entry((from, to)).or_insert([0.0; 3]);
                    match suffix {
                        "count" => entry[0] = value,
                        "latency_ms" => entry[1] = value,
                        "errors" => entry[2] = value,
                        _ => {}
                    }
                }
            }
        }
    }

    Ok(pairs
        .into_iter()
        .map(|((from, to), vals)| crate::types::TrafficSummary {
            from,
            to,
            count: vals[0],
            latency_ms: vals[1],
            errors: vals[2],
        })
        .collect())
}

// ── Aggregate reads (Data API) ───────────────────────────────────────────

/// Read metrics daily.
pub async fn read_metrics_daily(
    pool: &PgPool,
    env_id: Uuid,
    subject: &str,
    scopes: &str,
    is_admin: bool,
    property_id: Uuid,
    metric: &str,
    from: chrono::NaiveDate,
    to: chrono::NaiveDate,
) -> Result<Vec<crate::types::MetricPoint>, (axum::http::StatusCode, String)> {
    let mut conn = pool.begin().await.map_err(err_db)?;
    set_rls(&mut conn, env_id, subject, "machine", scopes, is_admin).await?;
    let rows = sqlx::query(
        r#"SELECT day, metric_name, value
           FROM aggregate_metrics_daily
           WHERE property_id = $1 AND metric_name = $2 AND day BETWEEN $3 AND $4
           ORDER BY day"#,
    )
    .bind(property_id)
    .bind(metric)
    .bind(from)
    .bind(to)
    .fetch_all(&mut *conn)
    .await
    .map_err(err_db)?;
    Ok(rows
        .into_iter()
        .map(|r| crate::types::MetricPoint {
            day: r.get("day"),
            metric_name: r.get("metric_name"),
            value: r.get("value"),
        })
        .collect())
}

/// Read aggregate.
pub async fn read_aggregate(
    pool: &PgPool,
    env_id: Uuid,
    subject: &str,
    scopes: &str,
    is_admin: bool,
    table: &str,
    property_id: Uuid,
    from: chrono::NaiveDate,
    to: chrono::NaiveDate,
) -> Result<Vec<crate::types::AggregateRow>, (axum::http::StatusCode, String)> {
    let mut conn = pool.begin().await.map_err(err_db)?;
    set_rls(&mut conn, env_id, subject, "machine", scopes, is_admin).await?;
    // table is a fixed allow-list at the handler layer; safe to interpolate.
    let sql = format!(
        "SELECT day, dimensions, metrics FROM {table} WHERE property_id = $1 AND day BETWEEN $2 AND $3 ORDER BY day"
    );
    let rows = sqlx::query(&sql)
        .bind(property_id)
        .bind(from)
        .bind(to)
        .fetch_all(&mut *conn)
        .await
        .map_err(err_db)?;
    Ok(rows
        .into_iter()
        .map(|r| crate::types::AggregateRow {
            day: r.get("day"),
            dimensions: r.get("dimensions"),
            metrics: r.get("metrics"),
        })
        .collect())
}
