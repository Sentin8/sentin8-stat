// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Stat
// SPDX-License-Identifier: Apache-2.0

//! Sentin8:Stat Admin UI handlers — RFW definitions.
//! Served from `GET /v1/admin/ui/{page}`, rendered by Sentin8:Dash at runtime.

use crate::handlers::AppState;
use axum::{
    extract::{Path, Query, State},
    http::HeaderMap,
    Json,
};
use sentin8::rfw::page::*;
use sentin8::rfw::response::AdminUiResponse;
use sentin8::rfw::widget::*;
use serde::Deserialize;
use sqlx::Row;

#[derive(Deserialize, utoipa::IntoParams, utoipa::ToSchema)]
/// The targetenvquery type.
pub struct TargetEnvQuery {
    #[serde(default)]
    /// target env identifier.
    pub target_env_id: Option<String>,
}

/// Fetch admin ui.
#[utoipa::path(
    get,
    path = "/v1/admin/ui/{page}",
    params(
        ("page" = String, Path, description = "RFW page name"),
        ("target_env_id" = String, Query, description = "Target env (RLS context)")
    ),
    responses(
        (status = 200, description = "RFW page definition (rendered by Sentin8:Dash)", body = serde_json::Value),
        (status = 403, description = "Caller lacks a stat read/admin scope"),
        (status = 404, description = "Unknown page"),
    ),
    security(("sentin8:stat:admin" = [])),
    tag = "admin-ui",
)]
pub async fn get_admin_ui(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(page): Path<String>,
) -> Result<Json<serde_json::Value>, (axum::http::StatusCode, String)> {
    let _a = crate::auth::require_admin(&state.config, &headers).await?;
    let def = match page.as_str() {
        "overview" => AdminPage::new("Stat Overview")
            .widget(card(
                "Summary",
                "Events today, active properties, metrics count.",
            ))
            .build(),
        "properties" => AdminPage::new("Properties")
            .action(link("Create Property", "properties/new"))
            .widget(table_with_actions(
                vec![col("id", "Property ID"), cols("name", "Name")],
                "/properties",
                vec![row_action_post("Delete", "properties/{id}/delete")],
            ))
            .build(),
        "properties/new" => AdminPage::new("Create Property")
            .widget(RemoteWidget::Form(WidgetForm {
                fields: vec![
                    WidgetFormField {
                        key: "name".into(),
                        label: "Property Name".into(),
                        field_type: FormFieldType::Text,
                        required: true,
                        placeholder: Some("e.g. Web Analytics".into()),
                        default_value: None,
                        options: None,
                        validation: None,
                        width: None,
                        help_text: None,
                        visible_if: None,
                    },
                    WidgetFormField {
                        key: "slug".into(),
                        label: "Slug".into(),
                        field_type: FormFieldType::Text,
                        required: true,
                        placeholder: Some("e.g. web-analytics".into()),
                        default_value: None,
                        options: None,
                        validation: None,
                        width: None,
                        help_text: Some("URL-safe slug for this property.".into()),
                        visible_if: None,
                    },
                ],
                submit_endpoint: "/v1/admin/properties".into(),
                submit_label: "Create Property".into(),
                cancel_label: "Cancel".into(),
                method: FormMethod::Post,
            }))
            .build(),
        "accounts" => AdminPage::new("Accounts")
            .action(link("Create Account", "accounts/new"))
            .widget(table(
                vec![col("id", "Account ID"), cols("name", "Name")],
                "/accounts",
            ))
            .build(),
        "accounts/new" => AdminPage::new("Create Account")
            .widget(RemoteWidget::Form(WidgetForm {
                fields: vec![WidgetFormField {
                    key: "name".into(),
                    label: "Account Name".into(),
                    field_type: FormFieldType::Text,
                    required: true,
                    placeholder: Some("e.g. Marketing Analytics".into()),
                    default_value: None,
                    options: None,
                    validation: None,
                    width: None,
                    help_text: None,
                    visible_if: None,
                }],
                submit_endpoint: "/v1/admin/accounts".into(),
                submit_label: "Create Account".into(),
                cancel_label: "Cancel".into(),
                method: FormMethod::Post,
            }))
            .build(),
        "events" => AdminPage::new("Events")
            .widget(table(
                vec![
                    col("id", "Event ID"),
                    cols("event_type", "Type"),
                    cols("event_name", "Name"),
                    cols("timestamp", "Timestamp"),
                ],
                "/events",
            ))
            .build(),
        "metrics" => AdminPage::new("Metrics")
            .widget(table(
                vec![
                    cols("metric_name", "Metric"),
                    cols("value", "Value"),
                    cols("day", "Day"),
                ],
                "/metrics",
            ))
            .build(),
        // ── Policy Studio — shared page
        // constructors; the guard guarantees `Some` ( dispatch).
        p if sentin8::rfw::policy_page("sentin8:stat", p).is_some() => {
            sentin8::rfw::policy_page("sentin8:stat", p)
                .expect("policy_page checked in guard")
                .build()
        }
        _ => {
            return Err((
                axum::http::StatusCode::NOT_FOUND,
                format!("Unknown admin UI page: {page}"),
            ))
        }
    };
    Ok(Json(
        serde_json::to_value(AdminUiResponse::page(def)).unwrap(),
    ))
}

/// `GET /v1/admin/{resource}` — returns a JSON array of admin data rows.
/// Fetch admin data.
#[utoipa::path(
    get,
    path = "/v1/admin/{resource}",
    params(
        ("resource" = String, Path, description = "Admin data resource"),
        ("target_env_id" = String, Query, description = "Target env (RLS context)")
    ),
    responses(
        (status = 200, description = "The resource's rows for the RFW table", body = serde_json::Value),
        (status = 403, description = "Caller lacks a stat read/admin scope"),
        (status = 404, description = "Unknown resource"),
    ),
    security(("sentin8:stat:admin" = [])),
    tag = "admin-ui",
)]
pub async fn get_admin_data(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<TargetEnvQuery>,
    Path(resource): Path<String>,
) -> Result<Json<serde_json::Value>, (axum::http::StatusCode, String)> {
    let a = crate::auth::require_admin(&state.config, &headers).await?;
    let env_id = q
        .target_env_id
        .as_deref()
        .and_then(|s| uuid::Uuid::parse_str(s).ok())
        .ok_or_else(|| {
            (
                axum::http::StatusCode::BAD_REQUEST,
                "missing target_env_id".into(),
            )
        })?;
    let rows: Vec<serde_json::Value> = match resource.as_str() {
        "properties" => {
            let mut conn = state.pool.begin().await.map_err(|e| {
                (
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                    format!("db error: {e}"),
                )
            })?;
            let _ = sqlx::query("SELECT sentin8_set_tenant_context($1, $2, $3, $4, $5)")
                .bind(env_id)
                .bind(&a.claims.sub)
                .bind(&a.claims.token_tp)
                .bind(&a.claims.scope)
                .bind(a.is_platform_admin())
                .execute(&mut *conn)
                .await;
            sqlx::query("SELECT id::text, name FROM sentin8_stat_properties WHERE status <> 'archived' ORDER BY created_at DESC LIMIT 100")
                .fetch_all(&mut *conn).await
                .map(|rows| rows.iter().map(|row| serde_json::json!({
                    "id": row.get::<Option<String>, &str>("id").unwrap_or_default(),
                    "name": row.get::<Option<String>, &str>("name").unwrap_or_default(),
                })).collect()).unwrap_or_default()
        }
        "events" => {
            let mut conn = state.pool.begin().await.map_err(|e| {
                (
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                    format!("db error: {e}"),
                )
            })?;
            let _ = sqlx::query("SELECT sentin8_set_tenant_context($1, $2, $3, $4, $5)")
                .bind(env_id)
                .bind(&a.claims.sub)
                .bind(&a.claims.token_tp)
                .bind(&a.claims.scope)
                .bind(a.is_platform_admin())
                .execute(&mut *conn)
                .await;
            sqlx::query("SELECT id::text, event_type, event_name, timestamp::text FROM sentin8_stat_events ORDER BY timestamp DESC LIMIT 100")
                .fetch_all(&mut *conn).await
                .map(|rows| rows.iter().map(|row| serde_json::json!({
                    "id": row.get::<Option<String>, &str>("id").unwrap_or_default(),
                    "event_type": row.get::<Option<String>, &str>("event_type").unwrap_or_default(),
                    "event_name": row.get::<Option<String>, &str>("event_name").unwrap_or_default(),
                    "timestamp": row.get::<Option<String>, &str>("timestamp").unwrap_or_default(),
                })).collect()).unwrap_or_default()
        }
        "metrics" => {
            let mut conn = state.pool.begin().await.map_err(|e| {
                (
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                    format!("db error: {e}"),
                )
            })?;
            let _ = sqlx::query("SELECT sentin8_set_tenant_context($1, $2, $3, $4, $5)")
                .bind(env_id)
                .bind(&a.claims.sub)
                .bind(&a.claims.token_tp)
                .bind(&a.claims.scope)
                .bind(a.is_platform_admin())
                .execute(&mut *conn)
                .await;
            sqlx::query("SELECT metric_name, value::text, day::text FROM sentin8_stat_aggregate_metrics_daily ORDER BY day DESC LIMIT 100")
                .fetch_all(&mut *conn).await
                .map(|rows| rows.iter().map(|row| serde_json::json!({
                    "metric_name": row.get::<Option<String>, &str>("metric_name").unwrap_or_default(),
                    "value": row.get::<Option<String>, &str>("value").unwrap_or_default(),
                    "day": row.get::<Option<String>, &str>("day").unwrap_or_default(),
                })).collect()).unwrap_or_default()
        }
        "accounts" => {
            let mut conn = state.pool.begin().await.map_err(|e| {
                (
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                    format!("db error: {e}"),
                )
            })?;
            let _ = sqlx::query("SELECT sentin8_set_tenant_context($1, $2, $3, $4, $5)")
                .bind(env_id)
                .bind(&a.claims.sub)
                .bind(&a.claims.token_tp)
                .bind(&a.claims.scope)
                .bind(a.is_platform_admin())
                .execute(&mut *conn)
                .await;
            sqlx::query("SELECT id::text, name FROM sentin8_stat_accounts WHERE status <> 'archived' ORDER BY created_at DESC LIMIT 100")
                .fetch_all(&mut *conn).await
                .map(|rows| rows.iter().map(|row| serde_json::json!({
                    "id": row.get::<Option<String>, &str>("id").unwrap_or_default(),
                    "name": row.get::<Option<String>, &str>("name").unwrap_or_default(),
                })).collect()).unwrap_or_default()
        }
        _ => vec![],
    };
    Ok(Json(serde_json::Value::Array(rows)))
}

fn col(key: &str, label: &str) -> WidgetDataTableColumn {
    WidgetDataTableColumn {
        key: key.into(),
        label: label.into(),
        sortable: false,
        width: None,
        format: None,
    }
}
fn cols(key: &str, label: &str) -> WidgetDataTableColumn {
    WidgetDataTableColumn {
        key: key.into(),
        label: label.into(),
        sortable: true,
        width: None,
        format: None,
    }
}
fn table(columns: Vec<WidgetDataTableColumn>, endpoint: &str) -> RemoteWidget {
    RemoteWidget::DataTable(WidgetDataTable {
        columns,
        data_endpoint: endpoint.into(),
        sortable: true,
        filterable: true,
        page_size: 20,
        empty_message: Some("No data.".into()),
        row_link: None,
        row_actions: vec![],
    })
}
fn table_with_actions(
    columns: Vec<WidgetDataTableColumn>,
    endpoint: &str,
    row_actions: Vec<WidgetButton>,
) -> RemoteWidget {
    RemoteWidget::DataTable(WidgetDataTable {
        columns,
        data_endpoint: endpoint.into(),
        sortable: true,
        filterable: true,
        page_size: 20,
        empty_message: Some("No data.".into()),
        row_link: None,
        row_actions,
    })
}
#[allow(dead_code)]
fn row_action(label: &str, route: &str) -> WidgetButton {
    WidgetButton {
        label: label.into(),
        button_type: ButtonType::Link,
        route: Some(route.into()),
        endpoint: None,
        icon: None,
    }
}
fn row_action_post(label: &str, endpoint: &str) -> WidgetButton {
    WidgetButton {
        label: label.into(),
        button_type: ButtonType::Primary,
        route: None,
        endpoint: Some(endpoint.into()),
        icon: None,
    }
}
fn card(title: &str, body: &str) -> RemoteWidget {
    RemoteWidget::Card(WidgetCard {
        title: Some(title.into()),
        subtitle: None,
        children: vec![RemoteWidget::Text(WidgetText {
            text: body.into(),
            text_type: WidgetTextType::Body,
            align: TextAlign::Left,
            max_lines: None,
        })],
        actions: vec![],
    })
}
#[allow(dead_code)]
fn link(label: &str, route: &str) -> AdminUiAction {
    AdminUiAction {
        label: label.into(),
        action_type: AdminUiActionType::Link,
        route: Some(route.into()),
        endpoint: None,
        icon: Some("add".into()),
    }
}
