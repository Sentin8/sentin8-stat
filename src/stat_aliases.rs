// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-License-Identifier: Apache-2.0

//! Annotated RFW POST-alias wrapper (Dash 28.14): the same handler body,
//! alias path (OAPEC design §2 rule 3).

use crate::handlers::AppState;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};

/// `POST /v1/admin/properties/{id}/delete` - RFW alias of
/// `DELETE /v1/admin/properties/{id}`.
#[utoipa::path(
    post,
    path = "/v1/admin/properties/{id}/delete",
    params(
        ("id" = uuid::Uuid, Path, description = "Property id"),
        ("target_env_id" = String, Query, description = "Target env (RLS context)")
    ),
    responses(
        (status = 200, description = "Property deleted (same contract as DELETE /v1/admin/properties/{id})"),
        (status = 403, description = "Missing stat:admin scope"),
        (status = 404, description = "Unknown property"),
    ),
    security(("sentin8:stat:admin" = [])),
    tag = "stat",
)]
pub async fn property_delete(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<crate::admin_ui::TargetEnvQuery>,
    Path(id): Path<uuid::Uuid>,
) -> Result<StatusCode, (StatusCode, String)> {
    crate::admin_api::delete_property(State(state), headers, Query(q), Path(id)).await
}
