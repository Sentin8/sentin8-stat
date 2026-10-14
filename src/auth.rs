// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Stat
// SPDX-License-Identifier: Apache-2.0

//! Auth token verification for Stat.
//!
//! Re-exports the shared types from the sentin8-auth-client SDK and provides
//! thin wrappers matching the original Stat call sites (taking `&StatConfig` + `&HeaderMap`).

use axum::http::{HeaderMap, StatusCode};

use crate::config::StatConfig;

pub use sentin8::auth::client::AuthContext;

/// Verify a Bearer token. Returns `None` if no token is present;
/// returns `Err` if a token is present but invalid.
pub async fn verify_token_opt(
    config: &StatConfig,
    headers: &HeaderMap,
) -> Result<Option<AuthContext>, (StatusCode, String)> {
    sentin8::auth::client::verify_bearer_token_opt(&config.auth_client, headers).await
}

/// Require a token and the `sentin8:stat:measure` scope (server/mobile ingest).
pub async fn require_measure(
    config: &StatConfig,
    headers: &HeaderMap,
) -> Result<AuthContext, (StatusCode, String)> {
    let a = verify_token_opt(config, headers).await?.ok_or((
        StatusCode::UNAUTHORIZED,
        "missing Authorization header".into(),
    ))?;
    if !a.has_scope("sentin8:stat:measure") {
        return Err((StatusCode::FORBIDDEN, "missing stat:measure scope".into()));
    }
    Ok(a)
}

/// Require a token and the `sentin8:stat:data:read` scope (Data API).
pub async fn require_data_read(
    config: &StatConfig,
    headers: &HeaderMap,
) -> Result<AuthContext, (StatusCode, String)> {
    let a = verify_token_opt(config, headers).await?.ok_or((
        StatusCode::UNAUTHORIZED,
        "missing Authorization header".into(),
    ))?;
    if !a.has_any_scope(&["sentin8:stat:data:read"]) {
        return Err((StatusCode::FORBIDDEN, "missing stat:data:read scope".into()));
    }
    Ok(a)
}

/// Require a token and the `sentin8:stat:data:read` or `sentin8:stat:admin` scope (Admin API).
pub async fn require_admin(
    config: &StatConfig,
    headers: &HeaderMap,
) -> Result<AuthContext, (StatusCode, String)> {
    let a = verify_token_opt(config, headers).await?.ok_or((
        StatusCode::UNAUTHORIZED,
        "missing Authorization header".into(),
    ))?;
    if !a.has_any_scope(&["sentin8:stat:data:read", "sentin8:stat:admin"]) {
        return Err((StatusCode::FORBIDDEN, "missing stat:admin scope".into()));
    }
    Ok(a)
}
