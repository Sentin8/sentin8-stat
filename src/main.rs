// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Stat
// SPDX-License-Identifier: Apache-2.0

//! Sentin8 Stat — standalone analytics and telemetry collection service.
//!
//! See.
//!
//! Boot runs on the platform `sentin8-shell` crate (design
//! ): registration
//! flag, PQ provider, config, capped pool, PG18 check, state binding, OpenAPI
//! merge, middleware stack and PQ-TLS listener are owned by the shell. This
//! binary supplies only its registration data, state and routes.

#[allow(dead_code)]
mod admin_api;
#[allow(dead_code)]
mod admin_ui;
#[allow(dead_code)]
mod auth;
#[allow(dead_code)]
mod config;
#[allow(dead_code)]
mod data_api;
#[allow(dead_code)]
mod handlers;
#[allow(dead_code)]
mod ingest;
mod openapi;
mod policy;
mod registration;
#[allow(dead_code)]
mod server;
#[allow(dead_code)]
mod store;
#[allow(dead_code)]
mod types;
#[allow(dead_code)]
mod worker;

use utoipa::OpenApi;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    sentin8::shell::serve(
        sentin8::shell::Sentin8Shell::new("sentin8:stat", "SENTIN8_STAT")
            .with_registration(registration::print)
            .with_state(server::build_state)
            .with_own_health()
            .with_router(|router, _state| server::routes(router))
            .with_openapi(openapi::StatOpenApi::openapi()),
    )
    .await
}
