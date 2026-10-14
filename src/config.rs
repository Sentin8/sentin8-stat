// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Stat
// SPDX-License-Identifier: Apache-2.0

//! Stat configuration loaded from environment variables.
//!
//! Stat service configuration.

use std::env;

use sentin8::auth::client::{Client as AuthClient, ClientOptions};

#[derive(Debug, Clone)]
/// Configuration for stat.
pub struct StatConfig {
    /// The port.
    pub port: u16,
    /// The database URL.
    pub database_url: String,
    /// The valkey URL.
    pub valkey_url: String,
    /// The sentin8 auth issuer.
    pub sentin8_auth_issuer: String,
    /// The sentin8 auth JWKS URL.
    pub sentin8_auth_jwks_url: String,
    /// The sentin8 bus URL.
    pub sentin8_bus_url: String,
    /// Storage base URL for the worker archive sweep (stat design §4.3.6).
    /// The sentin8 storage URL.
    pub sentin8_storage_url: String,
    /// Bus stream family for Stat admin CRUD events (default `"stat"`).
    /// The stream family.
    pub stream_family: String,
    /// Max events per `/v1/m/collect` batch.
    /// The collect batch max.
    pub collect_batch_max: usize,
    /// Max body size for `/v1/m/collect` (bytes).
    /// The collect body max bytes.
    pub collect_body_max_bytes: usize,
    /// Web ingest rate limit per clientId (events/minute).
    /// The web rate limit per minute.
    pub web_rate_limit_per_minute: u32,
    /// Server/mobile ingest rate limit per M2M client/property (events/minute).
    /// The server rate limit per minute.
    pub server_rate_limit_per_minute: u32,
    /// Shared Auth client — constructed once so the discovery and JWKS
    /// caches are reused across every request (5-minute TTL each).
    /// Cloning is cheap (the caches live behind an `Arc`).
    /// The auth client.
    pub auth_client: AuthClient,
}

impl StatConfig {
    /// Handle from env.
    pub fn from_env() -> Self {
        let cfg = sentin8::config::Sentin8Config::from_env();
        Self {
            port: env::var("SENTIN8_STAT_PORT")
                .expect("SENTIN8_STAT_PORT must be set by captain")
                .parse()
                .expect("SENTIN8_STAT_PORT must be a valid u16"),
            database_url: env::var("SENTIN8_STAT_DATABASE_URL").unwrap_or_else(|_| {
                env::var("DATABASE_URL").unwrap_or_else(|_| {
                    sentin8::config::Sentin8Config::default_database_url().to_string()
                })
            }),
            // VALKEYDERIVE-1 (group DESIGN.md §3.1): explicit env override,
            // else the plane-derived URL — the historical `/3` DB number was
            // inert (GLIDE connects at DB 0; ACLs are the isolation).
            valkey_url: env::var("SENTIN8_STAT_VALKEY_URL")
                .ok()
                .filter(|s| !s.trim().is_empty())
                .unwrap_or_else(|| sentin8::config::service_valkey_url()),
            sentin8_auth_issuer: env::var("SENTIN8_AUTH_ISSUER")
                .unwrap_or_else(|_| cfg.sentin8_auth_issuer()),
            sentin8_auth_jwks_url: env::var("SENTIN8_AUTH_JWKS_URL")
                .unwrap_or_else(|_| cfg.sentin8_auth_jwks_url()),
            sentin8_bus_url: env::var("SENTIN8_BUS_URL").unwrap_or_else(|_| cfg.sentin8_bus_url()),
            sentin8_storage_url: env::var("SENTIN8_STORAGE_URL")
                .unwrap_or_else(|_| cfg.sentin8_storage_url()),
            stream_family: env::var("SENTIN8_STAT_STREAM_FAMILY").unwrap_or_else(|_| "stat".into()),
            collect_batch_max: env::var("SENTIN8_STAT_COLLECT_BATCH_MAX")
                .unwrap_or("100".into())
                .parse()
                .unwrap_or(100),
            collect_body_max_bytes: env::var("SENTIN8_STAT_COLLECT_BODY_MAX_BYTES")
                .unwrap_or("1048576".into())
                .parse()
                .unwrap_or(1_048_576),
            web_rate_limit_per_minute: env::var("SENTIN8_STAT_WEB_RATE_LIMIT")
                .unwrap_or("1000".into())
                .parse()
                .unwrap_or(1000),
            server_rate_limit_per_minute: env::var("SENTIN8_STAT_SERVER_RATE_LIMIT")
                .unwrap_or("10000".into())
                .parse()
                .unwrap_or(10_000),
            auth_client: AuthClient::new(ClientOptions {
                base_url: env::var("SENTIN8_AUTH_ISSUER")
                    .unwrap_or_else(|_| cfg.sentin8_auth_issuer()),
                ..Default::default()
            }),
        }
    }
}
