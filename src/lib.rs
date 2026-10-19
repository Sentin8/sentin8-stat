// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Stat
// SPDX-License-Identifier: Apache-2.0

//! Sentin8 Stat - library re-exports for integration tests.

#![deny(missing_docs)]

/// Admin API handlers (property/dimension management).
pub mod admin_api;
/// Admin UI (RFW) handlers.
pub mod admin_ui;
/// Produce/consume authentication helpers.
pub mod auth;
/// Environment configuration.
pub mod config;
/// Data query API (read-side).
pub mod data_api;
/// Shared HTTP handlers and state.
pub mod handlers;
/// Ingest endpoint (metric envelopes).
pub mod ingest;
/// OpenAPI spec assembly.
pub mod openapi;
/// Shield (Sentin8:Policy) integration - shared bridge re-exports.
pub mod policy;
pub mod stat_aliases;
/// Service self-registration declarations.
pub mod registration;
/// Axum router and server.
pub mod server;
/// Durable metric storage.
pub mod store;
/// Wire types (envelopes, properties, dimensions).
pub mod types;
/// Embedded analytics pipeline worker (background tasks).
pub mod worker;
