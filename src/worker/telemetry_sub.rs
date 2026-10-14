// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Stat
// SPDX-License-Identifier: Apache-2.0

//! MemBus `stat.telemetry` ingest (SDD §2.3 receiving end).
//!
//! Services and the embedded Shield engine publish telemetry frames
//! (policy decisions, service metrics) to the MemBus Pub/Sub family
//! `stat.telemetry` — fire-and-forget, ephemeral (a stat outage drops
//! frames by contract). This worker subscribes, decodes each frame into
//! the `EventEnvelope` shape, resolves the emitter's slug to a property
//! server-side, and inserts the event — the same store path as the HTTP
//! ingest, minus the HTTP-plane concerns (auth, rate limit, pixel
//! fallback): the channel key already carries the env (membus tenant
//! isolation) and the frame carries the platform-trust `server`
//! client type.
//!
//! Ephemeral-class contract: no ack, no retry, no DLQ — a frame that
//! fails to decode or resolve is logged and dropped. "Non-important
//! updates" (owner decision, SDD §1.4 D5).

use sqlx::PgPool;

use sentin8::membus::{Envelope, MemBus, MemBusConfig};

use crate::types::EventEnvelope;

/// MemBus Pub/Sub family the worker subscribes to (matches Shield's
/// `stat_emit::TELEMETRY_FAMILY`).
const TELEMETRY_FAMILY: &str = "stat.telemetry";

/// Subscribe to the telemetry family and ingest frames until the process
/// exits. Reconnects with a bounded sleep on any transport failure; a
/// reconnect window's frames are lost (ephemeral contract).
pub async fn run_telemetry_subscriber(pool: PgPool, valkey_url: String) -> anyhow::Result<()> {
    let cfg = MemBusConfig {
        url: valkey_url,
        ..MemBusConfig::from_env("sentin8:stat")
    };
    let bus = MemBus::connect(cfg).await?;
    // Platform env: server telemetry is platform-scoped (frames carry
    // slugs stat resolves to their owning property/env server-side).
    let env_bus = bus.for_env(&sentin8::config::SYSTEM_ENV_ID.to_string())?;
    loop {
        let mut sub = match env_bus.subscribe_pubsub(TELEMETRY_FAMILY).await {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(error = %e, "stat: telemetry subscribe failed; retrying in 3s");
                tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                continue;
            }
        };
        tracing::info!("stat: subscribed to membus {TELEMETRY_FAMILY}");
        loop {
            let frame = match sub.next_frame().await {
                Ok(Some(f)) => f,
                Ok(None) => break, // channel closed — reconnect
                Err(e) => {
                    tracing::warn!(error = %e, "stat: telemetry frame error; reconnecting");
                    break;
                }
            };
            if let Err(e) = ingest_frame(&pool, &frame).await {
                tracing::warn!(error = %e, "stat: telemetry frame dropped (ingest failed)");
            }
        }
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    }
}

/// Decode one MemBus envelope into an `EventEnvelope`, resolve the slug,
/// and insert the event. The frame payload is the flat `EventEnvelope`
/// JSON the Shield emitter serializes (SDD §2.3 wire shape).
async fn ingest_frame(pool: &PgPool, frame: &Envelope) -> anyhow::Result<()> {
    let envelope: EventEnvelope = serde_json::from_slice(&frame.payload)
        .map_err(|e| anyhow::anyhow!("decode: {e}"))?;
    // Server emitters carry the slug; stat resolves it server-side.
    let Some(slug) = envelope.property_slug.as_deref().map(str::trim).filter(|s| !s.is_empty())
    else {
        anyhow::bail!("frame without property_slug (producer {})", frame.producer);
    };
    let Some((property_id, env_id)) = crate::store::resolve_property_slug(pool, slug)
        .await
        .map_err(|(_, e)| anyhow::anyhow!("resolve slug: {e}"))?
    else {
        anyhow::bail!("property slug not found: {slug}");
    };
    let mut envelope = envelope;
    envelope.property_id = property_id;
    crate::store::insert_event(pool, env_id, &envelope)
        .await
        .map_err(|(_, e)| anyhow::anyhow!("insert event: {e}"))?;
    Ok(())
}