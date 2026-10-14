// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Stat
// SPDX-License-Identifier: Apache-2.0

//! # stat-contracts
//!
//! Rust types for the Stat analytics and telemetry service — the event
//! envelope and property definitions shared by producers and the server.

#![deny(missing_docs)]

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// One analytics event sent to Stat's ingest.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EventEnvelope {
    /// Unique event id.
    pub event_id: Uuid,
    /// Anonymous client/device id.
    pub client_id: String,
    /// Property the event reports against.
    pub property_id: Uuid,
    /// Emitter type (`web` | `server` | …).
    pub client_type: String,
    /// Event class (`pageview` | `event` | …).
    pub event_type: String,
    /// Specific event name.
    pub event_name: String,
    /// Event timestamp (UTC).
    pub timestamp: chrono::DateTime<chrono::Utc>,
    /// Authenticated subject id, when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject_id: Option<String>,
    /// Arbitrary event properties.
    pub props: serde_json::Value,
}

/// An analytics property — the measurement scope events report against.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Property {
    /// Property identity.
    pub id: Uuid,
    /// Owning organization.
    pub org_id: Uuid,
    /// Owning environment (the tenant key).
    pub env_id: Uuid,
    /// Property name.
    pub name: String,
}

// Serde roundtrip tests — wire-format stability.

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn event_envelope_roundtrip() {
        let e = EventEnvelope {
            event_id: uuid::Uuid::new_v4(),
            client_id: "cli-1".into(),
            property_id: uuid::Uuid::new_v4(),
            client_type: "web".into(),
            event_type: "track".into(),
            event_name: "statement_downloaded".into(),
            timestamp: chrono::Utc::now(),
            subject_id: Some("user-1".into()),
            props: json!({"channel": "web", "amount": "50.00"}),
        };
        let v = serde_json::to_value(&e).unwrap();
        assert_eq!(v["event_name"], "statement_downloaded");
        let back: EventEnvelope = serde_json::from_value(v).unwrap();
        assert_eq!(back, e);
    }

    #[test]
    fn event_envelope_subject_optional() {
        let e = EventEnvelope {
            event_id: uuid::Uuid::new_v4(),
            client_id: "cli-1".into(),
            property_id: uuid::Uuid::new_v4(),
            client_type: "web".into(),
            event_type: "pageview".into(),
            event_name: "page_view".into(),
            timestamp: chrono::Utc::now(),
            subject_id: None,
            props: json!({}),
        };
        let v = serde_json::to_value(&e).unwrap();
        assert!(v.get("subject_id").is_none());
        let back: EventEnvelope = serde_json::from_value(v).unwrap();
        assert!(back.subject_id.is_none());
    }

    #[test]
    fn property_roundtrip() {
        let p = Property {
            id: uuid::Uuid::new_v4(),
            org_id: uuid::Uuid::new_v4(),
            env_id: uuid::Uuid::new_v4(),
            name: "ibank-prod".into(),
        };
        let v = serde_json::to_value(&p).unwrap();
        let back: Property = serde_json::from_value(v).unwrap();
        assert_eq!(back, p);
    }
}
