// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Stat
// SPDX-License-Identifier: Apache-2.0

//! Worker pipeline unit tests — ArchiveSummary / EventRecord serde shapes
//! (the pipeline itself needs live PG + Valkey + Bus and is covered by
//! the lifecycle e2e; see stat DESIGN.md §9).

use sentin8_stat_server::worker::pipeline::{ArchiveSummary, EventRecord};

#[test]
fn test_archive_summary_default() {
    let summary = ArchiveSummary::default();
    assert_eq!(summary.total_archived, 0);
    assert_eq!(summary.total_deleted, 0);
    assert!(summary.errors.is_empty());
}

#[test]
fn test_archive_summary_with_errors() {
    let summary = ArchiveSummary {
        total_archived: 100,
        total_deleted: 100,
        errors: vec!["property X failed".into()],
    };
    assert_eq!(summary.total_archived, 100);
    assert_eq!(summary.errors.len(), 1);
}

#[test]
fn test_event_record_serialize() {
    let event = test_event("web");
    let json = serde_json::to_value(&event).unwrap();
    assert_eq!(json["event_type"], "pageview");
    assert_eq!(json["client_type"], "web");
}

#[test]
fn test_event_record_client_type_web() {
    let event = test_event("web");
    assert_eq!(event.client_type, "web");
}

#[test]
fn test_event_record_client_type_server() {
    let event = test_event("server");
    assert_eq!(event.client_type, "server");
}

#[test]
fn test_event_record_client_type_mobile() {
    let event = test_event("mobile");
    assert_eq!(event.client_type, "mobile");
}

#[test]
fn test_event_record_metric_event() {
    let mut event = test_event("server");
    event.event_type = "metric".into();
    event.metrics = serde_json::json!({"users.count": 42, "tokens.issued": 100});
    assert_eq!(event.event_type, "metric");
    assert!(event.metrics.is_object());
}

fn test_event(client_type: &str) -> EventRecord {
    EventRecord {
        id: uuid::Uuid::new_v4(),
        env_id: uuid::Uuid::new_v4(),
        property_id: uuid::Uuid::new_v4(),
        client_id: "client-1".into(),
        client_type: client_type.into(),
        event_type: "pageview".into(),
        event_name: Some("page_view".into()),
        event_category: None,
        subject_id: None,
        timestamp: chrono::Utc::now(),
        page_url: Some("/home".into()),
        page_title: None,
        referrer: None,
        screen_name: None,
        app_version: None,
        utm_source: None,
        utm_medium: None,
        utm_campaign: None,
        conversions: serde_json::json!([]),
        engagement_time_ms: 0,
        metrics: serde_json::json!({}),
        props: serde_json::json!({}),
    }
}
