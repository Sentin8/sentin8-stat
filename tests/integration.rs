// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Stat
// SPDX-License-Identifier: Apache-2.0

// Integration tests for Stat - Story 3.1.19
//
// Tests ingest validation, PII stripping, dedupe logic, and event types.
// These are unit tests for pure functions; full pipeline tests require
// a live PostgreSQL + Valkey instance.

use sentin8_stat_server::types::{strip_pii, EventEnvelope, PII_DENY_LIST};

#[test]
fn strip_pii_removes_email() {
    let props = serde_json::json!({"email": "user@example.com", "name": "Alice"});
    let (cleaned, stripped) = strip_pii(&props);
    assert!(stripped);
    assert!(cleaned.get("email").is_none());
    assert_eq!(cleaned.get("name").unwrap(), "Alice");
}

#[test]
fn strip_pii_removes_phone() {
    let props = serde_json::json!({"phone": "+1234567890", "page": "/home"});
    let (cleaned, stripped) = strip_pii(&props);
    assert!(stripped);
    assert!(cleaned.get("phone").is_none());
    assert_eq!(cleaned.get("page").unwrap(), "/home");
}

#[test]
fn strip_pii_removes_all_deny_list_keys() {
    for key in PII_DENY_LIST {
        let props = serde_json::json!({*key: "sensitive-value"});
        let (cleaned, stripped) = strip_pii(&props);
        assert!(stripped, "expected {key} to be stripped");
        assert!(cleaned.get(*key).is_none(), "expected {key} to be removed");
    }
}

#[test]
fn strip_pii_is_case_insensitive() {
    let props = serde_json::json!({"Email": "user@example.com", "EMAIL": "x"});
    let (cleaned, stripped) = strip_pii(&props);
    assert!(stripped);
    assert!(cleaned.get("Email").is_none());
    assert!(cleaned.get("EMAIL").is_none());
}

#[test]
fn strip_pii_keeps_clean_payload() {
    let props = serde_json::json!({"page": "/home", "title": "Welcome", "count": 42});
    let (cleaned, stripped) = strip_pii(&props);
    assert!(!stripped);
    assert_eq!(cleaned.as_object().unwrap().len(), 3);
}

#[test]
fn strip_pii_non_object_returns_unchanged() {
    let props = serde_json::json!([1, 2, 3]);
    let (cleaned, stripped) = strip_pii(&props);
    assert!(!stripped);
    assert_eq!(cleaned, props);
}

#[test]
fn strip_pii_empty_object_roundtrip() {
    let props = serde_json::json!({});
    let (cleaned, stripped) = strip_pii(&props);
    assert!(!stripped);
    assert!(cleaned.is_object());
    assert_eq!(cleaned.as_object().unwrap().len(), 0);
}

#[test]
fn strip_pii_mixed_keys() {
    let props = serde_json::json!({
        "page": "/account",
        "ssn": "123-45-6789",
        "amount": 100.50,
        "card_number": "4111111111111111",
        "currency": "USD",
    });
    let (cleaned, stripped) = strip_pii(&props);
    assert!(stripped);
    assert_eq!(cleaned.as_object().unwrap().len(), 3);
    assert!(cleaned.get("page").is_some());
    assert!(cleaned.get("amount").is_some());
    assert!(cleaned.get("currency").is_some());
    assert!(cleaned.get("ssn").is_none());
    assert!(cleaned.get("card_number").is_none());
}

#[test]
fn pii_deny_list_includes_all_required_keys() {
    // Verify all keys from the design doc §4.2.1 are present.
    let required = [
        "email",
        "phone",
        "pan",
        "pin",
        "cvv",
        "ssn",
        "password",
        "token",
        "secret",
        "apikey",
        "iban",
        "account_number",
        "card_number",
    ];
    for key in required {
        assert!(
            PII_DENY_LIST.contains(&key),
            "PII_DENY_LIST missing required key: {key}"
        );
    }
}

#[test]
fn event_envelope_deserializes() {
    let json = serde_json::json!({
        "event_id": "550e8400-e29b-41d4-a716-446655440000",
        "client_id": "client-abc",
        "property_id": "660e8400-e29b-41d4-a716-446655440000",
        "client_type": "web",
        "event_type": "pageview",
        "event_name": "page_view",
        "timestamp": "2026-07-18T12:00:00Z",
        "page_url": "/home"
    });
    let envelope: EventEnvelope = serde_json::from_value(json).unwrap();
    assert_eq!(envelope.event_type, "pageview");
    assert_eq!(envelope.event_name, "page_view");
    assert_eq!(envelope.client_id, "client-abc");
    assert_eq!(envelope.client_type, "web");
}
