-- SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
-- SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
-- SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Stat
-- SPDX-License-Identifier: Apache-2.0

-- Sentin8:Stat - standalone analytics and telemetry collection service.
-- References: design/sentin8-stat-technical-design.md
-- RLS helpers (sentin8_context_initialized, sentin8_bypass_rls, sentin8_current_env_id,
-- sentin8_current_env_id) are defined in the platform migration SQL.
--
-- This file contains the stat tables (with archive columns on
-- stat.events) and the platform properties seed.

-- DBX (architecture-principles §6.8): the shared `sentin8.audit_events` table
-- is RETIRED. The canonical audit trail is `sys.audit_events`, owned by
-- Sentin8:Sys and ingested via `POST /v1/audit` (sys design §6.10). Stat keeps
-- analytics only - Stat's embedded worker consumes `sentin8:sys:audit:recorded`
-- from the bus
-- and aggregates into its own tables (DBX-STAT-1).

-- stat.properties: the unit of event grouping, bound to org/env.
CREATE TABLE IF NOT EXISTS stat.properties (
    id                        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id            UUID NOT NULL,
    account_id                UUID,
    name                      TEXT NOT NULL,
    slug                      TEXT NOT NULL,
    timezone                  TEXT NOT NULL DEFAULT 'UTC',
    session_timeout_minutes   INTEGER NOT NULL DEFAULT 30,
    retention_days            INTEGER NOT NULL DEFAULT 30,
    bot_filter_enabled        BOOLEAN NOT NULL DEFAULT true,
    pii_deny_list             JSONB NOT NULL DEFAULT '[]',
    status                    TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended', 'archived')),
    created_at                TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at                TIMESTAMPTZ NOT NULL DEFAULT now(),
    resource_version          INTEGER NOT NULL DEFAULT 1
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_stat_properties_slug_env ON stat.properties (slug, env_id);
CREATE INDEX IF NOT EXISTS idx_stat_properties_env ON stat.properties (env_id);

ALTER TABLE stat.properties ENABLE ROW LEVEL SECURITY;
ALTER TABLE stat.properties FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS stat_properties_select ON stat.properties;
CREATE POLICY stat_properties_select ON stat.properties FOR SELECT USING (sentin8_context_initialized() AND (sentin8_bypass_rls() OR (env_id = sentin8_current_env_id())));
DROP POLICY IF EXISTS stat_properties_insert ON stat.properties;
CREATE POLICY stat_properties_insert ON stat.properties FOR INSERT WITH CHECK (sentin8_context_initialized() AND (sentin8_bypass_rls() OR (env_id = sentin8_current_env_id())));
DROP POLICY IF EXISTS stat_properties_update ON stat.properties;
CREATE POLICY stat_properties_update ON stat.properties FOR UPDATE USING (sentin8_context_initialized() AND (sentin8_bypass_rls() OR (env_id = sentin8_current_env_id())));
DROP POLICY IF EXISTS stat_properties_delete ON stat.properties;
CREATE POLICY stat_properties_delete ON stat.properties FOR DELETE USING (sentin8_context_initialized() AND (sentin8_bypass_rls() OR (env_id = sentin8_current_env_id())));

-- Policy stat-emit boot read - RETIRED (SBI-STAT-2, architecture-
-- principles §6.6a): emitters identify by `property_slug` (SBI-STAT-1)
-- and stat resolves slug → property server-side at ingest. No non-stat
-- service holds grants on stat.* anymore.

-- stat.events: raw events, hot retention. Partitioned by day on timestamp.
-- Story 3.2.7 archive columns (archived, archived_at) are merged in here.
CREATE TABLE IF NOT EXISTS stat.events (
    id              UUID NOT NULL,
    env_id   UUID NOT NULL,
    property_id     UUID NOT NULL,
    client_id       TEXT NOT NULL,
    client_type     TEXT NOT NULL CHECK (client_type IN ('web', 'server', 'mobile')),
    event_type      TEXT NOT NULL CHECK (event_type IN ('pageview', 'screenview', 'event', 'conversion', 'metric', 'custom')),
    event_name      TEXT,
    event_category  TEXT,
    subject_id      UUID,
    session_id      UUID,
    session_sequence INTEGER,
    timestamp       TIMESTAMPTZ NOT NULL,
    page_url        TEXT,
    page_title      TEXT,
    referrer        TEXT,
    screen_name     TEXT,
    app_version     TEXT,
    device_type     TEXT,
    browser_name    TEXT,
    browser_version TEXT,
    os_name         TEXT,
    os_version      TEXT,
    country         TEXT,
    region          TEXT,
    city            TEXT,
    timezone        TEXT,
    is_bot          BOOLEAN NOT NULL DEFAULT false,
    utm_source      TEXT,
    utm_medium      TEXT,
    utm_campaign    TEXT,
    conversions     JSONB NOT NULL DEFAULT '[]',
    engagement_time_ms INTEGER NOT NULL DEFAULT 0,
    metrics         JSONB NOT NULL DEFAULT '{}',
    props           JSONB NOT NULL DEFAULT '{}',
    props_pii_stripped BOOLEAN NOT NULL DEFAULT false,
    processed       BOOLEAN NOT NULL DEFAULT false,
    processed_at    TIMESTAMPTZ,
    -- Archive sweep markers.
    archived        BOOLEAN NOT NULL DEFAULT false,
    archived_at     TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (id, timestamp)
) PARTITION BY RANGE (timestamp);

CREATE INDEX IF NOT EXISTS idx_stat_events_property_ts ON stat.events (property_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_stat_events_client_ts ON stat.events (client_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_stat_events_subject ON stat.events (subject_id) WHERE subject_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_stat_events_session ON stat.events (session_id) WHERE session_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_stat_events_unprocessed ON stat.events (created_at) WHERE processed = false;
CREATE INDEX IF NOT EXISTS idx_stat_events_event_type ON stat.events (property_id, event_type, event_name, timestamp);
-- Story 3.2.7: index for the archive sweep.
CREATE INDEX IF NOT EXISTS idx_stat_events_archive
    ON stat.events (property_id, created_at)
    WHERE archived = false;

-- RLS on stat.events - partitioned tables inherit RLS from parent.
ALTER TABLE stat.events ENABLE ROW LEVEL SECURITY;
ALTER TABLE stat.events FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS stat_events_select ON stat.events;
CREATE POLICY stat_events_select ON stat.events FOR SELECT USING (sentin8_context_initialized() AND (sentin8_bypass_rls() OR (env_id = sentin8_current_env_id())));
DROP POLICY IF EXISTS stat_events_insert ON stat.events;
CREATE POLICY stat_events_insert ON stat.events FOR INSERT WITH CHECK (sentin8_context_initialized() AND (sentin8_bypass_rls() OR (env_id = sentin8_current_env_id())));
DROP POLICY IF EXISTS stat_events_update ON stat.events;
CREATE POLICY stat_events_update ON stat.events FOR UPDATE USING (sentin8_context_initialized() AND (sentin8_bypass_rls() OR (env_id = sentin8_current_env_id())));
DROP POLICY IF EXISTS stat_events_delete ON stat.events;
CREATE POLICY stat_events_delete ON stat.events FOR DELETE USING (sentin8_context_initialized() AND (sentin8_bypass_rls() OR (env_id = sentin8_current_env_id())));

-- Create initial partitions for today + 7 days ahead.
-- (The stat also calls EnsurePartitionsAhead at startup, but having
-- these in the init SQL ensures the table is usable immediately.)
DO $$
DECLARE
    d DATE;
    part_name TEXT;
BEGIN
    FOR i IN 0..7 LOOP
        d := CURRENT_DATE + i;
        part_name := 'stat_events_' || to_char(d, 'YYYY_MM_DD');
        EXECUTE format('CREATE TABLE IF NOT EXISTS %s PARTITION OF stat.events FOR VALUES FROM (%L) TO (%L)',
            part_name, d, d + 1);
    END LOOP;
END $$;

-- stat.sessions: session records created/updated by the pipeline.
CREATE TABLE IF NOT EXISTS stat.sessions (
    id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id       UUID NOT NULL,
    property_id          UUID NOT NULL,
    client_id            TEXT NOT NULL,
    subject_id           UUID,
    started_at           TIMESTAMPTZ NOT NULL,
    ended_at             TIMESTAMPTZ,
    last_event_at        TIMESTAMPTZ NOT NULL,
    event_count          INTEGER NOT NULL DEFAULT 1,
    total_engagement_ms  BIGINT NOT NULL DEFAULT 0,
    traffic_source       JSONB NOT NULL DEFAULT '{}',
    entry_url            TEXT,
    exit_url             TEXT,
    is_bounce            BOOLEAN NOT NULL DEFAULT true,
    is_bot               BOOLEAN NOT NULL DEFAULT false,
    country              TEXT,
    device_type          TEXT,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    resource_version     INTEGER NOT NULL DEFAULT 1
);

CREATE INDEX IF NOT EXISTS idx_stat_sessions_property_client ON stat.sessions (property_id, client_id, last_event_at DESC);
CREATE INDEX IF NOT EXISTS idx_stat_sessions_subject ON stat.sessions (subject_id) WHERE subject_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_stat_sessions_env ON stat.sessions (env_id);

ALTER TABLE stat.sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE stat.sessions FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS stat_sessions_select ON stat.sessions;
CREATE POLICY stat_sessions_select ON stat.sessions FOR SELECT USING (sentin8_context_initialized() AND (sentin8_bypass_rls() OR (env_id = sentin8_current_env_id())));
DROP POLICY IF EXISTS stat_sessions_insert ON stat.sessions;
CREATE POLICY stat_sessions_insert ON stat.sessions FOR INSERT WITH CHECK (sentin8_context_initialized() AND (sentin8_bypass_rls() OR (env_id = sentin8_current_env_id())));
DROP POLICY IF EXISTS stat_sessions_update ON stat.sessions;
CREATE POLICY stat_sessions_update ON stat.sessions FOR UPDATE USING (sentin8_context_initialized() AND (sentin8_bypass_rls() OR (env_id = sentin8_current_env_id())));
DROP POLICY IF EXISTS stat_sessions_delete ON stat.sessions;
CREATE POLICY stat_sessions_delete ON stat.sessions FOR DELETE USING (sentin8_context_initialized() AND (sentin8_bypass_rls() OR (env_id = sentin8_current_env_id())));

-- stat.aggregate_metrics_daily: server telemetry metrics (gauge/counter per day).
CREATE TABLE IF NOT EXISTS stat.aggregate_metrics_daily (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id  UUID NOT NULL,
    property_id     UUID NOT NULL,
    day             DATE NOT NULL,
    metric_name     TEXT NOT NULL,
    dimensions      JSONB NOT NULL DEFAULT '{}',
    dimensions_hash TEXT NOT NULL DEFAULT 'none',
    value_type      TEXT NOT NULL DEFAULT 'gauge' CHECK (value_type IN ('gauge', 'counter')),
    value           DOUBLE PRECISION NOT NULL DEFAULT 0,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_stat_agg_metrics_prop_day ON stat.aggregate_metrics_daily (property_id, day, metric_name);
CREATE UNIQUE INDEX IF NOT EXISTS idx_stat_agg_metrics_uniq ON stat.aggregate_metrics_daily (property_id, day, metric_name, dimensions_hash);

ALTER TABLE stat.aggregate_metrics_daily ENABLE ROW LEVEL SECURITY;
ALTER TABLE stat.aggregate_metrics_daily FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS stat_agg_metrics_select ON stat.aggregate_metrics_daily;
CREATE POLICY stat_agg_metrics_select ON stat.aggregate_metrics_daily FOR SELECT USING (sentin8_context_initialized() AND (sentin8_bypass_rls() OR (env_id = sentin8_current_env_id())));
DROP POLICY IF EXISTS stat_agg_metrics_insert ON stat.aggregate_metrics_daily;
CREATE POLICY stat_agg_metrics_insert ON stat.aggregate_metrics_daily FOR INSERT WITH CHECK (sentin8_context_initialized() AND (sentin8_bypass_rls() OR (env_id = sentin8_current_env_id())));
DROP POLICY IF EXISTS stat_agg_metrics_update ON stat.aggregate_metrics_daily;
CREATE POLICY stat_agg_metrics_update ON stat.aggregate_metrics_daily FOR UPDATE USING (sentin8_context_initialized() AND (sentin8_bypass_rls() OR (env_id = sentin8_current_env_id())));
DROP POLICY IF EXISTS stat_agg_metrics_delete ON stat.aggregate_metrics_daily;
CREATE POLICY stat_agg_metrics_delete ON stat.aggregate_metrics_daily FOR DELETE USING (sentin8_context_initialized() AND (sentin8_bypass_rls() OR (env_id = sentin8_current_env_id())));

-- stat.aggregate_events_daily: event count by (property, eventType, eventName, day).
CREATE TABLE IF NOT EXISTS stat.aggregate_events_daily (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id  UUID NOT NULL,
    property_id     UUID NOT NULL,
    day             DATE NOT NULL,
    dimensions      JSONB NOT NULL DEFAULT '{}',
    metrics         JSONB NOT NULL DEFAULT '{}',
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_stat_agg_events_prop_day ON stat.aggregate_events_daily (property_id, day);
ALTER TABLE stat.aggregate_events_daily ENABLE ROW LEVEL SECURITY;
ALTER TABLE stat.aggregate_events_daily FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS stat_agg_events_select ON stat.aggregate_events_daily;
CREATE POLICY stat_agg_events_select ON stat.aggregate_events_daily FOR SELECT USING (sentin8_context_initialized() AND (sentin8_bypass_rls() OR (env_id = sentin8_current_env_id())));
DROP POLICY IF EXISTS stat_agg_events_insert ON stat.aggregate_events_daily;
CREATE POLICY stat_agg_events_insert ON stat.aggregate_events_daily FOR INSERT WITH CHECK (sentin8_context_initialized() AND (sentin8_bypass_rls() OR (env_id = sentin8_current_env_id())));
DROP POLICY IF EXISTS stat_agg_events_update ON stat.aggregate_events_daily;
CREATE POLICY stat_agg_events_update ON stat.aggregate_events_daily FOR UPDATE USING (sentin8_context_initialized() AND (sentin8_bypass_rls() OR (env_id = sentin8_current_env_id())));

-- stat.aggregate_sessions_daily: session count, engagement, bounce by (property, day).
CREATE TABLE IF NOT EXISTS stat.aggregate_sessions_daily (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id  UUID NOT NULL,
    property_id     UUID NOT NULL,
    day             DATE NOT NULL,
    dimensions      JSONB NOT NULL DEFAULT '{}',
    metrics         JSONB NOT NULL DEFAULT '{}',
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_stat_agg_sessions_prop_day ON stat.aggregate_sessions_daily (property_id, day);
ALTER TABLE stat.aggregate_sessions_daily ENABLE ROW LEVEL SECURITY;
ALTER TABLE stat.aggregate_sessions_daily FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS stat_agg_sessions_select ON stat.aggregate_sessions_daily;
CREATE POLICY stat_agg_sessions_select ON stat.aggregate_sessions_daily FOR SELECT USING (sentin8_context_initialized() AND (sentin8_bypass_rls() OR (env_id = sentin8_current_env_id())));
DROP POLICY IF EXISTS stat_agg_sessions_insert ON stat.aggregate_sessions_daily;
CREATE POLICY stat_agg_sessions_insert ON stat.aggregate_sessions_daily FOR INSERT WITH CHECK (sentin8_context_initialized() AND (sentin8_bypass_rls() OR (env_id = sentin8_current_env_id())));
DROP POLICY IF EXISTS stat_agg_sessions_update ON stat.aggregate_sessions_daily;
CREATE POLICY stat_agg_sessions_update ON stat.aggregate_sessions_daily FOR UPDATE USING (sentin8_context_initialized() AND (sentin8_bypass_rls() OR (env_id = sentin8_current_env_id())));

-- stat.aggregate_conversions_daily: conversion count + value by (property, conversionId, day).
CREATE TABLE IF NOT EXISTS stat.aggregate_conversions_daily (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id  UUID NOT NULL,
    property_id     UUID NOT NULL,
    day             DATE NOT NULL,
    dimensions      JSONB NOT NULL DEFAULT '{}',
    metrics         JSONB NOT NULL DEFAULT '{}',
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_stat_agg_conv_prop_day ON stat.aggregate_conversions_daily (property_id, day);
ALTER TABLE stat.aggregate_conversions_daily ENABLE ROW LEVEL SECURITY;
ALTER TABLE stat.aggregate_conversions_daily FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS stat_agg_conv_select ON stat.aggregate_conversions_daily;
CREATE POLICY stat_agg_conv_select ON stat.aggregate_conversions_daily FOR SELECT USING (sentin8_context_initialized() AND (sentin8_bypass_rls() OR (env_id = sentin8_current_env_id())));
DROP POLICY IF EXISTS stat_agg_conv_insert ON stat.aggregate_conversions_daily;
CREATE POLICY stat_agg_conv_insert ON stat.aggregate_conversions_daily FOR INSERT WITH CHECK (sentin8_context_initialized() AND (sentin8_bypass_rls() OR (env_id = sentin8_current_env_id())));
DROP POLICY IF EXISTS stat_agg_conv_update ON stat.aggregate_conversions_daily;
CREATE POLICY stat_agg_conv_update ON stat.aggregate_conversions_daily FOR UPDATE USING (sentin8_context_initialized() AND (sentin8_bypass_rls() OR (env_id = sentin8_current_env_id())));

-- stat.aggregate_engagement_daily: total engagement time by (property, subjectId, day).
CREATE TABLE IF NOT EXISTS stat.aggregate_engagement_daily (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id  UUID NOT NULL,
    property_id     UUID NOT NULL,
    day             DATE NOT NULL,
    dimensions      JSONB NOT NULL DEFAULT '{}',
    metrics         JSONB NOT NULL DEFAULT '{}',
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_stat_agg_engage_prop_day ON stat.aggregate_engagement_daily (property_id, day);
ALTER TABLE stat.aggregate_engagement_daily ENABLE ROW LEVEL SECURITY;
ALTER TABLE stat.aggregate_engagement_daily FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS stat_agg_engage_select ON stat.aggregate_engagement_daily;
CREATE POLICY stat_agg_engage_select ON stat.aggregate_engagement_daily FOR SELECT USING (sentin8_context_initialized() AND (sentin8_bypass_rls() OR (env_id = sentin8_current_env_id())));
DROP POLICY IF EXISTS stat_agg_engage_insert ON stat.aggregate_engagement_daily;
CREATE POLICY stat_agg_engage_insert ON stat.aggregate_engagement_daily FOR INSERT WITH CHECK (sentin8_context_initialized() AND (sentin8_bypass_rls() OR (env_id = sentin8_current_env_id())));
DROP POLICY IF EXISTS stat_agg_engage_update ON stat.aggregate_engagement_daily;
CREATE POLICY stat_agg_engage_update ON stat.aggregate_engagement_daily FOR UPDATE USING (sentin8_context_initialized() AND (sentin8_bypass_rls() OR (env_id = sentin8_current_env_id())));

-- stat.aggregate_geo_daily: event count by (property, country, day).
CREATE TABLE IF NOT EXISTS stat.aggregate_geo_daily (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id  UUID NOT NULL,
    property_id     UUID NOT NULL,
    day             DATE NOT NULL,
    dimensions      JSONB NOT NULL DEFAULT '{}',
    metrics         JSONB NOT NULL DEFAULT '{}',
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_stat_agg_geo_prop_day ON stat.aggregate_geo_daily (property_id, day);
ALTER TABLE stat.aggregate_geo_daily ENABLE ROW LEVEL SECURITY;
ALTER TABLE stat.aggregate_geo_daily FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS stat_agg_geo_select ON stat.aggregate_geo_daily;
CREATE POLICY stat_agg_geo_select ON stat.aggregate_geo_daily FOR SELECT USING (sentin8_context_initialized() AND (sentin8_bypass_rls() OR (env_id = sentin8_current_env_id())));
DROP POLICY IF EXISTS stat_agg_geo_insert ON stat.aggregate_geo_daily;
CREATE POLICY stat_agg_geo_insert ON stat.aggregate_geo_daily FOR INSERT WITH CHECK (sentin8_context_initialized() AND (sentin8_bypass_rls() OR (env_id = sentin8_current_env_id())));
DROP POLICY IF EXISTS stat_agg_geo_update ON stat.aggregate_geo_daily;
CREATE POLICY stat_agg_geo_update ON stat.aggregate_geo_daily FOR UPDATE USING (sentin8_context_initialized() AND (sentin8_bypass_rls() OR (env_id = sentin8_current_env_id())));

-- stat.aggregate_device_daily: event count by (property, deviceType, browser, os, day).
CREATE TABLE IF NOT EXISTS stat.aggregate_device_daily (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id  UUID NOT NULL,
    property_id     UUID NOT NULL,
    day             DATE NOT NULL,
    dimensions      JSONB NOT NULL DEFAULT '{}',
    metrics         JSONB NOT NULL DEFAULT '{}',
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_stat_agg_device_prop_day ON stat.aggregate_device_daily (property_id, day);
ALTER TABLE stat.aggregate_device_daily ENABLE ROW LEVEL SECURITY;
ALTER TABLE stat.aggregate_device_daily FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS stat_agg_device_select ON stat.aggregate_device_daily;
CREATE POLICY stat_agg_device_select ON stat.aggregate_device_daily FOR SELECT USING (sentin8_context_initialized() AND (sentin8_bypass_rls() OR (env_id = sentin8_current_env_id())));
DROP POLICY IF EXISTS stat_agg_device_insert ON stat.aggregate_device_daily;
CREATE POLICY stat_agg_device_insert ON stat.aggregate_device_daily FOR INSERT WITH CHECK (sentin8_context_initialized() AND (sentin8_bypass_rls() OR (env_id = sentin8_current_env_id())));
DROP POLICY IF EXISTS stat_agg_device_update ON stat.aggregate_device_daily;
CREATE POLICY stat_agg_device_update ON stat.aggregate_device_daily FOR UPDATE USING (sentin8_context_initialized() AND (sentin8_bypass_rls() OR (env_id = sentin8_current_env_id())));

-- stat.aggregate_traffic_source_daily: session count by (property, utm, day).
CREATE TABLE IF NOT EXISTS stat.aggregate_traffic_source_daily (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id  UUID NOT NULL,
    property_id     UUID NOT NULL,
    day             DATE NOT NULL,
    dimensions      JSONB NOT NULL DEFAULT '{}',
    metrics         JSONB NOT NULL DEFAULT '{}',
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_stat_agg_traffic_prop_day ON stat.aggregate_traffic_source_daily (property_id, day);
ALTER TABLE stat.aggregate_traffic_source_daily ENABLE ROW LEVEL SECURITY;
ALTER TABLE stat.aggregate_traffic_source_daily FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS stat_agg_traffic_select ON stat.aggregate_traffic_source_daily;
CREATE POLICY stat_agg_traffic_select ON stat.aggregate_traffic_source_daily FOR SELECT USING (sentin8_context_initialized() AND (sentin8_bypass_rls() OR (env_id = sentin8_current_env_id())));
DROP POLICY IF EXISTS stat_agg_traffic_insert ON stat.aggregate_traffic_source_daily;
CREATE POLICY stat_agg_traffic_insert ON stat.aggregate_traffic_source_daily FOR INSERT WITH CHECK (sentin8_context_initialized() AND (sentin8_bypass_rls() OR (env_id = sentin8_current_env_id())));
DROP POLICY IF EXISTS stat_agg_traffic_update ON stat.aggregate_traffic_source_daily;
CREATE POLICY stat_agg_traffic_update ON stat.aggregate_traffic_source_daily FOR UPDATE USING (sentin8_context_initialized() AND (sentin8_bypass_rls() OR (env_id = sentin8_current_env_id())));

-- stat.alert_rules: per-property custom alert rules (stat README §7, stat
-- DESIGN §3). rule_type 'threshold' compares the metric's current daily
-- aggregate value against `threshold` via `comparator`; rule_type 'anomaly'
-- compares the moving-average deviation factor over the past `window_hours`
-- of daily buckets (`min_sample` = minimum non-empty historical buckets
-- required before the rule evaluates). metric_name vocabulary:
-- 'events.count' (aggregate_events_daily), 'conversions.count'
-- (aggregate_conversions_daily), or 'metric:{name}'
-- (aggregate_metrics_daily.value) - validated at create time against the
-- aggregates (400 on unknown).
CREATE TABLE IF NOT EXISTS stat.alert_rules (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id          UUID NOT NULL,
    property_id     UUID NOT NULL,
    name            TEXT NOT NULL,
    rule_type       TEXT NOT NULL CHECK (rule_type IN ('threshold', 'anomaly')),
    metric_name     TEXT NOT NULL,
    comparator      TEXT NOT NULL CHECK (comparator IN ('gt', 'gte', 'lt', 'lte')),
    threshold       DOUBLE PRECISION NOT NULL,
    window_hours    INTEGER NOT NULL DEFAULT 24,
    min_sample      INTEGER NOT NULL DEFAULT 10,
    enabled         BOOLEAN NOT NULL DEFAULT true,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_stat_alert_rules_prop_enabled ON stat.alert_rules (property_id) WHERE enabled;

ALTER TABLE stat.alert_rules ENABLE ROW LEVEL SECURITY;
ALTER TABLE stat.alert_rules FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS stat_alert_rules_select ON stat.alert_rules;
CREATE POLICY stat_alert_rules_select ON stat.alert_rules FOR SELECT USING (sentin8_context_initialized() AND (sentin8_bypass_rls() OR (env_id = sentin8_current_env_id())));
DROP POLICY IF EXISTS stat_alert_rules_insert ON stat.alert_rules;
CREATE POLICY stat_alert_rules_insert ON stat.alert_rules FOR INSERT WITH CHECK (sentin8_context_initialized() AND (sentin8_bypass_rls() OR (env_id = sentin8_current_env_id())));
DROP POLICY IF EXISTS stat_alert_rules_update ON stat.alert_rules;
CREATE POLICY stat_alert_rules_update ON stat.alert_rules FOR UPDATE USING (sentin8_context_initialized() AND (sentin8_bypass_rls() OR (env_id = sentin8_current_env_id())));
DROP POLICY IF EXISTS stat_alert_rules_delete ON stat.alert_rules;
CREATE POLICY stat_alert_rules_delete ON stat.alert_rules FOR DELETE USING (sentin8_context_initialized() AND (sentin8_bypass_rls() OR (env_id = sentin8_current_env_id())));

-- stat.funnels: pre-defined funnel definitions.
CREATE TABLE IF NOT EXISTS stat.funnels (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id  UUID NOT NULL,
    property_id     UUID NOT NULL,
    name            TEXT NOT NULL,
    steps           JSONB NOT NULL DEFAULT '[]',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    resource_version INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS idx_stat_funnels_prop ON stat.funnels (property_id);
ALTER TABLE stat.funnels ENABLE ROW LEVEL SECURITY;
ALTER TABLE stat.funnels FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS stat_funnels_select ON stat.funnels;
CREATE POLICY stat_funnels_select ON stat.funnels FOR SELECT USING (sentin8_context_initialized() AND (sentin8_bypass_rls() OR (env_id = sentin8_current_env_id())));
DROP POLICY IF EXISTS stat_funnels_insert ON stat.funnels;
CREATE POLICY stat_funnels_insert ON stat.funnels FOR INSERT WITH CHECK (sentin8_context_initialized() AND (sentin8_bypass_rls() OR (env_id = sentin8_current_env_id())));
DROP POLICY IF EXISTS stat_funnels_update ON stat.funnels;
CREATE POLICY stat_funnels_update ON stat.funnels FOR UPDATE USING (sentin8_context_initialized() AND (sentin8_bypass_rls() OR (env_id = sentin8_current_env_id())));
DROP POLICY IF EXISTS stat_funnels_delete ON stat.funnels;
CREATE POLICY stat_funnels_delete ON stat.funnels FOR DELETE USING (sentin8_context_initialized() AND (sentin8_bypass_rls() OR (env_id = sentin8_current_env_id())));

-- stat.accounts: org-level grouping of properties.
CREATE TABLE IF NOT EXISTS stat.accounts (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id  UUID NOT NULL,
    name            TEXT NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    resource_version INTEGER NOT NULL DEFAULT 1
);
ALTER TABLE stat.accounts ENABLE ROW LEVEL SECURITY;
ALTER TABLE stat.accounts FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS stat_accounts_select ON stat.accounts;
CREATE POLICY stat_accounts_select ON stat.accounts FOR SELECT USING (sentin8_context_initialized() AND (sentin8_bypass_rls() OR (env_id = sentin8_current_env_id())));
DROP POLICY IF EXISTS stat_accounts_insert ON stat.accounts;
CREATE POLICY stat_accounts_insert ON stat.accounts FOR INSERT WITH CHECK (sentin8_context_initialized() AND (sentin8_bypass_rls() OR (env_id = sentin8_current_env_id())));
DROP POLICY IF EXISTS stat_accounts_update ON stat.accounts;
CREATE POLICY stat_accounts_update ON stat.accounts FOR UPDATE USING (sentin8_context_initialized() AND (sentin8_bypass_rls() OR (env_id = sentin8_current_env_id())));
DROP POLICY IF EXISTS stat_accounts_delete ON stat.accounts;
CREATE POLICY stat_accounts_delete ON stat.accounts FOR DELETE USING (sentin8_context_initialized() AND (sentin8_bypass_rls() OR (env_id = sentin8_current_env_id())));

-- ──────────────────────────────────────────────────────────────────────────
-- Story 3.4b.1 - Platform bootstrap creates one sentin8_stat_property per Sentin8 service.
-- Uses System org/env (00000000-0000-0000-0000-000000000001 / 00000000-0000-0000-0000-000000000002).
-- Each property gets a slug matching the service name (auth, app, db, storage,
-- bus, sys, cron, func, flow, bff).
-- The Sentin8:Auth M2M client registration for each (scope `sentin8:stat:measure`) is handled
-- by the Sentin8:Auth admin API at bootstrap time, not by this SQL.
--
-- NOTE: this seed covers the platform services' own properties. Every
-- other service's telemetry property is declared in its repo's
-- `service-registration.json` (`telemetry_property` -,
-- design `design/sentin8-provisioned-rls-and-telemetry-design.md`
-- §2.2) and seeded into this table on the platform DB by
-- `sentin8-cli vertical init`/`enroll` (a vertical's own init SQL runs
-- against the vertical's database and can never reach this one).
INSERT INTO stat.properties (env_id, name, slug, timezone, retention_days)
VALUES
    ('00000000-0000-0000-0000-000000000002', 'Sentin8:Auth Platform Telemetry',  'auth',  'UTC', 90),
    ('00000000-0000-0000-0000-000000000002', 'Sentin8:App Platform Telemetry',   'app',   'UTC', 90),
    ('00000000-0000-0000-0000-000000000002', 'Sentin8:DB Platform Telemetry',    'db',    'UTC', 90),
    ('00000000-0000-0000-0000-000000000002', 'Sentin8:Storage Platform Telemetry',  'storage',  'UTC', 90),
    ('00000000-0000-0000-0000-000000000002', 'Sentin8:Bus Platform Telemetry',   'bus',   'UTC', 90),
    ('00000000-0000-0000-0000-000000000002', 'Sentin8:Sys Platform Telemetry',    'sys',    'UTC', 90),
    ('00000000-0000-0000-0000-000000000002', 'Sentin8:Cron Platform Telemetry',  'cron',  'UTC', 90),
    ('00000000-0000-0000-0000-000000000002', 'Sentin8:Func Platform Telemetry',  'func',  'UTC', 90),
    ('00000000-0000-0000-0000-000000000002', 'Sentin8:Flow Platform Telemetry',  'flow',  'UTC', 90),
    ('00000000-0000-0000-0000-000000000002', 'Sentin8:BFF Platform Telemetry',   'bff',   'UTC', 90),
    ('00000000-0000-0000-0000-000000000002', 'Sentin8:Post Platform Telemetry',  'post',  'UTC', 90)
ON CONFLICT DO NOTHING;

-- Sentin8:Sentin8:TLS property with a fixed UUID so Sentin8:Sentin8:TLS's config default
-- (Sentin8:Sentin8:TLS_STAT8_PROPERTY_ID = a0000000-...-000000000004) matches.
INSERT INTO stat.properties (id, env_id, name, slug, timezone, retention_days)
VALUES
    ('a0000000-0000-0000-0000-000000000004', '00000000-0000-0000-0000-000000000002', 'Sentin8:Sentin8:TLS Platform Telemetry', 'tls', 'UTC', 90)
ON CONFLICT DO NOTHING;

-- ──────────────────────────────────────────────────────────────────────────
-- Multi-granularity rollup tables (minute, hourly, daily, weekly, monthly, yearly).
--
-- The per-event daily tables above (sentin8_stat_aggregate_*_daily) are written by
-- the pipeline as events arrive. The rollup tables below are populated by a
-- periodic rollup job in the embedded worker that aggregates from the finest
-- granularity to the coarsest:
--
--   minute  → 5-minute buckets, TTL 7 days (hot, for real-time charts)
--   hour    → rolled up from minute
--   day     → rolled up from hour (or directly from the *_daily tables)
--   week    → rolled up from day (ISO week, starting Monday)
--   month   → rolled up from day
--   year    → rolled up from month
--
-- A single generic table stores all granularities for all aggregate kinds
-- (events, sessions, conversions, engagement, geo, device, traffic-source,
-- metrics). This avoids 6 × 9 = 54 tables and lets the Data API query any
-- granularity with a single parameterized query.

-- stat.rollups: multi-granularity aggregates for all aggregate kinds.
CREATE TABLE IF NOT EXISTS stat.rollups (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id          UUID NOT NULL,
    property_id     UUID NOT NULL,
    -- The aggregate kind: events, sessions, conversions, engagement, geo,
    -- device, traffic_source, metrics.
    kind            TEXT NOT NULL,
    -- The time bucket. For minute/hour/day this is the truncated timestamp;
    -- for week/month/year it is the first day of the period.
    bucket          TIMESTAMPTZ NOT NULL,
    -- The granularity: minute, hour, day, week, month, year.
    granularity     TEXT NOT NULL,
    -- Dimension tags for this row (e.g. event_type+event_name for events,
    -- conversion_id for conversions, metric_name+dimensions for metrics).
    dimensions      JSONB NOT NULL DEFAULT '{}',
    -- The measured values: count, sum, value, etc.
    metrics         JSONB NOT NULL DEFAULT '{}',
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Unique constraint: one row per (property, kind, granularity, bucket, dimensions_hash).
CREATE UNIQUE INDEX IF NOT EXISTS idx_stat_rollups_uniq
    ON stat.rollups (property_id, kind, granularity, bucket, md5(dimensions::text));
CREATE INDEX IF NOT EXISTS idx_stat_rollups_prop_kind_gran_bucket
    ON stat.rollups (property_id, kind, granularity, bucket);
CREATE INDEX IF NOT EXISTS idx_stat_rollups_metric_name
    ON stat.rollups ((dimensions->>'metric_name'))
    WHERE kind = 'metrics';

ALTER TABLE stat.rollups ENABLE ROW LEVEL SECURITY;
ALTER TABLE stat.rollups FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS stat_rollups_select ON stat.rollups;
CREATE POLICY stat_rollups_select ON stat.rollups FOR SELECT USING (sentin8_context_initialized() AND (sentin8_bypass_rls() OR (env_id = sentin8_current_env_id())));
DROP POLICY IF EXISTS stat_rollups_insert ON stat.rollups;
CREATE POLICY stat_rollups_insert ON stat.rollups FOR INSERT WITH CHECK (sentin8_context_initialized() AND (sentin8_bypass_rls() OR (env_id = sentin8_current_env_id())));
DROP POLICY IF EXISTS stat_rollups_update ON stat.rollups;
CREATE POLICY stat_rollups_update ON stat.rollups FOR UPDATE USING (sentin8_context_initialized() AND (sentin8_bypass_rls() OR (env_id = sentin8_current_env_id())));
DROP POLICY IF EXISTS stat_rollups_delete ON stat.rollups;
CREATE POLICY stat_rollups_delete ON stat.rollups FOR DELETE USING (sentin8_context_initialized() AND (sentin8_bypass_rls() OR (env_id = sentin8_current_env_id())));

-- ── Grants ──

-- sentin8_stat_service: DML on all stat tables.
GRANT SELECT, INSERT, UPDATE, DELETE ON
    stat.properties, stat.events, stat.sessions,
    stat.aggregate_metrics_daily, stat.aggregate_events_daily,
    stat.aggregate_sessions_daily, stat.aggregate_conversions_daily,
    stat.aggregate_engagement_daily, stat.aggregate_geo_daily,
    stat.aggregate_device_daily, stat.aggregate_traffic_source_daily,
    stat.funnels, stat.accounts, stat.rollups
    TO sentin8_stat_service;


-- ── Local outbox (DBX, architecture-principles §6.7) ─────────────────────
-- Producer path: stat.outbox rows commit in the SAME transaction as the
-- domain change; a post-commit relay pushes them to Bus POST /v1/produce.
-- Generated from sentin8-outbox::outbox_table_sql("stat").
CREATE TABLE IF NOT EXISTS stat.outbox (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id          UUID NOT NULL,
    event_type      TEXT NOT NULL,
    stream_family   TEXT NOT NULL,
    payload         JSONB NOT NULL,
    publisher_id_token  TEXT,
    publisher_subject   TEXT,
    relayed         BOOLEAN NOT NULL DEFAULT false,
    relayed_at      TIMESTAMPTZ,
    relay_attempts  INT NOT NULL DEFAULT 0,
    next_retry_at   TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_stat_outbox_unrelayed
    ON stat.outbox (created_at) WHERE relayed = false;
ALTER TABLE stat.outbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE stat.outbox FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS outbox_select ON stat.outbox;
CREATE POLICY outbox_select ON stat.outbox FOR SELECT
    USING (sentin8_context_initialized() AND env_id = sentin8_current_env_id());
DROP POLICY IF EXISTS outbox_insert ON stat.outbox;
CREATE POLICY outbox_insert ON stat.outbox FOR INSERT
    WITH CHECK (sentin8_context_initialized() AND env_id = sentin8_current_env_id());
DROP POLICY IF EXISTS outbox_update ON stat.outbox;
CREATE POLICY outbox_update ON stat.outbox FOR UPDATE
    USING (sentin8_context_initialized() AND env_id = sentin8_current_env_id());
CREATE OR REPLACE FUNCTION stat.stat_notify_outbox() RETURNS TRIGGER
LANGUAGE plpgsql AS $fn$
BEGIN
    PERFORM pg_notify('stat_outbox_changed', '');
    RETURN NEW;
END;
$fn$;
DROP TRIGGER IF EXISTS outbox_notify_trigger ON stat.outbox;
CREATE TRIGGER outbox_notify_trigger
    AFTER INSERT ON stat.outbox
    FOR EACH ROW
    EXECUTE FUNCTION stat.stat_notify_outbox();


-- ── Local audit journal (DBX §6.8) ────────────────────────────────────────
-- Spill journal for the canonical audit push: rows written same-tx as the
-- domain change, pushed to Sys POST /v1/audit (sentin8:sys:audit:write), then
-- marked pushed. A Sys outage never drops audit. Generated from
-- sentin8-audit::audit_journal_sql("stat").
CREATE TABLE IF NOT EXISTS stat.audit_journal (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id          UUID NOT NULL,
    action          TEXT NOT NULL,
    target_resource_type TEXT,
    target_resource_id    TEXT,
    actor_user_id   TEXT,
    actor_subject_type TEXT,
    severity        TEXT NOT NULL DEFAULT 'info',
    correlation_id  TEXT,
    before_state    JSONB,
    after_state     JSONB,
    details         JSONB,
    pushed          BOOLEAN NOT NULL DEFAULT false,
    pushed_at       TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_stat_audit_journal_unpushed
    ON stat.audit_journal (created_at) WHERE pushed = false;
ALTER TABLE stat.audit_journal ENABLE ROW LEVEL SECURITY;
ALTER TABLE stat.audit_journal FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS audit_journal_dml ON stat.audit_journal;
CREATE POLICY audit_journal_dml ON stat.audit_journal
    USING (sentin8_context_initialized() AND env_id = sentin8_current_env_id())
    WITH CHECK (sentin8_context_initialized() AND env_id = sentin8_current_env_id());


-- ── Schema grants (service-owned - the 2026-10-03 ownership pass) ─────
-- This service's own schema: USAGE for its role (platform.sql no longer
-- seeds per-service USAGE; the service declares it here).
GRANT USAGE ON SCHEMA stat TO sentin8_stat_service;
-- alert rules consumed by the alerts worker.
GRANT SELECT, INSERT, UPDATE, DELETE ON stat.alert_rules TO sentin8_stat_service;
GRANT SELECT, INSERT, UPDATE, DELETE ON stat.outbox TO sentin8_stat_service;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA stat TO sentin8_stat_service;
GRANT SELECT, INSERT, UPDATE, DELETE ON stat.audit_journal TO sentin8_stat_service;
