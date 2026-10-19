// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Stat
// SPDX-License-Identifier: Apache-2.0

//! Service self-registration data for Sentin8:Stat.
//!
//! Output via `--print-registration` flag. The CLI runs the binary with this
//! flag and consumes the JSON to register the service in the platform DB.
//! See `design/sentin8-service-self-registration-design.md`.

use sentin8::registration::{
    AdminScope, AdminUi, AdminUiPage, CrossSchemaGrant, PgRole, PolicySetDecl, Registration,
    RelationDecl, SqlMigration,
};
use utoipa::OpenApi;

const PG_ROLES: &[PgRole] = &[PgRole {
    scope: "sentin8:stat:read,sentin8:stat:write",
    role: "sentin8_stat_service",
    bypass_rls: false,
    database: "sentin8",
    // The embedded worker's archive sweep resolves org_id from
    // `sys.environments` for its archive paths (worker/pipeline.rs -
    // platform-plane SYSTEM-env context read, SELECT-only, schema-
    // qualified). Declared explicitly; enroll's phase-2 grants pass
    // applies it (registration README §6).
    cross_schema_grants: &[CrossSchemaGrant {
        schema: "sys",
        table: "environments",
        privilege: "SELECT",
    }],
}];

// ── Registration data (single source of truth) ───────────────────────────

const ADMIN_SCOPES: &[AdminScope] = &[
    // Role vocabulary: admin API gates on
    // `sentin8:stat:data:read`|`sentin8:stat:admin` (auth.rs require_admin), Data API on
    // `sentin8:stat:data:read`. (`sentin8:stat:measure` is ingest-only - granted to M2M
    // clients, never to admin roles; `sentin8:stat:read` is accepted by no handler.)
    AdminScope::Typed {
        role: "sentin8:stat:admin",
        scope: "sentin8:stat:admin",
    },
    AdminScope::Typed {
        role: "sentin8:stat:admin",
        scope: "sentin8:stat:data:read",
    },
    // Policy-admin surface (policy design ; per-service scope).
    AdminScope::Tuple("sentin8:stat:admin", "sentin8:stat:policy:read"),
    AdminScope::Tuple("sentin8:stat:admin", "sentin8:stat:policy:write"),
];

const ADMIN_UI_PAGES: &[AdminUiPage] = &[
    AdminUiPage {
        route: "overview",
        label: "Overview",
        ui_endpoint: "/v1/admin/ui/overview",
        data_endpoint: "/v1/admin/overview",
        icon: "0xe1b1",
    },
    AdminUiPage {
        route: "properties",
        label: "Properties",
        ui_endpoint: "/v1/admin/ui/properties",
        data_endpoint: "/v1/admin/properties",
        icon: "0xe683",
    },
    AdminUiPage {
        route: "events",
        label: "Events",
        ui_endpoint: "/v1/admin/ui/events",
        data_endpoint: "/v1/admin/events",
        icon: "0xe44f",
    },
    AdminUiPage {
        route: "metrics",
        label: "Metrics",
        ui_endpoint: "/v1/admin/ui/metrics",
        data_endpoint: "/v1/admin/metrics",
        icon: "0xe0cc",
    },
    AdminUiPage {
        route: "accounts",
        label: "Accounts",
        ui_endpoint: "/v1/admin/ui/accounts",
        data_endpoint: "/v1/admin/accounts",
        icon: "0xe85d",
    },
    AdminUiPage {
        route: "policy-sets",
        label: "Policy Sets",
        ui_endpoint: "/v1/admin/ui/policy-sets",
        data_endpoint: "/v1/admin/policy-sets",
        icon: "0xe8b8",
    },
    AdminUiPage {
        route: "policy-decisions",
        label: "Policy Decisions",
        ui_endpoint: "/v1/admin/ui/policy-decisions",
        data_endpoint: "/v1/admin/policy-decisions",
        icon: "0xf070",
    },
];

/// SQL migrations embedded at compile time.
/// The stat service has one init.sql file.
const SQL_INIT: &str = include_str!("../sql/init.sql");

/// Serialize the utoipa OpenAPI spec (used for the `all` and `openapi` sections).
fn openapi_spec() -> serde_json::Value {
    serde_json::to_value(crate::openapi::StatOpenApi::openapi()).unwrap_or(serde_json::Value::Null)
}

/// Default declarative policy sets (Sentin8:Policy design /):
/// action-granular scope permits over the LIVE effective scope set. Seeded
/// `origin='platform'`, `mode='enforced'` ( - step 5 is
/// the only gate; shadow is the emergency one-UPDATE rollback lever only).
const POLICIES: &[PolicySetDecl] = &[
    PolicySetDecl {
        policy_set_name: "scope-mirror",
        description: "Action-granular scope permits for sentin8:stat over the LIVE effective scope set. Enforced - step 5 is the only gate.",
        policies: "permit(principal, action == Action::\"sentin8:stat:data:read\", resource) when { principal.scopes.contains(\"sentin8:stat:data:read\") };\npermit(principal, action == Action::\"sentin8:stat:data:read\", resource) when { principal.scopes.contains(\"sentin8:stat:admin\") };\npermit(principal, action == Action::\"sentin8:stat:measure\", resource) when { principal.scopes.contains(\"sentin8:stat:measure\") };",
        schema: None,
        mode: "enforced",
        default_enabled: true,
    },
];

/// Default ReBAC relation tuples - none declared by this
/// service today; env admins author their own graph via the admin API.
const RELATIONS: &[RelationDecl] = &[];

/// Print the registration JSON to stdout.
///
/// With no `--section` argument, outputs the full registration object.
/// With `--section=<name>`, outputs only that section as a standalone JSON value.
/// M2M DCR workload grants (self-registration ): this
/// service's own `certless:<workload>` rows, upserted by `vertical enroll`.
/// The static auth seed is retired - this declaration is the ONLY
/// provisioning path ( "DCR is dynamic").
/// Cover BOTH the full-identity `-policy` spelling (policy_bus_client) and
/// the bare `{short}-policy` spelling (stat_emit); the gate's superset
/// check admits any requested subset.
const M2M_GRANTS: &[sentin8::registration::M2mGrant] = &[
    sentin8::registration::M2mGrant {
        workload: "stat-audit",
        scopes: &["sentin8:sys:audit:write", "sentin8:bus:consume"],
    },
    sentin8::registration::M2mGrant {
        workload: "sentin8:stat",
        scopes: &[
            "sentin8:bus:produce",
            "sentin8:bus:consume",
            "sentin8:stat:measure",
        ],
    },
    sentin8::registration::M2mGrant {
        workload: "stat",
        scopes: &["sentin8:bus:produce", "sentin8:bus:consume"],
    },
    sentin8::registration::M2mGrant {
        workload: "sentin8:stat-policy",
        scopes: &["sentin8:bus:consume", "sentin8:stat:measure"],
    },
    sentin8::registration::M2mGrant {
        workload: "stat-policy",
        scopes: &["sentin8:bus:consume", "sentin8:stat:measure"],
    },
    // TLS-RLS-4 (design/sentin8-vertical-data-plane-contract.md §VDC.7): the database-free HostContextResolver’s resolve workload - cache miss calls Sys `GET /v1/resolve/hostname`.
    sentin8::registration::M2mGrant {
        workload: "sentin8-stat-tls",
        scopes: &["sentin8:sys:instances:read"],
    },
];

/// Handle print.
pub fn print(section: Option<String>) -> anyhow::Result<()> {
    let reg = Registration {
        service_type: "sentin8:stat",
        subdomain: "stat",
        health_path: "/v1/health",
        admin_scopes: ADMIN_SCOPES,
        error_codes: &[],
        consent_providers: &[],
        consent_flows: &[],
        admin_ui: Some(AdminUi {
            label: "Stat",
            icon: "0xe083",
            service_flag: "stat",
            pages: ADMIN_UI_PAGES,
        }),
        sql_migrations: vec![SqlMigration {
            version: 1,
            name: "init",
            sql: SQL_INIT,
        }],
        pg_roles: PG_ROLES,
        policies: POLICIES,
        relations: RELATIONS,
        event_triggers: &[],
        schedules: &[],
        audit_findings: None,
        service_actions: None,
        m2m_grants: Some(M2M_GRANTS),
        openapi_url: "/openapi.json",
        openapi: openapi_spec,
    };
    sentin8::registration::print_registration(section, &reg, openapi_spec)
}
