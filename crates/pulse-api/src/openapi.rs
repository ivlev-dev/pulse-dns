//! Статическая OpenAPI 3.1-схема реализованного подмножества.

use serde_json::{Value, json};

/// Возвращает OpenAPI-документ.
pub(crate) fn document() -> Value {
    json!({
        "openapi": "3.1.0",
        "info": {
            "title": "pulse-dns control-plane API (v1 subset)",
            "version": "1.0.0",
            "description": "Zones, rrsets, settings and observability for a single pulse-dns instance."
        },
        "servers": [{ "url": "http://127.0.0.1:8080" }],
        "security": [{ "bearerAuth": [] }],
        "paths": {
            "/healthz": {
                "get": {
                    "security": [],
                    "summary": "Liveness probe",
                    "responses": { "200": { "description": "Process is alive" } }
                }
            },
            "/readyz": {
                "get": {
                    "security": [],
                    "summary": "Readiness probe",
                    "responses": {
                        "200": { "description": "Ready" },
                        "503": { "description": "Not ready" }
                    }
                }
            },
            "/metrics": {
                "get": {
                    "security": [],
                    "summary": "Prometheus metrics",
                    "responses": { "200": { "description": "Text exposition 0.0.4" } }
                }
            },
            "/api/v1/openapi.json": {
                "get": {
                    "summary": "This document",
                    "responses": { "200": { "description": "OpenAPI document" } }
                }
            },
            "/api/v1/zones": {
                "get": {
                    "summary": "List zones visible to the token",
                    "parameters": [
                        { "name": "limit", "in": "query", "schema": { "type": "integer", "minimum": 1, "maximum": 500, "default": 50 } },
                        { "name": "cursor", "in": "query", "schema": { "type": "string" } },
                        { "name": "kind", "in": "query", "schema": { "type": "string", "enum": ["primary", "secondary", "forward"] } }
                    ],
                    "responses": {
                        "200": { "description": "Page of zones", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ZoneList" } } } },
                        "400": { "$ref": "#/components/responses/Problem" },
                        "401": { "$ref": "#/components/responses/Problem" },
                        "403": { "$ref": "#/components/responses/Problem" }
                    }
                },
                "post": {
                    "summary": "Create a zone",
                    "parameters": [{ "$ref": "#/components/parameters/IdempotencyKey" }],
                    "requestBody": {
                        "required": true,
                        "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ZoneWrite" } } }
                    },
                    "responses": {
                        "201": {
                            "description": "Created",
                            "headers": {
                                "Location": { "schema": { "type": "string" } },
                                "ETag": { "schema": { "type": "string" } }
                            },
                            "content": { "application/json": { "schema": { "$ref": "#/components/schemas/Zone" } } }
                        },
                        "401": { "$ref": "#/components/responses/Problem" },
                        "403": { "$ref": "#/components/responses/Problem" },
                        "409": { "$ref": "#/components/responses/Problem" },
                        "422": { "$ref": "#/components/responses/Problem" }
                    }
                }
            },
            "/api/v1/zones/{origin}": {
                "parameters": [{ "$ref": "#/components/parameters/Origin" }],
                "get": {
                    "summary": "Read a zone",
                    "responses": {
                        "200": {
                            "description": "Zone",
                            "headers": { "ETag": { "schema": { "type": "string" } } },
                            "content": { "application/json": { "schema": { "$ref": "#/components/schemas/Zone" } } }
                        },
                        "304": { "description": "If-None-Match matched" },
                        "404": { "$ref": "#/components/responses/Problem" }
                    }
                },
                "put": {
                    "summary": "Create a zone or replace its metadata",
                    "parameters": [
                        { "$ref": "#/components/parameters/IfMatch" },
                        { "$ref": "#/components/parameters/IfNoneMatch" }
                    ],
                    "requestBody": {
                        "required": true,
                        "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ZoneWrite" } } }
                    },
                    "responses": {
                        "200": { "description": "Replaced" },
                        "201": { "description": "Created", "headers": { "Location": { "schema": { "type": "string" } } } },
                        "412": { "$ref": "#/components/responses/Problem" },
                        "428": { "$ref": "#/components/responses/Problem" }
                    }
                },
                "delete": {
                    "summary": "Delete a zone",
                    "parameters": [{ "$ref": "#/components/parameters/IfMatch" }],
                    "responses": {
                        "204": { "description": "Deleted" },
                        "404": { "$ref": "#/components/responses/Problem" },
                        "412": { "$ref": "#/components/responses/Problem" },
                        "428": { "$ref": "#/components/responses/Problem" }
                    }
                }
            },
            "/api/v1/zones/{origin}/serial": {
                "parameters": [{ "$ref": "#/components/parameters/Origin" }],
                "get": {
                    "summary": "Read the zone serial",
                    "responses": {
                        "200": { "description": "Serial", "headers": { "ETag": { "schema": { "type": "string" } } } },
                        "401": { "$ref": "#/components/responses/Problem" },
                        "403": { "$ref": "#/components/responses/Problem" },
                        "404": { "$ref": "#/components/responses/Problem" }
                    }
                },
                "post": {
                    "summary": "Increment or set the serial (RFC 1982 monotonicity)",
                    "parameters": [{ "$ref": "#/components/parameters/IfMatch" }],
                    "requestBody": {
                        "required": true,
                        "content": { "application/json": { "schema": { "$ref": "#/components/schemas/SerialUpdate" } } }
                    },
                    "responses": {
                        "200": { "description": "Serial updated", "headers": { "ETag": { "schema": { "type": "string" } } } },
                        "404": { "$ref": "#/components/responses/Problem" },
                        "409": { "$ref": "#/components/responses/Problem" },
                        "412": { "$ref": "#/components/responses/Problem" },
                        "422": { "$ref": "#/components/responses/Problem" }
                    }
                }
            },
            "/api/v1/zones/{origin}/transfers": {
                "parameters": [{ "$ref": "#/components/parameters/Origin" }],
                "get": {
                    "summary": "List transfer jobs for the zone",
                    "parameters": [
                        { "name": "limit", "in": "query", "schema": { "type": "integer", "minimum": 1, "maximum": 500, "default": 50 } },
                        { "name": "cursor", "in": "query", "schema": { "type": "string" } },
                        { "name": "state", "in": "query", "schema": { "type": "string", "enum": ["pending", "running", "done", "failed", "cancelled"] } }
                    ],
                    "responses": {
                        "200": { "description": "Transfer jobs", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/JobList" } } } },
                        "401": { "$ref": "#/components/responses/Problem" },
                        "403": { "$ref": "#/components/responses/Problem" },
                        "404": { "$ref": "#/components/responses/Problem" }
                    }
                },
                "post": {
                    "summary": "Trigger AXFR/IXFR (primary: outgoing log, secondary: job)",
                    "parameters": [{ "$ref": "#/components/parameters/IdempotencyKey" }],
                    "requestBody": {
                        "required": true,
                        "content": { "application/json": { "schema": { "$ref": "#/components/schemas/TransferRequest" } } }
                    },
                    "responses": {
                        "200": { "description": "Primary outgoing transfer accepted (not a job)" },
                        "202": { "description": "Transfer job accepted", "headers": { "Location": { "schema": { "type": "string" } }, "Retry-After": { "schema": { "type": "integer" } } } },
                        "401": { "$ref": "#/components/responses/Problem" },
                        "403": { "$ref": "#/components/responses/Problem" },
                        "404": { "$ref": "#/components/responses/Problem" },
                        "409": { "$ref": "#/components/responses/Problem" },
                        "422": { "$ref": "#/components/responses/Problem" }
                    }
                }
            },
            "/api/v1/zones/{origin}/import": {
                "parameters": [{ "$ref": "#/components/parameters/Origin" }],
                "post": {
                    "summary": "Import master text into a primary zone (async job)",
                    "parameters": [
                        { "$ref": "#/components/parameters/IdempotencyKey" },
                        { "name": "mode", "in": "query", "schema": { "type": "string", "enum": ["replace", "merge", "check"], "default": "replace" } }
                    ],
                    "requestBody": {
                        "required": true,
                        "content": { "text/plain": { "schema": { "type": "string" } } }
                    },
                    "responses": {
                        "202": { "description": "Import job accepted", "headers": { "Location": { "schema": { "type": "string" } } } },
                        "401": { "$ref": "#/components/responses/Problem" },
                        "403": { "$ref": "#/components/responses/Problem" },
                        "404": { "$ref": "#/components/responses/Problem" },
                        "409": { "$ref": "#/components/responses/Problem" },
                        "413": { "$ref": "#/components/responses/Problem" },
                        "415": { "$ref": "#/components/responses/Problem" },
                        "422": { "$ref": "#/components/responses/Problem" }
                    }
                }
            },
            "/api/v1/zones/{origin}/settings": {
                "parameters": [{ "$ref": "#/components/parameters/Origin" }],
                "get": {
                    "summary": "Read zone settings",
                    "responses": { "200": { "description": "Settings" } }
                },
                "patch": {
                    "summary": "Patch zone settings",
                    "parameters": [{ "$ref": "#/components/parameters/IfMatch" }],
                    "requestBody": {
                        "required": true,
                        "content": { "application/json": { "schema": { "$ref": "#/components/schemas/SettingsPatch" } } }
                    },
                    "responses": {
                        "200": { "description": "Updated settings" },
                        "412": { "$ref": "#/components/responses/Problem" },
                        "428": { "$ref": "#/components/responses/Problem" }
                    }
                }
            },
            "/api/v1/zones/{origin}/keys": {
                "parameters": [{ "$ref": "#/components/parameters/Origin" }],
                "get": {
                    "summary": "Read public DNSSEC keys and DS records",
                    "description": "Private key material is never exposed.",
                    "responses": {
                        "200": { "description": "DNSKEY and DS records" },
                        "404": { "$ref": "#/components/responses/Problem" }
                    }
                }
            },
            "/api/v1/zones/{origin}/keys/status": {
                "parameters": [{ "$ref": "#/components/parameters/Origin" }],
                "get": {
                    "summary": "DNSSEC key rotation state (no private material)",
                    "responses": {
                        "200": { "description": "Rotation status" },
                        "401": { "$ref": "#/components/responses/Problem" },
                        "403": { "$ref": "#/components/responses/Problem" },
                        "404": { "$ref": "#/components/responses/Problem" }
                    }
                }
            },
            "/api/v1/zones/{origin}/keys/rollover": {
                "parameters": [{ "$ref": "#/components/parameters/Origin" }],
                "post": {
                    "summary": "Start KSK/ZSK rollover",
                    "parameters": [{ "$ref": "#/components/parameters/IdempotencyKey" }],
                    "requestBody": {
                        "required": true,
                        "content": { "application/json": { "schema": { "$ref": "#/components/schemas/Rollover" } } }
                    },
                    "responses": {
                        "202": { "description": "Rollover job accepted", "headers": { "Location": { "schema": { "type": "string" } } } },
                        "401": { "$ref": "#/components/responses/Problem" },
                        "403": { "$ref": "#/components/responses/Problem" },
                        "404": { "$ref": "#/components/responses/Problem" },
                        "409": { "$ref": "#/components/responses/Problem" },
                        "422": { "$ref": "#/components/responses/Problem" }
                    }
                }
            },
            "/api/v1/zones/{origin}/sign": {
                "parameters": [{ "$ref": "#/components/parameters/Origin" }],
                "post": {
                    "summary": "Re-sign a zone with the configured DNSSEC keys",
                    "responses": {
                        "200": { "description": "Zone re-signed" },
                        "404": { "$ref": "#/components/responses/Problem" },
                        "409": { "$ref": "#/components/responses/Problem" },
                        "422": { "$ref": "#/components/responses/Problem" }
                    }
                }
            },
            "/api/v1/zones/{origin}/records/{name}/{type}": {
                "parameters": [
                    { "$ref": "#/components/parameters/Origin" },
                    { "$ref": "#/components/parameters/Owner" },
                    { "$ref": "#/components/parameters/Type" }
                ],
                "get": {
                    "summary": "Read an RRset",
                    "responses": {
                        "200": {
                            "description": "RRset",
                            "headers": { "ETag": { "schema": { "type": "string" } } },
                            "content": { "application/json": { "schema": { "$ref": "#/components/schemas/Rrset" } } }
                        },
                        "404": { "$ref": "#/components/responses/Problem" }
                    }
                },
                "put": {
                    "summary": "Create or replace an RRset",
                    "parameters": [
                        { "$ref": "#/components/parameters/IfMatch" },
                        { "$ref": "#/components/parameters/IfNoneMatch" }
                    ],
                    "requestBody": {
                        "required": true,
                        "content": { "application/json": { "schema": { "$ref": "#/components/schemas/RrsetWrite" } } }
                    },
                    "responses": {
                        "200": { "description": "Replaced" },
                        "201": { "description": "Created" },
                        "412": { "$ref": "#/components/responses/Problem" },
                        "422": { "$ref": "#/components/responses/Problem" },
                        "428": { "$ref": "#/components/responses/Problem" }
                    }
                },
                "patch": {
                    "summary": "Atomically add/remove records or change TTL",
                    "parameters": [{ "$ref": "#/components/parameters/IfMatch" }],
                    "requestBody": {
                        "required": true,
                        "content": { "application/json": { "schema": { "$ref": "#/components/schemas/RrsetPatch" } } }
                    },
                    "responses": {
                        "200": { "description": "Updated or deleted" },
                        "404": { "$ref": "#/components/responses/Problem" },
                        "412": { "$ref": "#/components/responses/Problem" },
                        "422": { "$ref": "#/components/responses/Problem" },
                        "428": { "$ref": "#/components/responses/Problem" }
                    }
                },
                "delete": {
                    "summary": "Delete an RRset",
                    "parameters": [{ "$ref": "#/components/parameters/IfMatch" }],
                    "responses": {
                        "204": { "description": "Deleted" },
                        "404": { "$ref": "#/components/responses/Problem" },
                        "412": { "$ref": "#/components/responses/Problem" },
                        "428": { "$ref": "#/components/responses/Problem" }
                    }
                }
            },
            "/api/v1/zones/{origin}/rrsets": {
                "parameters": [{ "$ref": "#/components/parameters/Origin" }],
                "get": {
                    "summary": "List RRsets (alias surface)",
                    "responses": { "200": { "description": "Page of RRsets" } }
                }
            },
            "/api/v1/zones/{origin}/rrsets/{owner}/{type}": {
                "parameters": [
                    { "$ref": "#/components/parameters/Origin" },
                    { "$ref": "#/components/parameters/Owner" },
                    { "$ref": "#/components/parameters/Type" }
                ],
                "get": { "summary": "Alias of /records/{name}/{type}", "responses": { "200": { "description": "RRset" } } },
                "put": { "summary": "Alias of /records/{name}/{type}", "responses": { "200": { "description": "RRset" } } },
                "patch": { "summary": "Alias of /records/{name}/{type}", "responses": { "200": { "description": "RRset" } } },
                "delete": { "summary": "Alias of /records/{name}/{type}", "responses": { "204": { "description": "Deleted" } } }
            },
            "/api/v1/jobs": {
                "get": {
                    "summary": "List jobs of the token",
                    "parameters": [
                        { "name": "limit", "in": "query", "schema": { "type": "integer", "minimum": 1, "maximum": 500, "default": 50 } },
                        { "name": "cursor", "in": "query", "schema": { "type": "string" } },
                        { "name": "state", "in": "query", "schema": { "type": "string", "enum": ["pending", "running", "done", "failed", "cancelled"] } },
                        { "name": "kind", "in": "query", "schema": { "type": "string" } }
                    ],
                    "responses": {
                        "200": { "description": "Jobs", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/JobList" } } } },
                        "401": { "$ref": "#/components/responses/Problem" },
                        "403": { "$ref": "#/components/responses/Problem" }
                    }
                }
            },
            "/api/v1/jobs/{job_id}": {
                "parameters": [{ "$ref": "#/components/parameters/JobId" }],
                "get": {
                    "summary": "Read a job",
                    "responses": {
                        "200": { "description": "Job", "content": { "application/json": { "schema": { "$ref": "#/components/schemas/Job" } } } },
                        "401": { "$ref": "#/components/responses/Problem" },
                        "403": { "$ref": "#/components/responses/Problem" },
                        "404": { "$ref": "#/components/responses/Problem" }
                    }
                },
                "delete": {
                    "summary": "Cancel a job",
                    "responses": {
                        "200": { "description": "Job already finished" },
                        "202": { "description": "Cancellation accepted" },
                        "404": { "$ref": "#/components/responses/Problem" }
                    }
                }
            },
            "/api/v1/transfers/{job_id}": {
                "parameters": [{ "$ref": "#/components/parameters/JobId" }],
                "get": {
                    "summary": "Read a transfer job",
                    "responses": {
                        "200": { "description": "Job" },
                        "404": { "$ref": "#/components/responses/Problem" }
                    }
                },
                "delete": {
                    "summary": "Cancel a transfer job",
                    "responses": {
                        "200": { "description": "Job already finished" },
                        "202": { "description": "Cancellation accepted" },
                        "404": { "$ref": "#/components/responses/Problem" }
                    }
                }
            },
            "/api/v1/tsig-keys": {
                "get": {
                    "summary": "List managed TSIG keys (secrets are never returned)",
                    "responses": {
                        "200": { "description": "TSIG key list" },
                        "401": { "$ref": "#/components/responses/Problem" },
                        "403": { "$ref": "#/components/responses/Problem" }
                    }
                },
                "post": {
                    "summary": "Create a managed TSIG key",
                    "requestBody": {
                        "required": true,
                        "content": {
                            "application/json": {
                                "schema": { "$ref": "#/components/schemas/TsigKeyWrite" }
                            }
                        }
                    },
                    "responses": {
                        "201": { "description": "Created" },
                        "409": { "$ref": "#/components/responses/Problem" },
                        "422": { "$ref": "#/components/responses/Problem" }
                    }
                }
            },
            "/api/v1/tsig-keys/{name}": {
                "get": {
                    "summary": "Read a managed TSIG key",
                    "parameters": [
                        { "name": "name", "in": "path", "required": true, "schema": { "type": "string" } }
                    ],
                    "responses": {
                        "200": { "description": "TSIG key" },
                        "404": { "$ref": "#/components/responses/Problem" }
                    }
                },
                "delete": {
                    "summary": "Delete a managed TSIG key",
                    "parameters": [
                        { "name": "name", "in": "path", "required": true, "schema": { "type": "string" } }
                    ],
                    "responses": {
                        "204": { "description": "Deleted" },
                        "404": { "$ref": "#/components/responses/Problem" },
                        "409": { "$ref": "#/components/responses/Problem" }
                    }
                }
            },
            "/api/v1/audit": {
                "get": {
                    "summary": "Read the control-plane audit ring",
                    "parameters": [
                        { "name": "limit", "in": "query", "schema": { "type": "integer", "minimum": 1, "maximum": 500, "default": 50 } },
                        { "name": "cursor", "in": "query", "schema": { "type": "string" } },
                        { "name": "principal", "in": "query", "schema": { "type": "string" } },
                        { "name": "action", "in": "query", "schema": { "type": "string" } },
                        { "name": "result", "in": "query", "schema": { "type": "string" } }
                    ],
                    "responses": {
                        "200": { "description": "Audit page" },
                        "401": { "$ref": "#/components/responses/Problem" },
                        "403": { "$ref": "#/components/responses/Problem" }
                    }
                }
            }
        },
        "components": {
            "securitySchemes": {
                "bearerAuth": { "type": "http", "scheme": "bearer" }
            },
            "parameters": {
                "Origin": { "name": "origin", "in": "path", "required": true, "schema": { "type": "string", "example": "example.com." } },
                "Owner": { "name": "name", "in": "path", "required": true, "schema": { "type": "string", "example": "www.example.com." } },
                "Type": { "name": "type", "in": "path", "required": true, "schema": { "type": "string", "example": "A" } },
                "IfMatch": { "name": "If-Match", "in": "header", "required": false, "schema": { "type": "string" } },
                "IfNoneMatch": { "name": "If-None-Match", "in": "header", "required": false, "schema": { "type": "string" } },
                "IdempotencyKey": { "name": "Idempotency-Key", "in": "header", "required": false, "schema": { "type": "string", "minLength": 8, "maxLength": 128 } },
                "JobId": { "name": "job_id", "in": "path", "required": true, "schema": { "type": "string", "example": "job_0000000000000001_00000001" } }
            },
            "responses": {
                "Problem": {
                    "description": "RFC 9457 problem",
                    "content": { "application/problem+json": { "schema": { "$ref": "#/components/schemas/Problem" } } }
                }
            },
            "schemas": {
                "Zone": {
                    "type": "object",
                    "required": ["id", "origin", "kind", "serial", "version", "default_ttl", "denial", "rrsets", "created_at", "updated_at"],
                    "properties": {
                        "id": { "type": "integer" },
                        "origin": { "type": "string" },
                        "kind": { "type": "string", "enum": ["primary", "secondary", "forward"] },
                        "serial": { "type": "integer" },
                        "version": { "type": "integer" },
                        "default_ttl": { "type": "integer" },
                        "denial": { "type": "string", "enum": ["nsec", "nsec3"] },
                        "rrsets": { "type": "integer" },
                        "created_at": { "type": "string", "format": "date-time" },
                        "updated_at": { "type": "string", "format": "date-time" }
                    }
                },
                "ZoneWrite": {
                    "type": "object",
                    "properties": {
                        "origin": { "type": "string" },
                        "kind": { "type": "string", "enum": ["primary", "secondary", "forward"] },
                        "default_ttl": { "type": "integer", "minimum": 0, "maximum": 2147483647 },
                        "denial": { "type": "string", "enum": ["nsec", "nsec3"] }
                    }
                },
                "ZoneList": {
                    "type": "object",
                    "required": ["items", "next_cursor", "has_more"],
                    "properties": {
                        "items": { "type": "array", "items": { "$ref": "#/components/schemas/Zone" } },
                        "next_cursor": { "type": ["string", "null"] },
                        "has_more": { "type": "boolean" }
                    }
                },
                "Rrset": {
                    "type": "object",
                    "required": ["zone", "owner", "type", "class", "ttl", "records", "etag", "updated_at"],
                    "properties": {
                        "zone": { "type": "string" },
                        "owner": { "type": "string" },
                        "type": { "type": "string" },
                        "class": { "type": "string", "enum": ["IN"] },
                        "ttl": { "type": "integer" },
                        "records": { "type": "array", "items": { "type": "string" } },
                        "etag": { "type": "string" },
                        "updated_at": { "type": "string", "format": "date-time" }
                    }
                },
                "RrsetWrite": {
                    "type": "object",
                    "required": ["ttl", "records"],
                    "properties": {
                        "ttl": { "type": "integer", "minimum": 0, "maximum": 2147483647 },
                        "records": { "type": "array", "minItems": 1, "maxItems": 4096, "items": { "type": "string" } },
                        "class": { "type": "string", "enum": ["IN"] }
                    }
                },
                "RrsetPatch": {
                    "type": "object",
                    "properties": {
                        "ttl": { "type": "integer" },
                        "add": { "type": "array", "items": { "type": "string" } },
                        "remove": { "type": "array", "items": { "type": "string" } }
                    }
                },
                "Settings": {
                    "type": "object",
                    "properties": {
                        "zone": { "type": "string" },
                        "default_ttl": { "type": "integer" },
                        "denial": { "type": "string", "enum": ["nsec", "nsec3"] },
                        "version": { "type": "integer" },
                        "updated_at": { "type": "string", "format": "date-time" }
                    }
                },
                "SettingsPatch": {
                    "type": "object",
                    "properties": {
                        "default_ttl": { "type": "integer" },
                        "denial": { "type": "string", "enum": ["nsec", "nsec3"] }
                    }
                },
                "SerialUpdate": {
                    "type": "object",
                    "required": ["mode"],
                    "properties": {
                        "mode": { "type": "string", "enum": ["increment", "set"] },
                        "value": { "type": "integer", "minimum": 0, "maximum": 4_294_967_295_u64 }
                    }
                },
                "TransferRequest": {
                    "type": "object",
                    "required": ["kind"],
                    "properties": {
                        "kind": { "type": "string", "enum": ["axfr", "ixfr"] },
                        "peer": { "type": "string" },
                        "tsig_key": { "type": "string" },
                        "from_serial": { "type": "integer" }
                    }
                },
                "Rollover": {
                    "type": "object",
                    "required": ["role"],
                    "properties": {
                        "role": { "type": "string", "enum": ["ksk", "zsk"] },
                        "scheme": { "type": "string", "enum": ["pre_publish", "double_sign"] },
                        "overlap": { "type": "string", "example": "7d" },
                        "retire_after": { "type": "string", "example": "30d" }
                    }
                },
                "TsigKey": {
                    "type": "object",
                    "required": ["name", "algorithm", "created_at", "configured"],
                    "properties": {
                        "name": { "type": "string" },
                        "algorithm": { "type": "string" },
                        "created_at": { "type": "string", "format": "date-time" },
                        "last_used": { "type": ["string", "null"], "format": "date-time" },
                        "configured": { "type": "boolean" }
                    }
                },
                "TsigKeyList": {
                    "type": "object",
                    "required": ["items", "next_cursor", "has_more"],
                    "properties": {
                        "items": { "type": "array", "items": { "$ref": "#/components/schemas/TsigKey" } },
                        "next_cursor": { "type": ["string", "null"] },
                        "has_more": { "type": "boolean" }
                    }
                },
                "TsigKeyWrite": {
                    "type": "object",
                    "required": ["name", "secret"],
                    "properties": {
                        "name": { "type": "string" },
                        "algorithm": { "type": "string", "default": "hmac-sha256" },
                        "secret": { "type": "string", "description": "Base64; write-only" }
                    }
                },
                "Job": {
                    "type": "object",
                    "required": ["job_id", "kind", "state", "resource", "created_at"],
                    "properties": {
                        "job_id": { "type": "string" },
                        "kind": { "type": "string" },
                        "state": { "type": "string", "enum": ["pending", "running", "done", "failed", "cancelled"] },
                        "status": { "type": "string" },
                        "resource": { "type": "string" },
                        "zone": { "type": ["string", "null"] },
                        "progress": { "type": ["object", "null"] },
                        "result": { "type": ["object", "null"] },
                        "error": { "type": ["object", "null"] },
                        "created_at": { "type": "string", "format": "date-time" },
                        "started_at": { "type": ["string", "null"], "format": "date-time" },
                        "finished_at": { "type": ["string", "null"], "format": "date-time" },
                        "cancellable": { "type": "boolean" },
                        "expires_at": { "type": ["string", "null"], "format": "date-time" }
                    }
                },
                "JobList": {
                    "type": "object",
                    "required": ["items", "next_cursor", "has_more"],
                    "properties": {
                        "items": { "type": "array", "items": { "$ref": "#/components/schemas/Job" } },
                        "next_cursor": { "type": ["string", "null"] },
                        "has_more": { "type": "boolean" }
                    }
                },
                "Problem": {
                    "type": "object",
                    "required": ["type", "title", "status", "code"],
                    "properties": {
                        "type": { "type": "string", "format": "uri" },
                        "title": { "type": "string" },
                        "status": { "type": "integer" },
                        "detail": { "type": "string" },
                        "instance": { "type": "string" },
                        "code": { "type": "string" },
                        "request_id": { "type": "string" },
                        "retryable": { "type": "boolean" },
                        "errors": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "pointer": { "type": "string" },
                                    "code": { "type": "string" },
                                    "detail": { "type": "string" }
                                }
                            }
                        },
                        "current_etag": { "type": "string" },
                        "current_version": { "type": "integer" }
                    }
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn document_is_openapi_31() {
        let document = document();
        assert_eq!(document["openapi"], "3.1.0");
        assert!(document["paths"]["/api/v1/zones/{origin}"].is_object());
        assert!(document["paths"]["/api/v1/zones/{origin}/serial"].is_object());
        assert!(document["paths"]["/api/v1/zones/{origin}/transfers"].is_object());
        assert!(document["paths"]["/api/v1/zones/{origin}/import"].is_object());
        assert!(document["paths"]["/api/v1/jobs/{job_id}"].is_object());
        assert!(document["paths"]["/api/v1/audit"].is_object());
        assert!(document["paths"]["/api/v1/tsig-keys"].is_object());
        assert!(document["paths"]["/api/v1/tsig-keys/{name}"].is_object());
        assert!(document["paths"]["/api/v1/zones/{origin}/keys/status"].is_object());
        assert_eq!(
            document["components"]["securitySchemes"]["bearerAuth"]["scheme"],
            "bearer"
        );
    }
}
