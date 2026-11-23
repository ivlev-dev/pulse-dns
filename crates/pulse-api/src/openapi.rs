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
                "IfNoneMatch": { "name": "If-None-Match", "in": "header", "required": false, "schema": { "type": "string" } }
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
        assert_eq!(
            document["components"]["securitySchemes"]["bearerAuth"]["scheme"],
            "bearer"
        );
    }
}
