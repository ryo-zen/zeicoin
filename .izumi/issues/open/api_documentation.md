---
id: api_documentation
key: ZEI-1
title: Create OpenAPI and OpenRPC specifications
type: Task
status: Backlog
priority: Low
assignee: null
labels:
- documentation
- api
sprint: null
story_points: null
due_date: null
parent_id: null
rank: 1773125882061.0
comments: []
created_at: 2026-03-07T00:00:00+00:00
updated_at: 2026-04-01T05:27:06.765091786+00:00
closed_at: null
---

## Summary

Document the REST and JSON-RPC APIs with formal specifications to enable client SDK generation and tooling integration.

## Acceptance Criteria

- [ ] `openapi.yaml` created covering all REST endpoints (port 8080)
- [ ] `openrpc.json` created covering all JSON-RPC methods (port 10803)
- [ ] Each endpoint includes request parameters, response schemas, and worked examples
- [ ] OpenAPI spec served at `/openapi.yaml` on the REST server for discoverability
- [ ] Both specs versioned and kept in sync with API changes

## Notes

REST endpoints: `GET /health`, `/api/balance`, `/api/nonce`, `/api/account`, `/api/transaction`, `/api/network/health`, `/api/transactions/volume`.

JSON-RPC methods: `getBalance`, `getNonce`, `submitTransaction`, `getBlockHeight`, `getTransaction`, `getBlock`, `getStatus`, `ping`.

OpenAPI spec enables auto-generated client SDKs and Swagger UI. OpenRPC spec enables tooling like MetaMask-style wallet integration. Consider hosting the spec at `/openapi.yaml` on the REST server for discoverability.
