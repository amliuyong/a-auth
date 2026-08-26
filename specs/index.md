# Capability Specifications

This index groups Agent Auth conformance requirements by capability. Normative
protocol and deployment decisions remain in [`docs/`](../docs/).

## Status

- The conformance inventory contains 149 requirements: 144 complete, 2 partial,
  and 3 not yet complete.
- `done` means the capability's tracked requirements are complete.
- `building` means one or more tracked requirements or external
  interoperability gates remain open.
- The exact evidence for each requirement is maintained in
  [`docs/CONFORMANCE.md`](../docs/CONFORMANCE.md) and
  [`.github/conformance/`](../.github/conformance/).

## Specifications

| Area | Capability | Phase | Status | Conformance |
|---|---|:---:|:---:|---|
| 000 | Discovery and metadata | P0 | done | C1 |
| 001 | Token design and lifecycle | P0-P2 | done | C2, C3 |
| 002 | Clients, DCR, and redirect validation | P0-P1 | building | C4 |
| 003 | User authentication and recovery | P0-P1 | building | C9, C10.24, C10.25 |
| 004 | Authorization-session state machine | P1 | done | C6 |
| 005 | AWS architecture, keys, and rate limits | P0-P3 | building | C10 |
| 006 | Endpoints, grants, and resource binding | P0-P3 | done | C2.5, C2.8, C2.11 |
| 007 | Resource-server user attributes | P1 | done | C8.11, C8.12 |
| 010 | MCP integration and resource-server SDKs | P1-P3 | building | C8 |
| 011 | Delegation, grants, and token exchange | P2 | done | C7 |
| 012 | Workload client authentication | P2 | building | C5 |
| 013 | CIBA and device authorization | P2-P3 | building | C7b |
| 020 | Multi-tenant isolation and multi-Region recovery | P2-P3 | building | C10, C11 |
| 025 | Administration console | P1-P2 | done | C4.3, C10.23, C10.24 |
| 030 | Enterprise identity and operational readiness | P0-P3 | building | C12 |
| 031 | MCP Enterprise-Managed Authorization | P2 | building | C13 |

## Dependency Outline

```text
Protocol foundation: 000, 001, 002, 005, 006
         │
         ├── User authentication: 003
         ├── Authorization sessions: 004
         └── MCP integration: 010
                  │
                  ├── Delegation and grants: 011
                  ├── Workload identity: 012
                  ├── Device and CIBA: 013
                  └── Enterprise-managed authorization: 031
                           │
                           ├── Multi-tenant and multi-Region: 020
                           └── Enterprise operations: 025, 030
```

When changing behavior, update the implementation, focused tests, public
documentation, and conformance mapping together.
