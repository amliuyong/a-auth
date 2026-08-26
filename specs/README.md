# Capability Specifications

This directory provides a compact capability index for Agent Auth.

The public, normative sources are:

- [`docs/DESIGN.md`](../docs/DESIGN.md) for protocol and trust-boundary design;
- [`docs/DEPLOYMENT.md`](../docs/DEPLOYMENT.md) for deployment architecture;
- [`docs/CONFORMANCE.md`](../docs/CONFORMANCE.md) for requirement status and
  exact automated evidence;
- [`.github/conformance/`](../.github/conformance/) for the machine-readable
  inventory and evidence map.

[`index.md`](./index.md) groups the conformance requirements into capability
areas. It is a navigation aid, not a second normative specification.

Behavioral changes should update the implementation, focused tests, public
documentation, OpenAPI surface when applicable, and conformance evidence in the
same pull request.
