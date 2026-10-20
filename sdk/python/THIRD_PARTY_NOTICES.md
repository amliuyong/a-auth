# Third-party dependencies

The SDK source is Apache-2.0, as specified in LICENSE. Runtime dependencies are
installed separately and retain their own licenses; they are not vendored into
the wheel or source distribution.

| Dependency | Declared range | License | Source |
| --- | --- | --- | --- |
| PyJWT | >=2.8 | MIT | <https://github.com/jpadilla/pyjwt> |
| cryptography | >=41 | Apache-2.0 OR BSD-3-Clause | <https://github.com/pyca/cryptography> |

Platform-dependent transitive dependencies retain the notices supplied in
their own distributions. Test and build tools are excluded from SDK runtime
dependencies.
