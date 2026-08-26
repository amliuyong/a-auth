# Contributing

Thank you for contributing to A Auth.

## Development Setup

1. Follow [`docs/GETTING_STARTED.md`](docs/GETTING_STARTED.md).
2. Install the repository dependencies required by the component you change.
3. Enable the repository hook:

   ```bash
   git config core.hooksPath .githooks
   ```

4. Keep protocol behavior, tests, documentation, OpenAPI, generated client
   types, and infrastructure configuration synchronized.

## Before Submitting a Pull Request

Run the relevant focused tests and, when practical, the repository checks:

```bash
cargo fmt --all -- --check
cargo test --workspace --lib --locked
npm ci
npm run lint:markdown
```

Component-specific commands are documented under `docs/`, `web/`, `infra/`,
and `sdk/`.

## Security

Do not report vulnerabilities or include secrets in public issues. Follow
[`SECURITY.md`](SECURITY.md) for private reporting.
