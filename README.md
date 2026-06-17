<p align="left">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/logo-dark.svg">
    <img src="assets/logo-light.svg" alt="Trestle logo" height="18">
  </picture>
</p>

A local secret scanner for source code. Trestle finds API keys, access tokens,
passwords, private keys, and certificates before commiting them by mistake,
and keeps them from leaving your machine.

This is the Community edition. Open source under Apache-2.0, and a mirror of
the version distributed at [trestlescan.com][trestlescan].

## What Trestle does

- **Detection.** Hundreds of credential patterns from real services (OpenAI,
  Anthropic, Stripe, AWS, GitHub, Google, Slack, Sentry, and more), plus
  unfamiliar keys spotted by entropy, variable names, and surrounding code.
- **Code-aware.** Trestle parses your files instead of running plain regular
  expressions, so it can tell an environment variable from a build argument,
  a header, a parameter, or a constant in source.
- **Runs everywhere you work.** Command line scanner, file watcher,
  pre-commit hook, language server for LSP-aware editors (Neovim, Helix, Zed,
  JetBrains), MCP server for AI assistants (Claude Code, Cursor, Copilot,
  Codex), and a native VS Code extension.
- **Local only.** Runs entirely on your machine. No network, no telemetry,
  no account, no signup.
- **One static binary.** No runtime to install, multi-threaded, and honors
  `.gitignore` and your own skip rules.

## Building from source

A recent stable Rust toolchain is the only prerequisite.

```sh
cargo build --release
```

This builds two binaries: `trestle`, which does not make network requests, and
`trestle-net`, which can check whether found secrets are still live.

## Quick start

In any project directory:

```sh
trestle install  # adds a pre-commit hook and AI instructions
trestle scan     # scans the current directory
```

Other commands:

- `trestle watch` keeps scanning as files change.
- `trestle lsp` starts the language server.
- `trestle mcp` starts the MCP server.
- `trestle uninstall` removes the integration from a project.

## Checking whether a secret is live

The default `trestle` binary does not make network requests. The separate
`trestle-net` binary adds an optional check that contacts each detected
secret's provider to confirm whether the credential is still valid:

```sh
trestle-net scan --validate
```

Each finding is then labeled `(active)`, `(inactive)`, or `(could not
verify)`. This check runs only in `trestle-net`, so the `trestle` binary
remains fully offline.

The full documentation is available at [trestlescan.com/documentation][docs].

## GitHub Action

Use the official GitHub Action to scan every push and pull request:

```yaml
name: Secret scan

on:
  push:
  pull_request:

jobs:
  trestle:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: toro-guapo/trestle-action@v1
```

See [toro-guapo/trestle-action][trestle-action] for inputs, outputs, SARIF
upload to the GitHub Security tab, and supported runners.

## Community and Pro

Trestle is open core.

- **Community** (this repository) handles detection. Every finding is reported
  with its location and the rule that flagged it. Apache-2.0 licensed.
- **Pro** adds remediation guidance: for each finding, the steps to remove the
  secret from source, what to keep in your local `.env`, and per-platform
  rotation guides for AWS, GitHub Actions, Vercel, Netlify, Kubernetes,
  Doppler, and other targets. Distributed under a commercial license.

Pro is available at [trestlescan.com][trestlescan].

## About this repository

This is a read-only mirror, refreshed on every Community release. Development
happens in a private repository.

Issues and discussion are welcome on GitHub. **Pull requests are not accepted
through this mirror.** If you have a fix or an idea, please open an issue.

## License

Apache License 2.0. See [LICENSE](LICENSE).

[trestlescan]: https://trestlescan.com
[docs]: https://trestlescan.com/documentation
[trestle-action]: https://github.com/toro-guapo/trestle-action
