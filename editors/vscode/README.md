# Trestle for VS Code

This extension integrates [Trestle](https://trestlescan.com), a local secret scanner, with Visual Studio Code. Findings appear inline in your editor as you work.

## Features

- Diagnostics for API keys, tokens, passwords, private keys, certificates, and other credentials, shown inline in the editor.
- Hover a finding to see the credential type and the rule that matched. With a Pro license, the hover also includes remediation guidance.
- Files are re-scanned as you edit them, using the same rules as `trestle scan` on the command line.

## Installation

The extension ships with the Trestle Community binary for your platform. After installing the extension, no further setup is required.

To use a different binary (for example, the Pro edition or a different release), make sure that `trestle` is on the system `PATH`, or set the `trestle.path` setting to its absolute path. The extension resolves the binary in this order:

1. The path in `trestle.path`, if set.
2. `trestle` on the system `PATH`.
3. The Community binary bundled with the extension.

## Commands

| Command | Description |
| --- | --- |
| `Trestle: Restart Language Server` | Re-reads the path to the trestle binary and restarts the language server. |

## Settings

| Setting | Default | Description |
| --- | --- | --- |
| `trestle.path` | (empty) | Absolute path to a specific `trestle` executable. When empty, the extension uses `trestle` from the system `PATH` if available, otherwise falls back to the bundled Community binary. |

## Privacy

Trestle runs entirely on the local machine. There are no network calls, no telemetry, no account, and no signup.

## Community and Pro

The Community edition is free and includes the full detection engine; this is the binary bundled with the extension. The Pro edition adds remediation guidance, with rotation steps for the deployment targets detected in the repository. See [trestlescan.com](https://trestlescan.com/#pricing) for details on Pro.

## License

This extension is licensed under Apache 2.0. See the `LICENSE` file bundled with the extension for the full text.
