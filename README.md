# adc-login

A standalone, single-binary tool that replicates the core functionality of
`gcloud auth application-default login` without requiring the Google Cloud SDK.

**This is a Proof of Concept (PoC). Use at your own risk.**

## Motivation

There are environments where installing the full Google Cloud SDK is
difficult or impossible:

- **Termux** on Android
- Minimal container images / CI runners without `gcloud`
- Air-gapped or restricted machines where only a single static binary
  can be transferred
- Embedded / IoT development environments

In these situations, obtaining Application Default Credentials (ADC) for
local development becomes a challenge. `adc-login` solves this by providing
the same OAuth2 flow in a single Go binary with zero runtime dependencies.

## Disclaimer

This tool uses the OAuth Client ID that is embedded in the Google Cloud SDK,
which is distributed under the Apache License 2.0. These values are not
secret -- they are present in plain text in the publicly available SDK source
code.

However, Google may restrict or block access for applications that use this
Client ID outside of the official Cloud SDK. Possible consequences include:

- OAuth consent being blocked
- API requests being rejected
- Account suspension

**Recommendations:**

- Use a dedicated test/development account only.
  Do NOT use this with your primary Google account.
- For production workflows, install the official
  [Google Cloud SDK](https://cloud.google.com/sdk/docs/install).
- Do NOT use this in production systems or with accounts that have access
  to sensitive resources.

This software is provided "as is", without warranty of any kind.

## Installation

```bash
go install github.com/apstndb/adclogin@latest
```

Or download a pre-built binary from the [Releases](https://github.com/apstndb/adclogin/releases) page.

Cross-compile for Termux (aarch64 Android):

```bash
GOOS=android GOARCH=arm64 go build -o adc-login .
```

## Usage

### Basic (browser flow)

```bash
adc-login
```

### No-browser flow (for headless / Termux environments)

```bash
adc-login --no-browser
```

### Custom scopes

```bash
adc-login \
  --client-id-file=my-client.json \
  --scopes="openid,https://www.googleapis.com/auth/userinfo.email,https://www.googleapis.com/auth/cloud-platform,https://www.googleapis.com/auth/drive"
```

### With quota project

```bash
adc-login --quota-project=my-billing-project
```

### Without quota project

```bash
adc-login --disable-quota-project
```

### Service account impersonation

```bash
# Direct impersonation
adc-login --impersonate-service-account=sa@my-project.iam.gserviceaccount.com

# Delegation chain: SA1 -> SA2 (SA2 is the final target)
adc-login --impersonate-service-account=sa1@proj.iam.gserviceaccount.com,sa2@proj.iam.gserviceaccount.com
```

### Combined flags

```bash
adc-login \
  --impersonate-service-account=sa@my-project.iam.gserviceaccount.com \
  --quota-project=my-billing-project \
  --no-browser
```

## Flags

| Flag | Description |
|------|-------------|
| `--scopes` | Comma-separated OAuth scopes (`cloud-platform` is always required) |
| `--client-id-file` | Path to a JSON file containing a custom OAuth Client ID (installed type) |
| `--quota-project` | Quota project ID to embed in the ADC file |
| `--disable-quota-project` | Do not write a quota project to the ADC file |
| `--impersonate-service-account` | Service account to impersonate (comma-separated list for delegation chain) |
| `--no-browser` | Manual copy/paste flow -- does not open a browser |

## Output

Credentials are written to the well-known ADC file path:

| OS | Path |
|----|------|
| Linux / macOS | `~/.config/gcloud/application_default_credentials.json` |
| Windows | `%APPDATA%\gcloud\application_default_credentials.json` |

The output format is identical to what `gcloud auth application-default login`
produces, so all Google Cloud client libraries (Go, Python, Java, Node.js,
etc.) will pick it up automatically.

## License

Apache License 2.0
