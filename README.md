# kube-reaper

Kubernetes RBAC attack path mapper. It finds what your identity can do, flags dangerous configurations, and chains permissions into multi-step paths to cluster compromise.

Built for red teamers and penetration testers.

## What It Does

kube-reaper scans a Kubernetes cluster from any identity (user, service account, group) and produces:

- **55 dangerous permission patterns** with severity ratings and attack instructions
- **12 attack chain types** that link permissions into multi-step escalation paths
- **Pod pivot mapping** that connects exec access, running pods, and service account permissions into full chains
- **Dangerous pod detection** that flags privileged containers, host mounts, runtime sockets, and exposed secrets
- **31 CRD threat patterns** that identify attack surface from ArgoCD, Flux, Istio, cert-manager, Kyverno, Gatekeeper, Tekton, Crossplane, Calico, and others
- **Secret triage** that classifies accessible secrets by type (SA tokens, registry creds, TLS certs, SSH keys, basic auth, opaque)
- **Pod context analysis** that detects when you run inside a pod and inspects SA tokens, mounts, and environment variables
- **RBAC graph enumeration** that maps all identities to their effective permissions and flags overprivileged pivot targets
- **Impersonation scanning** that lets you scan as a different user or group

## Install

### Build from source

Requires a Rust toolchain (`rustup` + stable).

```bash
git clone https://github.com/youruser/kube-reaper.git
cd kube-reaper
cargo build --release
```

The binary is at `target/release/kube-reaper`.

### Build a static binary (recommended for target deployment)

Use musl to produce a fully static binary with no glibc dependency. This binary works on any Linux x86_64 system.

```bash
# Install the musl target (one-time setup)
rustup target add x86_64-unknown-linux-musl

# Build the static binary
cargo build --release --target x86_64-unknown-linux-musl
```

The binary is at `target/x86_64-unknown-linux-musl/release/kube-reaper` (approx. 5.4 MB, stripped and LTO-optimized).

Copy it to the target system. No dependencies required.

```bash
# Example: copy to a Kubernetes node
scp target/x86_64-unknown-linux-musl/release/kube-reaper user@node:/tmp/

# Example: copy into a running pod
kubectl cp target/x86_64-unknown-linux-musl/release/kube-reaper mynamespace/mypod:/tmp/kube-reaper
```

## Quick Start

```bash
# Scan with current kubeconfig context
kube-reaper

# Scan a specific namespace
kube-reaper -n production

# Scan with a specific kubeconfig
kube-reaper -k /path/to/kubeconfig

# Scan with a stolen SA token
kube-reaper --token <JWT> --server https://10.0.0.1:6443

# Scan as a different user (requires impersonate permissions)
kube-reaper --as-user system:admin

# Show only critical and high findings
kube-reaper -s high

# Output JSON to stdout
kube-reaper -o json

# Save JSON report to file
kube-reaper -w results.json
```

## CLI Reference

```
Usage: kube-reaper [OPTIONS]

Options:
  -n, --namespace <NAMESPACE>     Target namespace (default: all accessible)
  -k, --kubeconfig <KUBECONFIG>   Path to kubeconfig file [env: KUBECONFIG=]
      --token <TOKEN>             Authenticate with a raw bearer token (requires --server)
      --server <SERVER>           API server URL (required with --token)
      --as-user <USER>            Scan as a different user (requires impersonate perms)
      --as-group <GROUP>          Scan as a different group (requires impersonate perms)
  -o, --output <OUTPUT>           Output format [default: terminal] [values: terminal, json]
  -w, --write <WRITE>             Write results to file (JSON format)
  -s, --severity <SEVERITY>       Minimum severity [default: low] [values: critical, high, medium, low, info]
      --unconventional-only       Show only unconventional RBAC abuses
      --chains-only               Show only attack chains
  -h, --help                      Print help
  -V, --version                   Print version
```

### Authentication modes

kube-reaper supports three authentication methods. It tries them in this order:

1. **`--token` + `--server`** - Direct bearer token authentication. Use this when you have a stolen SA token or JWT. Automatically accepts self-signed certificates. Requires `--server` with the API server URL.

2. **`--kubeconfig` / `-k`** - Explicit kubeconfig file. Points to a specific kubeconfig. Also accepts the `KUBECONFIG` environment variable.

3. **Default infer** - If no flags are set, kube-reaper uses the standard Kubernetes client resolution: in-cluster config (when inside a pod), then `~/.kube/config`.

### Impersonation flags

`--as-user` and `--as-group` set Kubernetes impersonation headers. These work with all three authentication modes. Your identity must have the `impersonate` verb on `users`, `groups`, or `serviceaccounts` for this to work.

```bash
# Scan as a specific service account
kube-reaper --as-user system:serviceaccount:development:code-server

# Scan as the system:masters group
kube-reaper --as-group system:masters

# Combine with token auth
kube-reaper --token <JWT> --server https://api:6443 --as-user developer
```

## Output Sections

The terminal output has these sections (each appears only when it has findings):

| Section | Description |
|---|---|
| Pod Context Analysis | Findings from inside the current pod (SA token, mounts, env vars) |
| Attack Path Chains | Multi-step attack paths with step-by-step instructions |
| Dangerous Pods | Running pods with security issues (privileged, host mounts, secrets) |
| Secret Triage | Accessible secrets classified by type and attack value |
| CRD Attack Surface | Custom resources from known dangerous operators |
| Other Identities | Overprivileged identities that are pivot targets |
| Namespace Security | PSS enforcement status and pod creation capability per namespace |
| Dangerous Permissions | Individual permission findings grouped by severity |
| Summary | Counts of all finding categories |

### JSON output

Use `-o json` for machine-readable output or `-w results.json` to save to a file.

```bash
# List all critical attack chains
kube-reaper -o json | jq '.chains[] | select(.severity == "Critical") | .title'

# Find namespaces without PSS enforcement where you can create pods
kube-reaper -o json | jq '.namespace_findings[] | select(.privileged_pod_path == true) | .namespace'

# List SA token secrets (instant identity pivot)
kube-reaper -o json | jq '.secret_findings[] | select(.category == "SA Token") | {name, namespace}'

# Find pod pivot chains
kube-reaper -o json | jq '.chains[] | select(.id | startswith("pod-pivot")) | .title'

# Get unconventional findings only
kube-reaper -o json | jq '.findings[] | select(.unconventional == true) | {title, namespace, attack_path}'
```

## Detailed Documentation

For full details on each feature, see the docs folder:

- **[Dangerous Permissions](docs/permissions.md)** - All 55 permission patterns with severity, attack path, and capabilities
- **[Attack Chains](docs/chains.md)** - All 12 chain types with step-by-step exploitation details
- **[CRD Awareness](docs/crds.md)** - All 31 CRD patterns across 10 operator categories
- **[Pod Context Detection](docs/pod-context.md)** - How pod context analysis works and what it detects
- **[Architecture](docs/architecture.md)** - Source layout and module responsibilities

## Requirements

- A valid kubeconfig, a bearer token, or in-cluster service account token
- The identity needs at minimum `create` on `selfsubjectrulesreviews` (this is granted to all authenticated users by default)
- More permissions on the scanning identity = more complete results
- Cluster-admin gives full visibility across all scan modules

### Minimum permissions vs. full scan

| Scan module | Required permissions |
|---|---|
| Permission enumeration | `selfsubjectrulesreviews` (default grant) |
| Namespace listing | `list namespaces` |
| Pod enumeration | `list pods` in target namespaces |
| Secret triage | `list secrets` in target namespaces |
| RBAC graph | `list roles, clusterroles, rolebindings, clusterrolebindings` |
| CRD detection | `list customresourcedefinitions` |
| Pod context | No API permissions needed (reads local filesystem) |

If a scan module lacks permissions, it reports that and continues. No module failure stops the scan.

## Disclaimer

kube-reaper is intended for authorized security testing, penetration testing engagements, and defensive security assessments only. You are responsible for obtaining proper authorization before scanning any cluster. Unauthorized access to computer systems is illegal. The authors accept no liability for misuse of this tool.

## License

MIT
