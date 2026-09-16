# kube-reaper

Kubernetes RBAC attack path mapper. It finds what your identity can do, flags dangerous permissions, and chains them into multi-step paths to cluster compromise.

Built for red teamers and penetration testers.

## What It Does

kube-reaper scans a Kubernetes cluster from any identity (user, service account, group) and produces:

- **55 dangerous permission patterns** with severity ratings and attack instructions
- **16 attack chain types** that link permissions into multi-step escalation paths
- **Recursive identity pivoting** that reads SA token secrets and mints tokens to map transitive access across identities
- **Pod pivot mapping** that connects exec access, running pods, and service account permissions
- **Dangerous pod detection** that flags privileged containers, host mounts, runtime sockets, and exposed secrets
- **RBAC graph enumeration** that maps all identities to their effective permissions and flags overprivileged pivot targets
- **31 CRD threat patterns** for ArgoCD, Flux, Istio, cert-manager, Kyverno, Gatekeeper, Tekton, Crossplane, Calico, and others
- **Secret triage** that classifies accessible secrets by type (SA tokens, registry creds, TLS certs, SSH keys, opaque)
- **Pod context analysis** for container escape vectors, Linux capabilities, cloud IMDS, and network interfaces
- **kubectl-less mode** for local-only checks when the API server is not reachable from a pod

## Install

Requires a Rust toolchain (`rustup` + stable).

```bash
git clone https://github.com/youruser/kube-reaper.git
cd kube-reaper
cargo build --release
```

The binary is at `target/release/kube-reaper`.

### Static binary (recommended for deployment)

A musl build produces a fully static binary with no dependencies. It works on any Linux x86_64 system.

```bash
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl
```

The binary is at `target/x86_64-unknown-linux-musl/release/kube-reaper` (~5.4 MB).

```bash
# Copy to a Kubernetes node
scp target/x86_64-unknown-linux-musl/release/kube-reaper user@node:/tmp/

# Copy into a running pod
kubectl cp target/x86_64-unknown-linux-musl/release/kube-reaper mynamespace/mypod:/tmp/kube-reaper
```

## Quick Start

```bash
# Scan with current kubeconfig
kube-reaper

# Scan a specific namespace
kube-reaper -n production

# Scan with a stolen SA token
kube-reaper --token <JWT> --server https://10.0.0.1:6443

# Scan as a different user (requires impersonate permissions)
kube-reaper --as-user system:serviceaccount:development:code-server

# Recursive identity pivot (read SA tokens, mint new tokens, map transitive access)
kube-reaper --pivot

# Pivot with custom depth (default: 3)
kube-reaper --pivot --pivot-depth 5

# Show only critical and high findings
kube-reaper -s high

# Output JSON
kube-reaper -o json

# Save JSON report to file
kube-reaper -w results.json
```

## CLI Reference

```
Usage: kube-reaper [OPTIONS]

Options:
  -n, --namespace <NAMESPACE>     Target namespace (default: all accessible)
  -k, --kubeconfig <KUBECONFIG>   Path to kubeconfig file
      --token <TOKEN>             Bearer token (requires --server)
      --server <SERVER>           API server URL (required with --token)
      --as-user <USER>            Impersonate a user
      --as-group <GROUP>          Impersonate a group
      --pivot                     Recursive identity pivot via SA secrets and TokenRequest
      --pivot-depth <N>           Maximum pivot depth [default: 3]
  -o, --output <OUTPUT>           Output format [default: terminal] [values: terminal, json]
  -w, --write <WRITE>             Write JSON results to file
  -s, --severity <SEVERITY>       Minimum severity [default: low] [values: critical, high, medium, low, info]
      --unconventional-only       Show only unconventional RBAC abuses
      --chains-only               Show only attack chains
  -h, --help                      Print help
  -V, --version                   Print version
```

### Authentication

kube-reaper tries these authentication methods in order:

1. **`--token` + `--server`** - Direct bearer token. Use with a stolen SA token or JWT. Accepts self-signed certificates automatically.
2. **`--kubeconfig` / `-k`** - Explicit kubeconfig file. Also reads the `KUBECONFIG` environment variable.
3. **Default** - In-cluster config (inside a pod), then `~/.kube/config`.

`--as-user` and `--as-group` add impersonation headers to any authentication method. Your identity must have the `impersonate` verb for this to work.

## Identity Pivot

The `--pivot` flag enables recursive identity pivoting. This feature discovers transitive attack paths by pivoting through service account credentials.

### How it works

1. kube-reaper analyzes the current identity's permissions per namespace.
2. For each namespace where the identity can read secrets, it reads SA token secrets (`kubernetes.io/service-account-token` type) and extracts the token.
3. For each namespace where the identity can create `serviceaccounts/token` without resource name restrictions, it mints short-lived tokens via the TokenRequest API.
4. For each discovered token, it authenticates as that service account and enumerates its permissions across all known namespaces.
5. If the pivoted identity can also read secrets or mint tokens, the process repeats up to `--pivot-depth` (default: 3).

The scan uses BFS traversal to find the shortest pivot paths first. It stops at 50 identities to prevent runaway scans.

### What appears in the output

Each pivoted identity shows:
- **Severity** based on its dangerous permissions
- **Pivot method** (SecretToken or TokenRequest) and source
- **Dangerous permissions** found on that identity
- **Further pivot capability** (which namespaces it can read secrets or mint tokens in)

### Permission checks

The pivot scanner applies these guards to prevent false positives:

- **API group scoping**: Only rules in the core API group (or `apiGroups: ["*"]`) count for secret read and token creation checks. Rules in non-core groups (e.g., `custom.metrics.k8s.io`) do not match.
- **Resource name restrictions**: Rules with `resourceNames` set do not count for token creation. A rule that permits token creation for one named service account is not the same as unrestricted token creation.
- **Verb wildcard matching**: The "Wildcard on All Resources" pattern requires `verbs: ["*"]`, not just any verb on `resources: ["*"]`.

## Output Sections

The terminal output shows these sections (each appears only when it has findings):

| Section | Content |
|---|---|
| Pod Context Analysis | Escape vectors, capabilities, cloud IMDS, network, SA token, mounts, env vars |
| Attack Path Chains | Multi-step attack paths with step-by-step instructions |
| Identity Pivot Graph | Recursive identity pivot map with methods, permissions, and further pivot capability |
| Dangerous Pods | Privileged containers, host mounts, runtime sockets, exposed secrets |
| Exposed Services | LoadBalancer and NodePort services reachable from outside the cluster |
| Sensitive ConfigMaps | ConfigMaps with keys that contain credentials or secrets |
| CronJobs | Scheduled jobs with dangerous service account permissions |
| Secret Triage | Accessible secrets classified by type and attack value |
| CRD Attack Surface | Custom resources from known dangerous operators |
| Other Identities | Overprivileged identities that are pivot targets |
| Namespace Security | PSS enforcement status per namespace |
| Dangerous Permissions | Individual permission findings by severity |
| Summary | Counts of all finding categories |

## Detailed Documentation

- **[Dangerous Permissions](docs/permissions.md)** - All 55 permission patterns
- **[Attack Chains](docs/chains.md)** - All 16 chain types with exploitation details
- **[CRD Awareness](docs/crds.md)** - All 31 CRD patterns across 10 operator categories
- **[Pod Context Detection](docs/pod-context.md)** - Escape vectors, capabilities, IMDS, network, and kubectl-less mode
- **[Architecture](docs/architecture.md)** - Source layout, module responsibilities, and data flow

## Requirements

- A valid kubeconfig, a bearer token, or in-cluster service account token
- The identity needs `create` on `selfsubjectrulesreviews` at minimum (granted to all authenticated users by default)
- More permissions on the scanning identity = more complete results

| Scan module | Required permissions |
|---|---|
| Permission enumeration | `selfsubjectrulesreviews` (default grant) |
| Namespace listing | `list namespaces` |
| Pod enumeration | `list pods` in target namespaces |
| Secret triage | `list secrets` in target namespaces |
| RBAC graph | `list roles, clusterroles, rolebindings, clusterrolebindings` |
| CRD detection | `list customresourcedefinitions` |
| Identity pivot | `list secrets` or `create serviceaccounts/token` in target namespaces |
| Pod context | No API permissions (reads local filesystem and network) |

If a scan module lacks permissions, it reports that and continues. No module failure stops the scan.

## Disclaimer

kube-reaper is for authorized security testing, penetration testing engagements, and defensive security assessments only. You must get proper authorization before you scan any cluster. Unauthorized access to computer systems is illegal. The authors accept no liability for misuse of this tool.

