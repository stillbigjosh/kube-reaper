# Architecture

kube-reaper has three layers: scanning, analysis, and output. Each layer runs in sequence. The scanner collects cluster state, the analyzer finds dangerous patterns and builds attack chains, and the output layer formats the results.

## Source Layout

```
src/
  main.rs              Entry point, client build, kubectl-less fallback
  cli.rs               CLI argument parsing (clap derive)
  scanner/
    mod.rs             Scan orchestration, ScanData types
    rbac.rs            Identity detection, namespace permission enumeration
    rbac_graph.rs      Full RBAC graph (roles, bindings, identities)
    namespace.rs       Namespace enumeration with PSS label parsing
    pods.rs            Pod enumeration with security context extraction
    secrets.rs         Secret enumeration (types and metadata only)
    services.rs        Service scan (type, ports, nodePort)
    configmaps.rs      ConfigMap scan with sensitive key detection
    cronjobs.rs        CronJob scan (schedule, SA, image)
    crds.rs            CRD enumeration and threat classification
    pod_context.rs     In-pod checks (escape vectors, capabilities, IMDS, network, SA token, mounts, env vars)
  analyzer/
    mod.rs             Analysis control, all finding types, false positive suppression
    patterns.rs        55 dangerous permission definitions
    chains.rs          12 chain builder types, chain deduplication
  output/
    terminal.rs        Colored terminal output (PEASS-style)
    json.rs            JSON serialization and file output
```

## Scanner Layer

The scanner runs API calls and local filesystem checks to collect raw cluster state into a `ScanData` struct. Each scanner module is independent and fails gracefully if it lacks permissions.

| Module | What it collects |
|---|---|
| `rbac.rs` | Current identity, `SelfSubjectRulesReview` per namespace |
| `rbac_graph.rs` | All Roles, ClusterRoles, RoleBindings, ClusterRoleBindings |
| `namespace.rs` | Namespace list with PSS enforcement labels |
| `pods.rs` | Running pods with security contexts, volumes, SA references |
| `secrets.rs` | Secret metadata and types (not values) |
| `services.rs` | Service type, ports, clusterIP, and nodePort |
| `configmaps.rs` | ConfigMap names and data keys. Marks keys that match sensitive patterns. |
| `cronjobs.rs` | CronJob schedule, service account, image, and suspended state |
| `crds.rs` | CRD definitions from the API server |
| `pod_context.rs` | Does not use the API. Checks escape vectors, Linux capabilities, cloud IMDS, network interfaces and ports, SA token, mounts, and env vars. |

## Analyzer Layer

The analyzer takes `ScanData` and produces findings, chains, and enriched identity profiles.

| Module | What it produces |
|---|---|
| `patterns.rs` | 55 dangerous permission definitions with severity, resource, verbs, and attack path |
| `chains.rs` | 12 chain types that link permissions into multi-step escalation paths |
| `mod.rs` | Permission matching with namespace-aware false positive suppression. Analyzes pods, CRDs, secrets, identities, services, ConfigMaps, CronJobs, and pod context (escape vectors, capabilities, IMDS, network). |

### False Positive Suppression

The analyzer applies context-aware filters during permission matching:

- **Create Pods (No PSS)**: suppressed when the namespace has PSS enforcement
- **Modify ConfigMaps (kube-system)**: suppressed when the namespace is not kube-system
- **Services + Endpoints**: suppressed when the identity lacks endpoints create/update/patch in that namespace
- **Escape vectors**: `is_writable()` checks the effective UID/GID against file ownership. It does not use permission bits only.
- **Sensitive ConfigMaps**: suppressed when no data keys match the sensitive pattern list. Name-only matches are not reported.
- **Multiple network interfaces**: CNI interfaces (cali*, tunl*, vxlan*, flannel*, veth*, etc.) are removed before the count.
- **ALL CAPABILITIES**: when all capabilities are set, the tool reports one "ALL CAPABILITIES" entry. It does not list each capability separately.

### Chain Building

Each chain type checks specific permission combinations and namespace security state. Chains are scoped to the identity's namespace (where its permissions actually apply), not all namespaces in the cluster. Chains are deduplicated by type and target.

## Output Layer

| Module | Format |
|---|---|
| `terminal.rs` | Colored, boxed terminal output grouped by section. Sections only appear when they have findings. |
| `json.rs` | Full results as a JSON object. Supports stdout (`-o json`) and file output (`-w`). |

## Data Flow

```
main.rs
  -> detect pod context (filesystem/network only, no API)
  -> construct kube client (kubeconfig / token / in-cluster)
     |
     +-- client OK -> scanner::run_scan() -> ScanData (full scan)
     |
     +-- client FAIL + in pod -> ScanData with pod_context only (kubectl-less mode)
     |
     +-- client FAIL + not in pod -> error exit
     |
  -> analyzer::analyze(ScanData) -> ScanResults
  -> output::terminal or output::json
```

Pod context detection runs first, before the tool builds the API client. Escape vectors, capabilities, cloud IMDS, and network checks work even when the pod has no API access.

If the kube client fails and the binary runs inside a pod, kube-reaper uses kubectl-less mode. In this mode it reports only pod context results (escape vectors, capabilities, IMDS, network). If the client fails outside a pod, the tool exits with an error.

The client build uses three auth modes in this order: `--token`/`--server`, `--kubeconfig`, then default. The tool applies impersonation headers (`--as-user`, `--as-group`) on top of any auth mode.
