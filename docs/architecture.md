# Architecture

kube-reaper has three layers: scanning, analysis, and output. Each layer runs in sequence. The scanner collects cluster state, the analyzer finds dangerous patterns and builds attack chains, and the output layer formats the results.

## Source Layout

```
src/
  main.rs              Entry point, client construction, auth modes
  cli.rs               CLI argument parsing (clap derive)
  scanner/
    mod.rs             Scan orchestration, ScanData types
    rbac.rs            Identity detection, namespace permission enumeration
    rbac_graph.rs      Full RBAC graph (roles, bindings, identities)
    namespace.rs       Namespace enumeration with PSS label parsing
    pods.rs            Pod enumeration with security context extraction
    secrets.rs         Secret enumeration (types and metadata only)
    crds.rs            CRD enumeration and threat classification
    pod_context.rs     In-pod detection (SA token, mounts, env vars)
  analyzer/
    mod.rs             Analysis orchestration, pod/CRD/identity/secret analysis
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
| `crds.rs` | CRD definitions from the API server |
| `pod_context.rs` | Local filesystem: SA token, mounts, env vars (no API calls) |

## Analyzer Layer

The analyzer takes `ScanData` and produces findings, chains, and enriched identity profiles.

| Module | What it produces |
|---|---|
| `patterns.rs` | 55 dangerous permission definitions with severity, resource, verbs, and attack path |
| `chains.rs` | 12 chain types that link permissions into multi-step escalation paths |
| `mod.rs` | Permission matching with namespace-aware false positive suppression, pod analysis, CRD classification, secret triage, identity profiling |

### False Positive Suppression

The analyzer applies context-aware filters during permission matching:

- **Create Pods (No PSS)**: suppressed when the namespace has PSS enforcement
- **Modify ConfigMaps (kube-system)**: suppressed when the namespace is not kube-system
- **Services + Endpoints**: suppressed when the identity lacks endpoints create/update/patch in that namespace

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
  -> construct kube client (kubeconfig / token / in-cluster)
  -> scanner::run_scan() -> ScanData
  -> analyzer::analyze(ScanData) -> AnalysisResults
  -> output::terminal or output::json
```

The client construction in `main.rs` handles three auth modes in priority order: `--token`/`--server`, `--kubeconfig`, then default inference. Impersonation headers (`--as-user`, `--as-group`) are applied on top of any auth mode.
