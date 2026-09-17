# Architecture

kube-reaper has three layers: scanning, analysis, and output. Each layer runs in sequence. The scanner collects cluster state, the analyzer finds dangerous patterns and builds attack chains, and the output layer formats the results.

## Source Layout

```
src/
  main.rs              Entry point, client build, pivot orchestration, kubectl-less fallback
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
    dns_discovery.rs   CoreDNS service discovery (raw UDP queries, no RBAC needed)
    admission.rs       Admission controller probing (dry-run pod creates per namespace)
    pod_context.rs     In-pod checks (escape vectors, capabilities, IMDS, network, SA token, mounts, env vars)
    pivot.rs           Recursive identity pivoting (SA token secrets, TokenRequest, BFS traversal)
  analyzer/
    mod.rs             Analysis control, all finding types, false positive suppression
    patterns.rs        55 dangerous permission definitions
    chains.rs          18 chain types, chain deduplication
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
| `dns_discovery.rs` | Does not use the API. Reads `/etc/resolv.conf` for the cluster DNS server, then sends raw UDP A-record queries for 48 common service names across all known namespaces. Returns discovered services with ClusterIPs. Only runs inside a pod. |
| `admission.rs` | Sends dry-run pod creates (`PostParams { dry_run: true }`) to test admission controller enforcement per namespace. Probes 6 configurations: privileged, hostPID, hostNetwork, hostPath, CAP_SYS_ADMIN, runAsRoot. No pods are created. Requires `create pods` in the target namespace. |
| `pod_context.rs` | Does not use the API. Checks escape vectors, Linux capabilities, cloud IMDS, network interfaces and ports, SA token, mounts, and env vars. |
| `pivot.rs` | Recursive identity pivot via SA token secrets and TokenRequest API. See [Pivot Scanner](#pivot-scanner). |

## Pivot Scanner

The pivot scanner (`pivot.rs`) discovers transitive attack paths by pivoting through service account credentials. It runs after the main scan completes, only when the `--pivot` flag is set.

### Traversal

The scanner uses BFS (breadth-first search) to find the shortest pivot paths first. Each identity in the queue is processed in this order:

1. **Analyze permissions**: Check which namespaces this identity can read secrets in and which namespaces it can create tokens in.
2. **Read SA token secrets**: For each namespace where the identity can read secrets, list all secrets of type `kubernetes.io/service-account-token`. Extract the token from `.data.token` and the SA name from the `kubernetes.io/service-account.name` annotation.
3. **Mint tokens via TokenRequest**: For each namespace where the identity can create `serviceaccounts/token` without resource name restrictions, list all service accounts and mint a short-lived token (3600 seconds) for each one.
4. **Enumerate pivoted permissions**: For each discovered token, build a new API client and run `SelfSubjectRulesReview` in all known namespaces.
5. **Recurse**: If the pivoted identity can also read secrets or mint tokens, add it to the BFS queue for the next depth level.

### Limits

- **Maximum identities**: 50. The scanner stops when this cap is reached.
- **Maximum depth**: Set by `--pivot-depth` (default: 3). The scanner does not add identities at the maximum depth to the queue.

### False positive guards

The pivot scanner applies these checks to prevent false positives in capability detection and dangerous permission labeling:

**API group scoping**: The `can_read_secrets` and `can_create_tokens` checks require the rule to be in the core API group (`""`) or a wildcard group (`"*"`). Rules in non-core groups (e.g., `custom.metrics.k8s.io`) do not match. This prevents identities like `horizontal-pod-autoscaler` from being falsely flagged for secret read access when their wildcard resource permission applies only to custom metrics.

**Resource name restrictions**: The `can_create_tokens` check requires `resource_names` to be empty. A rule that permits token creation for one named service account (e.g., `resource_names: [calico-cni-plugin]`) is not the same as unrestricted token creation. The scanner also skips dangerous permission label matching for rules with non-empty `resource_names` when the pattern targets a specific resource.

**Verb wildcard matching**: The `permission_matches` function treats a pattern with `verbs: ["*"]` as a requirement for the rule's verb to also be `"*"`. It does not match any verb. This prevents identities with `resources: ["*"]` and verbs like `[get, list]` from matching the "Wildcard on All Resources" pattern, which is for true `verbs: ["*"]` (cluster-admin equivalent) access.

### Output

The pivot graph appears in the terminal output between attack chains and dangerous pods. Each pivot node shows:

- Severity (based on dangerous permissions found on that identity)
- Pivot method (`SecretToken` with secret name, or `TokenRequest` with SA name)
- Source identity that pivoted to this one
- Dangerous permission labels (up to 5, with overflow count)
- Further pivot capability (namespaces where this identity can read secrets or mint tokens)

### Data types

```
PivotGraph
  root_identity: String
  nodes: Vec<PivotNode>
  edges: Vec<PivotEdge>
  max_depth_reached: u32

PivotNode
  identity: String
  depth: u32
  dangerous_permissions: Vec<String>
  accessible_namespaces: Vec<String>
  can_read_secrets_in: Vec<String>
  can_create_tokens_in: Vec<String>
  severity: Severity

PivotEdge
  from_identity: String
  to_identity: String
  method: PivotMethod (SecretToken | TokenRequest)
  via: String
  namespace: String
  depth: u32
```

## Analyzer Layer

The analyzer takes `ScanData` and produces findings, chains, and enriched identity profiles.

| Module | What it produces |
|---|---|
| `patterns.rs` | 55 dangerous permission definitions with severity, resource, verbs, and attack path |
| `chains.rs` | 18 chain types that link permissions into multi-step escalation paths |
| `mod.rs` | Permission matching with namespace-aware false positive suppression. Analyzes pods, CRDs, secrets, identities, services, ConfigMaps, CronJobs, and pod context. |

### False Positive Suppression

The analyzer applies context-aware filters during permission matching:

- **Create Pods (No PSS)**: suppressed when the namespace has PSS enforcement
- **Modify ConfigMaps (kube-system)**: suppressed when the namespace is not kube-system
- **Services + Endpoints**: suppressed when the identity lacks endpoints create/update/patch in that namespace
- **Resource name restrictions**: dangerous permission labels are suppressed when the rule has non-empty `resource_names` and the pattern targets a specific resource
- **Verb wildcard matching**: the "Wildcard on All Resources" pattern requires the rule's verb to be `"*"`, not just any verb on `resources: ["*"]`
- **Escape vectors**: `is_writable()` checks the effective UID/GID against file ownership. It does not use permission bits only.
- **Sensitive ConfigMaps**: suppressed when no data keys match the sensitive pattern list
- **Multiple network interfaces**: CNI interfaces (cali*, tunl*, vxlan*, flannel*, veth*, etc.) are removed before the count
- **ALL CAPABILITIES**: when all capabilities are set, the tool reports one entry instead of each capability separately

### Chain Building

Each chain type checks specific permission combinations and namespace security state. Chains are scoped to the identity's namespace, not all namespaces. Chains are deduplicated by type and target.

## Output Layer

| Module | Format |
|---|---|
| `terminal.rs` | Colored, boxed terminal output grouped by section. Sections only appear when they have findings. Includes pivot graph rendering. |
| `json.rs` | Full results as a JSON object. Supports stdout (`-o json`) and file output (`-w`). Includes pivot graph when `--pivot` is set. |

## Data Flow

```
main.rs
  -> detect pod context (filesystem/network only, no API)
  -> construct kube client (kubeconfig / token / in-cluster)
     |
     +-- client OK -> scanner::run_scan() -> ScanData (full scan)
     |                  |
     |                  +-- in pod -> dns_discovery (raw UDP to CoreDNS, no API)
     |                  |
     |                  +-- admission probing (dry-run pod creates per namespace)
     |                  |
     |                  +-- --pivot flag set -> pivot::run_pivot()
     |                  |     BFS: read SA secrets, mint tokens,
     |                  |     enumerate permissions per pivoted identity
     |                  |     -> PivotGraph added to ScanData
     |                  |
     |                  +-- no --pivot -> ScanData without pivot graph
     |
     +-- client FAIL + in pod -> ScanData with pod_context only (kubectl-less mode)
     |
     +-- client FAIL + not in pod -> error exit
     |
  -> analyzer::analyze(ScanData) -> ScanResults
  -> output::terminal or output::json
```

Pod context detection runs first, before the API client is built. Escape vectors, capabilities, cloud IMDS, and network checks work without API access.

DNS discovery runs only inside a pod. It reads `/etc/resolv.conf` for the cluster DNS server and sends raw UDP queries. It does not use the Kubernetes API.

Admission probing runs for every namespace where the identity can create pods. It uses dry-run requests, so no pods are created. Namespaces where RBAC blocks pod creation are skipped.

If the kube client fails inside a pod, kube-reaper uses kubectl-less mode and reports only pod context results. If the client fails outside a pod, the tool exits with an error.

The client build uses three auth modes in order: `--token`/`--server`, `--kubeconfig`, then default. Impersonation headers (`--as-user`, `--as-group`) apply on top of any auth mode.
