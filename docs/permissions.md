# Dangerous Permission Patterns

kube-reaper checks 55 permission patterns. Each pattern has a severity, attack path, and list of capabilities it enables.

Patterns marked **[U]** are unconventional. Most RBAC scanners do not check for them.

## CRITICAL

These permissions give direct paths to cluster takeover.

| # | Pattern | Resource | Verbs | Attack Path |
|---|---------|----------|-------|-------------|
| 1 | Wildcard on All Resources | `*` | `*` | Direct cluster-admin equivalent. Do anything. |
| 2 | Create/Modify ClusterRoleBindings | `clusterrolebindings` | `create, update, patch` | Create a ClusterRoleBinding that binds cluster-admin to your SA. |
| 3 | Create/Modify RoleBindings | `rolebindings` | `create, update, patch` | Create a RoleBinding that references a ClusterRole with broad permissions. |
| 4 | **[U]** Escalate Verb on Roles | `roles` | `escalate` | Modify an existing Role to add any permission, then bind it to yourself. |
| 5 | **[U]** Escalate Verb on ClusterRoles | `clusterroles` | `escalate` | Modify a ClusterRole to add wildcard permissions. Instant cluster-admin. |
| 6 | **[U]** Bind Verb on Roles | `roles` | `bind` | Bind a pre-existing powerful Role to your SA without needing those permissions yourself. |
| 7 | **[U]** Bind Verb on ClusterRoles | `clusterroles` | `bind` | Bind cluster-admin to your SA without needing cluster-admin yourself. |
| 8 | **[U]** Impersonate Users | `users` | `impersonate` | `kubectl --as=system:admin` to act as cluster admin. |
| 9 | **[U]** Impersonate Groups | `groups` | `impersonate` | `kubectl --as-group=system:masters` to act as the cluster admin group. |
| 10 | **[U]** Impersonate Service Accounts | `serviceaccounts` | `impersonate` | `kubectl --as=system:serviceaccount:kube-system:default` to act as any SA. |
| 11 | Create Pods (No PSS) | `pods` | `create` | Deploy a privileged pod with hostPID + hostNetwork + hostPath:/ then chroot /mnt for node root. |
| 12 | **[U]** Create Token Requests | `serviceaccounts/token` | `create` | Mint a token for a privileged SA, then authenticate as that SA. |
| 13 | **[U]** Approve CSRs | `certificatesigningrequests/approval` | `update` | Create a CSR for the system:masters group, approve it, then use the cert as cluster-admin. |

## HIGH

These permissions enable lateral movement and credential access.

| # | Pattern | Resource | Verbs | Attack Path |
|---|---------|----------|-------|-------------|
| 14 | **[U]** Create CSRs | `certificatesigningrequests` | `create` | Submit a CSR with O=system:masters. If auto-approved or you can approve, you get a cluster-admin cert. |
| 15 | Create Pods/Exec | `pods/exec` | `create` | `kubectl exec` into a pod, read the mounted SA token, then pivot to a new identity. |
| 16 | Read Secrets | `secrets` | `get, list` | List secrets, find SA token secrets, then authenticate as those SAs. |
| 17 | **[U]** Create Pods/Attach | `pods/attach` | `create` | Attach to a privileged pod, interact with its process, then inherit the SA. |
| 18 | **[U]** Create Ephemeral Containers | `pods/ephemeralcontainers` | `create, update, patch` | Inject an ephemeral container into a privileged pod. Code execution without pod restart. |
| 19 | Create DaemonSets | `daemonsets` | `create` | Deploy a DaemonSet with a privileged pod spec. Instant root on all nodes. |
| 20 | Create Deployments | `deployments` | `create` | Deploy a Deployment with a privileged pod template and your C2 payload. |
| 21 | **[U]** Create CronJobs | `cronjobs` | `create` | Create a CronJob that runs every minute with your payload. Survives pod deletion. |
| 22 | **[U]** Create Jobs | `jobs` | `create` | Create a Job with a privileged pod spec. One-shot code execution with a different audit trail. |
| 23 | Patch/Update Pods | `pods` | `patch, update` | Patch a pod to add a privileged container or modify securityContext. |
| 24 | Create Port Forwards | `pods/portforward` | `create` | Port-forward to internal dashboards, databases, and admin UIs. |
| 25 | **[U]** Patch Service Accounts | `serviceaccounts` | `patch, update` | Patch a privileged SA to add your own secret, then mount that secret in a new pod. |
| 26 | **[U]** Create/Modify Services | `services` | `create, update, patch` | Create/modify a Service + Endpoints to redirect traffic to your pod. |
| 27 | **[U]** Create/Modify Endpoints | `endpoints` | `create, update, patch` | Modify endpoints for an existing service to redirect traffic to your pod. MITM. |
| 28 | **[U]** Create/Modify EndpointSlices | `endpointslices` | `create, update, patch` | Create/modify EndpointSlice to redirect service traffic to your pod. |
| 29 | Create Pods (With SA Spec) | `pods` | `create` | Create a pod with serviceAccountName set to a privileged SA. Inherit its RBAC permissions. |

## MEDIUM

These permissions enable bypass, persistence, and information disclosure.

| # | Pattern | Resource | Verbs | Attack Path |
|---|---------|----------|-------|-------------|
| 30 | **[U]** Create/Modify Mutating Webhooks | `mutatingwebhookconfigurations` | `create, update, patch` | Register a MutatingWebhookConfiguration that injects a sidecar into every new pod cluster-wide. |
| 31 | **[U]** Create/Modify Validating Webhooks | `validatingwebhookconfigurations` | `create, update, patch` | Register a ValidatingWebhookConfiguration that points to your server. See all API requests. |
| 32 | **[U]** Modify ValidatingAdmissionPolicies | `validatingadmissionpolicies` | `delete, update, patch` | Delete or weaken ValidatingAdmissionPolicies to bypass security controls. |
| 33 | **[U]** Patch/Update Namespaces | `namespaces` | `patch, update` | Remove the pod-security.kubernetes.io/enforce label. The namespace then accepts privileged pods. |
| 34 | **[U]** Create PersistentVolumes | `persistentvolumes` | `create` | Create a PV with hostPath:/, create a PVC that claims it, then mount in your pod. |
| 35 | **[U]** Create PersistentVolumeClaims | `persistentvolumeclaims` | `create` | Create a PVC that matches an existing PV. Mount it to read data from other workloads. |
| 36 | **[U]** Delete NetworkPolicies | `networkpolicies` | `delete` | Delete NetworkPolicies so pods can communicate freely across namespace boundaries. |
| 37 | **[U]** Create/Modify NetworkPolicies | `networkpolicies` | `create, update, patch` | Create a permissive NetworkPolicy that allows ingress/egress to your attacker pod. |
| 38 | **[U]** Read Pod Logs | `pods/log` | `get` | Read logs of all accessible pods. Grep for passwords, tokens, and API keys. |
| 39 | **[U]** Access Node Proxy | `nodes/proxy` | `create, get` | Use node proxy to reach Kubelet API (10250) through the API server. |
| 40 | **[U]** Modify ConfigMaps (kube-system) | `configmaps` | `update, patch, delete` | Modify the coredns configmap for DNS poisoning. Modify kube-proxy for traffic manipulation. |
| 41 | Create/Modify Roles | `roles` | `create, update, patch` | Create a Role with broad permissions, then create a RoleBinding to your SA. |
| 42 | Create/Modify ClusterRoles | `clusterroles` | `create, update, patch` | Create a ClusterRole with * permissions, then bind it to your SA. |
| 43 | **[U]** Create StatefulSets | `statefulsets` | `create` | Create a StatefulSet with a privileged pod template. Persistent workload with stable network identity. |
| 44 | **[U]** Create ReplicaSets | `replicasets` | `create` | Create a ReplicaSet directly. Deploy pods without a Deployment audit trail. |
| 45 | Read ConfigMaps | `configmaps` | `get, list` | List ConfigMaps. Find kubeconfig templates, connection strings, and API keys stored as config. |
| 46 | **[U]** Delete ClusterRoleBindings | `clusterrolebindings` | `delete` | Delete security-critical bindings. Disable monitoring SAs, break OPA/Gatekeeper, disrupt RBAC enforcement. |

## LOW

These permissions enable reconnaissance and disruption.

| # | Pattern | Resource | Verbs | Attack Path |
|---|---------|----------|-------|-------------|
| 47 | Read Node Information | `nodes` | `get, list` | List nodes to map cluster topology. Identify node IPs for direct Kubelet API probing. |
| 48 | **[U]** Patch/Update Nodes | `nodes` | `patch, update` | Taint all nodes except one. Force all new pods to schedule on your compromised node. |
| 49 | Delete Pods | `pods` | `delete` | Delete a pod so the controller recreates it. Intercept during startup (mount injection, env var capture). |
| 50 | **[U]** Create Events | `events` | `create` | Create misleading events to confuse SOC/monitoring and mask real attack activity. |
| 51 | **[U]** Manipulate Leases | `leases` | `delete, update, patch` | Delete/modify lease objects to force leader re-election. Can cause split-brain in controllers. |
| 52 | **[U]** Create/Modify ResourceQuotas | `resourcequotas` | `create, update, patch` | Set extremely low quotas so legitimate pods cannot be created. Denial of service. |
| 53 | **[U]** Create/Modify LimitRanges | `limitranges` | `create, update, patch` | Set extremely low limit ranges so new pods get minimal resources. Performance denial of service. |
| 54 | **[U]** Create PriorityClasses | `priorityclasses` | `create` | Create a PriorityClass with max priority. Deploy your pods with it to evict legitimate workloads. |

## Pattern #55

Pattern 55 is a composite: it checks for `selfsubjectaccessreviews`, `selfsubjectrulesreviews`, and `selfsubjectreviews`. These are default grants to all authenticated users and are excluded from findings.

## Capabilities

Each permission pattern maps to one or more attack capabilities:

| Capability | Description |
|---|---|
| Node Breakout | Escape from pod to node root |
| Cluster Admin Takeover | Gain full cluster-admin access |
| Credential Harvest | Extract tokens, passwords, keys, or certificates |
| Code Execution | Run arbitrary code inside the cluster |
| Persistent Backdoor | Maintain access that survives pod deletion |
| Lateral Movement | Pivot to a different identity or namespace |
| Privilege Escalation | Gain permissions beyond current level |
| Traffic Interception | Redirect or intercept cluster network traffic |
| Admission Bypass | Disable or bypass admission controllers |
| Information Disclosure | Read sensitive data not intended for this identity |
| Denial of Service | Disrupt legitimate workloads |
| Log Injection | Insert fake events to confuse monitoring |
| Network Bypass | Remove or circumvent network segmentation |
| Identity Forge | Create or mint new identities (tokens, certs) |
