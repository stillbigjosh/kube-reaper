# CRD Awareness

kube-reaper detects 31 Custom Resource Definition patterns across 10 operator categories. When a CRD is present in the cluster, kube-reaper checks whether the current identity can access it and reports the attack path.

## How It Works

1. kube-reaper lists all CRDs in the cluster (`list customresourcedefinitions`)
2. Each CRD is matched against the 31 known dangerous patterns by API group and kind
3. For each match, kube-reaper checks your RBAC permissions on that resource
4. Findings include the CRD name, your access level (verbs), severity, and attack path

If the identity cannot list CRDs, this module is skipped.

## Categories

### GitOps (ArgoCD, Flux)

| # | Group | Kind | Severity | Attack Path |
|---|-------|------|----------|-------------|
| 1 | `argoproj.io` | Application | CRITICAL | Create/modify ArgoCD Application to deploy malicious manifests from an attacker-controlled repo. |
| 2 | `argoproj.io` | AppProject | HIGH | Modify AppProject to expand allowed repos/clusters/namespaces and bypass deployment restrictions. |
| 3 | `flux` | Kustomization | CRITICAL | Create/modify Flux Kustomization to point to an attacker repo and deploy arbitrary manifests. |
| 4 | `flux` | HelmRelease | CRITICAL | Create/modify Flux HelmRelease to deploy a malicious Helm chart. |
| 5 | `flux` | GitRepository | HIGH | Modify GitRepository source to point Flux at an attacker-controlled repo. Supply chain compromise. |

### CI/CD (ArgoCD Workflows, Tekton)

| # | Group | Kind | Severity | Attack Path |
|---|-------|------|----------|-------------|
| 6 | `argoproj.io` | Workflow | HIGH | Create Argo Workflow to execute arbitrary containers with a custom SA. |
| 7 | `tekton.dev` | Pipeline | HIGH | Create/modify Tekton Pipeline to execute arbitrary build steps with the pipeline SA. |
| 8 | `tekton.dev` | Task | HIGH | Create Tekton Task to run arbitrary commands in a CI context with access to build secrets. |
| 9 | `tekton.dev` | PipelineRun | HIGH | Create PipelineRun to trigger pipeline execution. |

### Service Mesh (Istio, Calico)

| # | Group | Kind | Severity | Attack Path |
|---|-------|------|----------|-------------|
| 10 | `networking.istio.io` | VirtualService | HIGH | Create/modify VirtualService to redirect service traffic to an attacker pod. MITM. |
| 11 | `networking.istio.io` | Gateway | MEDIUM | Create Gateway to expose internal services externally and bypass network boundaries. |
| 12 | `security.istio.io` | AuthorizationPolicy | HIGH | Modify/delete AuthorizationPolicy to disable mTLS enforcement or access controls. |
| 13 | `security.istio.io` | PeerAuthentication | HIGH | Modify PeerAuthentication to disable mTLS and intercept plaintext service traffic. |
| 14 | `projectcalico.org` | GlobalNetworkPolicy | HIGH | Modify/delete Calico GlobalNetworkPolicy to disable network segmentation cluster-wide. |
| 15 | `crd.projectcalico.org` | GlobalNetworkPolicy | HIGH | Same as above (alternative Calico API group). |
| 16 | `projectcalico.org` | NetworkPolicy | MEDIUM | Modify Calico NetworkPolicy to weaken namespace network isolation. |
| 17 | `crd.projectcalico.org` | NetworkPolicy | MEDIUM | Same as above (alternative Calico API group). |

### Certificate Management (cert-manager, External Secrets)

| # | Group | Kind | Severity | Attack Path |
|---|-------|------|----------|-------------|
| 18 | `cert-manager.io` | Certificate | HIGH | Create Certificate to mint TLS certs signed by the cluster CA. Impersonate services. |
| 19 | `cert-manager.io` | Issuer | CRITICAL | Create/modify Issuer to control certificate signing. Forge any TLS cert in the cluster. |
| 20 | `cert-manager.io` | ClusterIssuer | CRITICAL | Modify ClusterIssuer to control cluster-wide cert issuance. |
| 21 | `external-secrets.io` | SecretStore | CRITICAL | Modify SecretStore to redirect secret fetching to an attacker-controlled vault. |
| 22 | `external-secrets.io` | ExternalSecret | HIGH | Create ExternalSecret to fetch secrets from an external store into K8s. |

### Policy Engines (Kyverno, OPA/Gatekeeper)

| # | Group | Kind | Severity | Attack Path |
|---|-------|------|----------|-------------|
| 23 | `kyverno.io` | ClusterPolicy | CRITICAL | Delete/modify Kyverno ClusterPolicy to disable admission controls. Deploy privileged pods freely. |
| 24 | `kyverno.io` | Policy | HIGH | Delete/modify Kyverno Policy to disable namespace-scoped admission controls. |
| 25 | `constraints.gatekeeper` | (any) | CRITICAL | Delete OPA/Gatekeeper constraints to disable policy enforcement. |
| 26 | `templates.gatekeeper` | ConstraintTemplate | CRITICAL | Modify ConstraintTemplate to weaken OPA policies and bypass admission controls. |

### Infrastructure as Code (Crossplane)

| # | Group | Kind | Severity | Attack Path |
|---|-------|------|----------|-------------|
| 27 | `crossplane.io` | Composition | CRITICAL | Modify Crossplane Composition to alter cloud infrastructure definitions. Pivot to cloud provider. |
| 28 | `crossplane.io` | ProviderConfig | CRITICAL | Read/modify ProviderConfig to access cloud provider credentials. Pivot from K8s to cloud. |

### Security Tools (Falco, Aqua/Trivy)

| # | Group | Kind | Severity | Attack Path |
|---|-------|------|----------|-------------|
| 29 | `falco.org` | FalcoRule | HIGH | Modify FalcoRules to disable runtime detection rules and evade security monitoring. |
| 30 | `aquasecurity` | (any) | HIGH | Modify Aqua/Trivy security policies to disable vulnerability scanning or runtime protection. |

## Access Checking

For each detected CRD, kube-reaper reports which verbs your identity has on that resource. The output shows:

```
[CRITICAL] ClusterIssuer (CertManagement)
  CRD: clusterissuers.cert-manager.io | Group: cert-manager.io
  Access: kubernetes-admin [get, list, watch, create, update, patch, delete]
  Attack: Modify ClusterIssuer -> control cluster-wide cert issuance -> forge certs for any service
```

If you have no access to a detected CRD, it is not shown in the output.
