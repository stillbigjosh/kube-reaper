use anyhow::Result;
use k8s_openapi::apiextensions_apiserver::pkg::apis::apiextensions::v1::CustomResourceDefinition;
use kube::api::{Api, ListParams};
use kube::Client;

#[derive(Debug, Clone)]
pub struct CrdInfo {
    pub name: String,
    pub group: String,
    pub kind: String,
    pub scope: String,
    pub category: CrdCategory,
}

#[derive(Debug, Clone, PartialEq)]
pub enum CrdCategory {
    GitOps,
    ServiceMesh,
    CertManagement,
    PolicyEngine,
    CiCd,
    SecurityTool,
    InfraAsCode,
    Other,
}

impl CrdCategory {
    pub fn label(&self) -> &'static str {
        match self {
            CrdCategory::GitOps => "GitOps",
            CrdCategory::ServiceMesh => "Service Mesh",
            CrdCategory::CertManagement => "Cert Management",
            CrdCategory::PolicyEngine => "Policy Engine",
            CrdCategory::CiCd => "CI/CD",
            CrdCategory::SecurityTool => "Security Tool",
            CrdCategory::InfraAsCode => "Infrastructure-as-Code",
            CrdCategory::Other => "Other",
        }
    }
}

struct DangerousCrd {
    group_contains: &'static str,
    kind_contains: &'static str,
    category: CrdCategory,
    severity: &'static str,
    attack_path: &'static str,
}

const DANGEROUS_CRDS: &[DangerousCrd] = &[
    DangerousCrd {
        group_contains: "argoproj.io",
        kind_contains: "Application",
        category: CrdCategory::GitOps,
        severity: "CRITICAL",
        attack_path: "Create/modify ArgoCD Application -> deploy malicious manifests from attacker-controlled repo -> cluster-wide code execution",
    },
    DangerousCrd {
        group_contains: "argoproj.io",
        kind_contains: "AppProject",
        category: CrdCategory::GitOps,
        severity: "HIGH",
        attack_path: "Modify AppProject -> expand allowed repos/clusters/namespaces -> bypass deployment restrictions",
    },
    DangerousCrd {
        group_contains: "argoproj.io",
        kind_contains: "Workflow",
        category: CrdCategory::CiCd,
        severity: "HIGH",
        attack_path: "Create Argo Workflow -> execute arbitrary containers with custom SA -> code execution and credential access",
    },
    DangerousCrd {
        group_contains: "flux",
        kind_contains: "Kustomization",
        category: CrdCategory::GitOps,
        severity: "CRITICAL",
        attack_path: "Create/modify Flux Kustomization -> point to attacker repo -> deploy arbitrary manifests",
    },
    DangerousCrd {
        group_contains: "flux",
        kind_contains: "HelmRelease",
        category: CrdCategory::GitOps,
        severity: "CRITICAL",
        attack_path: "Create/modify Flux HelmRelease -> deploy malicious Helm chart -> cluster-wide code execution",
    },
    DangerousCrd {
        group_contains: "flux",
        kind_contains: "GitRepository",
        category: CrdCategory::GitOps,
        severity: "HIGH",
        attack_path: "Modify GitRepository source -> point Flux at attacker-controlled repo -> supply chain compromise",
    },
    DangerousCrd {
        group_contains: "networking.istio.io",
        kind_contains: "VirtualService",
        category: CrdCategory::ServiceMesh,
        severity: "HIGH",
        attack_path: "Create/modify VirtualService -> redirect service traffic to attacker pod -> man-in-the-middle",
    },
    DangerousCrd {
        group_contains: "networking.istio.io",
        kind_contains: "Gateway",
        category: CrdCategory::ServiceMesh,
        severity: "MEDIUM",
        attack_path: "Create Gateway -> expose internal services externally -> bypass network boundaries",
    },
    DangerousCrd {
        group_contains: "security.istio.io",
        kind_contains: "AuthorizationPolicy",
        category: CrdCategory::ServiceMesh,
        severity: "HIGH",
        attack_path: "Modify/delete AuthorizationPolicy -> disable mTLS enforcement or access controls between services",
    },
    DangerousCrd {
        group_contains: "security.istio.io",
        kind_contains: "PeerAuthentication",
        category: CrdCategory::ServiceMesh,
        severity: "HIGH",
        attack_path: "Modify PeerAuthentication -> disable mTLS -> intercept plaintext service traffic",
    },
    DangerousCrd {
        group_contains: "cert-manager.io",
        kind_contains: "Certificate",
        category: CrdCategory::CertManagement,
        severity: "HIGH",
        attack_path: "Create Certificate -> mint TLS certs signed by cluster CA -> impersonate services",
    },
    DangerousCrd {
        group_contains: "cert-manager.io",
        kind_contains: "Issuer",
        category: CrdCategory::CertManagement,
        severity: "CRITICAL",
        attack_path: "Create/modify Issuer/ClusterIssuer -> control certificate signing -> forge any TLS cert in the cluster",
    },
    DangerousCrd {
        group_contains: "cert-manager.io",
        kind_contains: "ClusterIssuer",
        category: CrdCategory::CertManagement,
        severity: "CRITICAL",
        attack_path: "Modify ClusterIssuer -> control cluster-wide cert issuance -> forge certs for any service",
    },
    DangerousCrd {
        group_contains: "kyverno.io",
        kind_contains: "ClusterPolicy",
        category: CrdCategory::PolicyEngine,
        severity: "CRITICAL",
        attack_path: "Delete/modify Kyverno ClusterPolicy -> disable admission controls -> deploy privileged pods freely",
    },
    DangerousCrd {
        group_contains: "kyverno.io",
        kind_contains: "Policy",
        category: CrdCategory::PolicyEngine,
        severity: "HIGH",
        attack_path: "Delete/modify Kyverno Policy -> disable namespace-scoped admission controls",
    },
    DangerousCrd {
        group_contains: "constraints.gatekeeper",
        kind_contains: "",
        category: CrdCategory::PolicyEngine,
        severity: "CRITICAL",
        attack_path: "Delete OPA/Gatekeeper constraints -> disable policy enforcement -> bypass security guardrails",
    },
    DangerousCrd {
        group_contains: "templates.gatekeeper",
        kind_contains: "ConstraintTemplate",
        category: CrdCategory::PolicyEngine,
        severity: "CRITICAL",
        attack_path: "Modify ConstraintTemplate -> weaken OPA policies -> bypass admission controls",
    },
    DangerousCrd {
        group_contains: "tekton.dev",
        kind_contains: "Pipeline",
        category: CrdCategory::CiCd,
        severity: "HIGH",
        attack_path: "Create/modify Tekton Pipeline -> execute arbitrary build steps with pipeline SA -> code execution and secret access",
    },
    DangerousCrd {
        group_contains: "tekton.dev",
        kind_contains: "Task",
        category: CrdCategory::CiCd,
        severity: "HIGH",
        attack_path: "Create Tekton Task -> run arbitrary commands in CI context -> access build secrets and source code",
    },
    DangerousCrd {
        group_contains: "tekton.dev",
        kind_contains: "PipelineRun",
        category: CrdCategory::CiCd,
        severity: "HIGH",
        attack_path: "Create PipelineRun -> trigger pipeline execution -> code execution via CI/CD",
    },
    DangerousCrd {
        group_contains: "crossplane.io",
        kind_contains: "Composition",
        category: CrdCategory::InfraAsCode,
        severity: "CRITICAL",
        attack_path: "Modify Crossplane Composition -> alter cloud infrastructure definitions -> pivot to cloud provider",
    },
    DangerousCrd {
        group_contains: "crossplane.io",
        kind_contains: "ProviderConfig",
        category: CrdCategory::InfraAsCode,
        severity: "CRITICAL",
        attack_path: "Read/modify ProviderConfig -> access cloud provider credentials -> pivot from K8s to cloud",
    },
    DangerousCrd {
        group_contains: "external-secrets.io",
        kind_contains: "SecretStore",
        category: CrdCategory::CertManagement,
        severity: "CRITICAL",
        attack_path: "Modify SecretStore -> redirect secret fetching to attacker-controlled vault -> credential interception",
    },
    DangerousCrd {
        group_contains: "external-secrets.io",
        kind_contains: "ExternalSecret",
        category: CrdCategory::CertManagement,
        severity: "HIGH",
        attack_path: "Create ExternalSecret -> fetch secrets from external store into K8s -> credential access",
    },
    DangerousCrd {
        group_contains: "falco.org",
        kind_contains: "FalcoRule",
        category: CrdCategory::SecurityTool,
        severity: "HIGH",
        attack_path: "Modify FalcoRules -> disable runtime detection rules -> evade security monitoring",
    },
    DangerousCrd {
        group_contains: "aquasecurity",
        kind_contains: "",
        category: CrdCategory::SecurityTool,
        severity: "HIGH",
        attack_path: "Modify Aqua/Trivy security policies -> disable vulnerability scanning or runtime protection",
    },
    DangerousCrd {
        group_contains: "projectcalico.org",
        kind_contains: "GlobalNetworkPolicy",
        category: CrdCategory::ServiceMesh,
        severity: "HIGH",
        attack_path: "Modify/delete Calico GlobalNetworkPolicy -> disable network segmentation cluster-wide",
    },
    DangerousCrd {
        group_contains: "crd.projectcalico.org",
        kind_contains: "GlobalNetworkPolicy",
        category: CrdCategory::ServiceMesh,
        severity: "HIGH",
        attack_path: "Modify/delete Calico GlobalNetworkPolicy -> disable network segmentation cluster-wide",
    },
    DangerousCrd {
        group_contains: "projectcalico.org",
        kind_contains: "NetworkPolicy",
        category: CrdCategory::ServiceMesh,
        severity: "MEDIUM",
        attack_path: "Modify Calico NetworkPolicy -> weaken namespace network isolation",
    },
    DangerousCrd {
        group_contains: "crd.projectcalico.org",
        kind_contains: "NetworkPolicy",
        category: CrdCategory::ServiceMesh,
        severity: "MEDIUM",
        attack_path: "Modify Calico NetworkPolicy -> weaken namespace network isolation",
    },
];

pub fn classify_crd(group: &str, kind: &str) -> Option<&'static DangerousCrd> {
    DANGEROUS_CRDS.iter().find(|d| {
        group.contains(d.group_contains)
            && (d.kind_contains.is_empty() || kind.contains(d.kind_contains))
    })
}

#[derive(Debug, Clone)]
pub struct CrdFinding {
    pub crd_name: String,
    pub group: String,
    pub kind: String,
    pub category: String,
    pub severity: String,
    pub attack_path: String,
    pub identity_has_access: Vec<CrdAccess>,
}

#[derive(Debug, Clone)]
pub struct CrdAccess {
    pub identity: String,
    pub verbs: Vec<String>,
    pub namespace: Option<String>,
}

pub async fn enumerate_crds(client: &Client) -> Result<Vec<CrdInfo>> {
    let api: Api<CustomResourceDefinition> = Api::all(client.clone());
    let list = api.list(&ListParams::default()).await?;

    let mut results = Vec::new();

    for crd in list.items {
        let name = crd.metadata.name.unwrap_or_default();
        let spec = crd.spec;
        let group = spec.group;
        let kind = spec
            .names
            .kind
            .clone();
        let scope = match spec.scope.as_str() {
            "Cluster" => "Cluster",
            _ => "Namespaced",
        };

        let category = classify_crd(&group, &kind)
            .map(|d| d.category.clone())
            .unwrap_or(CrdCategory::Other);

        results.push(CrdInfo {
            name,
            group,
            kind,
            scope: scope.to_string(),
            category,
        });
    }

    Ok(results)
}

pub fn analyze_crd_access(
    crds: &[CrdInfo],
    namespace_permissions: &[super::NamespacePermissions],
    current_identity: &str,
) -> Vec<CrdFinding> {
    let mut findings = Vec::new();

    for crd in crds {
        let dangerous = match classify_crd(&crd.group, &crd.kind) {
            Some(d) => d,
            None => continue,
        };

        let plural = crd
            .name
            .split('.')
            .next()
            .unwrap_or(&crd.name);

        let mut accesses = Vec::new();

        for ns_perms in namespace_permissions {
            for rule in &ns_perms.rules {
                let resource_match = rule.resource == "*"
                    || rule.resource == plural
                    || rule.resource.to_lowercase() == crd.kind.to_lowercase();

                let group_match = rule.api_group == "*" || rule.api_group == crd.group;

                if resource_match && group_match {
                    let dangerous_verbs: Vec<String> = rule
                        .verbs
                        .iter()
                        .filter(|v| {
                            matches!(
                                v.as_str(),
                                "*" | "create" | "update" | "patch" | "delete" | "get" | "list"
                            )
                        })
                        .cloned()
                        .collect();

                    if !dangerous_verbs.is_empty() {
                        accesses.push(CrdAccess {
                            identity: current_identity.to_string(),
                            verbs: dangerous_verbs,
                            namespace: Some(ns_perms.namespace.clone()),
                        });
                    }
                }
            }
        }

        if !accesses.is_empty() {
            let deduped: Vec<CrdAccess> = vec![accesses.into_iter().next().unwrap()];
            findings.push(CrdFinding {
                crd_name: crd.name.clone(),
                group: crd.group.clone(),
                kind: crd.kind.clone(),
                category: dangerous.category.label().to_string(),
                severity: dangerous.severity.to_string(),
                attack_path: dangerous.attack_path.to_string(),
                identity_has_access: deduped,
            });
        }
    }

    findings
}
