use serde::Serialize;
use super::patterns::{AttackCapability, Severity};

#[derive(Debug, Clone, Serialize)]
pub struct AttackStep {
    pub identity: String,
    pub namespace: String,
    pub action: String,
    pub result: String,
    pub capability_gained: AttackCapability,
}

impl std::fmt::Display for AttackStep {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "[{}@{}] {} -> {}",
            self.identity, self.namespace, self.action, self.result
        )
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct AttackChain {
    pub id: String,
    pub title: String,
    pub severity: Severity,
    pub steps: Vec<AttackStep>,
    pub final_capability: AttackCapability,
    pub description: String,
}

impl AttackChain {
    pub fn step_count(&self) -> usize {
        self.steps.len()
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub permission: String,
    pub resource: String,
    pub verbs: Vec<String>,
    pub namespace: String,
    pub identity: String,
    pub severity: Severity,
    pub title: String,
    pub description: String,
    pub attack_path: String,
    pub capabilities: Vec<AttackCapability>,
    pub unconventional: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct NamespaceFinding {
    pub namespace: String,
    pub has_pss: bool,
    pub pss_level: Option<String>,
    pub can_create_pods: bool,
    pub privileged_pod_path: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct PodFinding {
    pub pod_name: String,
    pub namespace: String,
    pub service_account: String,
    pub node: Option<String>,
    pub severity: Severity,
    pub issues: Vec<String>,
    pub attack_path: String,
    pub image: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct CrdFindingResult {
    pub crd_name: String,
    pub group: String,
    pub kind: String,
    pub category: String,
    pub severity: Severity,
    pub attack_path: String,
    pub your_access: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct IdentityProfile {
    pub identity: String,
    pub kind: String,
    pub bound_roles: Vec<String>,
    pub dangerous_permissions: Vec<String>,
    pub namespaces: Vec<String>,
    pub is_overprivileged: bool,
    pub severity: Severity,
}

#[derive(Debug, Clone, Serialize)]
pub struct PodContextFinding {
    pub finding_type: String,
    pub detail: String,
    pub severity: Severity,
    pub attack_path: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SecretFinding {
    pub name: String,
    pub namespace: String,
    pub secret_type: String,
    pub category: String,
    pub severity: Severity,
    pub attack_path: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ServiceFinding {
    pub name: String,
    pub namespace: String,
    pub service_type: String,
    pub ports: String,
    pub severity: Severity,
    pub attack_path: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ConfigMapFinding {
    pub name: String,
    pub namespace: String,
    pub sensitive_keys: Vec<String>,
    pub severity: Severity,
    pub attack_path: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct CronJobFinding {
    pub name: String,
    pub namespace: String,
    pub schedule: String,
    pub service_account: String,
    pub severity: Severity,
    pub attack_path: String,
}

#[derive(Debug, Default, Serialize)]
pub struct ScanResults {
    pub findings: Vec<Finding>,
    pub chains: Vec<AttackChain>,
    pub namespace_findings: Vec<NamespaceFinding>,
    pub pod_findings: Vec<PodFinding>,
    pub crd_findings: Vec<CrdFindingResult>,
    pub identity_profiles: Vec<IdentityProfile>,
    pub pod_context_findings: Vec<PodContextFinding>,
    pub secret_findings: Vec<SecretFinding>,
    pub service_findings: Vec<ServiceFinding>,
    pub configmap_findings: Vec<ConfigMapFinding>,
    pub cronjob_findings: Vec<CronJobFinding>,
    pub pivot_graph: Option<crate::scanner::pivot::PivotGraph>,
    pub identity: String,
    pub cluster_info: ClusterInfo,
}

#[derive(Debug, Default, Clone, Serialize)]
pub struct ClusterInfo {
    pub server: String,
    pub version: String,
    pub current_namespace: String,
    pub namespaces: Vec<String>,
}

#[derive(Debug)]
pub struct IdentityPermissions {
    pub identity: String,
    pub namespace: String,
    pub rules: Vec<PermissionRule>,
}

#[derive(Debug, Clone)]
pub struct PermissionRule {
    pub resource: String,
    pub api_group: String,
    pub verbs: Vec<String>,
    pub resource_names: Vec<String>,
}

pub struct PodTarget {
    pub pod_name: String,
    pub namespace: String,
    pub service_account: String,
    pub privileged: bool,
    pub host_pid: bool,
    pub host_path_mounts: Vec<String>,
    pub node: Option<String>,
}

pub struct SaProfile {
    pub identity: String,
    pub dangerous_permissions: Vec<String>,
    pub has_wildcard: bool,
    pub severity: Severity,
}

pub struct ChainBuilder {
    identities: Vec<IdentityPermissions>,
    namespace_security: Vec<NamespaceSecurity>,
    pods: Vec<PodTarget>,
    sa_profiles: Vec<SaProfile>,
}

#[derive(Debug)]
pub struct NamespaceSecurity {
    pub name: String,
    pub pss_enforce: Option<String>,
    pub has_privileged_sa: bool,
    pub service_accounts: Vec<String>,
}

impl ChainBuilder {
    pub fn new(
        identities: Vec<IdentityPermissions>,
        namespace_security: Vec<NamespaceSecurity>,
        pods: Vec<PodTarget>,
        sa_profiles: Vec<SaProfile>,
    ) -> Self {
        Self {
            identities,
            namespace_security,
            pods,
            sa_profiles,
        }
    }

    pub fn build_chains(&self) -> Vec<AttackChain> {
        let mut chains = Vec::new();

        chains.extend(self.find_privileged_pod_chains());
        chains.extend(self.find_rbac_escalation_chains());
        chains.extend(self.find_exec_lateral_chains());
        chains.extend(self.find_secret_harvest_chains());
        chains.extend(self.find_impersonation_chains());
        chains.extend(self.find_webhook_chains());
        chains.extend(self.find_pss_removal_chains());
        chains.extend(self.find_token_forge_chains());
        chains.extend(self.find_pv_breakout_chains());
        chains.extend(self.find_csr_chains());
        chains.extend(self.find_pod_pivot_chains());

        // Deduplicate chains by id (same identity + namespace + chain type)
        let mut seen = std::collections::HashSet::new();
        chains.retain(|c| seen.insert(c.id.clone()));

        chains.sort_by(|a, b| a.severity.cmp(&b.severity));
        chains
    }

    fn find_privileged_pod_chains(&self) -> Vec<AttackChain> {
        let mut chains = Vec::new();

        for identity in &self.identities {
            let can_create_pods = identity.rules.iter().any(|r| {
                (r.resource == "pods" || r.resource == "*")
                    && (r.verbs.contains(&"create".to_string()) || r.verbs.contains(&"*".to_string()))
            });

            if !can_create_pods {
                continue;
            }

            let ns = match self.namespace_security.iter().find(|ns| ns.name == identity.namespace) {
                Some(ns) => ns,
                None => continue,
            };

            if ns.pss_enforce.is_none() {
                chains.push(AttackChain {
                    id: format!("priv-pod-{}-{}", identity.identity, ns.name),
                    title: format!(
                        "Privileged Pod Breakout via {} in {}",
                        identity.identity, ns.name
                    ),
                    severity: Severity::Critical,
                    steps: vec![
                        AttackStep {
                            identity: identity.identity.clone(),
                            namespace: ns.name.clone(),
                            action: "Create privileged pod with hostPID, hostNetwork, hostPath:/".into(),
                            result: "Pod deployed with full node access".into(),
                            capability_gained: AttackCapability::CodeExecution,
                        },
                        AttackStep {
                            identity: identity.identity.clone(),
                            namespace: ns.name.clone(),
                            action: "chroot /mnt from inside privileged container".into(),
                            result: "Root shell on worker node".into(),
                            capability_gained: AttackCapability::NodeBreakout,
                        },
                    ],
                    final_capability: AttackCapability::NodeBreakout,
                    description: format!(
                        "{} can create pods in namespace {} which has no PSS enforcement. Deploy a privileged pod to break out to the node.",
                        identity.identity, ns.name
                    ),
                });
            }
        }

        chains
    }

    fn find_rbac_escalation_chains(&self) -> Vec<AttackChain> {
        let mut chains = Vec::new();

        for identity in &self.identities {
            let can_create_crb = identity.rules.iter().any(|r| {
                (r.resource == "clusterrolebindings" || r.resource == "*")
                    && (r.verbs.contains(&"create".to_string()) || r.verbs.contains(&"*".to_string()))
            });

            if can_create_crb {
                chains.push(AttackChain {
                    id: format!("rbac-escalate-crb-{}", identity.identity),
                    title: format!(
                        "Cluster-Admin via ClusterRoleBinding: {}",
                        identity.identity
                    ),
                    severity: Severity::Critical,
                    steps: vec![AttackStep {
                        identity: identity.identity.clone(),
                        namespace: "cluster-wide".into(),
                        action: "Create ClusterRoleBinding binding cluster-admin to self".into(),
                        result: "Full cluster-admin access".into(),
                        capability_gained: AttackCapability::ClusterAdmin,
                    }],
                    final_capability: AttackCapability::ClusterAdmin,
                    description: format!(
                        "{} can create ClusterRoleBindings. One-step escalation to cluster-admin.",
                        identity.identity
                    ),
                });
            }

            let can_create_rb = identity.rules.iter().any(|r| {
                (r.resource == "rolebindings" || r.resource == "*")
                    && (r.verbs.contains(&"create".to_string()) || r.verbs.contains(&"*".to_string()))
            });
            let can_create_roles = identity.rules.iter().any(|r| {
                (r.resource == "roles" || r.resource == "*")
                    && (r.verbs.contains(&"create".to_string()) || r.verbs.contains(&"*".to_string()))
            });

            if can_create_rb && can_create_roles {
                chains.push(AttackChain {
                    id: format!("rbac-escalate-role-{}", identity.identity),
                    title: format!(
                        "Privilege Escalation via Role+RoleBinding: {}",
                        identity.identity
                    ),
                    severity: Severity::Critical,
                    steps: vec![
                        AttackStep {
                            identity: identity.identity.clone(),
                            namespace: identity.namespace.clone(),
                            action: "Create Role with broad permissions (get secrets, create pods, etc.)".into(),
                            result: "New privileged Role exists".into(),
                            capability_gained: AttackCapability::PrivilegeEscalation,
                        },
                        AttackStep {
                            identity: identity.identity.clone(),
                            namespace: identity.namespace.clone(),
                            action: "Create RoleBinding binding the new Role to self".into(),
                            result: "Identity now has the broader permissions".into(),
                            capability_gained: AttackCapability::PrivilegeEscalation,
                        },
                    ],
                    final_capability: AttackCapability::PrivilegeEscalation,
                    description: format!(
                        "{} can create both Roles and RoleBindings in {}. Self-escalation by creating a permissive role and binding it.",
                        identity.identity, identity.namespace
                    ),
                });
            }

            let has_escalate = identity.rules.iter().any(|r| {
                (r.resource == "clusterroles" || r.resource == "roles" || r.resource == "*")
                    && r.verbs.contains(&"escalate".to_string())
            });

            if has_escalate {
                chains.push(AttackChain {
                    id: format!("rbac-escalate-verb-{}", identity.identity),
                    title: format!("RBAC Escalation Prevention Bypass: {}", identity.identity),
                    severity: Severity::Critical,
                    steps: vec![AttackStep {
                        identity: identity.identity.clone(),
                        namespace: identity.namespace.clone(),
                        action: "Use 'escalate' verb to grant permissions beyond own level".into(),
                        result: "Can add any permission to any Role/ClusterRole".into(),
                        capability_gained: AttackCapability::ClusterAdmin,
                    }],
                    final_capability: AttackCapability::ClusterAdmin,
                    description: format!(
                        "{} has the 'escalate' verb which bypasses Kubernetes RBAC escalation prevention.",
                        identity.identity
                    ),
                });
            }
        }

        chains
    }

    fn find_exec_lateral_chains(&self) -> Vec<AttackChain> {
        let mut chains = Vec::new();

        for identity in &self.identities {
            let can_exec = identity.rules.iter().any(|r| {
                (r.resource == "pods/exec" || r.resource == "*")
                    && (r.verbs.contains(&"create".to_string()) || r.verbs.contains(&"*".to_string()))
            });

            if can_exec {
                chains.push(AttackChain {
                    id: format!("exec-lateral-{}", identity.identity),
                    title: format!("Lateral Movement via Pod Exec: {}", identity.identity),
                    severity: Severity::High,
                    steps: vec![
                        AttackStep {
                            identity: identity.identity.clone(),
                            namespace: identity.namespace.clone(),
                            action: "kubectl exec into target pod".into(),
                            result: "Shell access, inherit pod's service account".into(),
                            capability_gained: AttackCapability::CodeExecution,
                        },
                        AttackStep {
                            identity: identity.identity.clone(),
                            namespace: identity.namespace.clone(),
                            action: "Read /var/run/secrets/kubernetes.io/serviceaccount/token".into(),
                            result: "New SA token acquired, pivot to new identity".into(),
                            capability_gained: AttackCapability::LateralMovement,
                        },
                    ],
                    final_capability: AttackCapability::LateralMovement,
                    description: format!(
                        "{} can exec into pods in {}. Each pod exec gives a new SA identity to enumerate.",
                        identity.identity, identity.namespace
                    ),
                });
            }

            let can_ephemeral = identity.rules.iter().any(|r| {
                (r.resource == "pods/ephemeralcontainers" || r.resource == "*")
                    && (r.verbs.contains(&"create".to_string())
                        || r.verbs.contains(&"update".to_string())
                        || r.verbs.contains(&"patch".to_string())
                        || r.verbs.contains(&"*".to_string()))
            });

            if can_ephemeral {
                chains.push(AttackChain {
                    id: format!("ephemeral-inject-{}", identity.identity),
                    title: format!("Ephemeral Container Injection: {}", identity.identity),
                    severity: Severity::High,
                    steps: vec![AttackStep {
                        identity: identity.identity.clone(),
                        namespace: identity.namespace.clone(),
                        action: "Inject ephemeral debug container into running pod".into(),
                        result: "Code execution in pod context without restart".into(),
                        capability_gained: AttackCapability::CodeExecution,
                    }],
                    final_capability: AttackCapability::CodeExecution,
                    description: format!(
                        "{} can inject ephemeral containers into running pods in {} without restarting them. Stealthier than exec.",
                        identity.identity, identity.namespace
                    ),
                });
            }
        }

        chains
    }

    fn find_secret_harvest_chains(&self) -> Vec<AttackChain> {
        let mut chains = Vec::new();

        for identity in &self.identities {
            let can_get_secrets = identity.rules.iter().any(|r| {
                (r.resource == "secrets" || r.resource == "*")
                    && (r.verbs.contains(&"get".to_string())
                        || r.verbs.contains(&"list".to_string())
                        || r.verbs.contains(&"*".to_string()))
            });

            if can_get_secrets {
                chains.push(AttackChain {
                    id: format!("secret-harvest-{}", identity.identity),
                    title: format!("Secret Harvest: {}", identity.identity),
                    severity: Severity::High,
                    steps: vec![
                        AttackStep {
                            identity: identity.identity.clone(),
                            namespace: identity.namespace.clone(),
                            action: "kubectl get secrets -> list all secrets".into(),
                            result: "SA tokens, TLS certs, passwords, API keys exposed".into(),
                            capability_gained: AttackCapability::CredentialHarvest,
                        },
                        AttackStep {
                            identity: identity.identity.clone(),
                            namespace: identity.namespace.clone(),
                            action: "Authenticate with harvested SA tokens".into(),
                            result: "Pivot to new identities with different permissions".into(),
                            capability_gained: AttackCapability::LateralMovement,
                        },
                    ],
                    final_capability: AttackCapability::CredentialHarvest,
                    description: format!(
                        "{} can read secrets in {}. SA token secrets enable identity pivoting.",
                        identity.identity, identity.namespace
                    ),
                });
            }
        }

        chains
    }

    fn find_impersonation_chains(&self) -> Vec<AttackChain> {
        let mut chains = Vec::new();

        for identity in &self.identities {
            let can_impersonate_users = identity.rules.iter().any(|r| {
                (r.resource == "users" || r.resource == "*")
                    && r.verbs.contains(&"impersonate".to_string())
            });
            let can_impersonate_groups = identity.rules.iter().any(|r| {
                (r.resource == "groups" || r.resource == "*")
                    && r.verbs.contains(&"impersonate".to_string())
            });
            let can_impersonate_sa = identity.rules.iter().any(|r| {
                (r.resource == "serviceaccounts" || r.resource == "*")
                    && r.verbs.contains(&"impersonate".to_string())
            });

            if can_impersonate_users || can_impersonate_groups {
                chains.push(AttackChain {
                    id: format!("impersonate-admin-{}", identity.identity),
                    title: format!("Impersonate Cluster Admin: {}", identity.identity),
                    severity: Severity::Critical,
                    steps: vec![AttackStep {
                        identity: identity.identity.clone(),
                        namespace: "cluster-wide".into(),
                        action: "kubectl --as=system:admin / --as-group=system:masters".into(),
                        result: "Acting as cluster admin".into(),
                        capability_gained: AttackCapability::ClusterAdmin,
                    }],
                    final_capability: AttackCapability::ClusterAdmin,
                    description: format!(
                        "{} can impersonate users/groups. --as=system:admin or --as-group=system:masters gives instant cluster-admin.",
                        identity.identity
                    ),
                });
            }

            if can_impersonate_sa {
                chains.push(AttackChain {
                    id: format!("impersonate-sa-{}", identity.identity),
                    title: format!("Impersonate Service Accounts: {}", identity.identity),
                    severity: Severity::Critical,
                    steps: vec![AttackStep {
                        identity: identity.identity.clone(),
                        namespace: "any".into(),
                        action: "kubectl --as=system:serviceaccount:<ns>:<sa>".into(),
                        result: "Acting as any SA in any namespace".into(),
                        capability_gained: AttackCapability::IdentityForge,
                    }],
                    final_capability: AttackCapability::IdentityForge,
                    description: format!(
                        "{} can impersonate any service account. Enumerate SAs across namespaces to find the most privileged one.",
                        identity.identity
                    ),
                });
            }
        }

        chains
    }

    fn find_webhook_chains(&self) -> Vec<AttackChain> {
        let mut chains = Vec::new();

        for identity in &self.identities {
            let can_mutating = identity.rules.iter().any(|r| {
                (r.resource == "mutatingwebhookconfigurations" || r.resource == "*")
                    && (r.verbs.contains(&"create".to_string())
                        || r.verbs.contains(&"update".to_string())
                        || r.verbs.contains(&"*".to_string()))
            });

            if can_mutating {
                chains.push(AttackChain {
                    id: format!("webhook-backdoor-{}", identity.identity),
                    title: format!("Cluster-Wide Backdoor via MutatingWebhook: {}", identity.identity),
                    severity: Severity::High,
                    steps: vec![
                        AttackStep {
                            identity: identity.identity.clone(),
                            namespace: "cluster-wide".into(),
                            action: "Deploy webhook server pod + register MutatingWebhookConfiguration".into(),
                            result: "All new pods get sidecar container injected".into(),
                            capability_gained: AttackCapability::PersistentBackdoor,
                        },
                    ],
                    final_capability: AttackCapability::PersistentBackdoor,
                    description: format!(
                        "{} can create MutatingWebhookConfigurations. Register a webhook that injects a sidecar into every new pod for persistent cluster-wide access.",
                        identity.identity
                    ),
                });
            }
        }

        chains
    }

    fn find_pss_removal_chains(&self) -> Vec<AttackChain> {
        let mut chains = Vec::new();

        for identity in &self.identities {
            let can_patch_ns = identity.rules.iter().any(|r| {
                (r.resource == "namespaces" || r.resource == "*")
                    && (r.verbs.contains(&"patch".to_string())
                        || r.verbs.contains(&"update".to_string())
                        || r.verbs.contains(&"*".to_string()))
            });
            let can_create_pods = identity.rules.iter().any(|r| {
                (r.resource == "pods" || r.resource == "*")
                    && (r.verbs.contains(&"create".to_string()) || r.verbs.contains(&"*".to_string()))
            });

            if !can_patch_ns || !can_create_pods {
                continue;
            }

            let ns = match self.namespace_security.iter().find(|ns| ns.name == identity.namespace) {
                Some(ns) => ns,
                None => continue,
            };

            if ns.pss_enforce.is_some() {
                chains.push(AttackChain {
                    id: format!("pss-remove-{}-{}", identity.identity, ns.name),
                    title: format!(
                        "PSS Bypass + Privileged Pod: {} in {}",
                        identity.identity, ns.name
                    ),
                    severity: Severity::Critical,
                    steps: vec![
                        AttackStep {
                            identity: identity.identity.clone(),
                            namespace: ns.name.clone(),
                            action: "Patch namespace to remove pod-security.kubernetes.io/enforce label".into(),
                            result: "PSS enforcement disabled".into(),
                            capability_gained: AttackCapability::AdmissionBypass,
                        },
                        AttackStep {
                            identity: identity.identity.clone(),
                            namespace: ns.name.clone(),
                            action: "Deploy privileged pod with host mounts".into(),
                            result: "Node breakout".into(),
                            capability_gained: AttackCapability::NodeBreakout,
                        },
                    ],
                    final_capability: AttackCapability::NodeBreakout,
                    description: format!(
                        "{} can patch namespaces AND create pods. Remove PSS from {} then deploy a privileged pod.",
                        identity.identity, ns.name
                    ),
                });
            }
        }

        chains
    }

    fn find_token_forge_chains(&self) -> Vec<AttackChain> {
        let mut chains = Vec::new();

        for identity in &self.identities {
            let can_create_tokens = identity.rules.iter().any(|r| {
                (r.resource == "serviceaccounts/token" || r.resource == "*")
                    && (r.verbs.contains(&"create".to_string()) || r.verbs.contains(&"*".to_string()))
            });

            if can_create_tokens {
                chains.push(AttackChain {
                    id: format!("token-forge-{}", identity.identity),
                    title: format!("Token Forging: {}", identity.identity),
                    severity: Severity::Critical,
                    steps: vec![AttackStep {
                        identity: identity.identity.clone(),
                        namespace: identity.namespace.clone(),
                        action: "Create TokenRequest for privileged SA in namespace".into(),
                        result: "Valid JWT token for any SA in the namespace".into(),
                        capability_gained: AttackCapability::IdentityForge,
                    }],
                    final_capability: AttackCapability::IdentityForge,
                    description: format!(
                        "{} can create token requests in {}. Mint tokens for any SA in the namespace.",
                        identity.identity, identity.namespace
                    ),
                });
            }
        }

        chains
    }

    fn find_pv_breakout_chains(&self) -> Vec<AttackChain> {
        let mut chains = Vec::new();

        for identity in &self.identities {
            let can_create_pv = identity.rules.iter().any(|r| {
                (r.resource == "persistentvolumes" || r.resource == "*")
                    && (r.verbs.contains(&"create".to_string()) || r.verbs.contains(&"*".to_string()))
            });
            let can_create_pvc = identity.rules.iter().any(|r| {
                (r.resource == "persistentvolumeclaims" || r.resource == "*")
                    && (r.verbs.contains(&"create".to_string()) || r.verbs.contains(&"*".to_string()))
            });
            let can_create_pods = identity.rules.iter().any(|r| {
                (r.resource == "pods" || r.resource == "*")
                    && (r.verbs.contains(&"create".to_string()) || r.verbs.contains(&"*".to_string()))
            });

            if can_create_pv && can_create_pvc && can_create_pods {
                chains.push(AttackChain {
                    id: format!("pv-breakout-{}", identity.identity),
                    title: format!("Node Breakout via PV+PVC: {}", identity.identity),
                    severity: Severity::High,
                    steps: vec![
                        AttackStep {
                            identity: identity.identity.clone(),
                            namespace: identity.namespace.clone(),
                            action: "Create PV with hostPath: /".into(),
                            result: "PV pointing to node root filesystem".into(),
                            capability_gained: AttackCapability::NodeBreakout,
                        },
                        AttackStep {
                            identity: identity.identity.clone(),
                            namespace: identity.namespace.clone(),
                            action: "Create PVC claiming the PV, create pod mounting it".into(),
                            result: "Host filesystem accessible inside pod".into(),
                            capability_gained: AttackCapability::NodeBreakout,
                        },
                    ],
                    final_capability: AttackCapability::NodeBreakout,
                    description: format!(
                        "{} can create PVs, PVCs, and pods. Alternative node breakout path via PersistentVolume with hostPath, works even in some PSS-restricted namespaces.",
                        identity.identity
                    ),
                });
            }
        }

        chains
    }

    fn find_csr_chains(&self) -> Vec<AttackChain> {
        let mut chains = Vec::new();

        for identity in &self.identities {
            let can_create_csr = identity.rules.iter().any(|r| {
                (r.resource == "certificatesigningrequests" || r.resource == "*")
                    && (r.verbs.contains(&"create".to_string()) || r.verbs.contains(&"*".to_string()))
            });
            let can_approve_csr = identity.rules.iter().any(|r| {
                (r.resource == "certificatesigningrequests/approval" || r.resource == "*")
                    && (r.verbs.contains(&"update".to_string()) || r.verbs.contains(&"*".to_string()))
            });

            if can_create_csr && can_approve_csr {
                chains.push(AttackChain {
                    id: format!("csr-forge-{}", identity.identity),
                    title: format!("Certificate Forging via CSR: {}", identity.identity),
                    severity: Severity::Critical,
                    steps: vec![
                        AttackStep {
                            identity: identity.identity.clone(),
                            namespace: "cluster-wide".into(),
                            action: "Create CSR with O=system:masters".into(),
                            result: "CSR pending approval".into(),
                            capability_gained: AttackCapability::IdentityForge,
                        },
                        AttackStep {
                            identity: identity.identity.clone(),
                            namespace: "cluster-wide".into(),
                            action: "Approve the CSR".into(),
                            result: "Valid client certificate for system:masters group".into(),
                            capability_gained: AttackCapability::ClusterAdmin,
                        },
                    ],
                    final_capability: AttackCapability::ClusterAdmin,
                    description: format!(
                        "{} can both create and approve CSRs. Mint a client certificate with system:masters group for persistent cluster-admin.",
                        identity.identity
                    ),
                });
            }
        }

        chains
    }

    fn find_pod_pivot_chains(&self) -> Vec<AttackChain> {
        let mut chains = Vec::new();

        for identity in &self.identities {
            let can_exec = identity.rules.iter().any(|r| {
                (r.resource == "pods/exec" || r.resource == "*")
                    && (r.verbs.contains(&"create".to_string())
                        || r.verbs.contains(&"*".to_string()))
            });
            let can_attach = identity.rules.iter().any(|r| {
                (r.resource == "pods/attach" || r.resource == "*")
                    && (r.verbs.contains(&"create".to_string())
                        || r.verbs.contains(&"*".to_string()))
            });

            if !can_exec && !can_attach {
                continue;
            }

            let access_method = if can_exec { "exec" } else { "attach" };

            for pod in &self.pods {
                if pod.namespace != identity.namespace {
                    continue;
                }

                let sa_identity = format!(
                    "system:serviceaccount:{}:{}",
                    pod.namespace, pod.service_account
                );

                // Skip if the pod's SA is the same as our identity
                if sa_identity == identity.identity {
                    continue;
                }

                let sa_profile = match self.sa_profiles.iter().find(|p| p.identity == sa_identity) {
                    Some(p) => p,
                    None => continue,
                };

                if sa_profile.dangerous_permissions.is_empty() {
                    continue;
                }

                let mut steps = Vec::new();

                steps.push(AttackStep {
                    identity: identity.identity.clone(),
                    namespace: pod.namespace.clone(),
                    action: format!(
                        "kubectl {} -n {} {}",
                        access_method, pod.namespace, pod.pod_name
                    ),
                    result: format!(
                        "Shell in container (SA: {})",
                        pod.service_account
                    ),
                    capability_gained: AttackCapability::CodeExecution,
                });

                steps.push(AttackStep {
                    identity: sa_identity.clone(),
                    namespace: pod.namespace.clone(),
                    action: "Read /var/run/secrets/kubernetes.io/serviceaccount/token".into(),
                    result: format!("Now acting as {}", sa_identity),
                    capability_gained: AttackCapability::LateralMovement,
                });

                let (final_cap, severity) = if sa_profile.has_wildcard {
                    (AttackCapability::ClusterAdmin, Severity::Critical)
                } else if sa_profile.severity == Severity::Critical {
                    (AttackCapability::PrivilegeEscalation, Severity::Critical)
                } else {
                    (AttackCapability::LateralMovement, Severity::High)
                };

                let top_perms: Vec<&str> = sa_profile
                    .dangerous_permissions
                    .iter()
                    .take(3)
                    .map(|s| s.as_str())
                    .collect();
                let perms_display = top_perms.join(", ");
                let more = if sa_profile.dangerous_permissions.len() > 3 {
                    format!(" (+{} more)", sa_profile.dangerous_permissions.len() - 3)
                } else {
                    String::new()
                };

                steps.push(AttackStep {
                    identity: sa_identity.clone(),
                    namespace: pod.namespace.clone(),
                    action: format!("SA has: {}{}", perms_display, more),
                    result: if sa_profile.has_wildcard {
                        "Wildcard access, cluster-admin equivalent".into()
                    } else {
                        format!("Escalated permissions via {}", pod.service_account)
                    },
                    capability_gained: final_cap,
                });

                let mut extra = Vec::new();
                if pod.privileged {
                    extra.push("privileged");
                }
                if pod.host_pid {
                    extra.push("hostPID");
                }
                if !pod.host_path_mounts.is_empty() {
                    extra.push("hostPath");
                }
                let pod_flags = if extra.is_empty() {
                    String::new()
                } else {
                    format!(" [{}]", extra.join(", "))
                };

                chains.push(AttackChain {
                    id: format!(
                        "pod-pivot-{}-{}-{}",
                        identity.identity, pod.namespace, pod.pod_name
                    ),
                    title: format!(
                        "Pivot via {}/{} -> {}{}",
                        pod.namespace, pod.pod_name, pod.service_account, pod_flags
                    ),
                    severity,
                    steps,
                    final_capability: final_cap,
                    description: format!(
                        "{} can {} into {}/{} which runs as {}. That SA has: {}{}.",
                        identity.identity,
                        access_method,
                        pod.namespace,
                        pod.pod_name,
                        sa_identity,
                        perms_display,
                        more
                    ),
                });
            }
        }

        chains
    }
}
