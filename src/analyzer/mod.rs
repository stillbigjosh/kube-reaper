pub mod chains;
pub mod patterns;

use anyhow::Result;
use chains::{
    ChainBuilder, CrdFindingResult, Finding, IdentityPermissions,
    IdentityProfile, NamespaceFinding, NamespaceSecurity, PodContextFinding, PodFinding,
    PodTarget, SaProfile, SecretFinding, PermissionRule, ScanResults,
};
use patterns::{all_dangerous_permissions, Severity};

use crate::scanner::ScanData;

pub fn analyze(data: &ScanData) -> Result<ScanResults> {
    let mut results = ScanResults {
        identity: data.identity.clone(),
        cluster_info: data.cluster_info.clone(),
        ..Default::default()
    };

    let dangerous = all_dangerous_permissions();

    // === Current identity permission findings ===
    for ns_perms in &data.namespace_permissions {
        let ns_has_pss = data
            .namespaces
            .iter()
            .any(|n| n.name == ns_perms.namespace && n.pss_enforce.is_some());

        let ns_has_endpoints = ns_perms.rules.iter().any(|r| {
            (r.resource == "endpoints" || r.resource == "*")
                && (r.verbs.contains(&"create".to_string())
                    || r.verbs.contains(&"update".to_string())
                    || r.verbs.contains(&"patch".to_string())
                    || r.verbs.contains(&"*".to_string()))
        });

        for rule in &ns_perms.rules {
            if is_default_grant(&rule.resource) {
                continue;
            }
            for verb in &rule.verbs {
                for perm in &dangerous {
                    if permission_matches(perm, &rule.resource, verb, &rule.api_group) {
                        if perm.id == "create-pods-no-pss" && ns_has_pss {
                            continue;
                        }

                        if perm.id == "modify-configmaps-kubesystem"
                            && ns_perms.namespace != "kube-system"
                        {
                            continue;
                        }

                        if perm.id == "create-services-endpoints" && !ns_has_endpoints {
                            continue;
                        }

                        let finding = Finding {
                            permission: perm.id.to_string(),
                            resource: rule.resource.clone(),
                            verbs: rule.verbs.clone(),
                            namespace: ns_perms.namespace.clone(),
                            identity: data.identity.clone(),
                            severity: perm.severity,
                            title: perm.title.to_string(),
                            description: perm.description.to_string(),
                            attack_path: perm.attack_path.to_string(),
                            capabilities: perm.enables.to_vec(),
                            unconventional: perm.unconventional,
                        };

                        if !results.findings.iter().any(|f| {
                            f.permission == finding.permission && f.namespace == finding.namespace
                        }) {
                            results.findings.push(finding);
                        }
                    }
                }
            }
        }
    }

    // === Namespace findings ===
    for ns in &data.namespaces {
        let can_create_pods = data.namespace_permissions.iter().any(|np| {
            np.namespace == ns.name
                && np.rules.iter().any(|r| {
                    (r.resource == "pods" || r.resource == "*")
                        && (r.verbs.contains(&"create".to_string())
                            || r.verbs.contains(&"*".to_string()))
                })
        });

        results.namespace_findings.push(NamespaceFinding {
            namespace: ns.name.clone(),
            has_pss: ns.pss_enforce.is_some(),
            pss_level: ns.pss_enforce.clone(),
            can_create_pods,
            privileged_pod_path: can_create_pods && ns.pss_enforce.is_none(),
        });
    }

    // === Dangerous pod findings ===
    results.pod_findings = analyze_pods(data);

    // === CRD findings ===
    results.crd_findings = analyze_crds(data);

    // === Identity profiles from RBAC graph ===
    results.identity_profiles = analyze_identities(data);

    // === Pod context findings ===
    results.pod_context_findings = analyze_pod_context(data);

    // === Secret triage ===
    results.secret_findings = analyze_secrets(data);

    // === Attack chains ===
    let identities: Vec<IdentityPermissions> = data
        .namespace_permissions
        .iter()
        .map(|np| IdentityPermissions {
            identity: data.identity.clone(),
            namespace: np.namespace.clone(),
            rules: np
                .rules
                .iter()
                .map(|r| PermissionRule {
                    resource: r.resource.clone(),
                    api_group: r.api_group.clone(),
                    verbs: r.verbs.clone(),
                    resource_names: r.resource_names.clone(),
                })
                .collect(),
        })
        .collect();

    let ns_security: Vec<NamespaceSecurity> = data
        .namespaces
        .iter()
        .map(|ns| NamespaceSecurity {
            name: ns.name.clone(),
            pss_enforce: ns.pss_enforce.clone(),
            has_privileged_sa: false,
            service_accounts: ns.service_accounts.clone(),
        })
        .collect();

    let pod_targets: Vec<PodTarget> = data
        .pods
        .iter()
        .map(|p| PodTarget {
            pod_name: p.name.clone(),
            namespace: p.namespace.clone(),
            service_account: p.service_account.clone(),
            privileged: p.privileged,
            host_pid: p.host_pid,
            host_path_mounts: p.host_path_mounts.clone(),
            node: p.node_name.clone(),
        })
        .collect();

    let sa_profiles: Vec<SaProfile> = results
        .identity_profiles
        .iter()
        .filter(|p| p.kind == "ServiceAccount")
        .map(|p| SaProfile {
            identity: p.identity.clone(),
            dangerous_permissions: p.dangerous_permissions.clone(),
            has_wildcard: p.is_overprivileged,
            severity: p.severity,
        })
        .collect();

    let chain_builder = ChainBuilder::new(identities, ns_security, pod_targets, sa_profiles);
    results.chains = chain_builder.build_chains();

    results.findings.sort_by(|a, b| a.severity.cmp(&b.severity));

    Ok(results)
}

fn analyze_pods(data: &ScanData) -> Vec<PodFinding> {
    let mut findings = Vec::new();

    for pod in &data.pods {
        let mut issues = Vec::new();
        let mut severity = Severity::Info;
        let mut attack_parts = Vec::new();

        if pod.privileged {
            issues.push("PRIVILEGED container".to_string());
            severity = Severity::Critical;
            attack_parts.push("exec into privileged container -> full node access");
        }

        if pod.host_pid {
            issues.push("hostPID enabled".to_string());
            if severity > Severity::Critical {
                severity = Severity::Critical;
            }
            attack_parts.push("host PID namespace -> read /proc/1/environ, ptrace host processes");
        }

        if pod.host_network {
            issues.push("hostNetwork enabled".to_string());
            if severity > Severity::High {
                severity = Severity::High;
            }
            attack_parts.push("host network -> sniff traffic, access node-local services");
        }

        for mount in &pod.host_path_mounts {
            let mount_severity = if mount == "/" || mount == "/etc" || mount == "/var" {
                issues.push(format!("hostPath mount: {} (ROOT/SENSITIVE)", mount));
                Severity::Critical
            } else if mount.contains("docker.sock")
                || mount.contains("containerd.sock")
                || mount.contains("crio.sock")
            {
                issues.push(format!("hostPath mount: {} (CONTAINER RUNTIME SOCKET)", mount));
                Severity::Critical
            } else if mount.starts_with("/var/log") || mount.starts_with("/tmp") {
                issues.push(format!("hostPath mount: {}", mount));
                Severity::Medium
            } else {
                issues.push(format!("hostPath mount: {}", mount));
                Severity::High
            };
            if mount_severity < severity {
                severity = mount_severity;
            }
            attack_parts.push("hostPath volume -> access host filesystem");
        }

        let has_secret_env = pod.env_vars.iter().any(|e| e.from_secret.is_some());
        if has_secret_env {
            let secret_names: Vec<String> = pod
                .env_vars
                .iter()
                .filter_map(|e| e.from_secret.clone())
                .collect();
            issues.push(format!("secrets in env: {}", secret_names.join(", ")));
            if severity > Severity::Medium {
                severity = Severity::Medium;
            }
            attack_parts.push("secrets mounted as env vars -> credential access via exec");
        }

        if pod.automount_sa_token && !issues.is_empty() {
            issues.push(format!("SA token auto-mounted (SA: {})", pod.service_account));
        }

        if issues.is_empty() {
            continue;
        }

        let attack_path = if attack_parts.is_empty() {
            "Exec into pod to access mounted resources".to_string()
        } else {
            attack_parts.join(" | ")
        };

        findings.push(PodFinding {
            pod_name: pod.name.clone(),
            namespace: pod.namespace.clone(),
            service_account: pod.service_account.clone(),
            node: pod.node_name.clone(),
            severity,
            issues,
            attack_path,
            image: pod.image.clone(),
        });
    }

    findings.sort_by(|a, b| a.severity.cmp(&b.severity));
    findings
}

fn analyze_crds(data: &ScanData) -> Vec<CrdFindingResult> {
    let crd_findings =
        crate::scanner::crds::analyze_crd_access(&data.crds, &data.namespace_permissions, &data.identity);

    crd_findings
        .into_iter()
        .map(|f| {
            let severity = match f.severity.as_str() {
                "CRITICAL" => Severity::Critical,
                "HIGH" => Severity::High,
                "MEDIUM" => Severity::Medium,
                _ => Severity::Low,
            };

            let access_strs: Vec<String> = f
                .identity_has_access
                .iter()
                .map(|a| {
                    format!(
                        "{} [{}]",
                        a.identity,
                        a.verbs.join(", ")
                    )
                })
                .collect();

            CrdFindingResult {
                crd_name: f.crd_name,
                group: f.group,
                kind: f.kind,
                category: f.category,
                severity,
                attack_path: f.attack_path,
                your_access: access_strs,
            }
        })
        .collect()
}

fn analyze_identities(data: &ScanData) -> Vec<IdentityProfile> {
    let graph = match &data.rbac_graph {
        Some(g) => g,
        None => return Vec::new(),
    };

    let profiles = graph.build_identity_profiles();
    let dangerous = all_dangerous_permissions();

    let mut results = Vec::new();

    for profile in &profiles {
        if profile.identity == data.identity {
            continue;
        }
        // Skip system identities that are expected to have broad access
        if is_system_identity(&profile.identity) {
            continue;
        }

        let mut dangerous_perms = Vec::new();
        let mut max_severity = Severity::Info;

        for rule in &profile.effective_rules {
            if is_default_grant(&rule.resource) {
                continue;
            }
            for verb in &rule.verbs {
                for perm in &dangerous {
                    if permission_matches(perm, &rule.resource, verb, &rule.api_group) {
                        let perm_str = perm.title.to_string();
                        if !dangerous_perms.contains(&perm_str) {
                            dangerous_perms.push(perm_str);
                            if perm.severity < max_severity {
                                max_severity = perm.severity;
                            }
                        }
                    }
                }
            }
        }

        if dangerous_perms.is_empty() {
            continue;
        }

        let has_wildcard = profile
            .effective_rules
            .iter()
            .any(|r| r.resource == "*" && r.verbs.contains(&"*".to_string()));

        results.push(IdentityProfile {
            identity: profile.identity.clone(),
            kind: profile.kind.clone(),
            bound_roles: profile.bound_roles.clone(),
            dangerous_permissions: dangerous_perms,
            namespaces: profile.namespaces_with_access.clone(),
            is_overprivileged: has_wildcard,
            severity: max_severity,
        });
    }

    results.sort_by(|a, b| a.severity.cmp(&b.severity));
    results
}

fn analyze_pod_context(data: &ScanData) -> Vec<PodContextFinding> {
    let ctx = &data.pod_context;
    if !ctx.running_in_pod {
        return Vec::new();
    }

    let mut findings = Vec::new();

    if ctx.sa_token_mounted {
        findings.push(PodContextFinding {
            finding_type: "SA Token Mounted".to_string(),
            detail: format!(
                "Token at {}. Identity: {}",
                ctx.token_path.as_deref().unwrap_or("unknown"),
                ctx.sa_name
                    .as_ref()
                    .map(|n| {
                        format!(
                            "system:serviceaccount:{}:{}",
                            ctx.sa_namespace.as_deref().unwrap_or("?"),
                            n
                        )
                    })
                    .unwrap_or_else(|| "unknown".to_string())
            ),
            severity: Severity::Medium,
            attack_path: "Use mounted token to authenticate to API server. Check permissions with kube-reaper.".to_string(),
        });
    }

    for mount in &ctx.interesting_mounts {
        let severity = if mount.mount_type.contains("Docker Socket")
            || mount.mount_type.contains("Containerd Socket")
            || mount.mount_type.contains("CRI-O Socket")
        {
            Severity::Critical
        } else if mount.mount_type.contains("K8s PKI")
            || mount.mount_type.contains("Host PID")
        {
            Severity::Critical
        } else if mount.mount_type.contains("K8s Config")
            || mount.mount_type.contains("Root SSH")
            || mount.mount_type.contains("Shadow")
        {
            Severity::High
        } else {
            Severity::Medium
        };

        findings.push(PodContextFinding {
            finding_type: format!("Dangerous Mount: {}", mount.mount_type),
            detail: format!("{} at {}", mount.reason, mount.path),
            severity,
            attack_path: mount.reason.clone(),
        });
    }

    for env in &ctx.interesting_env_vars {
        findings.push(PodContextFinding {
            finding_type: format!("Sensitive Env: {}", env.name),
            detail: format!("{} (value: {})", env.reason, env.value),
            severity: Severity::High,
            attack_path: "Environment variable contains credentials. Extract and use for lateral movement.".to_string(),
        });
    }

    if let Some(ref api) = ctx.api_server_env {
        findings.push(PodContextFinding {
            finding_type: "API Server Reachable".to_string(),
            detail: format!("API server at {}", api),
            severity: Severity::Info,
            attack_path: "API server is reachable from this pod. Use kubectl or kube-reaper to enumerate.".to_string(),
        });
    }

    findings.sort_by(|a, b| a.severity.cmp(&b.severity));
    findings
}

fn analyze_secrets(data: &ScanData) -> Vec<SecretFinding> {
    let mut findings = Vec::new();

    for secret in &data.secrets_accessible {
        let (category, severity, attack_path) = match secret.secret_type.as_str() {
            "kubernetes.io/service-account-token" => (
                "SA Token",
                Severity::Critical,
                "Contains a non-expiring SA token. Decode and use: kubectl --token=<token> --server=<api>. Pivot to this SA's identity.",
            ),
            "kubernetes.io/dockerconfigjson" | "kubernetes.io/dockercfg" => (
                "Registry Credentials",
                Severity::High,
                "Contains container registry credentials. Pull private images, push backdoored images, or access the registry API.",
            ),
            "kubernetes.io/tls" => (
                "TLS Certificate",
                Severity::Medium,
                "Contains TLS cert + private key. Impersonate the service this cert belongs to, or decrypt captured traffic.",
            ),
            "kubernetes.io/basic-auth" => (
                "Basic Auth",
                Severity::High,
                "Contains username/password. Try against other services, dashboards, databases.",
            ),
            "kubernetes.io/ssh-auth" => (
                "SSH Key",
                Severity::High,
                "Contains SSH private key. Use for lateral movement to nodes or external systems.",
            ),
            "Opaque" => (
                "Opaque Secret",
                Severity::Medium,
                "Opaque secret. May contain passwords, API keys, connection strings. Decode: kubectl get secret <name> -o jsonpath='{.data}' | base64 -d",
            ),
            _ => continue,
        };

        findings.push(SecretFinding {
            name: secret.name.clone(),
            namespace: secret.namespace.clone(),
            secret_type: secret.secret_type.clone(),
            category: category.to_string(),
            severity,
            attack_path: attack_path.to_string(),
        });
    }

    findings.sort_by(|a, b| a.severity.cmp(&b.severity));
    findings
}

fn is_system_identity(identity: &str) -> bool {
    let system_prefixes = [
        "system:kube-",
        "system:controller:",
        "system:serviceaccount:kube-system:kube-",
        "system:serviceaccount:kube-system:bootstrap-signer",
        "system:serviceaccount:kube-system:token-cleaner",
        "system:serviceaccount:kube-system:node-controller",
        "system:serviceaccount:kube-system:replication-controller",
        "system:serviceaccount:kube-system:endpoint-controller",
        "system:serviceaccount:kube-system:service-account-controller",
        "system:serviceaccount:kube-system:namespace-controller",
        "system:serviceaccount:kube-system:resourcequota-controller",
        "system:serviceaccount:kube-system:certificate-controller",
        "system:node:",
        "system:anonymous",
        "system:authenticated",
        "system:unauthenticated",
        "system:masters",
        "system:monitoring",
    ];

    for prefix in &system_prefixes {
        if identity.starts_with(prefix) {
            return true;
        }
    }

    identity == "system:admin"
        || identity == "kubernetes-admin"
        || identity == "system:serviceaccount:kube-system:default"
}

fn is_default_grant(resource: &str) -> bool {
    matches!(
        resource,
        "selfsubjectaccessreviews"
            | "selfsubjectrulesreviews"
            | "selfsubjectreviews"
    )
}

fn permission_matches(
    perm: &patterns::DangerousPermission,
    resource: &str,
    verb: &str,
    api_group: &str,
) -> bool {
    let resource_match = if perm.resource == "*" {
        resource == "*"
    } else {
        perm.resource == resource || resource == "*"
    };

    let verb_match = perm.verbs.contains(&"*") || perm.verbs.contains(&verb);
    let group_match = perm.api_group == "*" || perm.api_group == api_group || api_group == "*";
    resource_match && verb_match && group_match
}
