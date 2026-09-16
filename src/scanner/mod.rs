pub mod admission;
pub mod configmaps;
pub mod crds;
pub mod cronjobs;
pub mod dns_discovery;
pub mod namespace;
pub mod pivot;
pub mod pod_context;
pub mod pods;
pub mod rbac;
pub mod rbac_graph;
pub mod secrets;
pub mod services;

use anyhow::Result;
use kube::Client;
use serde::Serialize;

use crate::analyzer::chains::ClusterInfo;

#[derive(Debug, Default)]
pub struct ScanData {
    pub identity: String,
    pub cluster_info: ClusterInfo,
    pub namespaces: Vec<NamespaceInfo>,
    pub namespace_permissions: Vec<NamespacePermissions>,
    pub pods: Vec<PodInfo>,
    pub secrets_accessible: Vec<SecretRef>,
    pub rbac_graph: Option<rbac_graph::RbacGraph>,
    pub crds: Vec<crds::CrdInfo>,
    pub pod_context: pod_context::PodContext,
    pub services: Vec<services::ServiceInfo>,
    pub configmaps: Vec<configmaps::ConfigMapRef>,
    pub cronjobs: Vec<cronjobs::CronJobInfo>,
    pub pivot_graph: Option<pivot::PivotGraph>,
    pub dns_discovery: Option<dns_discovery::DnsDiscoveryResults>,
    pub admission_results: Vec<admission::NamespaceAdmissionResult>,
}

#[derive(Debug, Clone, Serialize)]
pub struct NamespaceInfo {
    pub name: String,
    pub pss_enforce: Option<String>,
    pub pss_audit: Option<String>,
    pub pss_warn: Option<String>,
    pub labels: std::collections::HashMap<String, String>,
    pub service_accounts: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct NamespacePermissions {
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

#[derive(Debug, Clone, Serialize)]
pub struct PodInfo {
    pub name: String,
    pub namespace: String,
    pub service_account: String,
    pub node_name: Option<String>,
    pub privileged: bool,
    pub host_pid: bool,
    pub host_network: bool,
    pub host_path_mounts: Vec<String>,
    pub env_vars: Vec<EnvVar>,
    pub image: String,
    pub automount_sa_token: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct EnvVar {
    pub name: String,
    pub value: Option<String>,
    pub from_secret: Option<String>,
    pub from_configmap: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SecretRef {
    pub name: String,
    pub namespace: String,
    pub secret_type: String,
}

pub async fn run_scan(
    client: &Client,
    target_namespace: Option<&str>,
    pod_ctx: pod_context::PodContext,
) -> Result<ScanData> {
    let mut data = ScanData::default();

    let default_ns = client.default_namespace().to_string();

    data.pod_context = pod_ctx;
    if data.pod_context.running_in_pod {
        eprintln!("[*] Running inside a pod. Analyzing pod context...");
        if let Some(ref sa) = data.pod_context.sa_name {
            eprintln!("[+] Service Account: {}", sa);
        }
        if data.pod_context.sa_token_mounted {
            eprintln!("[+] SA token is mounted");
        }
        if !data.pod_context.interesting_mounts.is_empty() {
            eprintln!(
                "[!] {} interesting mounts detected",
                data.pod_context.interesting_mounts.len()
            );
        }
        if !data.pod_context.interesting_env_vars.is_empty() {
            eprintln!(
                "[!] {} sensitive env vars detected",
                data.pod_context.interesting_env_vars.len()
            );
        }
        if !data.pod_context.capabilities.is_empty() {
            eprintln!(
                "[!] {} dangerous capabilities detected",
                data.pod_context.capabilities.len()
            );
        }
        if !data.pod_context.cloud_metadata.is_empty() {
            eprintln!(
                "[!] {} cloud metadata endpoints accessible",
                data.pod_context.cloud_metadata.len()
            );
        }
        if !data.pod_context.escape_vectors.is_empty() {
            eprintln!(
                "[!] {} container escape vectors detected",
                data.pod_context.escape_vectors.len()
            );
        }
    }

    eprintln!("[*] Identifying current identity...");
    data.identity = rbac::get_current_identity(client).await?;
    eprintln!("[+] Identity: {}", data.identity);

    eprintln!("[*] Enumerating namespaces...");
    match namespace::enumerate_namespaces(client).await {
        Ok(ns_list) => {
            data.namespaces = ns_list;
            eprintln!("[+] Found {} namespaces", data.namespaces.len());
        }
        Err(_) => {
            let fallback = target_namespace.unwrap_or(&default_ns);
            eprintln!(
                "[!] Cannot list namespaces cluster-wide (RBAC denied). Falling back to: {}",
                fallback
            );
            data.namespaces.push(NamespaceInfo {
                name: fallback.to_string(),
                pss_enforce: None,
                pss_audit: None,
                pss_warn: None,
                labels: std::collections::HashMap::new(),
                service_accounts: Vec::new(),
            });
        }
    }

    let target_namespaces: Vec<&str> = match target_namespace {
        Some(ns) => vec![ns],
        None => data.namespaces.iter().map(|n| n.name.as_str()).collect(),
    };

    eprintln!(
        "[*] Enumerating RBAC permissions across {} namespaces...",
        target_namespaces.len()
    );
    for ns in &target_namespaces {
        match rbac::get_permissions_in_namespace(client, ns).await {
            Ok(perms) => {
                if !perms.rules.is_empty() {
                    data.namespace_permissions.push(perms);
                }
            }
            Err(_) => {}
        }
    }
    eprintln!(
        "[+] Enumerated permissions in {} namespaces",
        data.namespace_permissions.len()
    );

    eprintln!("[*] Enumerating pods...");
    for ns in &target_namespaces {
        match pods::enumerate_pods(client, ns).await {
            Ok(mut pod_list) => data.pods.append(&mut pod_list),
            Err(_) => {}
        }
    }
    eprintln!("[+] Found {} pods", data.pods.len());

    eprintln!("[*] Checking secret accessibility...");
    for ns in &target_namespaces {
        match secrets::enumerate_secrets(client, ns).await {
            Ok(mut secret_list) => data.secrets_accessible.append(&mut secret_list),
            Err(_) => {}
        }
    }
    eprintln!("[+] {} secrets accessible", data.secrets_accessible.len());

    eprintln!("[*] Enumerating services...");
    for ns in &target_namespaces {
        match services::enumerate_services(client, ns).await {
            Ok(mut svc_list) => data.services.append(&mut svc_list),
            Err(_) => {}
        }
    }
    eprintln!("[+] Found {} services", data.services.len());

    eprintln!("[*] Enumerating configmaps...");
    for ns in &target_namespaces {
        match configmaps::enumerate_configmaps(client, ns).await {
            Ok(mut cm_list) => data.configmaps.append(&mut cm_list),
            Err(_) => {}
        }
    }
    eprintln!("[+] Found {} configmaps", data.configmaps.len());

    eprintln!("[*] Enumerating cronjobs...");
    for ns in &target_namespaces {
        match cronjobs::enumerate_cronjobs(client, ns).await {
            Ok(mut cj_list) => data.cronjobs.append(&mut cj_list),
            Err(_) => {}
        }
    }
    eprintln!("[+] Found {} cronjobs", data.cronjobs.len());

    // RBAC graph enumeration
    eprintln!("[*] Enumerating RBAC graph (roles, bindings, identities)...");
    match rbac_graph::enumerate_rbac_graph(client).await {
        Ok(graph) => {
            let profiles = graph.build_identity_profiles();
            let sa_count = profiles
                .iter()
                .filter(|p| p.kind == "ServiceAccount")
                .count();
            let user_count = profiles.iter().filter(|p| p.kind == "User").count();
            let group_count = profiles.iter().filter(|p| p.kind == "Group").count();
            eprintln!(
                "[+] RBAC graph: {} roles, {} bindings, {} identities ({} SAs, {} users, {} groups)",
                graph.roles.len(),
                graph.bindings.len(),
                profiles.len(),
                sa_count,
                user_count,
                group_count
            );
            data.rbac_graph = Some(graph);
        }
        Err(_) => {
            eprintln!("[!] Cannot enumerate RBAC graph (RBAC denied). Skipping identity analysis.");
        }
    }

    // CRD enumeration
    eprintln!("[*] Enumerating Custom Resource Definitions...");
    match crds::enumerate_crds(client).await {
        Ok(crd_list) => {
            let dangerous_count = crd_list
                .iter()
                .filter(|c| c.category != crds::CrdCategory::Other)
                .count();
            eprintln!(
                "[+] Found {} CRDs ({} with known attack surface)",
                crd_list.len(),
                dangerous_count
            );
            data.crds = crd_list;
        }
        Err(_) => {
            eprintln!("[!] Cannot enumerate CRDs (RBAC denied). Skipping CRD analysis.");
        }
    }

    // DNS service discovery (runs from inside a pod without RBAC)
    if data.pod_context.running_in_pod {
        eprintln!("[*] Running DNS service discovery...");
        let ns_names: Vec<String> = data.namespaces.iter().map(|n| n.name.clone()).collect();
        let dns_results = dns_discovery::discover_services(&ns_names);
        let count = dns_results.discovered_services.len();
        if count > 0 {
            eprintln!(
                "[+] DNS discovery: {} services found via CoreDNS",
                count
            );
        } else {
            eprintln!("[!] DNS discovery: no services resolved (DNS may be restricted)");
        }
        data.dns_discovery = Some(dns_results);
    }

    // Admission controller probing (dry-run, no pods created)
    eprintln!("[*] Probing admission controller enforcement...");
    let mut admission_count = 0;
    for ns in &target_namespaces {
        let result = admission::probe_namespace(client, ns).await;
        if result.can_create_pods {
            admission_count += 1;
        }
        data.admission_results.push(result);
    }
    if admission_count > 0 {
        eprintln!(
            "[+] Admission probing: {} namespaces probed ({} allow pod creation)",
            data.admission_results.len(),
            admission_count
        );
    } else {
        eprintln!("[!] Admission probing: cannot create pods in any namespace");
    }

    // Enumerate service accounts per namespace
    for ns_info in &mut data.namespaces {
        match rbac::get_service_accounts(client, &ns_info.name).await {
            Ok(sas) => ns_info.service_accounts = sas,
            Err(_) => {}
        }
    }

    // Build cluster info
    data.cluster_info = ClusterInfo {
        server: "".to_string(),
        version: "".to_string(),
        current_namespace: target_namespace.unwrap_or(&default_ns).to_string(),
        namespaces: data.namespaces.iter().map(|n| n.name.clone()).collect(),
    };

    Ok(data)
}
