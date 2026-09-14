use anyhow::Result;
use k8s_openapi::api::rbac::v1::{
    ClusterRole, ClusterRoleBinding, Role, RoleBinding,
};
use kube::api::{Api, ListParams};
use kube::Client;

use super::PermissionRule;

#[derive(Debug, Clone)]
pub struct RbacSubject {
    pub kind: String,
    pub name: String,
    pub namespace: Option<String>,
}

impl RbacSubject {
    pub fn identity_string(&self) -> String {
        match self.kind.as_str() {
            "ServiceAccount" => {
                let ns = self.namespace.as_deref().unwrap_or("default");
                format!("system:serviceaccount:{}:{}", ns, self.name)
            }
            _ => self.name.clone(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct RbacPolicyRule {
    pub api_groups: Vec<String>,
    pub resources: Vec<String>,
    pub verbs: Vec<String>,
    pub resource_names: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct RbacRoleInfo {
    pub name: String,
    pub namespace: Option<String>,
    pub is_cluster_role: bool,
    pub rules: Vec<RbacPolicyRule>,
}

#[derive(Debug, Clone)]
pub struct RbacBindingInfo {
    pub name: String,
    pub namespace: Option<String>,
    pub role_ref_name: String,
    pub role_ref_kind: String,
    pub subjects: Vec<RbacSubject>,
}

#[derive(Debug, Default)]
pub struct RbacGraph {
    pub roles: Vec<RbacRoleInfo>,
    pub bindings: Vec<RbacBindingInfo>,
}

#[derive(Debug, Clone)]
pub struct IdentityRbacProfile {
    pub identity: String,
    pub kind: String,
    pub namespace: Option<String>,
    pub bound_roles: Vec<String>,
    pub effective_rules: Vec<PermissionRule>,
    pub namespaces_with_access: Vec<String>,
}

impl RbacGraph {
    pub fn build_identity_profiles(&self) -> Vec<IdentityRbacProfile> {
        let mut profiles: std::collections::HashMap<String, IdentityRbacProfile> =
            std::collections::HashMap::new();

        for binding in &self.bindings {
            let role = self.roles.iter().find(|r| {
                r.name == binding.role_ref_name
                    && ((binding.role_ref_kind == "ClusterRole" && r.is_cluster_role)
                        || (binding.role_ref_kind == "Role"
                            && !r.is_cluster_role
                            && r.namespace == binding.namespace))
            });

            let role = match role {
                Some(r) => r,
                None => continue,
            };

            for subject in &binding.subjects {
                let identity = subject.identity_string();

                let profile = profiles.entry(identity.clone()).or_insert_with(|| {
                    IdentityRbacProfile {
                        identity: identity.clone(),
                        kind: subject.kind.clone(),
                        namespace: subject.namespace.clone(),
                        bound_roles: Vec::new(),
                        effective_rules: Vec::new(),
                        namespaces_with_access: Vec::new(),
                    }
                });

                let role_display = if role.is_cluster_role {
                    format!("ClusterRole/{}", role.name)
                } else {
                    format!(
                        "Role/{}/{}",
                        role.namespace.as_deref().unwrap_or("?"),
                        role.name
                    )
                };
                if !profile.bound_roles.contains(&role_display) {
                    profile.bound_roles.push(role_display);
                }

                let effective_ns = binding
                    .namespace
                    .clone()
                    .unwrap_or_else(|| "cluster-wide".to_string());
                if !profile.namespaces_with_access.contains(&effective_ns) {
                    profile.namespaces_with_access.push(effective_ns.clone());
                }

                for rule in &role.rules {
                    for resource in &rule.resources {
                        for api_group in &rule.api_groups {
                            let perm = PermissionRule {
                                resource: resource.clone(),
                                api_group: api_group.clone(),
                                verbs: rule.verbs.clone(),
                                resource_names: rule.resource_names.clone(),
                            };
                            profile.effective_rules.push(perm);
                        }
                    }
                }
            }
        }

        let mut result: Vec<IdentityRbacProfile> = profiles.into_values().collect();
        result.sort_by(|a, b| a.identity.cmp(&b.identity));
        result
    }
}

pub async fn enumerate_rbac_graph(client: &Client) -> Result<RbacGraph> {
    let mut graph = RbacGraph::default();

    if let Ok(roles) = enumerate_cluster_roles(client).await {
        graph.roles.extend(roles);
    }
    if let Ok(bindings) = enumerate_cluster_role_bindings(client).await {
        graph.bindings.extend(bindings);
    }
    if let Ok(roles) = enumerate_all_roles(client).await {
        graph.roles.extend(roles);
    }
    if let Ok(bindings) = enumerate_all_role_bindings(client).await {
        graph.bindings.extend(bindings);
    }

    Ok(graph)
}

async fn enumerate_cluster_roles(client: &Client) -> Result<Vec<RbacRoleInfo>> {
    let api: Api<ClusterRole> = Api::all(client.clone());
    let list = api.list(&ListParams::default()).await?;

    Ok(list
        .items
        .into_iter()
        .map(|cr| {
            let rules = cr
                .rules
                .unwrap_or_default()
                .into_iter()
                .map(|r| RbacPolicyRule {
                    api_groups: r.api_groups.unwrap_or_default(),
                    resources: r.resources.unwrap_or_default(),
                    verbs: r.verbs,
                    resource_names: r.resource_names.unwrap_or_default(),
                })
                .collect();

            RbacRoleInfo {
                name: cr.metadata.name.unwrap_or_default(),
                namespace: None,
                is_cluster_role: true,
                rules,
            }
        })
        .collect())
}

async fn enumerate_all_roles(client: &Client) -> Result<Vec<RbacRoleInfo>> {
    let api: Api<Role> = Api::all(client.clone());
    let list = api.list(&ListParams::default()).await?;

    Ok(list
        .items
        .into_iter()
        .map(|r| {
            let rules = r
                .rules
                .unwrap_or_default()
                .into_iter()
                .map(|rule| RbacPolicyRule {
                    api_groups: rule.api_groups.unwrap_or_default(),
                    resources: rule.resources.unwrap_or_default(),
                    verbs: rule.verbs,
                    resource_names: rule.resource_names.unwrap_or_default(),
                })
                .collect();

            RbacRoleInfo {
                name: r.metadata.name.unwrap_or_default(),
                namespace: r.metadata.namespace,
                is_cluster_role: false,
                rules,
            }
        })
        .collect())
}

async fn enumerate_cluster_role_bindings(client: &Client) -> Result<Vec<RbacBindingInfo>> {
    let api: Api<ClusterRoleBinding> = Api::all(client.clone());
    let list = api.list(&ListParams::default()).await?;

    Ok(list
        .items
        .into_iter()
        .map(|crb| {
            let subjects = crb
                .subjects
                .unwrap_or_default()
                .into_iter()
                .map(|s| RbacSubject {
                    kind: s.kind,
                    name: s.name,
                    namespace: s.namespace,
                })
                .collect();

            RbacBindingInfo {
                name: crb.metadata.name.unwrap_or_default(),
                namespace: None,
                role_ref_name: crb.role_ref.name,
                role_ref_kind: crb.role_ref.kind,
                subjects,
            }
        })
        .collect())
}

async fn enumerate_all_role_bindings(client: &Client) -> Result<Vec<RbacBindingInfo>> {
    let api: Api<RoleBinding> = Api::all(client.clone());
    let list = api.list(&ListParams::default()).await?;

    Ok(list
        .items
        .into_iter()
        .map(|rb| {
            let subjects = rb
                .subjects
                .unwrap_or_default()
                .into_iter()
                .map(|s| RbacSubject {
                    kind: s.kind,
                    name: s.name,
                    namespace: s.namespace,
                })
                .collect();

            RbacBindingInfo {
                name: rb.metadata.name.unwrap_or_default(),
                namespace: rb.metadata.namespace,
                role_ref_name: rb.role_ref.name,
                role_ref_kind: rb.role_ref.kind,
                subjects,
            }
        })
        .collect())
}
