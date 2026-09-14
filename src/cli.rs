use clap::{Parser, ValueEnum};

#[derive(Parser, Debug)]
#[command(
    name = "kube-reaper",
    about = "Kubernetes RBAC Attack Path Scanner",
    long_about = "Enumerate RBAC permissions, flag dangerous misconfigurations, and chain attack paths from your current identity to cluster compromise.",
    version
)]
pub struct Cli {
    /// Target namespace (default: scan all accessible namespaces)
    #[arg(short, long)]
    pub namespace: Option<String>,

    /// Path to kubeconfig file
    #[arg(short, long, env = "KUBECONFIG")]
    pub kubeconfig: Option<String>,

    /// Authenticate with a raw bearer token (requires --server)
    #[arg(long)]
    pub token: Option<String>,

    /// API server URL (required with --token, e.g. https://10.3.10.20:6443)
    #[arg(long)]
    pub server: Option<String>,

    /// Scan as a different user (requires impersonate permissions)
    #[arg(long, value_name = "USER")]
    pub as_user: Option<String>,

    /// Scan as a different group (requires impersonate permissions)
    #[arg(long, value_name = "GROUP")]
    pub as_group: Option<String>,

    /// Output format
    #[arg(short, long, default_value = "terminal")]
    pub output: OutputFormat,

    /// Write results to file (JSON format)
    #[arg(short = 'w', long)]
    pub write: Option<String>,

    /// Only show findings at or above this severity
    #[arg(short, long, default_value = "low")]
    pub severity: SeverityFilter,

    /// Show only unconventional RBAC abuses
    #[arg(long)]
    pub unconventional_only: bool,

    /// Show only attack chains (skip individual findings)
    #[arg(long)]
    pub chains_only: bool,
}

#[derive(Debug, Clone, ValueEnum)]
pub enum OutputFormat {
    Terminal,
    Json,
}

#[derive(Debug, Clone, ValueEnum)]
pub enum SeverityFilter {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl SeverityFilter {
    pub fn to_severity(&self) -> crate::analyzer::patterns::Severity {
        match self {
            SeverityFilter::Critical => crate::analyzer::patterns::Severity::Critical,
            SeverityFilter::High => crate::analyzer::patterns::Severity::High,
            SeverityFilter::Medium => crate::analyzer::patterns::Severity::Medium,
            SeverityFilter::Low => crate::analyzer::patterns::Severity::Low,
            SeverityFilter::Info => crate::analyzer::patterns::Severity::Info,
        }
    }
}
