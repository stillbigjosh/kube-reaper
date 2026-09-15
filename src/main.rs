mod analyzer;
mod cli;
mod output;
mod scanner;

use anyhow::{bail, Result};
use clap::Parser;
use kube::Client;

use cli::{Cli, OutputFormat};

#[tokio::main]
async fn main() -> Result<()> {
    let args = Cli::parse();

    // Pod context detection runs first (no API needed, pure filesystem)
    let pod_context = scanner::pod_context::detect_pod_context();
    let in_pod = pod_context.running_in_pod;
    let pod_identity = pod_context.sa_name.as_ref().map(|n| {
        format!(
            "system:serviceaccount:{}:{}",
            pod_context.sa_namespace.as_deref().unwrap_or("unknown"),
            n
        )
    });

    // Try to build kube client. If it fails and we're in a pod, degrade to local-only mode.
    let scan_data = match build_client(&args).await {
        Ok(client) => {
            scanner::run_scan(&client, args.namespace.as_deref(), pod_context).await?
        }
        Err(e) => {
            if in_pod {
                eprintln!(
                    "[!] API client failed: {}",
                    e
                );
                eprintln!("[*] Running in local-only mode (no API access).");
                scanner::ScanData {
                    identity: pod_identity
                        .unwrap_or_else(|| "unknown (no API access)".to_string()),
                    pod_context,
                    ..Default::default()
                }
            } else {
                bail!("Cannot connect to cluster: {}", e);
            }
        }
    };

    let mut results = analyzer::analyze(&scan_data)?;

    let min_severity = args.severity.to_severity();
    results.findings.retain(|f| f.severity <= min_severity);
    results.chains.retain(|c| c.severity <= min_severity);

    if args.unconventional_only {
        results.findings.retain(|f| f.unconventional);
    }

    match args.output {
        OutputFormat::Terminal => {
            if args.chains_only {
                output::terminal::print_banner();
            }
            output::terminal::print_results(&results);
        }
        OutputFormat::Json => {
            output::json::print_json(&results)?;
        }
    }

    if let Some(path) = &args.write {
        output::json::write_json(&results, path)?;
    }

    Ok(())
}

async fn build_client(args: &Cli) -> Result<Client> {
    if let Some(token) = &args.token {
        let server = match &args.server {
            Some(s) => s.clone(),
            None => bail!("--server is required when using --token"),
        };

        let mut config = kube::Config::new(server.parse()?);
        config.auth_info.token = Some(secrecy::SecretString::from(token.clone()));
        config.accept_invalid_certs = true;

        if let Some(ref user) = args.as_user {
            config.auth_info.impersonate = Some(user.clone());
        }
        if let Some(ref group) = args.as_group {
            config.auth_info.impersonate_groups = Some(vec![group.clone()]);
        }

        return Client::try_from(config).map_err(Into::into);
    }

    let config = match &args.kubeconfig {
        Some(path) => {
            std::env::set_var("KUBECONFIG", path);
            let mut cfg =
                kube::Config::from_kubeconfig(&kube::config::KubeConfigOptions::default()).await?;
            if let Some(ref user) = args.as_user {
                cfg.auth_info.impersonate = Some(user.clone());
            }
            if let Some(ref group) = args.as_group {
                cfg.auth_info.impersonate_groups = Some(vec![group.clone()]);
            }
            cfg
        }
        None => {
            let mut cfg = kube::Config::infer().await?;
            if let Some(ref user) = args.as_user {
                cfg.auth_info.impersonate = Some(user.clone());
            }
            if let Some(ref group) = args.as_group {
                cfg.auth_info.impersonate_groups = Some(vec![group.clone()]);
            }
            cfg
        }
    };

    Client::try_from(config).map_err(Into::into)
}
