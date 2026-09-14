use colored::Colorize;

use crate::analyzer::chains::{
    AttackChain, CrdFindingResult, Finding, IdentityProfile, NamespaceFinding, PodContextFinding,
    PodFinding, ScanResults, SecretFinding,
};
use crate::analyzer::patterns::Severity;

pub fn print_banner() {
    let banner = r#"
    ╦╔═╦ ╦╔╗ ╔═╗  ╦═╗╔═╗╔═╗╔═╗╔═╗╦═╗
    ╠╩╗║ ║╠╩╗║╣   ╠╦╝║╣ ╠═╣╠═╝║╣ ╠╦╝
    ╩ ╩╚═╝╚═╝╚═╝  ╩╚═╚═╝╩ ╩╩  ╚═╝╩╚═
    Kubernetes RBAC Attack Path Scanner
    "#;
    println!("{}", banner.red().bold());
}

pub fn print_results(results: &ScanResults) {
    print_banner();

    println!("{}", "═══════════════════════════════════════════════════════".bright_white());
    println!("  {} {}", "Identity:".bright_white().bold(), results.identity.cyan());
    println!(
        "  {} {}",
        "Namespace:".bright_white().bold(),
        results.cluster_info.current_namespace.cyan()
    );
    println!(
        "  {} {}",
        "Namespaces Found:".bright_white().bold(),
        results.cluster_info.namespaces.len().to_string().cyan()
    );
    println!(
        "  {} {}",
        "Findings:".bright_white().bold(),
        results.findings.len().to_string().yellow()
    );
    println!(
        "  {} {}",
        "Attack Chains:".bright_white().bold(),
        results.chains.len().to_string().red()
    );
    if !results.pod_findings.is_empty() {
        println!(
            "  {} {}",
            "Dangerous Pods:".bright_white().bold(),
            results.pod_findings.len().to_string().red()
        );
    }
    if !results.crd_findings.is_empty() {
        println!(
            "  {} {}",
            "CRD Attack Surface:".bright_white().bold(),
            results.crd_findings.len().to_string().yellow()
        );
    }
    if !results.identity_profiles.is_empty() {
        println!(
            "  {} {}",
            "Overprivileged Identities:".bright_white().bold(),
            results.identity_profiles.len().to_string().yellow()
        );
    }
    if !results.secret_findings.is_empty() {
        println!(
            "  {} {}",
            "Accessible Secrets:".bright_white().bold(),
            results.secret_findings.len().to_string().green()
        );
    }
    println!("{}", "═══════════════════════════════════════════════════════".bright_white());
    println!();

    if !results.pod_context_findings.is_empty() {
        print_pod_context(&results.pod_context_findings);
    }

    if !results.chains.is_empty() {
        print_attack_chains(&results.chains);
    }

    if !results.pod_findings.is_empty() {
        print_pod_findings(&results.pod_findings);
    }

    if !results.crd_findings.is_empty() {
        print_crd_findings(&results.crd_findings);
    }

    if !results.identity_profiles.is_empty() {
        print_identity_profiles(&results.identity_profiles);
    }

    if !results.secret_findings.is_empty() {
        print_secret_findings(&results.secret_findings);
    }

    if !results.namespace_findings.is_empty() {
        print_namespace_findings(&results.namespace_findings);
    }

    if !results.findings.is_empty() {
        print_findings(&results.findings);
    }

    print_summary(results);
}

fn severity_colored(severity: &Severity) -> colored::ColoredString {
    match severity {
        Severity::Critical => "CRITICAL".bright_red().bold(),
        Severity::High => "HIGH".red(),
        Severity::Medium => "MEDIUM".yellow(),
        Severity::Low => "LOW".blue(),
        Severity::Info => "INFO".white(),
    }
}

fn print_pod_context(findings: &[PodContextFinding]) {
    println!(
        "\n{}\n",
        "╔══════════════════════════════════════════════════╗"
            .bright_magenta()
            .bold()
    );
    println!(
        "{}",
        "║           POD CONTEXT ANALYSIS                   ║"
            .bright_magenta()
            .bold()
    );
    println!(
        "{}",
        "╚══════════════════════════════════════════════════╝"
            .bright_magenta()
            .bold()
    );
    println!(
        "  {}",
        "Running inside a Kubernetes pod".bright_magenta().bold()
    );
    println!();

    for finding in findings {
        println!(
            "    {} [{}] {}",
            "●".bright_white(),
            severity_colored(&finding.severity),
            finding.finding_type.bright_white().bold()
        );
        println!(
            "      {} {}",
            "│".bright_black(),
            finding.detail.white()
        );
        println!(
            "      {} {}: {}",
            "└".bright_black(),
            "Attack".bright_black(),
            finding.attack_path.bright_yellow()
        );
        println!();
    }
}

fn print_attack_chains(chains: &[AttackChain]) {
    println!(
        "\n{}\n",
        "╔══════════════════════════════════════════════════╗"
            .bright_red()
            .bold()
    );
    println!(
        "{}",
        "║           ATTACK PATH CHAINS                     ║"
            .bright_red()
            .bold()
    );
    println!(
        "{}",
        "╚══════════════════════════════════════════════════╝"
            .bright_red()
            .bold()
    );

    for (i, chain) in chains.iter().enumerate() {
        println!(
            "\n  {} [{}] {}",
            format!("Chain #{}", i + 1).bright_white().bold(),
            severity_colored(&chain.severity),
            chain.title.bright_white()
        );
        println!("  {}", "─".repeat(60).bright_black());
        println!("  {}", chain.description.bright_black());
        println!();

        for (j, step) in chain.steps.iter().enumerate() {
            let arrow = if j == chain.steps.len() - 1 {
                "└──▶".bright_red()
            } else {
                "├──▶".bright_yellow()
            };

            println!(
                "    {} {} {}",
                arrow,
                format!("[{}@{}]", step.identity, step.namespace).cyan(),
                step.action.white()
            );
            println!(
                "    {}   {} {} ({})",
                if j == chain.steps.len() - 1 { " " } else { "│" },
                "→".green(),
                step.result.green(),
                step.capability_gained.to_string().bright_yellow()
            );
        }

        println!(
            "\n    {} {}",
            "Final Capability:".bright_white().bold(),
            chain.final_capability.to_string().bright_red().bold()
        );
    }
}

fn print_pod_findings(findings: &[PodFinding]) {
    println!(
        "\n\n{}\n",
        "╔══════════════════════════════════════════════════╗"
            .bright_red()
            .bold()
    );
    println!(
        "{}",
        "║           DANGEROUS PODS                         ║"
            .bright_red()
            .bold()
    );
    println!(
        "{}",
        "╚══════════════════════════════════════════════════╝"
            .bright_red()
            .bold()
    );

    for pod in findings {
        println!(
            "\n  {} [{}] {}/{}",
            "●".bright_white(),
            severity_colored(&pod.severity),
            pod.namespace.cyan(),
            pod.pod_name.bright_white().bold()
        );
        println!(
            "    {} SA: {} | Image: {} | Node: {}",
            "│".bright_black(),
            pod.service_account.cyan(),
            pod.image.bright_black(),
            pod.node
                .as_deref()
                .unwrap_or("?")
                .to_string()
                .bright_black()
        );

        for (i, issue) in pod.issues.iter().enumerate() {
            let prefix = if i == pod.issues.len() - 1 {
                "└"
            } else {
                "├"
            };
            println!(
                "    {} {} {}",
                prefix.bright_black(),
                "⚠".bright_red(),
                issue.bright_yellow()
            );
        }

        println!(
            "    {} {}",
            "Attack:".bright_black(),
            pod.attack_path.bright_yellow()
        );
    }
}

fn print_crd_findings(findings: &[CrdFindingResult]) {
    println!(
        "\n\n{}\n",
        "╔══════════════════════════════════════════════════╗"
            .bright_cyan()
            .bold()
    );
    println!(
        "{}",
        "║           CRD ATTACK SURFACE                     ║"
            .bright_cyan()
            .bold()
    );
    println!(
        "{}",
        "╚══════════════════════════════════════════════════╝"
            .bright_cyan()
            .bold()
    );

    for finding in findings {
        println!(
            "\n  {} [{}] {} ({})",
            "●".bright_white(),
            severity_colored(&finding.severity),
            finding.kind.bright_white().bold(),
            finding.category.bright_cyan()
        );
        println!(
            "    {} CRD: {} | Group: {}",
            "│".bright_black(),
            finding.crd_name.bright_black(),
            finding.group.bright_black()
        );
        println!(
            "    {} Access: {}",
            "│".bright_black(),
            finding
                .your_access
                .join(", ")
                .cyan()
        );
        println!(
            "    {} {}: {}",
            "└".bright_black(),
            "Attack".bright_black(),
            finding.attack_path.bright_yellow()
        );
    }
}

fn print_identity_profiles(profiles: &[IdentityProfile]) {
    println!(
        "\n\n{}\n",
        "╔══════════════════════════════════════════════════╗"
            .bright_yellow()
            .bold()
    );
    println!(
        "{}",
        "║           OTHER IDENTITIES (PIVOT TARGETS)        ║"
            .bright_yellow()
            .bold()
    );
    println!(
        "{}",
        "╚══════════════════════════════════════════════════╝"
            .bright_yellow()
            .bold()
    );

    for profile in profiles {
        let overprivileged = if profile.is_overprivileged {
            " [WILDCARD ACCESS]".bright_red().bold()
        } else {
            "".normal()
        };

        println!(
            "\n  {} [{}] {} ({}){}",
            "●".bright_white(),
            severity_colored(&profile.severity),
            profile.identity.bright_white().bold(),
            profile.kind.bright_black(),
            overprivileged
        );
        println!(
            "    {} Roles: {}",
            "│".bright_black(),
            profile.bound_roles.join(", ").cyan()
        );
        println!(
            "    {} Namespaces: {}",
            "│".bright_black(),
            profile.namespaces.join(", ").bright_black()
        );

        let display_perms: Vec<&str> = profile
            .dangerous_permissions
            .iter()
            .take(5)
            .map(|s| s.as_str())
            .collect();
        let more = if profile.dangerous_permissions.len() > 5 {
            format!(" (+{} more)", profile.dangerous_permissions.len() - 5)
        } else {
            String::new()
        };
        println!(
            "    {} Dangerous: {}{}",
            "└".bright_black(),
            display_perms.join(", ").bright_yellow(),
            more.bright_black()
        );
    }
}

fn print_secret_findings(findings: &[SecretFinding]) {
    println!(
        "\n\n{}\n",
        "╔══════════════════════════════════════════════════╗"
            .bright_green()
            .bold()
    );
    println!(
        "{}",
        "║           SECRET TRIAGE                          ║"
            .bright_green()
            .bold()
    );
    println!(
        "{}",
        "╚══════════════════════════════════════════════════╝"
            .bright_green()
            .bold()
    );

    for secret in findings {
        println!(
            "\n  {} [{}] {}/{} ({})",
            "●".bright_white(),
            severity_colored(&secret.severity),
            secret.namespace.cyan(),
            secret.name.bright_white().bold(),
            secret.category.bright_green()
        );
        println!(
            "    {} Type: {}",
            "│".bright_black(),
            secret.secret_type.bright_black()
        );
        println!(
            "    {} {}: {}",
            "└".bright_black(),
            "Attack".bright_black(),
            secret.attack_path.bright_yellow()
        );
    }
}

fn print_namespace_findings(findings: &[NamespaceFinding]) {
    println!(
        "\n\n{}\n",
        "╔══════════════════════════════════════════════════╗"
            .yellow()
            .bold()
    );
    println!(
        "{}",
        "║           NAMESPACE SECURITY                     ║"
            .yellow()
            .bold()
    );
    println!(
        "{}",
        "╚══════════════════════════════════════════════════╝"
            .yellow()
            .bold()
    );

    for ns in findings {
        let pss_status = if ns.has_pss {
            format!(
                "PSS: {}",
                ns.pss_level.as_deref().unwrap_or("unknown")
            )
            .green()
        } else {
            "NO PSS ENFORCEMENT".bright_red().bold()
        };

        let pod_create = if ns.can_create_pods {
            "can create pods".bright_yellow()
        } else {
            "cannot create pods".bright_black()
        };

        let breakout = if ns.privileged_pod_path {
            " <- PRIVILEGED POD BREAKOUT PATH".bright_red().bold()
        } else {
            "".normal()
        };

        println!(
            "  {} {} | {} | {}{}",
            "●".bright_white(),
            ns.namespace.cyan().bold(),
            pss_status,
            pod_create,
            breakout
        );
    }
}

fn print_findings(findings: &[Finding]) {
    println!(
        "\n\n{}\n",
        "╔══════════════════════════════════════════════════╗"
            .bright_white()
            .bold()
    );
    println!(
        "{}",
        "║           DANGEROUS PERMISSIONS                  ║"
            .bright_white()
            .bold()
    );
    println!(
        "{}",
        "╚══════════════════════════════════════════════════╝"
            .bright_white()
            .bold()
    );

    let mut current_severity: Option<Severity> = None;

    for finding in findings {
        if current_severity.as_ref() != Some(&finding.severity) {
            current_severity = Some(finding.severity);
            println!(
                "\n  {} {}",
                "▸".bright_white(),
                severity_colored(&finding.severity)
            );
            println!("  {}", "─".repeat(50).bright_black());
        }

        let unconventional_tag = if finding.unconventional {
            " [UNCONVENTIONAL]".bright_magenta().bold()
        } else {
            "".normal()
        };

        println!(
            "    {} {} ({}@{}){}",
            "●".bright_white(),
            finding.title.bright_white().bold(),
            finding.identity.cyan(),
            finding.namespace.cyan(),
            unconventional_tag
        );
        println!(
            "      {} {}: {}",
            "│".bright_black(),
            "Resource".bright_black(),
            format!("{} [{}]", finding.resource, finding.verbs.join(", ")).white()
        );
        println!(
            "      {} {}: {}",
            "│".bright_black(),
            "Attack".bright_black(),
            finding.attack_path.bright_yellow()
        );
        println!(
            "      {} {}: {}",
            "└".bright_black(),
            "Enables".bright_black(),
            finding
                .capabilities
                .iter()
                .map(|c| c.to_string())
                .collect::<Vec<_>>()
                .join(", ")
                .bright_red()
        );
        println!();
    }
}

fn print_summary(results: &ScanResults) {
    println!(
        "\n{}\n",
        "═══════════════════════════════════════════════════════".bright_white()
    );
    println!("{}", "  SUMMARY".bright_white().bold());
    println!(
        "{}",
        "═══════════════════════════════════════════════════════".bright_white()
    );

    let critical = results
        .findings
        .iter()
        .filter(|f| f.severity == Severity::Critical)
        .count();
    let high = results
        .findings
        .iter()
        .filter(|f| f.severity == Severity::High)
        .count();
    let medium = results
        .findings
        .iter()
        .filter(|f| f.severity == Severity::Medium)
        .count();
    let low = results
        .findings
        .iter()
        .filter(|f| f.severity == Severity::Low)
        .count();
    let unconventional = results.findings.iter().filter(|f| f.unconventional).count();

    let breakout_ns = results
        .namespace_findings
        .iter()
        .filter(|f| f.privileged_pod_path)
        .count();

    println!(
        "  {} {}  {} {}  {} {}  {} {}",
        "CRITICAL:".bright_red().bold(),
        critical.to_string().bright_red().bold(),
        "HIGH:".red(),
        high.to_string().red(),
        "MEDIUM:".yellow(),
        medium.to_string().yellow(),
        "LOW:".blue(),
        low.to_string().blue()
    );
    println!(
        "  {} {}",
        "Unconventional RBAC Abuses:".bright_magenta().bold(),
        unconventional.to_string().bright_magenta()
    );
    println!(
        "  {} {}",
        "Attack Chains:".bright_red().bold(),
        results.chains.len().to_string().bright_red()
    );
    println!(
        "  {} {}",
        "Privileged Pod Breakout Paths:".bright_red().bold(),
        breakout_ns.to_string().bright_red()
    );

    if !results.pod_findings.is_empty() {
        let critical_pods = results
            .pod_findings
            .iter()
            .filter(|p| p.severity == Severity::Critical)
            .count();
        println!(
            "  {} {} ({} critical)",
            "Dangerous Pods:".bright_red().bold(),
            results.pod_findings.len().to_string().bright_red(),
            critical_pods.to_string().bright_red().bold()
        );
    }

    if !results.crd_findings.is_empty() {
        println!(
            "  {} {}",
            "CRD Attack Surface:".bright_cyan().bold(),
            results.crd_findings.len().to_string().bright_cyan()
        );
    }

    if !results.identity_profiles.is_empty() {
        let critical_ids = results
            .identity_profiles
            .iter()
            .filter(|p| p.severity == Severity::Critical)
            .count();
        println!(
            "  {} {} ({} with critical perms)",
            "Pivot Target Identities:".bright_yellow().bold(),
            results.identity_profiles.len().to_string().bright_yellow(),
            critical_ids.to_string().bright_red().bold()
        );
    }

    if !results.secret_findings.is_empty() {
        let sa_tokens = results
            .secret_findings
            .iter()
            .filter(|s| s.category == "SA Token")
            .count();
        println!(
            "  {} {} ({} SA tokens for identity pivot)",
            "Accessible Secrets:".bright_green().bold(),
            results.secret_findings.len().to_string().bright_green(),
            sa_tokens.to_string().bright_red().bold()
        );
    }

    println!();
}
