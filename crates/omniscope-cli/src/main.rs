//! OmniScope CLI entry point
//!
//! This is the main entry point for the OmniScope static analyzer.
//! It provides three subcommands:
//! - `analyze`: Full pipeline analysis with rich/JSON/SARIF output
//! - `audit`: Language-specific FFI audit
//! - `info`: Show configuration and pass information

mod output;

use clap::Parser;
use omniscope_ir::loader_v2::{load_ir, LoadStrategy};
use omniscope_pipeline::Pipeline;
use output::json::JsonFormatter;
use output::rich::RichFormatter;
use output::sarif::SarifFormatter;
use output::{OutputFormat, OutputFormatter};
use std::path::PathBuf;
use std::time::Instant;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(name = "omniscope")]
#[command(version, about = "LLVM IR-based static analyzer for FFI safety", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(clap::Subcommand)]
enum Commands {
    /// Analyze LLVM IR file for safety issues
    Analyze(AnalyzeCommand),

    /// Run audit on specific language FFI patterns
    Audit(AuditCommand),

    /// Show configuration and statistics
    Info(InfoCommand),
}

#[derive(clap::Args)]
struct AnalyzeCommand {
    /// Input LLVM IR file (.ll or .bc)
    #[arg(value_name = "INPUT")]
    input: PathBuf,

    /// Output file path (stdout if omitted)
    #[arg(short, long)]
    output: Option<PathBuf>,

    /// Output format (rich, json, sarif)
    #[arg(short = 'f', long, default_value = "rich")]
    format: String,

    /// Target language (c, cpp, rust, zig, go, python, java)
    #[arg(short = 'l', long)]
    language: Option<String>,

    /// Enable verbose output (pipeline metrics)
    #[arg(short, long)]
    verbose: bool,

    /// Enable debug-level logging (full trace)
    #[arg(long)]
    debug: bool,

    /// Run in parallel mode
    #[arg(long, default_value = "false")]
    parallel: bool,

    /// IR loading strategy (auto, llvm-sys, cpp-pass, text-parser)
    #[arg(long, default_value = "auto")]
    strategy: String,

    /// Only show FFI boundary issues (cross-language memory safety)
    #[arg(short = 'b', long)]
    boundary_only: bool,
}

#[derive(clap::Args)]
struct AuditCommand {
    /// Input LLVM IR file
    #[arg(value_name = "INPUT")]
    input: PathBuf,

    /// Target language for audit
    #[arg(short = 'l', long)]
    language: String,

    /// Audit type (ffi, memory, concurrency)
    #[arg(short = 't', long, default_value = "ffi")]
    audit_type: String,

    /// IR loading strategy (auto, llvm-sys, cpp-pass, text-parser)
    #[arg(long, default_value = "auto")]
    strategy: String,
}

#[derive(clap::Args)]
struct InfoCommand {
    /// Show pass information
    #[arg(long)]
    passes: bool,
}

fn main() -> anyhow::Result<()> {
    // Parse CLI first so we can determine the desired log level.
    // CLI parsing is lightweight and does not need tracing.
    let cli = Cli::parse();

    // Determine default log level from --debug / --verbose flags.
    // RUST_LOG env var always takes precedence when set.
    let default_level = match &cli.command {
        Commands::Analyze(cmd) if cmd.debug => "omniscope=trace",
        Commands::Analyze(cmd) if cmd.verbose => "omniscope=debug",
        _ => "omniscope=warn",
    };
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_level));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .init();

    let start = Instant::now();

    match cli.command {
        Commands::Analyze(cmd) => {
            run_analyze(cmd, start)?;
        }
        Commands::Audit(cmd) => {
            run_audit(cmd, start)?;
        }
        Commands::Info(cmd) => {
            run_info(cmd)?;
        }
    }

    Ok(())
}

/// Runs the analyze command — the primary analysis entry point.
fn run_analyze(cmd: AnalyzeCommand, start: Instant) -> anyhow::Result<()> {
    tracing::info!("Starting analysis of {:?}", cmd.input);
    tracing::debug!("Format: {}, Parallel: {}", cmd.format, cmd.parallel);

    // Parse the IR file — auto-detects best backend (llvm-sys > cpp pass > text)
    let strategy = parse_strategy(&cmd.strategy);
    tracing::info!(
        "Parsing LLVM IR from {:?} (strategy: {})",
        cmd.input,
        strategy
    );
    let module = load_ir(&cmd.input, strategy)?;
    let func_count = module.functions.len();
    let decl_count = module.declarations.len();
    tracing::info!(
        "IR parsed: {} functions, {} declarations, {} calls",
        func_count,
        decl_count,
        module.calls.len()
    );

    // Create and configure pipeline
    let mut pipeline = Pipeline::new();
    pipeline.register_default_passes();
    pipeline.set_parallel(cmd.parallel);
    pipeline.set_ir_module(module);
    tracing::debug!("Pipeline configured with {} passes", pipeline.pass_count());

    // Run the full analysis pipeline
    tracing::info!("Running analysis pipeline");
    let result = pipeline.run()?;
    tracing::info!(
        "Pipeline completed: {} issues, {} nodes, {}ms",
        result.total_issues,
        result.total_nodes,
        result.duration_ms()
    );

    // Apply boundary-only filter if requested
    let result = if cmd.boundary_only {
        filter_boundary_issues(result)
    } else {
        result
    };

    // Format output according to selected format
    let fmt = OutputFormat::from_str_ignore_case(&cmd.format);
    let output = match fmt {
        OutputFormat::Rich => RichFormatter::new().format(&result),
        OutputFormat::Json => {
            // Use compact JSON for file output, pretty for terminal
            let formatter = if cmd.output.is_some() {
                JsonFormatter::compact()
            } else {
                JsonFormatter::from_pretty(true)
            };
            formatter.format(&result)
        }
        OutputFormat::Sarif => SarifFormatter::new().format(&result),
    };

    // Write output to file or stdout
    if let Some(ref out_path) = cmd.output {
        tracing::info!("Writing output to {:?}", out_path);
        std::fs::write(out_path, &output)?;
    } else {
        println!("{}", output);
    }

    // Verbose: print pipeline metrics
    if cmd.verbose {
        eprintln!("\n--- Pipeline Metrics ---");
        for pr in &result.pass_results {
            eprintln!(
                "  {:30} {} issues, {} nodes, {}ms",
                pr.name, pr.issues_found, pr.nodes_analyzed, pr.duration_ms
            );
        }
        eprintln!(
            "  {:30} {} total issues, {}ms",
            "TOTAL",
            result.total_issues,
            result.duration_ms()
        );
    }

    let duration = start.elapsed();
    tracing::info!("Analysis completed in {:?}", duration);

    Ok(())
}

/// Filters pipeline result to only include FFI boundary issues.
///
/// This creates a new `PipelineResult` containing only issues that
/// cross language boundaries (FFI safety issues). Local memory issues
/// like double-free or use-after-free are excluded.
fn filter_boundary_issues(
    result: omniscope_pipeline::PipelineResult,
) -> omniscope_pipeline::PipelineResult {
    // Filter issues to only include FFI boundary issues
    let boundary_issues: Vec<omniscope_core::Issue> = result
        .issues
        .into_iter()
        .filter(|issue| issue.kind.is_ffi_boundary())
        .collect();

    // Create a new pipeline result with filtered issues
    // We need to adjust the pass_results to reflect the filtered count
    let mut filtered_pass_results = result.pass_results;
    for pr in &mut filtered_pass_results {
        // Count how many issues from this pass are boundary issues
        // Note: We filter based on issue kind since we don't track which pass created which issue
        let boundary_count = pr
            .issues
            .iter()
            .filter(|issue| issue.kind.is_ffi_boundary())
            .count();
        pr.issues_found = boundary_count;
        // Clear the issues vector since we'll use the aggregated boundary_issues
        pr.issues.clear();
    }

    let total_nodes = filtered_pass_results.iter().map(|r| r.nodes_analyzed).sum();

    omniscope_pipeline::PipelineResult {
        pass_results: filtered_pass_results,
        total_issues: boundary_issues.len(),
        total_nodes,
        duration: result.duration,
        stats: result.stats,
        issues: boundary_issues,
    }
}

/// Runs the audit command — language-specific FFI audit.
fn run_audit(cmd: AuditCommand, start: Instant) -> anyhow::Result<()> {
    use colored::Colorize;

    tracing::info!(
        "Starting FFI audit: lang={}, type={}",
        cmd.language,
        cmd.audit_type
    );

    println!("{}", "OmniScope FFI Auditor".cyan().bold());
    println!("{}", "═".repeat(50).dimmed());

    println!("{} {:?}", "Input:".green(), cmd.input);
    println!("{} {}", "Language:".green(), cmd.language);
    println!("{} {}", "Audit type:".green(), cmd.audit_type);

    // Parse the IR file — auto-detects best backend (llvm-sys > cpp pass > text)
    let strategy = parse_strategy(&cmd.strategy);
    tracing::info!(
        "Parsing LLVM IR from {:?} (strategy: {})",
        cmd.input,
        strategy
    );
    let module = load_ir(&cmd.input, strategy)?;

    // Create pipeline and load IR
    let mut pipeline = Pipeline::new();
    pipeline.register_default_passes();
    pipeline.set_ir_module(module);

    // Run analysis
    let result = pipeline.run()?;
    let duration = start.elapsed();

    println!("{}", "═".repeat(50).dimmed());
    println!("Audit completed: {} issues found", result.issue_count());
    println!("Completed in {:?}", duration);

    Ok(())
}

/// Parses a strategy string into a [`LoadStrategy`].
fn parse_strategy(s: &str) -> LoadStrategy {
    match s.to_lowercase().as_str() {
        "llvm-sys" | "llvm_sys" | "llvmsys" => LoadStrategy::LlvmSys,
        "cpp-pass" | "cpp_pass" | "cpppass" => LoadStrategy::CppPass,
        "text-parser" | "text_parser" | "textparser" | "text" => LoadStrategy::TextParser,
        _ => LoadStrategy::Auto,
    }
}

/// Runs the info command — display configuration and pass info.
fn run_info(cmd: InfoCommand) -> anyhow::Result<()> {
    use colored::Colorize;

    println!("{}", "OmniScope Information".cyan().bold());
    println!("{}", "═".repeat(50).dimmed());

    println!("{} {}", "Version:".green(), env!("CARGO_PKG_VERSION"));
    println!(
        "{} {}",
        "Description:".green(),
        env!("CARGO_PKG_DESCRIPTION")
    );

    if cmd.passes {
        println!("\n{}", "Available Passes:".yellow().bold());
        println!("  Foundation:");
        println!("    - CFG (Control Flow Graph)");
        println!("    - DFG (Data Flow Graph)");
        println!("    - CallGraph (Call graph construction)");
        println!("  Analysis:");
        println!("    - FFIBoundary (FFI boundary detection)");
        println!("    - SurfaceClassifier (Function surface classification)");
        println!("    - DangerSurface (Danger surface analysis)");
        println!("    - MemorySafety (Memory safety analysis)");
        println!("    - PointerOwnership (Ownership tracking)");
        println!("    - BufferOverflow (Buffer overflow detection)");
        println!("  Filtering:");
        println!("    - NoiseReduction (False positive suppression)");
        println!("    - PrecisionMetrics (Precision gate with 88% threshold)");
        println!("\n{}", "Output Formats:".yellow().bold());
        println!("    - rich   (colored terminal output with detection paths)");
        println!("    - json   (machine-readable JSON)");
        println!("    - sarif  (GitHub Code Scanning integration)");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use omniscope_core::{Issue, IssueKind, Severity};
    use omniscope_pass::PassResult;
    use std::time::Duration;

    /// Objective: Verify that boundary-only filter correctly filters FFI boundary issues.
    /// Invariants: Only issues with FFI boundary kinds (CrossLanguageFree, OwnershipViolation, etc.) should remain.
    #[test]
    fn test_filter_boundary_issues() {
        // Create test issues with mixed kinds
        let issues = vec![
            Issue::new(
                1,
                IssueKind::CrossLanguageFree,
                Severity::Error,
                "Rust frees C-allocated memory",
            ),
            Issue::new(
                2,
                IssueKind::DoubleFree,
                Severity::Warning,
                "Double free of allocation",
            ),
            Issue::new(
                3,
                IssueKind::OwnershipViolation,
                Severity::Error,
                "Ownership transfer violation across FFI",
            ),
            Issue::new(
                4,
                IssueKind::MemoryLeak,
                Severity::Note,
                "Memory leak in local scope",
            ),
            Issue::new(
                5,
                IssueKind::FfiTypeMismatch,
                Severity::Warning,
                "ABI type mismatch at boundary",
            ),
        ];

        // Create a pass result with the issues
        let mut pass_result = PassResult::new("FFIBoundary").with_nodes(10);
        for issue in &issues {
            pass_result.add_issue(issue.clone());
        }

        let pass_results = vec![pass_result];
        let result = omniscope_pipeline::PipelineResult::from_pass_results(
            pass_results,
            Duration::from_millis(100),
        );

        // Apply the filter
        let filtered = filter_boundary_issues(result);

        // Verify only FFI boundary issues remain
        assert_eq!(
            filtered.issues.len(),
            3,
            "Should have 3 FFI boundary issues (CrossLanguageFree, OwnershipViolation, FfiTypeMismatch)"
        );

        // Verify the correct issue kinds are present
        let kinds: Vec<IssueKind> = filtered.issues.iter().map(|i| i.kind).collect();
        assert!(
            kinds.contains(&IssueKind::CrossLanguageFree),
            "Filtered issues must contain CrossLanguageFree"
        );
        assert!(
            kinds.contains(&IssueKind::OwnershipViolation),
            "Filtered issues must contain OwnershipViolation"
        );
        assert!(
            kinds.contains(&IssueKind::FfiTypeMismatch),
            "Filtered issues must contain FfiTypeMismatch"
        );

        // Verify local memory issues are excluded
        assert!(
            !kinds.contains(&IssueKind::DoubleFree),
            "Filtered issues must not contain DoubleFree"
        );
        assert!(
            !kinds.contains(&IssueKind::MemoryLeak),
            "Filtered issues must not contain MemoryLeak"
        );

        // Verify total count is updated
        assert_eq!(
            filtered.total_issues, 3,
            "Total issues count must be updated to 3"
        );
    }

    /// Objective: Verify that boundary-only filter handles empty issue list.
    /// Invariants: Empty input should produce empty output with zero counts.
    #[test]
    fn test_filter_boundary_issues_empty() {
        let pass_result = PassResult::new("FFIBoundary").with_nodes(5);
        let result = omniscope_pipeline::PipelineResult::from_pass_results(
            vec![pass_result],
            Duration::from_millis(50),
        );

        let filtered = filter_boundary_issues(result);

        assert!(
            filtered.issues.is_empty(),
            "Filtered issues must be empty when input has no issues"
        );
        assert_eq!(
            filtered.total_issues, 0,
            "Total issues must be 0 when no issues exist"
        );
    }

    /// Objective: Verify that boundary-only filter handles all-local issues.
    /// Invariants: When all issues are local memory issues, result should have zero boundary issues.
    #[test]
    fn test_filter_boundary_issues_all_local() {
        let issues = vec![
            Issue::new(
                1,
                IssueKind::DoubleFree,
                Severity::Error,
                "Double free detected",
            ),
            Issue::new(
                2,
                IssueKind::UseAfterFree,
                Severity::Warning,
                "Use after free detected",
            ),
            Issue::new(
                3,
                IssueKind::MemoryLeak,
                Severity::Note,
                "Memory leak detected",
            ),
        ];

        let mut pass_result = PassResult::new("MemorySafety").with_nodes(15);
        for issue in &issues {
            pass_result.add_issue(issue.clone());
        }

        let result = omniscope_pipeline::PipelineResult::from_pass_results(
            vec![pass_result],
            Duration::from_millis(75),
        );

        let filtered = filter_boundary_issues(result);

        assert!(
            filtered.issues.is_empty(),
            "Filtered issues must be empty when all issues are local memory issues"
        );
        assert_eq!(
            filtered.total_issues, 0,
            "Total issues must be 0 when no boundary issues exist"
        );
    }

    /// Objective: Verify that boundary-only filter preserves issue details.
    /// Invariants: Issue ID, severity, description, and other fields must be preserved.
    #[test]
    fn test_filter_boundary_issues_preserves_details() {
        let issue = Issue::new(
            42,
            IssueKind::CrossLanguageFree,
            Severity::Error,
            "Critical: Rust frees C-allocated memory at FFI boundary",
        )
        .with_location(omniscope_core::IssueLocation::new(
            std::path::PathBuf::from("ffi_bridge.rs"),
            123,
        ));

        let mut pass_result = PassResult::new("FFIBoundary").with_nodes(8);
        pass_result.add_issue(issue);

        let result = omniscope_pipeline::PipelineResult::from_pass_results(
            vec![pass_result],
            Duration::from_millis(200),
        );

        let filtered = filter_boundary_issues(result);

        assert_eq!(filtered.issues.len(), 1, "Must have exactly one issue");

        let filtered_issue = &filtered.issues[0];
        assert_eq!(filtered_issue.id, 42, "Issue ID must be preserved as 42");
        assert_eq!(
            filtered_issue.kind,
            IssueKind::CrossLanguageFree,
            "Issue kind must be preserved as CrossLanguageFree"
        );
        assert_eq!(
            filtered_issue.severity,
            Severity::Error,
            "Issue severity must be preserved as Error"
        );
        assert!(
            filtered_issue.description.contains("Critical"),
            "Issue description must be preserved"
        );
        assert!(
            filtered_issue.location.is_some(),
            "Issue location must be preserved"
        );
    }
}
