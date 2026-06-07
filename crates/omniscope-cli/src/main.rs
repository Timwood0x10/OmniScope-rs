//! OmniScope CLI entry point
//!
//! This is the main entry point for the OmniScope static analyzer.
//! It provides four subcommands:
//! - `analyze`: Full pipeline analysis with rich/JSON/SARIF output
//! - `audit`: Language-specific FFI audit
//! - `info`: Show configuration and pass information
//! - `init`: Generate default configuration file
//! - `validate`: Validate configuration file

mod output;

use clap::Parser;
use omniscope_ir::loader_v2::{load_ir, LoadStrategy};
use omniscope_pipeline::Pipeline;
use omniscope_types::{FFIBoundaryConfig, Language, OmniScopeConfig, ProjectConfig};
use output::json::JsonFormatter;
use output::rich::RichFormatter;
use output::sarif::SarifFormatter;
use output::{OutputFormat, OutputFormatter};
use std::path::PathBuf;
use std::time::Instant;
use tracing_subscriber::EnvFilter;

/// Cross-language boundary specification parsed from CLI.
///
/// Used with `--cross FROM:TO` to specify FFI boundaries.
/// Example: `--cross C:Cpp --cross Zig:C`
#[derive(Debug, Clone)]
struct CrossBoundary {
    /// Source language of the FFI call.
    from: Language,
    /// Target language of the FFI call.
    to: Language,
}

impl std::str::FromStr for CrossBoundary {
    type Err = String;

    /// Parse a cross boundary from "FROM:TO" format.
    ///
    /// Supported language names: C, Cpp/C++, Rust/RS, Zig, Go, Python/Py,
    /// Java, CSharp/C#/CS.  Case-insensitive.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() != 2 {
            return Err(format!(
                "Invalid cross boundary format: {s}. Expected FROM:TO (e.g. C:Cpp)"
            ));
        }

        let from = parse_language(parts[0])?;
        let to = parse_language(parts[1])?;

        Ok(Self { from, to })
    }
}

/// Parse a language name string into a [`Language`] enum value.
///
/// Accepts common aliases (e.g. "c++" for Cpp, "rs" for Rust).
/// Returns an error for unrecognized language names.
fn parse_language(s: &str) -> Result<Language, String> {
    match s.to_lowercase().as_str() {
        "c" => Ok(Language::C),
        "cpp" | "c++" => Ok(Language::Cpp),
        "rust" | "rs" => Ok(Language::Rust),
        "zig" => Ok(Language::Zig),
        "go" => Ok(Language::Go),
        "python" | "py" => Ok(Language::Python),
        "java" => Ok(Language::Java),
        "csharp" | "c#" | "cs" => Ok(Language::CSharp),
        _ => Err(format!("Unknown language: {s}")),
    }
}

/// Timing breakdown for CLI phases.
#[derive(Debug)]
struct CliTiming {
    /// Time spent loading IR in milliseconds.
    load_ms: u64,
    /// Time spent running the analysis pipeline in milliseconds.
    pipeline_ms: u64,
    /// Time spent formatting output in milliseconds.
    format_ms: u64,
    /// Total time from start to finish in milliseconds.
    total_ms: u64,
    /// The load strategy that was actually used.
    load_strategy: &'static str,
}

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

    /// Initialize configuration file
    Init(InitCommand),

    /// Validate configuration file
    Validate(ValidateCommand),
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

    /// Cross-language boundaries (format: FROM:TO, repeatable).
    /// Example: --cross C:Cpp --cross Zig:C
    #[arg(long = "cross", value_name = "FROM:TO")]
    cross: Vec<CrossBoundary>,

    /// Configuration file path (TOML format).
    /// Searches ./omniscope.toml and ~/.config/omniscope/config.toml when omitted.
    #[arg(long)]
    config: Option<PathBuf>,

    /// Enable verbose output (pipeline metrics)
    #[arg(short, long)]
    verbose: bool,

    /// Enable detailed timing report (pass-level breakdown)
    #[arg(long)]
    timing: bool,

    /// Enable debug-level logging (full trace)
    #[arg(long)]
    debug: bool,

    /// Run in parallel mode
    #[arg(long, default_value = "false")]
    parallel: bool,

    /// IR loading strategy (auto-fast, auto, direct-cpp-ffi, direct-cpp, llvm-sys, cpp-pass, text-parser)
    #[arg(long, default_value = "auto-fast")]
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

    /// IR loading strategy (auto-fast, auto, direct-cpp-ffi, direct-cpp, llvm-sys, cpp-pass, text-parser)
    #[arg(long, default_value = "auto-fast")]
    strategy: String,
}

#[derive(clap::Args)]
struct InfoCommand {
    /// Show pass information
    #[arg(long)]
    passes: bool,
}

/// Arguments for init command.
#[derive(clap::Args)]
struct InitCommand {
    /// Output file path.
    #[arg(long, default_value = "omniscope.toml")]
    output: PathBuf,

    /// Force overwrite existing file.
    #[arg(long)]
    force: bool,

    /// Project name.
    #[arg(long)]
    name: Option<String>,

    /// Project description.
    #[arg(long)]
    description: Option<String>,
}

/// Arguments for validate command.
#[derive(clap::Args)]
struct ValidateCommand {
    /// Configuration file path.
    #[arg(long, default_value = "omniscope.toml")]
    config: PathBuf,
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
        Commands::Init(cmd) => {
            run_init(cmd)?;
        }
        Commands::Validate(cmd) => {
            run_validate(cmd)?;
        }
    }

    Ok(())
}

/// Runs the analyze command — the primary analysis entry point.
fn run_analyze(cmd: AnalyzeCommand, start: Instant) -> anyhow::Result<()> {
    tracing::info!("Starting analysis of {:?}", cmd.input);
    tracing::debug!("Format: {}, Parallel: {}", cmd.format, cmd.parallel);

    // Load configuration from file and/or CLI arguments
    let config = load_config(&cmd)?;
    if !cmd.cross.is_empty() {
        tracing::info!(
            "CLI cross boundaries: {}",
            cmd.cross
                .iter()
                .map(|b| format!("{:?}:{:?}", b.from, b.to))
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    if !config.ffi_boundary.is_empty() {
        tracing::info!("Total FFI boundaries loaded: {}", config.ffi_boundary.len());
    }

    // Parse the IR file — auto-detects best backend (llvm-sys > cpp pass > text)
    let strategy = parse_strategy(&cmd.strategy);
    tracing::info!(
        "Parsing LLVM IR from {:?} (strategy: {})",
        cmd.input,
        strategy
    );
    let loaded = load_ir(&cmd.input, strategy)?;
    let func_count = loaded.module.functions.len();
    let decl_count = loaded.module.declarations.len();
    tracing::info!(
        "IR parsed: {} functions, {} declarations, {} calls",
        func_count,
        decl_count,
        loaded.module.calls.len()
    );

    // Create and configure pipeline
    let mut pipeline = Pipeline::new();
    pipeline.set_parallel(cmd.parallel);

    // Set configuration before registering passes so that
    // ContractGraphBuilderPass can pick up CLI --cross boundaries.
    let use_auto_inference = cmd.cross.is_empty() && config.ffi_boundary.is_empty();
    if use_auto_inference {
        tracing::info!("No explicit cross boundaries, using auto-inference");
        // Auto-infer boundaries BEFORE registering passes so that
        // ContractGraphBuilderPass and other passes see the config.
        // Use a reference to the module before moving it into the pipeline.
        let inferred_ctx = omniscope_pass::infer_boundaries(&loaded.module);
        if !inferred_ctx.is_empty() {
            let mut inferred_config = config;
            for edge in inferred_ctx.declared_edges() {
                inferred_config.ffi_boundary.push(FFIBoundaryConfig {
                    from: edge.from,
                    to: edge.to,
                    functions: edge.functions.clone(),
                    pattern: edge.pattern.clone(),
                    description: Some("Auto-inferred boundary".to_string()),
                });
            }
            pipeline.set_config(inferred_config);
        }
    } else {
        pipeline.set_config(config);
    }

    // Now set the IR module (after we've used it for inference)
    pipeline.set_ir_module(loaded.module);

    // Register passes AFTER config is set so they can read it.
    pipeline.register_default_passes();
    tracing::debug!("Pipeline configured with {} passes", pipeline.pass_count());

    // Run the full analysis pipeline
    tracing::info!("Running analysis pipeline");
    let pipeline_start = Instant::now();

    // Always run the pipeline. Config is already set before pass registration.
    let result = pipeline.run()?;

    let pipeline_ms = pipeline_start.elapsed().as_millis() as u64;
    tracing::info!(
        "Pipeline completed: {} issues, {} nodes, {}ms",
        result.total_issues,
        result.total_nodes,
        pipeline_ms
    );

    // Apply boundary-only filter if requested
    let result = if cmd.boundary_only {
        filter_boundary_issues(result)
    } else {
        result
    };

    // Format output according to selected format
    let format_start = Instant::now();
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
    let format_ms = format_start.elapsed().as_millis() as u64;

    // Write output to file or stdout
    if let Some(ref out_path) = cmd.output {
        tracing::info!("Writing output to {:?}", out_path);
        std::fs::write(out_path, &output)?;
    } else {
        println!("{}", output);
    }

    // Create timing breakdown
    let total_ms = start.elapsed().as_millis() as u64;
    let timing = CliTiming {
        load_ms: loaded.load_ms,
        pipeline_ms,
        format_ms,
        total_ms,
        load_strategy: strategy_to_static_str(loaded.strategy),
    };

    // Print detailed timing report if --timing flag is set
    if cmd.timing {
        print_detailed_timing_report(&timing, &result, loaded.strategy);
    } else {
        // Print simple timing breakdown
        print_timing_breakdown(&timing);
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
            "TOTAL", result.total_issues, pipeline_ms
        );
    }

    tracing::info!("Analysis completed in {:?}", start.elapsed());

    Ok(())
}

/// Load configuration from file and/or command line arguments.
///
/// Resolution order:
/// 1. If `--config` is provided, load that file exclusively.
/// 2. Otherwise, search default locations (`./omniscope.toml`,
///    `~/.config/omniscope/config.toml`).
/// 3. Merge any `--cross` boundaries from the CLI on top.
fn load_config(cmd: &AnalyzeCommand) -> anyhow::Result<OmniScopeConfig> {
    // Load base configuration
    let mut config = if let Some(ref config_path) = cmd.config {
        tracing::info!("Loading config from {:?}", config_path);
        OmniScopeConfig::load_from_file(config_path)
            .map_err(|e| anyhow::anyhow!("Failed to load config: {e}"))?
    } else {
        match OmniScopeConfig::load_default() {
            Ok(Some(cfg)) => {
                tracing::debug!("Loaded default config");
                cfg
            }
            Ok(None) => {
                tracing::debug!("No config file found, using defaults");
                OmniScopeConfig::default_config()
            }
            Err(e) => {
                tracing::warn!("Error loading default config: {e}");
                OmniScopeConfig::default_config()
            }
        }
    };

    // Merge CLI --cross boundaries into the configuration
    for boundary in &cmd.cross {
        tracing::debug!(
            "Adding CLI cross boundary: {:?} -> {:?}",
            boundary.from,
            boundary.to
        );
        config.ffi_boundary.push(FFIBoundaryConfig {
            from: boundary.from,
            to: boundary.to,
            functions: Vec::new(), // Empty = auto-detect all functions at boundary
            pattern: None,
            description: Some(format!("{:?} -> {:?} (CLI)", boundary.from, boundary.to)),
        });
    }

    Ok(config)
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

    // Update pass_timings to reflect filtered issue counts
    let mut filtered_pass_timings = result.pass_timings;
    for pt in &mut filtered_pass_timings {
        // Find corresponding pass result to get filtered issue count
        if let Some(pr) = filtered_pass_results
            .iter()
            .find(|pr| pr.name == pt.pass_name)
        {
            pt.issues_found = pr.issues_found;
        }
    }

    omniscope_pipeline::PipelineResult {
        pass_results: filtered_pass_results,
        total_issues: boundary_issues.len(),
        total_nodes,
        duration: result.duration,
        stats: result.stats,
        issues: boundary_issues,
        pass_timings: filtered_pass_timings,
        // Filtered view: dedup already happened upstream in `with_issues`.
        dedup_dropped: result.dedup_dropped,
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
    let loaded = load_ir(&cmd.input, strategy)?;

    // Create pipeline and load IR
    let mut pipeline = Pipeline::new();
    pipeline.register_default_passes();
    pipeline.set_ir_module(loaded.module);

    // Run analysis
    let pipeline_start = Instant::now();
    let result = pipeline.run()?;
    let pipeline_ms = pipeline_start.elapsed().as_millis() as u64;
    let total_ms = start.elapsed().as_millis() as u64;

    // Create timing breakdown
    let timing = CliTiming {
        load_ms: loaded.load_ms,
        pipeline_ms,
        format_ms: 0, // No formatting for audit
        total_ms,
        load_strategy: strategy_to_static_str(loaded.strategy),
    };

    println!("{}", "═".repeat(50).dimmed());
    println!("Audit completed: {} issues found", result.issue_count());

    // Print timing breakdown
    print_timing_breakdown(&timing);

    Ok(())
}

/// Parses a strategy string into a [`LoadStrategy`].
fn parse_strategy(s: &str) -> LoadStrategy {
    match s.to_lowercase().as_str() {
        "direct-cpp-ffi" | "direct_cpp_ffi" | "directcppffi" | "ffi" => LoadStrategy::DirectCppFfi,
        "direct-cpp" | "direct_cpp" | "directcpp" => LoadStrategy::DirectCpp,
        "llvm-sys" | "llvm_sys" | "llvmsys" => LoadStrategy::LlvmSys,
        "cpp-pass" | "cpp_pass" | "cpppass" => LoadStrategy::CppPass,
        "text-parser" | "text_parser" | "textparser" | "text" => LoadStrategy::TextParser,
        "msgpack" | "msg-pack" | "msg_pack" => LoadStrategy::MsgPack,
        "auto-fast" | "auto_fast" | "autofast" => LoadStrategy::AutoFast,
        _ => LoadStrategy::Auto,
    }
}

/// Converts a LoadStrategy to a static string for display.
fn strategy_to_static_str(strategy: LoadStrategy) -> &'static str {
    match strategy {
        LoadStrategy::DirectCppFfi => "direct-cpp-ffi",
        LoadStrategy::DirectCpp => "direct-cpp",
        LoadStrategy::LlvmSys => "llvm-sys",
        LoadStrategy::CppPass => "cpp-pass",
        LoadStrategy::TextParser => "text-parser",
        LoadStrategy::MsgPack => "msgpack",
        LoadStrategy::Auto => "auto",
        LoadStrategy::AutoFast => "auto-fast",
    }
}

/// Prints the timing breakdown for CLI phases.
fn print_timing_breakdown(timing: &CliTiming) {
    eprintln!("\n--- Timing Breakdown ---");
    eprintln!("  {:<20} {:>6}ms", "Loaded via:", timing.load_ms);
    eprintln!("  {:<20} {:>6}ms", "Pipeline:", timing.pipeline_ms);
    if timing.format_ms > 0 {
        eprintln!("  {:<20} {:>6}ms", "Format:", timing.format_ms);
    }
    eprintln!("  {:<20} {:>6}ms", "Total:", timing.total_ms);
    eprintln!("  {:<20} {}", "Strategy:", timing.load_strategy);
}

/// Prints a detailed timing report with pass-level breakdown.
///
/// This function outputs a comprehensive timing report that includes:
/// - IR loading time and strategy
/// - Individual pass timings with issue counts
/// - Pipeline total time
/// - Output formatting time
/// - Percentage breakdown of each phase
fn print_detailed_timing_report(
    timing: &CliTiming,
    result: &omniscope_pipeline::PipelineResult,
    strategy: LoadStrategy,
) {
    use colored::Colorize;

    // Header
    eprintln!();
    eprintln!("{}", "═".repeat(60).cyan().bold());
    eprintln!("{}", "  Timing Breakdown".cyan().bold());
    eprintln!("{}", "═".repeat(60).cyan().bold());
    eprintln!();

    // IR Loading section
    eprintln!("{}", "IR Loading".yellow().bold());
    eprintln!("{}", "─".repeat(60).dimmed());
    eprintln!(
        "  {:<20} {} ({})",
        "Strategy:".white(),
        strategy_to_static_str(strategy).green(),
        "ir_extractor".dimmed()
    );
    eprintln!(
        "  {:<20} {:>8}ms",
        "Load time:".white(),
        timing.load_ms.to_string().green()
    );
    eprintln!();

    // Pipeline Passes section
    eprintln!("{}", "Pipeline Passes".yellow().bold());
    eprintln!("{}", "─".repeat(60).dimmed());

    let mut total_pipeline_ms = 0u64;
    let mut total_issues = 0usize;

    // Print each pass with timing and issue count from pass_timings
    for pt in &result.pass_timings {
        let issue_text = if pt.issues_found == 1 {
            "1 issue".to_string()
        } else {
            format!("{} issues", pt.issues_found)
        };

        eprintln!(
            "  {:<30} {:>6}ms    ({})",
            pt.pass_name.white(),
            pt.duration_ms.to_string().green(),
            issue_text.dimmed()
        );

        total_pipeline_ms += pt.duration_ms;
        total_issues += pt.issues_found;
    }

    // Pipeline total line
    eprintln!("  {}", "─".repeat(56).dimmed());
    let total_issue_text = if total_issues == 1 {
        "1 issue".to_string()
    } else {
        format!("{} issues", total_issues)
    };
    eprintln!(
        "  {:<30} {:>6}ms    ({})",
        "Pipeline Total:".white().bold(),
        total_pipeline_ms.to_string().green().bold(),
        total_issue_text.dimmed().bold()
    );
    eprintln!();

    // Output Formatting section
    if timing.format_ms > 0 {
        eprintln!("{}", "Output Formatting".yellow().bold());
        eprintln!("{}", "─".repeat(60).dimmed());
        eprintln!(
            "  {:<20} {:>8}ms",
            "Format time:".white(),
            timing.format_ms.to_string().green()
        );
        eprintln!();
    }

    // Summary section
    eprintln!("{}", "Summary".yellow().bold());
    eprintln!("{}", "─".repeat(60).dimmed());

    let total_ms = timing.total_ms;
    let load_percent = if total_ms > 0 {
        (timing.load_ms as f64 / total_ms as f64) * 100.0
    } else {
        0.0
    };
    let pipeline_percent = if total_ms > 0 {
        (timing.pipeline_ms as f64 / total_ms as f64) * 100.0
    } else {
        0.0
    };
    let format_percent = if total_ms > 0 {
        (timing.format_ms as f64 / total_ms as f64) * 100.0
    } else {
        0.0
    };

    eprintln!(
        "  {:<20} {:>8}ms  ({:>5.1}%)",
        "IR Loading:".white(),
        timing.load_ms.to_string().green(),
        load_percent
    );
    eprintln!(
        "  {:<20} {:>8}ms  ({:>5.1}%)",
        "Pipeline:".white(),
        timing.pipeline_ms.to_string().green(),
        pipeline_percent
    );
    if timing.format_ms > 0 {
        eprintln!(
            "  {:<20} {:>8}ms  ({:>5.1}%)",
            "Formatting:".white(),
            timing.format_ms.to_string().green(),
            format_percent
        );
    }
    eprintln!("  {}", "─".repeat(56).dimmed());
    eprintln!(
        "  {:<20} {:>8}ms",
        "Total:".white().bold(),
        total_ms.to_string().green().bold()
    );

    eprintln!();
    eprintln!("{}", "═".repeat(60).cyan().bold());
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
        // Drive the list from the real pipeline registration so this output
        // cannot drift from `Pipeline::register_default_passes`.
        let mut pipeline = Pipeline::new();
        pipeline.register_default_passes();
        let names = pipeline.registered_pass_names();

        println!(
            "\n{} ({})",
            "Registered Passes:".yellow().bold(),
            names.len()
        );
        for name in &names {
            println!("    - {}", name);
        }

        println!("\n{}", "Output Formats:".yellow().bold());
        println!("    - rich   (colored terminal output with detection paths)");
        println!("    - json   (machine-readable JSON)");
        println!("    - sarif  (GitHub Code Scanning integration)");
    }

    Ok(())
}

/// Runs the init command — generate default configuration file.
fn run_init(cmd: InitCommand) -> anyhow::Result<()> {
    use colored::Colorize;

    tracing::info!("Initializing configuration file: {:?}", cmd.output);

    // Check if file exists and force flag is not set
    if cmd.output.exists() && !cmd.force {
        anyhow::bail!(
            "Configuration file already exists: {}. Use --force to overwrite.",
            cmd.output.display()
        );
    }

    // Generate default configuration with optional project info
    let mut config = OmniScopeConfig::generate_default();

    // Set project name and description if provided
    if cmd.name.is_some() || cmd.description.is_some() {
        config.project = Some(ProjectConfig {
            name: cmd.name.clone().or_else(|| {
                // Default to directory name if not specified
                std::env::current_dir()
                    .ok()
                    .and_then(|p| p.file_name().map(|n| n.to_string_lossy().to_string()))
            }),
            description: cmd.description.clone(),
        });
    } else {
        // Set default project name to directory name
        config.project = Some(ProjectConfig {
            name: std::env::current_dir()
                .ok()
                .and_then(|p| p.file_name().map(|n| n.to_string_lossy().to_string())),
            description: None,
        });
    }

    // Serialize to TOML
    let content = toml::to_string_pretty(&config)
        .map_err(|e| anyhow::anyhow!("Failed to serialize config: {}", e))?;

    // Write to file
    std::fs::write(&cmd.output, content)
        .map_err(|e| anyhow::anyhow!("Failed to write config file {:?}: {}", cmd.output, e))?;

    // Print success message
    println!("{}", "✓ Configuration file created".green().bold());
    println!();
    println!(
        "  {} {}",
        "File:".white(),
        cmd.output.display().to_string().cyan()
    );
    println!();
    println!("{}", "Next steps:".yellow().bold());
    println!(
        "  1. Edit {} to configure FFI boundaries",
        cmd.output.display()
    );
    println!(
        "  2. Run: omniscope analyze --config {} <input.ll>",
        cmd.output.display()
    );
    println!();

    tracing::info!("Configuration file created: {:?}", cmd.output);

    Ok(())
}

/// Runs the validate command — validate configuration file.
fn run_validate(cmd: ValidateCommand) -> anyhow::Result<()> {
    use colored::Colorize;

    tracing::info!("Validating configuration file: {:?}", cmd.config);

    // Load and parse configuration
    match OmniScopeConfig::load_from_file(&cmd.config) {
        Ok(config) => {
            println!("{}", "✓ Configuration file is valid".green().bold());
            println!();
            println!("{}", "Configuration summary:".yellow().bold());
            println!(
                "  {} {}",
                "FFI boundaries:".white(),
                config.ffi_boundary.len()
            );
            println!(
                "  {} {}",
                "Resource families:".white(),
                config.resource_family.len()
            );
            println!();
            println!("{}", "Analysis options:".yellow().bold());
            println!(
                "    {} {}",
                "Cross-language:".white(),
                config.analysis.cross_language
            );
            println!(
                "    {} {}",
                "Cross-family:".white(),
                config.analysis.cross_family
            );
            println!(
                "    {} {}",
                "Leak detection:".white(),
                config.analysis.leak_detection
            );
            println!(
                "    {} {}",
                "Use-after-free:".white(),
                config.analysis.use_after_free
            );
            println!();

            // Print FFI boundaries if any
            if !config.ffi_boundary.is_empty() {
                println!("{}", "FFI Boundaries:".yellow().bold());
                for (i, boundary) in config.ffi_boundary.iter().enumerate() {
                    println!("  {}. {} -> {}", i + 1, boundary.from, boundary.to);
                    if !boundary.functions.is_empty() {
                        println!("     Functions: {}", boundary.functions.join(", "));
                    }
                    if let Some(desc) = &boundary.description {
                        println!("     Description: {}", desc);
                    }
                }
                println!();
            }

            // Print resource families if any
            if !config.resource_family.is_empty() {
                println!("{}", "Resource Families:".yellow().bold());
                for (i, family) in config.resource_family.iter().enumerate() {
                    println!("  {}. {} ({:?})", i + 1, family.name, family.kind);
                    if !family.acquire.is_empty() {
                        println!("     Acquire: {}", family.acquire.join(", "));
                    }
                    if !family.release.is_empty() {
                        println!("     Release: {}", family.release.join(", "));
                    }
                }
                println!();
            }

            tracing::info!("Configuration file is valid: {:?}", cmd.config);
            Ok(())
        }
        Err(e) => {
            println!("{}", "✗ Configuration file is invalid".red().bold());
            println!();
            println!("{} {}", "Error:".red(), e);
            println!();
            tracing::warn!("Configuration file is invalid: {:?}", cmd.config);
            anyhow::bail!("Invalid configuration file: {}", e);
        }
    }
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
            Vec::new(), // No pass timings in test
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
            Vec::new(),
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
            Vec::new(),
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
            Vec::new(),
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

    // ========================================================================
    // Init Command Tests
    // ========================================================================

    /// Objective: Verify that generate_default_config produces valid config.
    /// Invariants: Default config should have example FFI boundaries and resource families.
    #[test]
    fn test_generate_default_config() {
        let config = OmniScopeConfig::generate_default();

        // Should have example FFI boundaries
        assert_eq!(
            config.ffi_boundary.len(),
            2,
            "Default config should have 2 example FFI boundaries"
        );

        // First boundary should be C -> C++
        assert_eq!(
            config.ffi_boundary[0].from,
            Language::C,
            "First FFI boundary should be from C"
        );
        assert_eq!(
            config.ffi_boundary[0].to,
            Language::Cpp,
            "First FFI boundary should be to C++"
        );

        // Should have example resource family
        assert_eq!(
            config.resource_family.len(),
            1,
            "Default config should have 1 example resource family"
        );
        assert_eq!(
            config.resource_family[0].name, "custom_allocator",
            "Example resource family should be named 'custom_allocator'"
        );

        // Analysis should have default values
        assert!(
            config.analysis.cross_language,
            "Cross-language analysis should be enabled by default"
        );
    }

    /// Objective: Verify that default config can be serialized to valid TOML.
    /// Invariants: Serialized config should contain expected sections.
    #[test]
    fn test_generate_default_config_serialization() {
        let config = OmniScopeConfig::generate_default();

        // Serialize to TOML
        let toml_content =
            toml::to_string_pretty(&config).expect("Config should serialize to valid TOML");

        // Verify it's not empty
        assert!(
            !toml_content.is_empty(),
            "Serialized TOML should not be empty"
        );

        // Verify it contains expected sections
        assert!(
            toml_content.contains("[[ffi_boundary]]"),
            "TOML should contain ffi_boundary section"
        );
        assert!(
            toml_content.contains("[[resource_family]]"),
            "TOML should contain resource_family section"
        );
        assert!(
            toml_content.contains("[analysis]"),
            "TOML should contain analysis section"
        );
    }

    /// Objective: Verify that default config roundtrip preserves data.
    /// Invariants: Serialized-then-deserialized config should match original.
    #[test]
    fn test_generate_default_config_roundtrip() {
        let original = OmniScopeConfig::generate_default();

        // Serialize to TOML
        let toml_content =
            toml::to_string_pretty(&original).expect("Config should serialize to valid TOML");

        // Deserialize back
        let deserialized: OmniScopeConfig =
            toml::from_str(&toml_content).expect("TOML should deserialize to valid config");

        // Verify roundtrip preserves data
        assert_eq!(
            deserialized.ffi_boundary.len(),
            original.ffi_boundary.len(),
            "Roundtrip should preserve FFI boundary count"
        );
        assert_eq!(
            deserialized.resource_family.len(),
            original.resource_family.len(),
            "Roundtrip should preserve resource family count"
        );
        assert_eq!(
            deserialized.analysis.cross_language, original.analysis.cross_language,
            "Roundtrip should preserve cross_language setting"
        );
    }

    // ========================================================================
    // Validate Command Tests
    // ========================================================================

    /// Objective: Verify that load_from_file parses valid TOML config.
    /// Invariants: Parsed config should match serialized config.
    #[test]
    fn test_load_from_file_valid_config() {
        use std::io::Write;

        // Create a temporary file with valid config
        let mut temp_file = tempfile::NamedTempFile::new().expect("Should create temp file");

        let config = OmniScopeConfig::generate_default();
        let toml_content = toml::to_string_pretty(&config).expect("Config should serialize");

        temp_file
            .write_all(toml_content.as_bytes())
            .expect("Should write to temp file");

        // Load from file
        let loaded_config = OmniScopeConfig::load_from_file(temp_file.path())
            .expect("Should load valid config file");

        // Verify loaded config matches original
        assert_eq!(
            loaded_config.ffi_boundary.len(),
            config.ffi_boundary.len(),
            "Loaded config should have same FFI boundary count"
        );
        assert_eq!(
            loaded_config.resource_family.len(),
            config.resource_family.len(),
            "Loaded config should have same resource family count"
        );
    }

    /// Objective: Verify that load_from_file handles invalid TOML.
    /// Invariants: Should return error for invalid TOML content.
    #[test]
    fn test_load_from_file_invalid_toml() {
        use std::io::Write;

        // Create a temporary file with invalid TOML
        let mut temp_file = tempfile::NamedTempFile::new().expect("Should create temp file");

        temp_file
            .write_all(b"this is not valid toml [[[")
            .expect("Should write to temp file");

        // Load from file should fail
        let result = OmniScopeConfig::load_from_file(temp_file.path());
        assert!(result.is_err(), "Should return error for invalid TOML");
    }

    /// Objective: Verify that load_from_file handles non-existent file.
    /// Invariants: Should return error for non-existent file.
    #[test]
    fn test_load_from_file_nonexistent() {
        let result =
            OmniScopeConfig::load_from_file(std::path::Path::new("/nonexistent/file.toml"));
        assert!(result.is_err(), "Should return error for non-existent file");
    }

    /// Objective: Verify that save_to_file writes valid TOML.
    /// Invariants: Written file should be loadable and match original config.
    #[test]
    fn test_save_to_file() {
        let config = OmniScopeConfig::generate_default();

        // Create a temporary file path
        let temp_dir = tempfile::tempdir().expect("Should create temp directory");
        let file_path = temp_dir.path().join("test_config.toml");

        // Save to file
        config
            .save_to_file(&file_path)
            .expect("Should save config to file");

        // Verify file exists
        assert!(file_path.exists(), "Config file should exist after saving");

        // Load from file and verify
        let loaded_config =
            OmniScopeConfig::load_from_file(&file_path).expect("Should load saved config");

        assert_eq!(
            loaded_config.ffi_boundary.len(),
            config.ffi_boundary.len(),
            "Loaded config should have same FFI boundary count"
        );
    }
}
