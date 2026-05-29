//! OmniScope CLI entry point
//!
//! This is the main entry point for the OmniScope static analyzer.
//! It provides three subcommands:
//! - `analyze`: Full pipeline analysis with rich/JSON/SARIF output
//! - `audit`: Language-specific FFI audit
//! - `info`: Show configuration and pass information

mod output;

use clap::Parser;
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

    // Parse the IR file
    tracing::info!("Parsing LLVM IR from {:?}", cmd.input);
    let module = omniscope_ir::IRModule::load_from_file(&cmd.input)?;
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

    // Parse the IR file — same as run_analyze
    tracing::info!("Parsing LLVM IR from {:?}", cmd.input);
    let module = omniscope_ir::IRModule::load_from_file(&cmd.input)?;

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
