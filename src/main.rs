//! OmniScope - LLVM IR-based static analyzer for FFI safety
//!
//! This is the main entry point for the OmniScope static analyzer.

use clap::Parser;
use colored::Colorize;
use omniscope_ir::IRModule;
use std::path::PathBuf;
use std::time::Instant;

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

    /// Output file path
    #[arg(short, long)]
    output: Option<PathBuf>,

    /// Output format (json, text, sarif)
    #[arg(short = 'f', long, default_value = "text")]
    format: String,

    /// Target language (c, cpp, rust, zig, go, python, java)
    #[arg(short = 'l', long)]
    language: Option<String>,

    /// Enable verbose output
    #[arg(short, long)]
    verbose: bool,
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
    // Initialize logging
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();
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

/// Runs the analyze command
fn run_analyze(cmd: AnalyzeCommand, start: Instant) -> anyhow::Result<()> {
    println!("{}", "OmniScope Analyzer".cyan().bold());
    println!("{}", "═".repeat(50).dimmed());

    if cmd.verbose {
        println!("{} {:?}", "Input:".green(), cmd.input);
        println!("{} {}", "Format:".green(), cmd.format);
    }

    // Parse the IR file
    println!("\n{}", "Parsing LLVM IR...".yellow());

    let module = IRModule::load_from_file(&cmd.input)?;

    println!("{} {} functions, {} declarations, {} calls",
        "✓".green(),
        module.functions.len(),
        module.declarations.len(),
        module.calls.len()
    );

    // Analyze FFI boundaries
    println!("\n{}", "Analyzing FFI boundaries...".yellow());

    let ffi_calls = module.ffi_boundaries();

    println!("{} {} FFI boundaries detected", "✓".green(), ffi_calls.len());

    // Report FFI calls
    if !ffi_calls.is_empty() {
        println!("\n{}", "FFI Calls:".cyan().bold());
        for call in &ffi_calls {
            let status = if is_dangerous_ffi(&call.callee) {
                "⚠ DANGEROUS".red()
            } else {
                "✓ safe".green()
            };
            println!("  → {} ({})", call.callee.yellow(), status);
        }
    }

    // Check for issues
    let dangerous_count = ffi_calls.iter().filter(|c| is_dangerous_ffi(&c.callee)).count();

    println!("\n{}", "═".repeat(50).dimmed());

    if dangerous_count > 0 {
        println!("{} {} potential safety issues found!", "⚠".red(), dangerous_count);
        println!("\n{}", "Issues:".red().bold());

        for call in &ffi_calls {
            if is_dangerous_ffi(&call.callee) {
                println!("  • Dangerous FFI: {} - may cause memory safety issues", call.callee);
            }
        }
    } else {
        println!("{} No safety issues detected", "✓".green());
    }

    let duration = start.elapsed();
    println!("\n{} {:?}", "Completed in".blue(), duration);

    Ok(())
}

/// Runs the audit command
fn run_audit(cmd: AuditCommand, start: Instant) -> anyhow::Result<()> {
    println!("{}", "OmniScope FFI Auditor".cyan().bold());
    println!("{}", "═".repeat(50).dimmed());

    println!("{} {:?}", "Input:".green(), cmd.input);
    println!("{} {}", "Language:".green(), cmd.language);
    println!("{} {}", "Audit type:".green(), cmd.audit_type);

    // Parse and analyze
    let module = IRModule::load_from_file(&cmd.input)?;
    let ffi_calls = module.ffi_boundaries();

    let duration = start.elapsed();

    println!("{}", "═".repeat(50).dimmed());
    println!("Audit completed: {} FFI calls, {} issues found",
        ffi_calls.len(),
        ffi_calls.iter().filter(|c| is_dangerous_ffi(&c.callee)).count()
    );
    println!("Completed in {:?}", duration);

    Ok(())
}

/// Runs the info command
fn run_info(cmd: InfoCommand) -> anyhow::Result<()> {
    println!("{}", "OmniScope Information".cyan().bold());
    println!("{}", "═".repeat(50).dimmed());

    println!("{} {}", "Version:".green(), env!("CARGO_PKG_VERSION"));
    println!("{} {}", "Description:".green(), env!("CARGO_PKG_DESCRIPTION"));

    if cmd.passes {
        println!("\n{}", "Available Passes:".yellow().bold());
        println!("  Foundation:");
        println!("    - CFG (Control Flow Graph)");
        println!("    - DFG (Data Flow Graph)");
        println!("  Analysis:");
        println!("    - FFIBoundary (FFI boundary detection)");
        println!("    - MemorySafety (Memory safety analysis)");
        println!("    - PointerOwnership (Ownership tracking)");
        println!("    - BufferOverflow (Buffer overflow detection)");
    }

    Ok(())
}

/// Check if an FFI function is potentially dangerous
fn is_dangerous_ffi(func_name: &str) -> bool {
    let dangerous_patterns = vec![
        "malloc", "free", "realloc", "calloc",
        "strcpy", "strcat", "sprintf", "vsprintf",
        "gets", "scanf", "fscanf",
        "memcpy", "memmove",
    ];

    dangerous_patterns.iter().any(|p| func_name.contains(p))
}
