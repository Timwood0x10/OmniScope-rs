//! OmniScope - LLVM IR-based static analyzer for FFI safety
//!
//! This is the main entry point for the OmniScope static analyzer.

use clap::Parser;
use colored::Colorize;
use omniscope_ir::{IRModule, Platform, PlatformFilterRegistry, PlatformInfo};
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

    println!(
        "{} {} functions, {} declarations, {} calls",
        "✓".green(),
        module.functions.len(),
        module.declarations.len(),
        module.calls.len()
    );

    // Display IR metadata
    if cmd.verbose {
        if let Some(ref triple) = module.data_layout.target_triple {
            println!("{} {}", "Target triple:".green(), triple);
        }
        if let Some(ptr_size) = module.data_layout.pointer_size {
            println!("{} {} bits", "Pointer size:".green(), ptr_size);
        }
        if let Some(little_endian) = module.data_layout.little_endian {
            let endian = if little_endian { "Little" } else { "Big" };
            println!("{} {}", "Endianness:".green(), endian);
        }
        if !module.calling_conventions.is_empty() {
            println!(
                "{} {} unique calling conventions",
                "Calling conventions:".green(),
                module.calling_conventions.len()
            );
        }
    }

    // Analyze FFI boundaries
    println!("\n{}", "Analyzing FFI boundaries...".yellow());

    // Initialize platform filter registry
    let registry = PlatformFilterRegistry::new();

    // Use target triple from IR if available, otherwise use current platform
    let platform_info = if let Some(ref triple) = module.data_layout.target_triple {
        PlatformInfo::from_target_triple(triple)
    } else {
        PlatformInfo::current()
    };

    println!(
        "{} Target platform: {}",
        "✓".green(),
        platform_info.platform
    );

    let ffi_calls = module.ffi_boundaries();

    println!(
        "{} {} FFI boundaries detected",
        "✓".green(),
        ffi_calls.len()
    );

    // Report FFI calls
    if !ffi_calls.is_empty() {
        println!("\n{}", "FFI Call Chains:".cyan().bold());
        for call in &ffi_calls {
            let status = if is_dangerous_ffi(&call.callee, &registry, platform_info.platform) {
                "⚠ DANGEROUS".red()
            } else {
                "✓ safe".green()
            };

            // Show call chain: caller -> callee
            println!(
                "  {} → {} ({})",
                call.caller.blue(),
                call.callee.yellow(),
                status
            );

            // Show location if available
            if let Some(ref loc) = call.location {
                println!(
                    "    at {}:{}:{}",
                    loc.file.dimmed(),
                    loc.line.to_string().yellow(),
                    loc.column.to_string().yellow()
                );
            }
        }
    }

    // Check for issues
    let dangerous_count = ffi_calls
        .iter()
        .filter(|c| is_dangerous_ffi(&c.callee, &registry, platform_info.platform))
        .count();

    println!("\n{}", "═".repeat(50).dimmed());

    if dangerous_count > 0 {
        println!(
            "{} {} potential safety issues found!",
            "⚠".red(),
            dangerous_count
        );
        println!("\n{}", "Issues:".red().bold());

        for call in &ffi_calls {
            if is_dangerous_ffi(&call.callee, &registry, platform_info.platform) {
                println!(
                    "  • Dangerous FFI: {} - may cause memory safety issues",
                    call.callee
                );
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

    // Initialize platform filter registry
    let registry = PlatformFilterRegistry::new();
    let platform_info = PlatformInfo::current();

    let duration = start.elapsed();

    println!("{}", "═".repeat(50).dimmed());
    println!(
        "Audit completed: {} FFI calls, {} issues found",
        ffi_calls.len(),
        ffi_calls
            .iter()
            .filter(|c| is_dangerous_ffi(&c.callee, &registry, platform_info.platform))
            .count()
    );
    println!("Completed in {:?}", duration);

    Ok(())
}

/// Runs the info command
fn run_info(cmd: InfoCommand) -> anyhow::Result<()> {
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
        println!("  Analysis:");
        println!("    - FFIBoundary (FFI boundary detection)");
        println!("    - MemorySafety (Memory safety analysis)");
        println!("    - PointerOwnership (Ownership tracking)");
        println!("    - BufferOverflow (Buffer overflow detection)");
    }

    Ok(())
}

/// Determines if an FFI function call is potentially dangerous.
///
/// This function uses semantic analysis to filter out false positives
/// by identifying safe patterns and only reporting genuine FFI hazards.
///
/// # Filtering Strategy
///
/// The function applies multiple filtering zones to reduce false positives:
///
/// 1. **Platform-Specific Zone**: Excludes platform-safe APIs
///    macOS zone allocators, Linux glibc, Windows heap APIs
///
/// 2. **Compiler Intrinsics Zone**: Excludes LLVM intrinsics (llvm.*)
///    These are compiler-generated calls, not real FFI boundaries.
///
/// 3. **Safe Variants Zone**: Excludes bounds-checked versions (*_chk)
///    Functions with _chk suffix have compile-time size validation.
///
/// 4. **Language-Specific Zone**: Excludes RAII-managed operations
///    Rust's drop and dealloc are automatically managed.
///
/// 5. **Dangerous Patterns Zone**: Reports genuine FFI hazards
///    Only functions that can cause memory leaks, overflows, or UAF.
///
/// # Arguments
///
/// * `func_name` - The name of the FFI function to check
/// * `registry` - Platform filter registry
/// * `platform` - Target platform
///
/// # Returns
///
/// `true` if the function is potentially dangerous, `false` otherwise
fn is_dangerous_ffi(
    func_name: &str,
    registry: &PlatformFilterRegistry,
    platform: Platform,
) -> bool {
    // === Zone 1: Platform-Specific Safe APIs ===
    // Check platform-specific safe APIs first
    if registry.is_platform_safe(func_name, platform) {
        return false;
    }

    // === Zone 2: Language-Specific Safe Patterns ===
    // Rust's RAII-managed operations (drop, dealloc) are safe.
    // Mangled names starting with _ZN indicate Rust symbols.
    if func_name.contains("_ZN") {
        // Rust's drop and dealloc are automatically managed
        if func_name.contains("drop") || func_name.contains("dealloc") {
            return false;
        }
        // Rust's allocation functions are also RAII-managed
        if func_name.contains("__rust_alloc")
            || func_name.contains("__rust_dealloc")
            || func_name.contains("__rust_realloc")
        {
            return false;
        }
    }

    // === Zone 3: Genuine Dangerous Patterns ===
    // Only report functions that can cause real issues:
    // - Memory leaks (malloc without free)
    // - Double free (free called incorrectly)
    // - Buffer overflow (strcpy, sprintf)
    // - Use-after-free (dangling pointers)
    let dangerous_patterns = [
        // Memory management - can cause leaks or double-free
        "malloc", "free", "realloc", "calloc",
        // String operations - can cause buffer overflow
        "strcpy", "strcat", "sprintf", "vsprintf",
        // Input functions - can cause buffer overflow
        "gets", "scanf", "fscanf",
    ];

    dangerous_patterns
        .iter()
        .any(|pattern| func_name.contains(pattern))
}
