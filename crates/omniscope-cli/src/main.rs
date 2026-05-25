//! OmniScope CLI entry point

use clap::Parser;
use omniscope_types::{AnalysisConfig, Language, OutputFormat};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "omniscope")]
#[command(about = "LLVM IR-based static analyzer", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(clap::Subcommand)]
enum Commands {
    Analyze(AnalyzeCommand),
}

#[derive(clap::Args)]
struct AnalyzeCommand {
    #[arg(value_name = "INPUT")]
    input: PathBuf,

    #[arg(short, long)]
    output: Option<PathBuf>,

    #[arg(short = 'f', long, default_value = "json")]
    format: String,
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Analyze(cmd) => {
            println!("Analyzing: {:?}", cmd.input);
            println!("Output format: {}", cmd.format);
        }
    }

    Ok(())
}
