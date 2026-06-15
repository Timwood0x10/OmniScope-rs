//! Terminal colored output for resource contract issues.
//!
//! Formats issue candidates and verified issues with ANSI colors
//! and language→language arrows for cross-family diagnostics.
//!
//! Color scheme:
//! - ConfirmedIssue → red
//! - ProbableIssue → yellow
//! - Diagnostic → blue
//! - ExplainedSafe → green
//! - Resource family → cyan
//!
//! Arrow format:
//! - Mismatch: `C ──✕──> C++`
//! - Safe:     `C ──✓──> C`

use crate::issue_candidate::IssueCandidate;
use omniscope_types::{FamilyId, IssueCandidateKind, LanguageHint, VerifierVerdict};

// ─── ANSI color codes ────────────────────────────────────────────────

const RED: &str = "\x1b[31m";
const YELLOW: &str = "\x1b[33m";
const BLUE: &str = "\x1b[34m";
const GREEN: &str = "\x1b[32m";
const CYAN: &str = "\x1b[36m";
const BOLD: &str = "\x1b[1m";
const RESET: &str = "\x1b[0m";

// ─── Language short labels ───────────────────────────────────────────

/// Returns a short display label for a language hint.
pub fn language_label(hint: LanguageHint) -> &'static str {
    match hint {
        LanguageHint::C => "C",
        LanguageHint::Cpp => "C++",
        LanguageHint::Rust => "Rust",
        LanguageHint::Python => "Python",
        LanguageHint::Java => "Java",
        LanguageHint::CSharp => "C#",
        LanguageHint::Go => "Go",
        LanguageHint::NodeJs => "Node.js",
        LanguageHint::Unknown => "?",
    }
}

/// Returns a colored language label.
fn colored_language_label(hint: LanguageHint, use_color: bool) -> String {
    let label = language_label(hint);
    if use_color {
        format!("{CYAN}{label}{RESET}")
    } else {
        label.to_string()
    }
}

// ─── Language arrow ──────────────────────────────────────────────────

/// Formats a language transition arrow for cross-family issues.
///
/// Mismatch: `C ──✕──> C++`
/// Safe:     `C ──✓──> C`
pub fn format_language_arrow(
    alloc_lang: LanguageHint,
    release_lang: LanguageHint,
    is_mismatch: bool,
    use_color: bool,
) -> String {
    let alloc = colored_language_label(alloc_lang, use_color);
    let release = colored_language_label(release_lang, use_color);

    let arrow = if is_mismatch {
        if use_color {
            format!("{RED}──✕──>{RESET}")
        } else {
            "--X-->".to_string()
        }
    } else {
        if use_color {
            format!("{GREEN}──✓──>{RESET}")
        } else {
            "--OK-->".to_string()
        }
    };

    format!("{alloc} {arrow} {release}")
}

// ─── Verdict badge ───────────────────────────────────────────────────

/// Formats a verdict badge with color.
pub fn format_verdict_badge(verdict: VerifierVerdict, use_color: bool) -> String {
    let (label, color) = match verdict {
        VerifierVerdict::ConfirmedIssue => ("ERROR", RED),
        VerifierVerdict::ProbableIssue => ("WARN", YELLOW),
        VerifierVerdict::Diagnostic => ("NOTE", BLUE),
        VerifierVerdict::ExplainedSafe => ("SAFE", GREEN),
    };

    if use_color {
        format!("{BOLD}{color}[{label}]{RESET}")
    } else {
        format!("[{label}]")
    }
}

// ─── Family label ────────────────────────────────────────────────────

/// Formats a resource family label with color.
pub fn format_family_label(family: omniscope_types::FamilyId, use_color: bool) -> String {
    let label = format!("{family:?}");
    if use_color {
        format!("{CYAN}{label}{RESET}")
    } else {
        label
    }
}

// ─── Full issue formatting ───────────────────────────────────────────

/// Terminal report formatter.
pub struct TerminalReporter {
    /// Whether to use ANSI colors.
    use_color: bool,
}

impl TerminalReporter {
    /// Creates a reporter with color detection.
    pub fn new(use_color: bool) -> Self {
        Self { use_color }
    }

    /// Creates a reporter that auto-detects color support.
    pub fn auto_detect() -> Self {
        Self {
            use_color: atty_is_terminal(),
        }
    }

    /// Formats a verified issue candidate for terminal output.
    pub fn format_candidate(&self, candidate: &IssueCandidate) -> String {
        let Some(verdict) = candidate.verdict else {
            return self.format_unverified(candidate);
        };

        let badge = format_verdict_badge(verdict, self.use_color);

        match candidate.kind {
            IssueCandidateKind::CrossFamilyFree => {
                self.format_cross_family(candidate, verdict, &badge)
            }
            IssueCandidateKind::DefiniteLeak | IssueCandidateKind::ConditionalLeak => {
                self.format_conditional_leak(candidate, verdict, &badge)
            }
            IssueCandidateKind::NeedsModel => self.format_needs_model(candidate, verdict, &badge),
            IssueCandidateKind::UseAfterRelease => {
                self.format_use_after_release(candidate, verdict, &badge)
            }
            IssueCandidateKind::DoubleRelease => {
                self.format_double_release(candidate, verdict, &badge)
            }
            IssueCandidateKind::BorrowEscape => {
                self.format_borrow_escape(candidate, verdict, &badge)
            }
            IssueCandidateKind::CallbackEscape => {
                self.format_callback_escape(candidate, verdict, &badge)
            }
            IssueCandidateKind::DoubleReclaim => {
                self.format_double_reclaim(candidate, verdict, &badge)
            }
            IssueCandidateKind::OwnershipEscapeLeak => {
                self.format_ownership_escape_leak(candidate, verdict, &badge)
            }
            IssueCandidateKind::UseAfterFree => {
                self.format_use_after_free(candidate, verdict, &badge)
            }
            IssueCandidateKind::InvalidBorrowedFree => {
                self.format_invalid_borrowed_free(candidate, verdict, &badge)
            }
            IssueCandidateKind::UncheckedFfiReturn => {
                self.format_unchecked_ffi_return(candidate, verdict, &badge)
            }
            IssueCandidateKind::NullDereference => {
                self.format_null_dereference(candidate, verdict, &badge)
            }
            IssueCandidateKind::CrossLanguageFree => {
                self.format_cross_family(candidate, verdict, &badge)
            }
            IssueCandidateKind::AbiLayoutMismatch => self.format_unverified(candidate),
            IssueCandidateKind::BoundaryMisuse => self.format_unverified(candidate),
        }
    }

    fn format_cross_family(
        &self,
        candidate: &IssueCandidate,
        verdict: VerifierVerdict,
        badge: &str,
    ) -> String {
        let alloc_family = format_family_label(candidate.alloc_family, self.use_color);
        let release_family = candidate
            .release_family
            .map(|f| format_family_label(f, self.use_color))
            .unwrap_or_else(|| "?".to_string());

        let is_mismatch = verdict != VerifierVerdict::ExplainedSafe;
        let alloc_lang = infer_lang_from_family(candidate.alloc_family);
        let release_lang = candidate
            .release_family
            .map_or(LanguageHint::Unknown, infer_lang_from_family);
        let arrow = format_language_arrow(alloc_lang, release_lang, is_mismatch, self.use_color);

        let release_func = candidate.release_function.as_deref().unwrap_or("unknown");

        format!(
            "{badge} cross-family free: {} ({}) {} {} ({})",
            candidate.alloc_function, alloc_family, arrow, release_family, release_func
        )
    }

    fn format_conditional_leak(
        &self,
        candidate: &IssueCandidate,
        _verdict: VerifierVerdict,
        badge: &str,
    ) -> String {
        let family = format_family_label(candidate.alloc_family, self.use_color);
        let lang = infer_lang_from_family(candidate.alloc_family);
        let lang_label = colored_language_label(lang, self.use_color);

        format!(
            "{badge} conditional leak: {} ({}) in '{}' — no same-family release on all paths",
            family, lang_label, candidate.alloc_function
        )
    }

    fn format_needs_model(
        &self,
        candidate: &IssueCandidate,
        _verdict: VerifierVerdict,
        badge: &str,
    ) -> String {
        let lang_label = colored_language_label(LanguageHint::Unknown, self.use_color);
        format!(
            "{badge} needs model: unknown family ({}) in '{}'",
            lang_label, candidate.alloc_function
        )
    }

    fn format_use_after_release(
        &self,
        candidate: &IssueCandidate,
        _verdict: VerifierVerdict,
        badge: &str,
    ) -> String {
        let family = format_family_label(candidate.alloc_family, self.use_color);
        format!(
            "{badge} use after release: {} in '{}'",
            family, candidate.alloc_function
        )
    }

    fn format_double_release(
        &self,
        candidate: &IssueCandidate,
        _verdict: VerifierVerdict,
        badge: &str,
    ) -> String {
        let family = format_family_label(candidate.alloc_family, self.use_color);
        format!(
            "{badge} double release: {} in '{}'",
            family, candidate.alloc_function
        )
    }

    fn format_borrow_escape(
        &self,
        candidate: &IssueCandidate,
        _verdict: VerifierVerdict,
        badge: &str,
    ) -> String {
        let family = format_family_label(candidate.alloc_family, self.use_color);
        format!(
            "{badge} borrow escape: {} in '{}'",
            family, candidate.alloc_function
        )
    }

    fn format_callback_escape(
        &self,
        candidate: &IssueCandidate,
        _verdict: VerifierVerdict,
        badge: &str,
    ) -> String {
        let family = format_family_label(candidate.alloc_family, self.use_color);
        format!(
            "{badge} callback escape: {} in '{}'",
            family, candidate.alloc_function
        )
    }

    fn format_double_reclaim(
        &self,
        candidate: &IssueCandidate,
        _verdict: VerifierVerdict,
        badge: &str,
    ) -> String {
        let family = format_family_label(candidate.alloc_family, self.use_color);
        format!(
            "{badge} double reclaim: raw pointer reclaimed multiple times in '{}' ({})",
            candidate.alloc_function, family
        )
    }

    fn format_ownership_escape_leak(
        &self,
        candidate: &IssueCandidate,
        _verdict: VerifierVerdict,
        badge: &str,
    ) -> String {
        let family = format_family_label(candidate.alloc_family, self.use_color);
        format!(
            "{badge} ownership escape leak: into_raw without from_raw in '{}' ({})",
            candidate.alloc_function, family
        )
    }

    fn format_use_after_free(
        &self,
        candidate: &IssueCandidate,
        _verdict: VerifierVerdict,
        badge: &str,
    ) -> String {
        let family = format_family_label(candidate.alloc_family, self.use_color);
        format!(
            "{badge} use-after-free: freed resource used in '{}' ({})",
            candidate.alloc_function, family
        )
    }

    fn format_invalid_borrowed_free(
        &self,
        candidate: &IssueCandidate,
        _verdict: VerifierVerdict,
        badge: &str,
    ) -> String {
        let family = format_family_label(candidate.alloc_family, self.use_color);
        format!(
            "{badge} invalid free of borrowed pointer: borrowed pointer freed in '{}' ({})",
            candidate.alloc_function, family
        )
    }

    fn format_unchecked_ffi_return(
        &self,
        candidate: &IssueCandidate,
        _verdict: VerifierVerdict,
        badge: &str,
    ) -> String {
        let family = format_family_label(candidate.alloc_family, self.use_color);
        format!(
            "{badge} unchecked FFI return value: unchecked return from '{}' ({})",
            candidate.alloc_function, family
        )
    }

    fn format_null_dereference(
        &self,
        candidate: &IssueCandidate,
        _verdict: VerifierVerdict,
        badge: &str,
    ) -> String {
        let family = format_family_label(candidate.alloc_family, self.use_color);
        format!(
            "{badge} null pointer dereference: potential null dereference in '{}' ({})",
            candidate.alloc_function, family
        )
    }

    fn format_unverified(&self, candidate: &IssueCandidate) -> String {
        let kind_label = format!("{:?}", candidate.kind);
        let family = format_family_label(candidate.alloc_family, self.use_color);
        format!(
            "[??] {kind_label}: {family} in '{}'",
            candidate.alloc_function
        )
    }
}

/// Infers a language hint from a family ID.
fn infer_lang_from_family(family: omniscope_types::FamilyId) -> LanguageHint {
    match family {
        omniscope_types::FamilyId::C_HEAP => LanguageHint::C,
        omniscope_types::FamilyId::CPP_NEW_SCALAR | omniscope_types::FamilyId::CPP_NEW_ARRAY => {
            LanguageHint::Cpp
        }
        omniscope_types::FamilyId::RUST_GLOBAL => LanguageHint::Rust,
        omniscope_types::FamilyId::PYTHON_OBJECT
        | omniscope_types::FamilyId::PYTHON_MEM
        | omniscope_types::FamilyId::PYTHON_MEM_RAW => LanguageHint::Python,
        omniscope_types::FamilyId::JAVA_LOCAL_REF | omniscope_types::FamilyId::JAVA_GLOBAL_REF => {
            LanguageHint::Java
        }
        omniscope_types::FamilyId::CSHARP_HGLOBAL | omniscope_types::FamilyId::CSHARP_COTASK => {
            LanguageHint::CSharp
        }
        omniscope_types::FamilyId::GO_GC => LanguageHint::Go,
        FamilyId(_) => LanguageHint::Unknown,
    }
}

/// Checks if stdout is a TTY (terminal).
fn atty_is_terminal() -> bool {
    use std::io::IsTerminal;
    std::io::stdout().is_terminal()
}

#[cfg(test)]
mod tests {
    use super::*;
    use omniscope_types::FamilyId;

    #[test]
    fn test_language_labels() {
        assert_eq!(
            language_label(LanguageHint::C),
            "C",
            "C language should display as 'C'"
        );
        assert_eq!(
            language_label(LanguageHint::Cpp),
            "C++",
            "C++ language should display as 'C++'"
        );
        assert_eq!(
            language_label(LanguageHint::Rust),
            "Rust",
            "Rust language should display as 'Rust'"
        );
        assert_eq!(
            language_label(LanguageHint::Python),
            "Python",
            "Python language should display as 'Python'"
        );
        assert_eq!(
            language_label(LanguageHint::Java),
            "Java",
            "Java language should display as 'Java'"
        );
        assert_eq!(
            language_label(LanguageHint::CSharp),
            "C#",
            "C# language should display as 'C#'"
        );
        assert_eq!(
            language_label(LanguageHint::Go),
            "Go",
            "Go language should display as 'Go'"
        );
        assert_eq!(
            language_label(LanguageHint::Unknown),
            "?",
            "Unknown language should display as '?'"
        );
    }

    #[test]
    fn test_language_arrow_mismatch() {
        let arrow = format_language_arrow(LanguageHint::C, LanguageHint::Cpp, true, false);
        assert!(
            arrow.contains("--X-->"),
            "Mismatch arrow must contain --X-->, got: {arrow}"
        );
    }

    #[test]
    fn test_language_arrow_safe() {
        let arrow = format_language_arrow(LanguageHint::C, LanguageHint::C, false, false);
        assert!(
            arrow.contains("--OK-->"),
            "Safe arrow must contain --OK-->, got: {arrow}"
        );
    }

    #[test]
    fn test_language_arrow_colored() {
        let arrow = format_language_arrow(LanguageHint::Rust, LanguageHint::C, true, true);
        assert!(arrow.contains(RED), "Mismatch arrow must contain red color");
        assert!(arrow.contains("Rust"), "Arrow must contain alloc language");
        assert!(arrow.contains("C"), "Arrow must contain release language");
    }

    #[test]
    fn test_verdict_badge_colors() {
        let badge = format_verdict_badge(VerifierVerdict::ConfirmedIssue, true);
        assert!(badge.contains(RED), "ConfirmedIssue must be red");

        let badge = format_verdict_badge(VerifierVerdict::ProbableIssue, true);
        assert!(badge.contains(YELLOW), "ProbableIssue must be yellow");

        let badge = format_verdict_badge(VerifierVerdict::Diagnostic, true);
        assert!(badge.contains(BLUE), "Diagnostic must be blue");

        let badge = format_verdict_badge(VerifierVerdict::ExplainedSafe, true);
        assert!(badge.contains(GREEN), "ExplainedSafe must be green");
    }

    #[test]
    fn test_verdict_badge_no_color() {
        let badge = format_verdict_badge(VerifierVerdict::ConfirmedIssue, false);
        assert_eq!(badge, "[ERROR]", "No-color badge must be plain");
    }

    #[test]
    fn test_infer_lang_from_family() {
        assert_eq!(
            infer_lang_from_family(FamilyId::C_HEAP),
            LanguageHint::C,
            "C_HEAP family should infer C language"
        );
        assert_eq!(
            infer_lang_from_family(FamilyId::CPP_NEW_SCALAR),
            LanguageHint::Cpp,
            "CPP_NEW_SCALAR family should infer C++ language"
        );
        assert_eq!(
            infer_lang_from_family(FamilyId::RUST_GLOBAL),
            LanguageHint::Rust,
            "RUST_GLOBAL family should infer Rust language"
        );
        assert_eq!(
            infer_lang_from_family(FamilyId::PYTHON_OBJECT),
            LanguageHint::Python,
            "PYTHON_OBJECT family should infer Python language"
        );
    }

    #[test]
    fn test_format_cross_family_candidate() {
        let reporter = TerminalReporter::new(false);
        let candidate = IssueCandidate::new(
            1,
            IssueCandidateKind::CrossFamilyFree,
            FamilyId::C_HEAP,
            "malloc",
        )
        .with_release_family(FamilyId::CPP_NEW_SCALAR)
        .with_release_function("operator delete")
        .with_verdict(VerifierVerdict::ConfirmedIssue);

        let output = reporter.format_candidate(&candidate);
        assert!(
            output.contains("cross-family free"),
            "Output must mention cross-family free"
        );
        assert!(
            output.contains("malloc"),
            "Output must mention alloc function"
        );
        assert!(
            output.contains("operator delete"),
            "Output must mention release function"
        );
        assert!(
            output.contains("--X-->"),
            "Cross-family must show mismatch arrow"
        );
    }

    #[test]
    fn test_format_conditional_leak_candidate() {
        let reporter = TerminalReporter::new(false);
        let candidate = IssueCandidate::new(
            1,
            IssueCandidateKind::ConditionalLeak,
            FamilyId::RUST_GLOBAL,
            "foo",
        )
        .with_verdict(VerifierVerdict::ProbableIssue);

        let output = reporter.format_candidate(&candidate);
        assert!(
            output.contains("conditional leak"),
            "Output must mention conditional leak"
        );
        assert!(output.contains("Rust"), "Output must mention language");
    }

    #[test]
    fn test_format_needs_model_candidate() {
        let reporter = TerminalReporter::new(false);
        let candidate = IssueCandidate::new(
            1,
            IssueCandidateKind::NeedsModel,
            FamilyId::C_HEAP,
            "custom_alloc",
        )
        .with_verdict(VerifierVerdict::Diagnostic);

        let output = reporter.format_candidate(&candidate);
        assert!(
            output.contains("needs model"),
            "Output must mention needs model"
        );
        assert!(output.contains("[NOTE]"), "NeedsModel must be NOTE badge");
    }
}
