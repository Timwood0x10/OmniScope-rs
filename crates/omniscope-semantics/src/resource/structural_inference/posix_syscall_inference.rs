//! POSIX syscall semantic classification for structural analysis (R-4).
//!
//! Classifies POSIX standard function calls into semantic categories
//! (file, network, process, memory). Only memory-class operations
//! participate in free/UAF semantic analysis; file/network/process
//! operations are suppressed from cross_language_free and use_after_free.
//!
//! # Key Insight (R-4)
//!
//! POSIX defines the semantics of these functions. `unlink()`, `close()`,
//! `socket()`, `execve()` etc. are NOT memory management operations.
//! Treating them as potential free/corrupt operations generates FP.
//!
//! This is NOT a whitelist — these are POSIX-specified semantic facts.

use omniscope_types::{
    Effect, Evidence, EvidenceKind, FunctionId, FunctionOrigin, LanguageHint, SymbolId,
};

use crate::resource::summary::ResourceSummary;

/// Result of POSIX syscall classification.
#[derive(Debug, Clone)]
pub struct PosixSyscallInferenceResult {
    /// Whether this function was classified as a POSIX syscall.
    pub is_posix_syscall: bool,
    /// The semantic category of the syscall.
    pub category: PosixSyscallCategory,
    /// Confidence of the classification (0.0 - 1.0).
    pub confidence: f32,
    /// Reason for the classification.
    pub reason: String,
}

/// Semantic category for POSIX operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PosixSyscallCategory {
    /// File operations: open, close, read, write, unlink, rename, etc.
    File,
    /// Network operations: socket, bind, connect, listen, send, recv, etc.
    Network,
    /// Process operations: fork, execve, waitpid, kill, etc.
    Process,
    /// Memory operations: mmap, munmap, mprotect, brk, etc.
    /// These DO participate in memory safety analysis.
    Memory,
    /// Time/signal operations: clock_gettime, nanosleep, sigaction, etc.
    TimeSignal,
}

impl PosixSyscallCategory {
    /// Returns true if this category should be suppressed from
    /// cross_language_free / use_after_free analysis.
    pub fn is_non_memory(&self) -> bool {
        !matches!(self, PosixSyscallCategory::Memory)
    }
}

/// Infers POSIX syscall category and builds its summary.
///
/// File/network/process/time operations are marked as safe — they
/// do not participate in memory safety analysis. Memory operations
/// (mmap, munmap, etc.) are kept in the analysis pipeline.
pub fn infer_posix_syscall_summary(
    name: &str,
    function: FunctionId,
    canonical_name: SymbolId,
    language_hint: LanguageHint,
) -> (ResourceSummary, PosixSyscallInferenceResult) {
    let mut summary = ResourceSummary::new(function, canonical_name, name);
    summary.language_hint = language_hint;

    let Some((category, confidence)) = classify_posix_syscall(name) else {
        let result = PosixSyscallInferenceResult {
            is_posix_syscall: false,
            category: PosixSyscallCategory::File,
            confidence: 0.0,
            reason: format!("not a recognized POSIX syscall: {name}"),
        };
        return (summary, result);
    };

    summary.origin = FunctionOrigin::Stdlib;
    summary.confidence = confidence;

    if category.is_non_memory() {
        // Non-memory POSIX operations are pure side-effects — no ownership
        summary.add_effect(Effect::ReturnsBorrowed);
    }

    summary.add_evidence(
        Evidence::new(
            EvidenceKind::PosixSyscallClass,
            format!(
                "function '{name}' classified as {:?} POSIX operation",
                category
            ),
        )
        .with_confidence(confidence),
    );

    let result = PosixSyscallInferenceResult {
        is_posix_syscall: true,
        category,
        confidence,
        reason: format!("POSIX {:?} operation: {}", category, name),
    };

    (summary, result)
}

/// POSIX syscall classification table.
/// Derived from POSIX/SUSv4 specification, NOT from project-specific knowledge.
/// Evidence: bun_fp R-4 — bun_paths.bc contains Bun__unlink (wraps libc unlink).
fn classify_posix_syscall(name: &str) -> Option<(PosixSyscallCategory, f32)> {
    // ── File operations ──
    const FILE_OPS: &[&str] = &[
        "open",
        "openat",
        "close",
        "read",
        "write",
        "pread",
        "pwrite",
        "readv",
        "writev",
        "lseek",
        "fstat",
        "stat",
        "lstat",
        "fstatat",
        "unlink",
        "unlinkat",
        "link",
        "linkat",
        "rename",
        "renameat",
        "renameat2",
        "symlink",
        "symlinkat",
        "readlink",
        "readlinkat",
        "mkdir",
        "mkdirat",
        "rmdir",
        "chmod",
        "fchmod",
        "fchmodat",
        "chown",
        "fchown",
        "lchown",
        "fchownat",
        "umask",
        "truncate",
        "ftruncate",
        "fsync",
        "fdatasync",
        "dup",
        "dup2",
        "dup3",
        "pipe",
        "pipe2",
        "fcntl",
        "ioctl",
        "access",
        "faccessat",
        "flock",
        "creat",
        "mkstemp",
        "mkdtemp",
        "tmpfile",
        "fdopen",
        "fopen",
        "fclose",
        "fflush",
        "freopen",
        "remove",
        "tempnam",
        "realpath",
        "opendir",
        "fdopendir",
        "readdir",
        "closedir",
        "rewinddir",
        "telldir",
        "seekdir",
        "getcwd",
        "chdir",
        "fchdir",
    ];

    // ── Network operations ──
    const NET_OPS: &[&str] = &[
        "socket",
        "socketpair",
        "bind",
        "listen",
        "accept",
        "accept4",
        "connect",
        "send",
        "sendto",
        "sendmsg",
        "recv",
        "recvfrom",
        "recvmsg",
        "shutdown",
        "getsockname",
        "getpeername",
        "getsockopt",
        "setsockopt",
        "select",
        "pselect",
        "poll",
        "ppoll",
        "epoll_create",
        "epoll_create1",
        "epoll_ctl",
        "epoll_wait",
        "kqueue",
        "kevent",
        "getaddrinfo",
        "freeaddrinfo",
        "getnameinfo",
        "inet_pton",
        "inet_ntop",
        "htonl",
        "htons",
        "ntohl",
        "ntohs",
    ];

    // ── Process operations ──
    const PROC_OPS: &[&str] = &[
        "fork",
        "vfork",
        "execve",
        "execv",
        "execvp",
        "execvpe",
        "execl",
        "execlp",
        "wait",
        "waitpid",
        "waitid",
        "wait3",
        "wait4",
        "kill",
        "raise",
        "sigaction",
        "sigprocmask",
        "sigpending",
        "sigsuspend",
        "sigemptyset",
        "sigfillset",
        "sigaddset",
        "sigdelset",
        "sigismember",
        "alarm",
        "pause",
        "abort",
        "exit",
        "_exit",
        "_Exit",
        "atexit",
        "getpid",
        "getppid",
        "getuid",
        "geteuid",
        "getgid",
        "getegid",
        "setuid",
        "seteuid",
        "setgid",
        "setegid",
        "getgroups",
        "setgroups",
        "chroot",
        "prctl",
        "ptrace",
        "getrlimit",
        "setrlimit",
        "getrusage",
        "sysconf",
        "gethostname",
        "sethostname",
        "uname",
    ];

    // ── Memory operations (these DO participate in memory analysis) ──
    const MEM_OPS: &[&str] = &[
        "mmap",
        "munmap",
        "mprotect",
        "mremap",
        "msync",
        "madvise",
        "posix_memalign",
        "aligned_alloc",
        "brk",
        "sbrk",
    ];

    // ── Time/signal operations ──
    const TIME_OPS: &[&str] = &[
        "clock_gettime",
        "clock_settime",
        "clock_getres",
        "gettimeofday",
        "settimeofday",
        "nanosleep",
        "clock_nanosleep",
        "time",
        "stime",
        "difftime",
        "gmtime",
        "localtime",
        "mktime",
        "strftime",
        "strptime",
        "asctime",
        "ctime",
        "timer_create",
        "timer_delete",
        "timer_settime",
        "timer_gettime",
        "getentropy",
        "arc4random",
        "arc4random_buf",
        "arc4random_uniform",
        "pthread_create",
        "pthread_join",
        "pthread_detach",
        "pthread_exit",
        "pthread_self",
        "pthread_equal",
        "pthread_mutex_init",
        "pthread_mutex_destroy",
        "pthread_mutex_lock",
        "pthread_mutex_unlock",
        "pthread_mutex_trylock",
        "pthread_cond_init",
        "pthread_cond_destroy",
        "pthread_cond_wait",
        "pthread_cond_signal",
        "pthread_cond_broadcast",
        "pthread_setname_np",
        "pthread_threadid_np",
        "pthread_atfork",
    ];

    for &op in FILE_OPS {
        if name == op {
            return Some((PosixSyscallCategory::File, 0.95));
        }
    }
    for &op in NET_OPS {
        if name == op {
            return Some((PosixSyscallCategory::Network, 0.95));
        }
    }
    for &op in PROC_OPS {
        if name == op {
            return Some((PosixSyscallCategory::Process, 0.95));
        }
    }
    for &op in MEM_OPS {
        if name == op {
            return Some((PosixSyscallCategory::Memory, 0.95));
        }
    }
    for &op in TIME_OPS {
        if name == op {
            return Some((PosixSyscallCategory::TimeSignal, 0.95));
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_close_is_file_op() {
        let (_, result) = infer_posix_syscall_summary("close", 1, 100, LanguageHint::C);
        assert!(result.is_posix_syscall, "close must be a POSIX syscall");
        assert_eq!(result.category, PosixSyscallCategory::File);
        assert!(result.category.is_non_memory());
    }

    #[test]
    fn test_unlink_is_file_op() {
        let (_, result) = infer_posix_syscall_summary("unlink", 2, 200, LanguageHint::C);
        assert!(result.is_posix_syscall);
        assert_eq!(result.category, PosixSyscallCategory::File);
    }

    #[test]
    fn test_socket_is_network_op() {
        let (_, result) = infer_posix_syscall_summary("socket", 3, 300, LanguageHint::C);
        assert!(result.is_posix_syscall);
        assert_eq!(result.category, PosixSyscallCategory::Network);
    }

    #[test]
    fn test_execve_is_process_op() {
        let (_, result) = infer_posix_syscall_summary("execve", 4, 400, LanguageHint::C);
        assert!(result.is_posix_syscall);
        assert_eq!(result.category, PosixSyscallCategory::Process);
    }

    #[test]
    fn test_mmap_is_memory_op() {
        let (_, result) = infer_posix_syscall_summary("mmap", 5, 500, LanguageHint::C);
        assert!(result.is_posix_syscall);
        assert_eq!(result.category, PosixSyscallCategory::Memory);
        assert!(!result.category.is_non_memory(), "mmap is a memory op");
    }

    #[test]
    fn test_malloc_is_not_posix() {
        let (_, result) = infer_posix_syscall_summary("malloc", 6, 600, LanguageHint::C);
        assert!(!result.is_posix_syscall, "malloc is not a POSIX syscall");
    }

    #[test]
    fn test_clock_gettime_is_time() {
        let (_, result) = infer_posix_syscall_summary("clock_gettime", 7, 700, LanguageHint::C);
        assert!(result.is_posix_syscall);
        assert_eq!(result.category, PosixSyscallCategory::TimeSignal);
    }
}
