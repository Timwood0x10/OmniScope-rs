// ir_extractor.cpp — Standalone tool to parse LLVM IR and output structured JSON.
//
// This tool reads an LLVM IR file and outputs the same JSON format as SafetyExportPass,
// but without requiring opt or the pass plugin infrastructure.
//
// Usage:
//   ir_extractor input.ll
//   ir_extractor input.ll -o output.json
//
// Designed for performance benchmarking against opt + SafetyExportPass.

#include "llvm/TargetParser/Triple.h"
#include "llvm/Demangle/Demangle.h"
#include "llvm/IR/DebugInfoMetadata.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#include "llvm/IRReader/IRReader.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/SourceMgr.h"
#include "llvm/Support/raw_ostream.h"

#include <string>
#include <chrono>
#include <iostream>
#include <set>
#include <map>
#include <vector>
#include <unordered_set>
#include <unordered_map>
#include <algorithm>
#include <functional>
#include <regex>
#include <fstream>

using namespace llvm;

// ── MessagePack Writer ─────────────────────────────────────────────
class MsgpackWriter {
  raw_ostream &OS;
public:
  explicit MsgpackWriter(raw_ostream &OS) : OS(OS) {}
  
  void write_nil() { OS << '\xc0'; }
  void write_bool(bool v) { OS << (v ? '\xc3' : '\xc2'); }
  
  void write_int(int64_t v) {
    if (v >= 0 && v <= 0x7f) { OS << static_cast<char>(v); }
    else if (v >= -32 && v < 0) { OS << static_cast<char>(v); }
    else if (v >= -128 && v <= 127) { OS << '\xd0' << static_cast<int8_t>(v); }
    else if (v >= -32768 && v <= 32767) {
      OS << '\xd1';
      char buf[2]; buf[0] = (v >> 8) & 0xff; buf[1] = v & 0xff;
      OS.write(buf, 2);
    } else if (v >= -2147483648LL && v <= 2147483647LL) {
      OS << '\xd2';
      char buf[4];
      buf[0] = (v >> 24) & 0xff; buf[1] = (v >> 16) & 0xff;
      buf[2] = (v >> 8) & 0xff; buf[3] = v & 0xff;
      OS.write(buf, 4);
    } else {
      OS << '\xd3';
      char buf[8];
      for (int i = 7; i >= 0; --i) { buf[7-i] = (v >> (i*8)) & 0xff; }
      OS.write(buf, 8);
    }
  }
  
  void write_uint(uint64_t v) {
    if (v <= 0x7f) { OS << static_cast<char>(v); }
    else if (v <= 0xff) { OS << '\xcc' << static_cast<uint8_t>(v); }
    else if (v <= 0xffff) {
      OS << '\xcd';
      char buf[2]; buf[0] = (v >> 8) & 0xff; buf[1] = v & 0xff;
      OS.write(buf, 2);
    } else if (v <= 0xffffffff) {
      OS << '\xce';
      char buf[4];
      buf[0] = (v >> 24) & 0xff; buf[1] = (v >> 16) & 0xff;
      buf[2] = (v >> 8) & 0xff; buf[3] = v & 0xff;
      OS.write(buf, 4);
    } else {
      OS << '\xcf';
      char buf[8];
      for (int i = 7; i >= 0; --i) { buf[7-i] = (v >> (i*8)) & 0xff; }
      OS.write(buf, 8);
    }
  }
  
  void write_str(StringRef s) {
    size_t n = s.size();
    if (n <= 31) { OS << static_cast<char>(0xa0 | n); }
    else if (n <= 0xff) { OS << '\xd9' << static_cast<uint8_t>(n); }
    else if (n <= 0xffff) {
      OS << '\xda';
      char buf[2]; buf[0] = (n >> 8) & 0xff; buf[1] = n & 0xff;
      OS.write(buf, 2);
    } else {
      OS << '\xdb';
      char buf[4];
      buf[0] = (n >> 24) & 0xff; buf[1] = (n >> 16) & 0xff;
      buf[2] = (n >> 8) & 0xff; buf[3] = n & 0xff;
      OS.write(buf, 4);
    }
    OS.write(s.data(), s.size());
  }
  
  void write_bin(StringRef b) {
    size_t n = b.size();
    if (n <= 0xff) { OS << '\xc4' << static_cast<uint8_t>(n); }
    else if (n <= 0xffff) {
      OS << '\xc5';
      char buf[2]; buf[0] = (n >> 8) & 0xff; buf[1] = n & 0xff;
      OS.write(buf, 2);
    } else {
      OS << '\xc6';
      char buf[4];
      buf[0] = (n >> 24) & 0xff; buf[1] = (n >> 16) & 0xff;
      buf[2] = (n >> 8) & 0xff; buf[3] = n & 0xff;
      OS.write(buf, 4);
    }
    OS.write(b.data(), b.size());
  }
  
  void write_array_header(uint32_t n) {
    if (n <= 15) { OS << static_cast<char>(0x90 | n); }
    else if (n <= 0xffff) {
      OS << '\xdc';
      char buf[2]; buf[0] = (n >> 8) & 0xff; buf[1] = n & 0xff;
      OS.write(buf, 2);
    } else {
      OS << '\xdd';
      char buf[4];
      buf[0] = (n >> 24) & 0xff; buf[1] = (n >> 16) & 0xff;
      buf[2] = (n >> 8) & 0xff; buf[3] = n & 0xff;
      OS.write(buf, 4);
    }
  }
  
  void write_map_header(uint32_t n) {
    if (n <= 15) { OS << static_cast<char>(0x80 | n); }
    else if (n <= 0xffff) {
      OS << '\xde';
      char buf[2]; buf[0] = (n >> 8) & 0xff; buf[1] = n & 0xff;
      OS.write(buf, 2);
    } else {
      OS << '\xdf';
      char buf[4];
      buf[0] = (n >> 24) & 0xff; buf[1] = (n >> 16) & 0xff;
      buf[2] = (n >> 8) & 0xff; buf[3] = n & 0xff;
      OS.write(buf, 4);
    }
  }
};

// ── Command line options ────────────────────────────────────────────
static cl::opt<std::string> InputFile(cl::Positional, cl::desc("<input .ll file>"), cl::Required);
static cl::opt<std::string> OutputFile("o", cl::desc("Output filename (default: stdout)"), cl::value_desc("filename"));
static cl::opt<bool> Verbose("v", cl::desc("Enable verbose output"));
static cl::opt<bool> Timing("t", cl::desc("Show timing information"));

// FFI Slice Filter options
enum SliceMode { SLICE_NONE, SLICE_FFI };
static cl::opt<SliceMode> Slice(
    "slice", cl::desc("Slice filter mode:"),
    cl::values(
        clEnumValN(SLICE_NONE, "none", "Export all functions (default)"),
        clEnumValN(SLICE_FFI, "ffi", "Export only FFI-related slice")),
    cl::init(SLICE_NONE));
static cl::opt<unsigned> SliceHops("slice-hops", cl::desc("Call graph expansion hops (default: 2)"), cl::init(2));
static cl::opt<bool> SliceStats("slice-stats", cl::desc("Output slice statistics to stderr"));

// Output format options
enum OutputFormat { FMT_JSON, FMT_MSGPACK };
static cl::opt<OutputFormat> Format(
    "format", cl::desc("Output format:"),
    cl::values(
        clEnumValN(FMT_JSON, "json", "JSON text (default)"),
        clEnumValN(FMT_MSGPACK, "msgpack", "MessagePack binary")),
    cl::init(FMT_JSON));
static cl::opt<bool> NoRaw("no-raw", cl::desc("Skip raw instruction text field (faster output)"), cl::init(true));

/// Check whether a function should be excluded from the output.
static bool shouldSkipFunction(const Function &F) {
  const StringRef Name = F.getName();

  if (Name.starts_with("llvm."))
    return true;

  static const char *const SkipList[] = {
      "__chkstk",    "__stack_chk", "_GLOBAL_", "__cxa_", "__gmon_",
      "__sanitizer", "__asan",      "__msan",   "__tsan", "__ubsan",
  };
  for (const char *Pfx : SkipList) {
    if (Name.starts_with(Pfx))
      return true;
  }

  return false;
}

/// Detailed timing statistics for ir_extractor
struct TimingStats {
  // Time durations in milliseconds
  int64_t parse_ms = 0;
  int64_t index_ms = 0;
  int64_t seed_detection_ms = 0;
  int64_t closure_computation_ms = 0;
  int64_t serialization_ms = 0;
  int64_t total_ms = 0;
  
  // Counters
  int64_t functions_total = 0;
  int64_t functions_selected = 0;
  int64_t instructions_total = 0;
  int64_t instructions_selected = 0;
  int64_t json_bytes = 0;
};
// ── Helpers ─────────────────────────────────────────────────────────

/// Print an LLVM Type to a string with fast path for common types.
static std::string typeToString(const Type *T) {
  if (!T)
    return "void";
  
  // Fast path for common primitive types
  switch (T->getTypeID()) {
  case Type::VoidTyID: return "void";
  case Type::HalfTyID: return "half";
  case Type::BFloatTyID: return "bfloat";
  case Type::FloatTyID: return "float";
  case Type::DoubleTyID: return "double";
  case Type::X86_FP80TyID: return "x86_fp80";
  case Type::FP128TyID: return "fp128";
  case Type::PPC_FP128TyID: return "ppc_fp128";
  case Type::IntegerTyID: {
    unsigned BitWidth = cast<IntegerType>(T)->getBitWidth();
    switch (BitWidth) {
    case 1: return "i1";
    case 8: return "i8";
    case 16: return "i16";
    case 32: return "i32";
    case 64: return "i64";
    case 128: return "i128";
    default: return "i" + std::to_string(BitWidth);
    }
  }
  case Type::PointerTyID: return "ptr";
  default: break;
  }
  
  // Fallback for complex types (structs, arrays, functions, etc.)
  std::string S;
  raw_string_ostream OS(S);
  T->print(OS);
  OS.flush();
  return S;
}

/// Print an LLVM Value (used for operand pretty-printing) to string with fast path.
static std::string valueToString(const Value *V) {
  if (!V)
    return "null";
  
  // Fast path for named values
  if (V->hasName()) {
    std::string S = "%";
    S += V->getName();
    return S;
  }
  
  // Fallback for unnamed values (constants, etc.)
  std::string S;
  raw_string_ostream OS(S);
  V->printAsOperand(OS, false);
  OS.flush();
  return S;
}

/// Write a JSON-escaped string (with surrounding quotes) to an output stream.
static void writeJsonString(raw_ostream &OS, StringRef S) {
  OS << '"';
  for (char C : S) {
    switch (C) {
    case '"':  OS << "\\\""; break;
    case '\\': OS << "\\\\"; break;
    case '\b': OS << "\\b";  break;
    case '\f': OS << "\\f";  break;
    case '\n': OS << "\\n";  break;
    case '\r': OS << "\\r";  break;
    case '\t': OS << "\\t";  break;
    default:
      if (static_cast<unsigned char>(C) < 0x20) {
        OS << "\\u00" << "0123456789abcdef"[((unsigned char)C >> 4)]
                        << "0123456789abcdef"[((unsigned char)C & 0xf)];
      } else {
        OS << C;
      }
    }
  }
  OS << '"';
}

/// Write a JSON-escaped string (with surrounding quotes) to an output stream (std::string overload).
static void writeJsonString(raw_ostream &OS, const std::string &S) {
  writeJsonString(OS, StringRef(S));
}

/// Write a JSON-escaped string (with surrounding quotes) to an output stream (Triple overload).
static void writeJsonString(raw_ostream &OS, const Triple &T) {
  writeJsonString(OS, T.str());
}

// Forward declarations for streaming JSON writers
static void writeInstruction(raw_ostream &OS, const Instruction &I, unsigned Id);
static void writeBasicBlock(raw_ostream &OS, const BasicBlock &BB, unsigned BBIndex,
                            const DenseMap<const BasicBlock *, std::string> &BBIndexMap);
static void writeFunction(raw_ostream &OS, const Function &F);
static void writeDeclaration(raw_ostream &OS, const Function &F);

/// Return the textual opcode name for an instruction.
static StringRef opcodeName(unsigned Opcode) {
  return Instruction::getOpcodeName(Opcode);
}

/// Get calling-convention name.
static StringRef ccName(unsigned CC) {
  switch (CC) {
  case CallingConv::C:
    return "ccc";
  case CallingConv::Fast:
    return "fastcc";
  case CallingConv::Cold:
    return "coldcc";
  case CallingConv::X86_StdCall:
    return "x86_stdcallcc";
  case CallingConv::X86_FastCall:
    return "x86_fastcallcc";
  case CallingConv::AArch64_VectorCall:
    return "aarch64_vector_pcs";
  default:
    return "ccc";
  }
}

// ── Module Index for FFI Slice Filter ───────────────────────────────

/// Lightweight function summary for indexing without full serialization.
struct FunctionSummary {
  std::string name;
  bool is_declaration = false;
  bool is_exported = false;
  unsigned calling_convention = 0;
  bool has_external_call = false;
  bool has_indirect_call = false;
  bool has_invoke = false;
  bool has_function_pointer_arg = false;
  bool has_pointer_param = false;
  bool returns_pointer = false;
  std::set<std::string> callee_names;
  std::set<std::string> external_callee_names;
};

/// Module index containing call graph and function summaries.
struct ModuleIndex {
  std::map<std::string, FunctionSummary> functions;
  std::map<std::string, std::set<std::string>> call_graph; // caller -> callees
  std::map<std::string, std::set<std::string>> reverse_call_graph; // callee -> callers
  std::set<std::string> selected_functions;
  std::set<std::string> selected_declarations;
};

// ── FFI Slice Filter Implementation ────────────────────────────────

/// Check if a function name matches common FFI/API prefixes.
static bool matchesFfiPrefix(const std::string &name) {
  // Core FFI/API prefixes that are most commonly used
  // Only match exact prefixes, not substrings
  static const char *const FFI_PREFIXES[] = {
      "sqlite3_", "malloc", "calloc", "realloc", "free", "strdup",
      "pthread_", "dlopen", "dlsym", "dlclose",
      "SSL_", "curl_", "Py_", "JNI_",
      "objc_", "swift_",
  };
  
  // Check if name starts with any of the core prefixes
  for (const char *prefix : FFI_PREFIXES) {
    if (name.substr(0, strlen(prefix)) == prefix)
      return true;
  }
  
  // Check for specific FFI functions (not prefixes)
  static const char *const FFI_FUNCTIONS[] = {
      "open", "close", "read", "write", "socket",
      "strcmp", "strlen", "memcpy", "memset", "memmove",
      "printf", "fprintf", "sprintf", "snprintf",
  };
  
  for (const char *func : FFI_FUNCTIONS) {
    if (name == func)
      return true;
  }
  
  return false;
}

/// Check if a function is exported (externally visible).
static bool isExportedFunction(const Function &F) {
  // Check for external linkage
  if (F.hasExternalLinkage() && !F.isDeclaration())
    return true;
  // Check for common export patterns
  const StringRef Name = F.getName();
  if (Name.starts_with("__") && Name.ends_with("__"))
    return false; // Likely internal
  // Check for C ABI style (no mangling)
  if (Name.find("$") == StringRef::npos && Name.find(".") == StringRef::npos)
    return true;
  return false;
}

/// Check if a function has risk factors (indirect call, invoke, function pointer args).
static bool hasRiskFactors(const Function &F) {
  for (const BasicBlock &BB : F) {
    for (const Instruction &I : BB) {
      // Check for indirect calls
      if (const auto *CI = dyn_cast<CallInst>(&I)) {
        if (!CI->getCalledFunction())
          return true;
      }
      // Check for invokes
      if (isa<InvokeInst>(&I))
        return true;
    }
  }
  // Check for function pointer parameters
  for (const Argument &Arg : F.args()) {
    if (Arg.getType()->isPointerTy()) {
      // Check if it's a function pointer by looking at uses
      for (const Use &U : Arg.uses()) {
        if (const auto *CI = dyn_cast<CallInst>(U.getUser())) {
          if (CI->getCalledOperand() == &Arg) {
            return true;
          }
        } else if (const auto *II = dyn_cast<InvokeInst>(U.getUser())) {
          if (II->getCalledOperand() == &Arg) {
            return true;
          }
        }
      }
    }
  }
  return false;
}

/// Build module index by scanning all functions.
static void buildModuleIndex(const Module &M, ModuleIndex &Index) {
  // First pass: collect function summaries
  for (const Function &F : M) {
    if (shouldSkipFunction(F))
      continue;

    FunctionSummary Summary;
    Summary.name = F.getName().str();
    Summary.is_declaration = F.isDeclaration();
    Summary.is_exported = isExportedFunction(F);
    Summary.calling_convention = F.getCallingConv();
    Summary.returns_pointer = F.getReturnType()->isPointerTy();

    // Check parameters
    for (const Argument &Arg : F.args()) {
      if (Arg.getType()->isPointerTy()) {
        Summary.has_pointer_param = true;
        // Check for function pointer by looking at uses
        for (const Use &U : Arg.uses()) {
          if (const auto *CI = dyn_cast<CallInst>(U.getUser())) {
            if (CI->getCalledOperand() == &Arg) {
              Summary.has_function_pointer_arg = true;
              break;
            }
          } else if (const auto *II = dyn_cast<InvokeInst>(U.getUser())) {
            if (II->getCalledOperand() == &Arg) {
              Summary.has_function_pointer_arg = true;
              break;
            }
          }
        }
      }
    }

    // Scan instructions for calls
    if (!F.isDeclaration()) {
      for (const BasicBlock &BB : F) {
        for (const Instruction &I : BB) {
          if (const auto *CI = dyn_cast<CallInst>(&I)) {
            if (const Function *Callee = CI->getCalledFunction()) {
              std::string CalleeName = Callee->getName().str();
              Summary.callee_names.insert(CalleeName);
              if (Callee->isDeclaration())
                Summary.external_callee_names.insert(CalleeName);
            } else {
              Summary.has_indirect_call = true;
            }
          } else if (const auto *II = dyn_cast<InvokeInst>(&I)) {
            Summary.has_invoke = true;
            if (const Function *Callee = II->getCalledFunction()) {
              std::string CalleeName = Callee->getName().str();
              Summary.callee_names.insert(CalleeName);
              if (Callee->isDeclaration())
                Summary.external_callee_names.insert(CalleeName);
            } else {
              Summary.has_indirect_call = true;
            }
          }
        }
      }
    }

    Index.functions[Summary.name] = Summary;
  }

  // Second pass: build call graphs
  for (const auto &[Name, Summary] : Index.functions) {
    if (Summary.is_declaration)
      continue;

    for (const auto &CalleeName : Summary.callee_names) {
      Index.call_graph[Name].insert(CalleeName);
      Index.reverse_call_graph[CalleeName].insert(Name);
    }
  }
}

/// Detect FFI seed functions.
static std::set<std::string> detectFfiSeeds(const ModuleIndex &Index) {
  std::set<std::string> Seeds;

  // 1. External declarations that are called (strong FFI signal)
  for (const auto &[Name, Summary] : Index.functions) {
    if (Summary.is_declaration) {
      // Check if any function calls this declaration
      // Only include if called by multiple functions (more likely to be important)
      if (Index.reverse_call_graph.find(Name) != Index.reverse_call_graph.end()) {
        const auto &Callers = Index.reverse_call_graph.at(Name);
        if (Callers.size() >= 3) {  // Called by at least 3 functions
          Seeds.insert(Name);
        }
      }
    }
  }

  // 2. Functions with FFI/API prefixes that are called by multiple functions
  for (const auto &[Name, Summary] : Index.functions) {
    if (matchesFfiPrefix(Name)) {
      // Only include if called by multiple functions or is a declaration
      if (Summary.is_declaration) {
        Seeds.insert(Name);
      } else if (Index.reverse_call_graph.find(Name) != Index.reverse_call_graph.end()) {
        const auto &Callers = Index.reverse_call_graph.at(Name);
        if (Callers.size() >= 3) {  // Called by at least 3 functions
          Seeds.insert(Name);
        }
      }
    }
  }

  // 3. Exported functions with C ABI style that have pointer parameters or return values
  for (const auto &[Name, Summary] : Index.functions) {
    if (Summary.is_exported && !Summary.is_declaration) {
      // Check for C ABI style (no mangling)
      if (Name.find("$") == std::string::npos && Name.find(".") == std::string::npos) {
        // Only include if has pointer params, returns pointer, or calls external functions
        // AND is called by multiple functions (not just exported)
        if ((Summary.has_pointer_param || Summary.returns_pointer || 
             Summary.has_external_call || Summary.has_function_pointer_arg) &&
            Index.reverse_call_graph.find(Name) != Index.reverse_call_graph.end()) {
          const auto &Callers = Index.reverse_call_graph.at(Name);
          if (Callers.size() >= 3) {  // Called by at least 3 functions
            Seeds.insert(Name);
          }
        }
      }
    }
  }

  // 4. Risk functions that are called and have external calls
  for (const auto &[Name, Summary] : Index.functions) {
    if (!Summary.is_declaration && 
        (Summary.has_indirect_call || Summary.has_invoke ||
         Summary.has_function_pointer_arg)) {
      // Only include if called by multiple functions AND has external calls
      if (Index.reverse_call_graph.find(Name) != Index.reverse_call_graph.end() &&
          Summary.has_external_call) {
        const auto &Callers = Index.reverse_call_graph.at(Name);
        if (Callers.size() >= 2) {  // Called by at least 2 functions
          Seeds.insert(Name);
        }
      }
    }
  }

  return Seeds;
}

/// Compute FFI closure (forward, backward, callback, resource).
static std::set<std::string> computeFfiClosure(
    const ModuleIndex &Index,
    const std::set<std::string> &Seeds,
    unsigned MaxHops) {
  std::set<std::string> Selected = Seeds;

  // Helper function to add a function and its callees (forward closure)
  // Only add callees that are called by selected functions
  auto addForwardClosure = [&](const std::string &Name, unsigned Hops) {
    std::set<std::string> Current = {Name};
    for (unsigned Hop = 0; Hop < Hops; ++Hop) {
      std::set<std::string> Next;
      for (const auto &F : Current) {
        if (Index.call_graph.find(F) != Index.call_graph.end()) {
          for (const auto &Callee : Index.call_graph.at(F)) {
            if (Selected.find(Callee) == Selected.end()) {
              // Only add callees that are called by selected functions
              // or are declarations
              if (Index.functions.find(Callee) != Index.functions.end()) {
                const auto &CalleeSummary = Index.functions.at(Callee);
                if (CalleeSummary.is_declaration || 
                    Index.reverse_call_graph.find(Callee) != Index.reverse_call_graph.end()) {
                  Selected.insert(Callee);
                  Next.insert(Callee);
                }
              }
            }
          }
        }
      }
      Current = Next;
    }
  };

  // Helper function to add callers (backward closure)
  // Only add callers that call selected functions
  auto addBackwardClosure = [&](const std::string &Name, unsigned Hops) {
    std::set<std::string> Current = {Name};
    for (unsigned Hop = 0; Hop < Hops; ++Hop) {
      std::set<std::string> Next;
      for (const auto &F : Current) {
        if (Index.reverse_call_graph.find(F) != Index.reverse_call_graph.end()) {
          for (const auto &Caller : Index.reverse_call_graph.at(F)) {
            if (Selected.find(Caller) == Selected.end()) {
              // Only add callers that call selected functions
              // and are not declarations
              if (Index.functions.find(Caller) != Index.functions.end()) {
                const auto &CallerSummary = Index.functions.at(Caller);
                if (!CallerSummary.is_declaration) {
                  Selected.insert(Caller);
                  Next.insert(Caller);
                }
              }
            }
          }
        }
      }
      Current = Next;
    }
  };

  // Process seeds with limited expansion
  for (const auto &Seed : Seeds) {
    // Only expand backward closure for seeds that are called
    if (Index.reverse_call_graph.find(Seed) != Index.reverse_call_graph.end()) {
      addBackwardClosure(Seed, 0);  // No backward expansion
    }
    
    // Only expand forward closure for seeds that call other functions
    if (Index.call_graph.find(Seed) != Index.call_graph.end()) {
      addForwardClosure(Seed, 0);  // No forward expansion
    }
  }

  // Resource closure: for allocator/free patterns
  static const char *const ALLOCATORS[] = {
      "malloc", "calloc", "realloc", "strdup",
      "sqlite3_malloc", "sqlite3_realloc",
  };
  static const char *const FREERS[] = {
      "free", "sqlite3_free",
  };

  // Check for allocator-free pairs
  std::set<std::string> Allocators;
  std::set<std::string> Freers;
  for (const auto &[Name, Summary] : Index.functions) {
    for (const char *Alloc : ALLOCATORS) {
      if (Name == Alloc || Name.substr(0, strlen(Alloc)) == Alloc)
        Allocators.insert(Name);
    }
    for (const char *Free : FREERS) {
      if (Name == Free || Name.substr(0, strlen(Free)) == Free)
        Freers.insert(Name);
    }
  }

  // If we have allocators or freers in seeds, expand closure
  for (const auto &Alloc : Allocators) {
    if (Seeds.find(Alloc) != Seeds.end()) {
      // Find all callers of allocator
      addBackwardClosure(Alloc, MaxHops);
    }
  }
  for (const auto &Free : Freers) {
    if (Seeds.find(Free) != Seeds.end()) {
      // Find all callers of freer
      addBackwardClosure(Free, MaxHops);
    }
  }

  return Selected;
}

// ── Streaming JSON writers ──────────────────────────────────────────

/// Build a label for a basic block.
static std::string blockLabel(const BasicBlock &BB, unsigned BBIndex) {
  if (!BB.getName().empty())
    return BB.getName().str();
  return "bb_" + std::to_string(BBIndex);
}

/// Write a single instruction as streaming JSON.
static void writeInstruction(raw_ostream &OS, const Instruction &I, unsigned Id) {
  OS << "{\"id\":" << Id
     << ",\"opcode\":";
  writeJsonString(OS, opcodeName(I.getOpcode()));
  OS << ",\"result_type\":";
  writeJsonString(OS, typeToString(I.getType()));

  // Operands - skip if empty
  unsigned NumOps = I.getNumOperands();
  if (NumOps > 0) {
    OS << ",\"operands\":[";
    for (unsigned OpIdx = 0; OpIdx < NumOps; ++OpIdx) {
      if (OpIdx) OS << ',';
      writeJsonString(OS, valueToString(I.getOperand(OpIdx)));
    }
    OS << "],\"operand_types\":[";
    for (unsigned OpIdx = 0; OpIdx < NumOps; ++OpIdx) {
      if (OpIdx) OS << ',';
      writeJsonString(OS, typeToString(I.getOperand(OpIdx)->getType()));
    }
    OS << ']';
  }

  // Bitcast chain: trace back through chains of bitcasts/inttoptr/ptrtoint
  if (I.getOpcode() == Instruction::BitCast ||
      I.getOpcode() == Instruction::IntToPtr ||
      I.getOpcode() == Instruction::PtrToInt) {
    const Value *Src = I.getOperand(0);
    while (auto *BC = dyn_cast<CastInst>(Src))
      Src = BC->getOperand(0);
    OS << ",\"source_type\":";
    writeJsonString(OS, typeToString(Src->getType()));
  }

  // GEP deconstruction: expose the source element type and per-index field types
  if (const auto *GEP = dyn_cast<GetElementPtrInst>(&I)) {
    Type *SourceElemTy = GEP->getSourceElementType();
    OS << ",\"gep_details\":{\"source_type\":";
    writeJsonString(OS, typeToString(SourceElemTy));
    OS << ",\"in_bounds\":" << (GEP->isInBounds() ? "true" : "false");
    OS << ",\"indices\":[";

    SmallVector<Value *, 4> IdxList;
    for (unsigned OpIdx = 1; OpIdx < GEP->getNumOperands(); ++OpIdx) {
      if (OpIdx > 1) OS << ',';
      Value *IdxVal = GEP->getOperand(OpIdx);
      IdxList.push_back(IdxVal);

      const Type *CurrentFieldTy =
          GetElementPtrInst::getIndexedType(SourceElemTy, IdxList);
      OS << "{\"value\":";
      writeJsonString(OS, valueToString(IdxVal));
      OS << ",\"field_type\":";
      writeJsonString(OS, CurrentFieldTy ? typeToString(CurrentFieldTy) : "unknown");
      OS << '}';
    }
    OS << "]}";
  }

  // Call-specific info
  if (const auto *CI = dyn_cast<CallInst>(&I)) {
    if (const Function *Callee = CI->getCalledFunction()) {
      OS << ",\"callee\":";
      writeJsonString(OS, Callee->getName());
      // is_indirect defaults to false, skip writing
    } else {
      OS << ",\"callee\":";
      writeJsonString(OS, valueToString(CI->getCalledOperand()));
      OS << ",\"is_indirect\":true";
    }
  }

  // Invoke instructions (landing-pad calls)
  if (const auto *II = dyn_cast<InvokeInst>(&I)) {
    if (const Function *Callee = II->getCalledFunction()) {
      OS << ",\"callee\":";
      writeJsonString(OS, Callee->getName());
      // is_indirect defaults to false, skip writing
    } else {
      OS << ",\"callee\":";
      writeJsonString(OS, valueToString(II->getCalledOperand()));
      OS << ",\"is_indirect\":true";
    }
  }

  // Debug location
  if (const DebugLoc &DL = I.getDebugLoc()) {
    std::string Loc =
        DL->getFilename().str() + ":" + std::to_string(DL->getLine());
    if (DL->getColumn() > 0)
      Loc += ":" + std::to_string(DL->getColumn());
    OS << ",\"debug_loc\":";
    writeJsonString(OS, Loc);
  }

  // Raw textual representation
  if (!NoRaw) {
    std::string Raw;
    raw_string_ostream RawOS(Raw);
    I.print(RawOS);
    RawOS.flush();
    auto Pos = Raw.find_first_not_of(" \t");
    OS << ",\"raw\":";
    writeJsonString(OS, (Pos != std::string::npos) ? Raw.substr(Pos) : Raw);
  }

  OS << '}';
}

/// Write a basic block as streaming JSON.
static void writeBasicBlock(
    raw_ostream &OS, const BasicBlock &BB, unsigned BBIndex,
    const DenseMap<const BasicBlock *, std::string> &BBIndexMap) {
  OS << "{\"label\":";
  writeJsonString(OS, blockLabel(BB, BBIndex));

  // Instructions
  OS << ",\"instructions\":[";
  unsigned Idx = 0;
  for (const Instruction &I : BB) {
    if (Idx) OS << ',';
    writeInstruction(OS, I, Idx++);
  }
  OS << ']';

  // CFG successors
  OS << ",\"successors\":[";
  bool FirstSucc = true;
  if (const Instruction *TI = BB.getTerminator()) {
    for (unsigned i = 0; i < TI->getNumSuccessors(); ++i) {
      if (!FirstSucc) OS << ',';
      FirstSucc = false;
      const BasicBlock *Succ = TI->getSuccessor(i);
      auto It = BBIndexMap.find(Succ);
      writeJsonString(OS, It != BBIndexMap.end() ? It->second : "unknown");
    }
  }
  OS << "]}";
}

/// Write a function (with body) as streaming JSON.
static void writeFunction(raw_ostream &OS, const Function &F) {
  const std::string Name = F.getName().str();
  OS << "{\"name\":";
  writeJsonString(OS, Name);
  OS << ",\"demangled\":";
  writeJsonString(OS, demangle(Name));
  OS << ",\"is_declaration\":" << (F.isDeclaration() ? "true" : "false");
  OS << ",\"return_type\":";
  writeJsonString(OS, typeToString(F.getReturnType()));

  OS << ",\"param_types\":[";
  unsigned ParamIdx = 0;
  for (const Argument &Arg : F.args()) {
    if (ParamIdx) OS << ',';
    writeJsonString(OS, typeToString(Arg.getType()));
    ParamIdx++;
  }
  OS << ']';

  OS << ",\"calling_convention\":";
  writeJsonString(OS, ccName(F.getCallingConv()));

  // Basic blocks (only for definitions)
  if (!F.isDeclaration()) {
    DenseMap<const BasicBlock *, std::string> BBIndexMap;
    unsigned BBIdx = 0;
    for (const BasicBlock &BB : F) {
      BBIndexMap[&BB] = blockLabel(BB, BBIdx++);
    }

    OS << ",\"blocks\":[";
    BBIdx = 0;
    for (const BasicBlock &BB : F) {
      if (BBIdx) OS << ',';
      writeBasicBlock(OS, BB, BBIdx++, BBIndexMap);
    }
    OS << ']';
  }

  OS << '}';
}

/// Write a function declaration as streaming JSON.
static void writeDeclaration(raw_ostream &OS, const Function &F) {
  const std::string Name = F.getName().str();
  OS << "{\"name\":";
  writeJsonString(OS, Name);
  OS << ",\"demangled\":";
  writeJsonString(OS, demangle(Name));
  OS << ",\"return_type\":";
  writeJsonString(OS, typeToString(F.getReturnType()));

  OS << ",\"param_types\":[";
  unsigned ParamIdx = 0;
  for (const Argument &Arg : F.args()) {
    if (ParamIdx) OS << ',';
    writeJsonString(OS, typeToString(Arg.getType()));
    ParamIdx++;
  }
  OS << "]}";
}

/// Write global variables as streaming JSON.
static void writeNamedStructs(raw_ostream &OS, const Module &M) {
  OS << '{';
  bool First = true;
  for (const StructType *ST : M.getIdentifiedStructTypes()) {
    if (!ST->hasName() || ST->isOpaque()) continue;
    if (!First) OS << ',';
    First = false;
    writeJsonString(OS, ST->getName());
    OS << ":[";
    for (unsigned i = 0; i < ST->getNumElements(); ++i) {
      if (i) OS << ',';
      writeJsonString(OS, typeToString(ST->getElementType(i)));
    }
    OS << ']';
  }
  OS << '}';
}

/// Write global variables as streaming JSON.
static void writeGlobalVariables(raw_ostream &OS, const Module &M) {
  OS << '[';
  bool First = true;
  for (const GlobalVariable &GV : M.globals()) {
    if (!First) OS << ',';
    First = false;
    OS << "{\"name\":";
    writeJsonString(OS, GV.getName());
    OS << ",\"type\":";
    writeJsonString(OS, typeToString(GV.getValueType()));
    OS << ",\"is_constant\":" << (GV.isConstant() ? "true" : "false");
    OS << '}';
  }
  OS << ']';
}

// ── MessagePack writers ─────────────────────────────────────────────

/// Write a single instruction as MessagePack.
static void mpWriteInstruction(MsgpackWriter &W, const Instruction &I, unsigned Id) {
  // Count fields
  unsigned NumFields = 5; // id, opcode, result_type, operands, operand_types
  
  // Check for optional fields
  bool hasBitcastChain = false;
  bool hasGepDetails = false;
  bool hasCallInfo = false;
  bool hasInvokeInfo = false;
  bool hasDebugLoc = false;
  
  if (I.getOpcode() == Instruction::BitCast ||
      I.getOpcode() == Instruction::IntToPtr ||
      I.getOpcode() == Instruction::PtrToInt) {
    hasBitcastChain = true;
    NumFields++;
  }
  
  if (isa<GetElementPtrInst>(&I)) {
    hasGepDetails = true;
    NumFields++;
  }
  
  if (const auto *CI = dyn_cast<CallInst>(&I)) {
    hasCallInfo = true;
    NumFields += 2; // callee, is_indirect
  }
  
  if (const auto *II = dyn_cast<InvokeInst>(&I)) {
    hasInvokeInfo = true;
    NumFields += 2; // callee, is_indirect
  }
  
  if (I.getDebugLoc()) {
    hasDebugLoc = true;
    NumFields++;
  }

  bool includeRaw = !NoRaw;
  if (includeRaw) {
    NumFields++; // raw
  }

  W.write_map_header(NumFields);
  
  // id
  W.write_str("id");
  W.write_uint(Id);
  
  // opcode
  W.write_str("opcode");
  W.write_str(opcodeName(I.getOpcode()));
  
  // result_type
  W.write_str("result_type");
  W.write_str(typeToString(I.getType()));
  
  // operands
  W.write_str("operands");
  W.write_array_header(I.getNumOperands());
  for (unsigned OpIdx = 0; OpIdx < I.getNumOperands(); ++OpIdx) {
    W.write_str(valueToString(I.getOperand(OpIdx)));
  }
  
  // operand_types
  W.write_str("operand_types");
  W.write_array_header(I.getNumOperands());
  for (unsigned OpIdx = 0; OpIdx < I.getNumOperands(); ++OpIdx) {
    W.write_str(typeToString(I.getOperand(OpIdx)->getType()));
  }
  
  // Bitcast chain
  if (hasBitcastChain) {
    const Value *Src = I.getOperand(0);
    while (auto *BC = dyn_cast<CastInst>(Src))
      Src = BC->getOperand(0);
    W.write_str("source_type");
    W.write_str(typeToString(Src->getType()));
  }
  
  // GEP details
  if (hasGepDetails) {
    const auto *GEP = cast<GetElementPtrInst>(&I);
    Type *SourceElemTy = GEP->getSourceElementType();
    
    SmallVector<Value *, 4> IdxList;
    unsigned NumIndices = GEP->getNumOperands() - 1;
    
    W.write_str("gep_details");
    W.write_map_header(3);
    
    W.write_str("source_type");
    W.write_str(typeToString(SourceElemTy));
    
    W.write_str("in_bounds");
    W.write_bool(GEP->isInBounds());
    
    W.write_str("indices");
    W.write_array_header(NumIndices);
    for (unsigned OpIdx = 1; OpIdx < GEP->getNumOperands(); ++OpIdx) {
      Value *IdxVal = GEP->getOperand(OpIdx);
      IdxList.push_back(IdxVal);
      
      const Type *CurrentFieldTy =
          GetElementPtrInst::getIndexedType(SourceElemTy, IdxList);
      
      W.write_map_header(2);
      W.write_str("value");
      W.write_str(valueToString(IdxVal));
      W.write_str("field_type");
      W.write_str(CurrentFieldTy ? typeToString(CurrentFieldTy) : "unknown");
    }
  }
  
  // Call info
  if (hasCallInfo) {
    const auto *CI = cast<CallInst>(&I);
    if (const Function *Callee = CI->getCalledFunction()) {
      W.write_str("callee");
      W.write_str(Callee->getName());
      W.write_str("is_indirect");
      W.write_bool(false);
    } else {
      W.write_str("callee");
      W.write_str(valueToString(CI->getCalledOperand()));
      W.write_str("is_indirect");
      W.write_bool(true);
    }
  }
  
  // Invoke info
  if (hasInvokeInfo) {
    const auto *II = cast<InvokeInst>(&I);
    if (const Function *Callee = II->getCalledFunction()) {
      W.write_str("callee");
      W.write_str(Callee->getName());
      W.write_str("is_indirect");
      W.write_bool(false);
    } else {
      W.write_str("callee");
      W.write_str(valueToString(II->getCalledOperand()));
      W.write_str("is_indirect");
      W.write_bool(true);
    }
  }
  
  // Debug location
  if (hasDebugLoc) {
    const DebugLoc &DL = I.getDebugLoc();
    std::string Loc =
        DL->getFilename().str() + ":" + std::to_string(DL->getLine());
    if (DL->getColumn() > 0)
      Loc += ":" + std::to_string(DL->getColumn());
    W.write_str("debug_loc");
    W.write_str(Loc);
  }
  
  // Raw textual representation
  if (includeRaw) {
    std::string Raw;
    raw_string_ostream RawOS(Raw);
    I.print(RawOS);
    RawOS.flush();
    auto Pos = Raw.find_first_not_of(" \t");
    W.write_str("raw");
    W.write_str((Pos != std::string::npos) ? Raw.substr(Pos) : Raw);
  }
}

/// Write a basic block as MessagePack.
static void mpWriteBasicBlock(
    MsgpackWriter &W, const BasicBlock &BB, unsigned BBIndex,
    const DenseMap<const BasicBlock *, std::string> &BBIndexMap) {
  W.write_map_header(3);
  
  // label
  W.write_str("label");
  W.write_str(blockLabel(BB, BBIndex));
  
  // instructions
  W.write_str("instructions");
  unsigned InstrCount = 0;
  for (const Instruction &I : BB) {
    InstrCount++;
  }
  W.write_array_header(InstrCount);
  unsigned Idx = 0;
  for (const Instruction &I : BB) {
    mpWriteInstruction(W, I, Idx++);
  }
  
  // CFG successors
  W.write_str("successors");
  unsigned NumSuccessors = 0;
  if (const Instruction *TI = BB.getTerminator()) {
    NumSuccessors = TI->getNumSuccessors();
  }
  W.write_array_header(NumSuccessors);
  if (const Instruction *TI = BB.getTerminator()) {
    for (unsigned i = 0; i < TI->getNumSuccessors(); ++i) {
      const BasicBlock *Succ = TI->getSuccessor(i);
      auto It = BBIndexMap.find(Succ);
      W.write_str(It != BBIndexMap.end() ? It->second : "unknown");
    }
  }
}

/// Write a function (with body) as MessagePack.
static void mpWriteFunction(MsgpackWriter &W, const Function &F) {
  const std::string Name = F.getName().str();
  
  // Count fields
  unsigned NumFields = 5; // name, demangled, is_declaration, return_type, param_types
  if (!F.isDeclaration()) {
    NumFields++; // blocks
  }
  NumFields++; // calling_convention
  
  W.write_map_header(NumFields);
  
  // name
  W.write_str("name");
  W.write_str(Name);
  
  // demangled
  W.write_str("demangled");
  W.write_str(demangle(Name));
  
  // is_declaration
  W.write_str("is_declaration");
  W.write_bool(F.isDeclaration());
  
  // return_type
  W.write_str("return_type");
  W.write_str(typeToString(F.getReturnType()));
  
  // param_types
  W.write_str("param_types");
  W.write_array_header(F.arg_size());
  for (const Argument &Arg : F.args()) {
    W.write_str(typeToString(Arg.getType()));
  }
  
  // calling_convention
  W.write_str("calling_convention");
  W.write_str(ccName(F.getCallingConv()));
  
  // Basic blocks (only for definitions)
  if (!F.isDeclaration()) {
    DenseMap<const BasicBlock *, std::string> BBIndexMap;
    unsigned BBIdx = 0;
    for (const BasicBlock &BB : F) {
      BBIndexMap[&BB] = blockLabel(BB, BBIdx++);
    }
    
    W.write_str("blocks");
    W.write_array_header(F.size());
    BBIdx = 0;
    for (const BasicBlock &BB : F) {
      mpWriteBasicBlock(W, BB, BBIdx++, BBIndexMap);
    }
  }
}

/// Write a function declaration as MessagePack.
static void mpWriteDeclaration(MsgpackWriter &W, const Function &F) {
  const std::string Name = F.getName().str();
  
  W.write_map_header(4);
  
  // name
  W.write_str("name");
  W.write_str(Name);
  
  // demangled
  W.write_str("demangled");
  W.write_str(demangle(Name));
  
  // return_type
  W.write_str("return_type");
  W.write_str(typeToString(F.getReturnType()));
  
  // param_types
  W.write_str("param_types");
  W.write_array_header(F.arg_size());
  for (const Argument &Arg : F.args()) {
    W.write_str(typeToString(Arg.getType()));
  }
}

/// Write named structs as MessagePack.
static void mpWriteNamedStructs(MsgpackWriter &W, const Module &M) {
  unsigned NumStructs = 0;
  for (const StructType *ST : M.getIdentifiedStructTypes()) {
    if (!ST->hasName() || ST->isOpaque()) continue;
    NumStructs++;
  }
  
  W.write_map_header(NumStructs);
  for (const StructType *ST : M.getIdentifiedStructTypes()) {
    if (!ST->hasName() || ST->isOpaque()) continue;
    W.write_str(ST->getName());
    W.write_array_header(ST->getNumElements());
    for (unsigned i = 0; i < ST->getNumElements(); ++i) {
      W.write_str(typeToString(ST->getElementType(i)));
    }
  }
}

/// Write global variables as MessagePack.
static void mpWriteGlobalVariables(MsgpackWriter &W, const Module &M) {
  unsigned NumGlobals = 0;
  for (const GlobalVariable &GV : M.globals()) {
    NumGlobals++;
  }
  
  W.write_array_header(NumGlobals);
  for (const GlobalVariable &GV : M.globals()) {
    W.write_map_header(3);
    
    W.write_str("name");
    W.write_str(GV.getName());
    
    W.write_str("type");
    W.write_str(typeToString(GV.getValueType()));
    
    W.write_str("is_constant");
    W.write_bool(GV.isConstant());
  }
}

// ── Main function ───────────────────────────────────────────────────

int main(int argc, char **argv) {
  // Parse command line options
  cl::ParseCommandLineOptions(argc, argv, "LLVM IR to JSON/MessagePack extractor\n");

  auto StartTime = std::chrono::high_resolution_clock::now();

  // Initialize timing stats
  TimingStats timing_stats;

  // Create LLVM context and parse IR
  LLVMContext Context;

  SMDiagnostic Err;
  std::unique_ptr<Module> M = parseIRFile(InputFile, Err, Context);

  if (!M) {
    Err.print(argv[0], errs());
    return 1;
  }

  auto ParseTime = std::chrono::high_resolution_clock::now();
  timing_stats.parse_ms = std::chrono::duration_cast<std::chrono::milliseconds>(ParseTime - StartTime).count();

  // Build module index if needed
  ModuleIndex Index;
  std::set<std::string> SelectedFunctions;
  std::set<std::string> SelectedDeclarations;
  auto IndexTime = ParseTime;
  auto SliceTime = ParseTime;

  if (Slice == SLICE_FFI) {
    // Build module index
    buildModuleIndex(*M, Index);
    IndexTime = std::chrono::high_resolution_clock::now();
    timing_stats.index_ms = std::chrono::duration_cast<std::chrono::milliseconds>(IndexTime - ParseTime).count();

    // Detect FFI seeds
    auto SeedDetectionStart = std::chrono::high_resolution_clock::now();
    std::set<std::string> Seeds = detectFfiSeeds(Index);
    auto SeedDetectionEnd = std::chrono::high_resolution_clock::now();
    timing_stats.seed_detection_ms = std::chrono::duration_cast<std::chrono::milliseconds>(SeedDetectionEnd - SeedDetectionStart).count();

    // Compute FFI closure
    auto ClosureStart = std::chrono::high_resolution_clock::now();
    SelectedFunctions = computeFfiClosure(Index, Seeds, SliceHops);
    SliceTime = std::chrono::high_resolution_clock::now();
    timing_stats.closure_computation_ms = std::chrono::duration_cast<std::chrono::milliseconds>(SliceTime - ClosureStart).count();

    // Select declarations that are called by selected functions
    for (const auto &FuncName : SelectedFunctions) {
      if (Index.functions.find(FuncName) != Index.functions.end()) {
        const auto &Summary = Index.functions.at(FuncName);
        for (const auto &CalleeName : Summary.callee_names) {
          if (Index.functions.find(CalleeName) != Index.functions.end()) {
            const auto &CalleeSummary = Index.functions.at(CalleeName);
            if (CalleeSummary.is_declaration) {
              SelectedDeclarations.insert(CalleeName);
            }
          }
        }
      }
    }
  }

  // Stream JSON directly
  auto SerializationStart = std::chrono::high_resolution_clock::now();

  // Open output stream
  raw_ostream *OutPtr = &outs();
  std::unique_ptr<raw_fd_ostream> FileOut;
  if (!OutputFile.empty()) {
    std::error_code EC;
    FileOut = std::make_unique<raw_fd_ostream>(OutputFile, EC);
    if (EC) {
      errs() << "Error opening output file: " << EC.message() << "\n";
      return 1;
    }
    OutPtr = FileOut.get();
  }
  // Use buffered output for better performance
  buffer_ostream BufferedOS(*OutPtr);
  raw_ostream &OS = BufferedOS;

  // Counters
  unsigned TotalFunctions = 0;
  unsigned SelectedFunctionCount = 0;
  unsigned TotalInstructions = 0;
  unsigned SelectedInstructionCount = 0;
  unsigned TotalDeclarations = 0;
  unsigned SelectedDeclarationCount = 0;

  if (Format == FMT_MSGPACK) {
    // ── MessagePack output ──────────────────────────────────────────
    MsgpackWriter W(OS);
    
    // Count functions and declarations first
    unsigned NumFunctions = 0;
    unsigned NumDeclarations = 0;
    for (const Function &F : *M) {
      if (shouldSkipFunction(F)) continue;
      if (F.isDeclaration()) {
        if (Slice == SLICE_NONE || SelectedDeclarations.find(F.getName().str()) != SelectedDeclarations.end()) {
          NumDeclarations++;
        }
      } else {
        if (Slice == SLICE_NONE || SelectedFunctions.find(F.getName().str()) != SelectedFunctions.end()) {
          NumFunctions++;
        }
      }
    }
    
    // Write top-level map
    W.write_map_header(6);
    
    // target_triple
    W.write_str("target_triple");
    W.write_str(M->getTargetTriple().str());
    
    // data_layout
    W.write_str("data_layout");
    W.write_str(M->getDataLayoutStr());
    
    // functions
    W.write_str("functions");
    W.write_array_header(NumFunctions);
    for (const Function &F : *M) {
      if (shouldSkipFunction(F)) continue;
      if (F.isDeclaration()) continue;
      
      TotalFunctions++;
      unsigned InstrCount = 0;
      for (const BasicBlock &BB : F)
        InstrCount += BB.size();
      TotalInstructions += InstrCount;

      if (Slice == SLICE_NONE || SelectedFunctions.find(F.getName().str()) != SelectedFunctions.end()) {
        mpWriteFunction(W, F);
        SelectedFunctionCount++;
        SelectedInstructionCount += InstrCount;
      }
    }
    
    // declarations
    W.write_str("declarations");
    W.write_array_header(NumDeclarations);
    for (const Function &F : *M) {
      if (shouldSkipFunction(F)) continue;
      if (!F.isDeclaration()) continue;
      
      TotalDeclarations++;
      if (Slice == SLICE_NONE || SelectedDeclarations.find(F.getName().str()) != SelectedDeclarations.end()) {
        mpWriteDeclaration(W, F);
        SelectedDeclarationCount++;
      }
    }
    
    // named_struct_types
    W.write_str("named_struct_types");
    mpWriteNamedStructs(W, *M);
    
    // global_variables
    W.write_str("global_variables");
    mpWriteGlobalVariables(W, *M);
    
  } else {
    // ── JSON output ─────────────────────────────────────────────────
    // Stream JSON directly
    OS << "{\"target_triple\":";
    writeJsonString(OS, M->getTargetTriple().str());
    OS << ",\"data_layout\":";
    writeJsonString(OS, M->getDataLayoutStr());

    // Functions
    OS << ",\"functions\":[";
    bool FirstFunc = true;
    for (const Function &F : *M) {
      if (shouldSkipFunction(F)) continue;
      if (F.isDeclaration()) continue;
      
      TotalFunctions++;
      unsigned InstrCount = 0;
      for (const BasicBlock &BB : F)
        InstrCount += BB.size();
      TotalInstructions += InstrCount;

      if (Slice == SLICE_NONE || SelectedFunctions.find(F.getName().str()) != SelectedFunctions.end()) {
        if (!FirstFunc) OS << ',';
        FirstFunc = false;
        writeFunction(OS, F);
        SelectedFunctionCount++;
        SelectedInstructionCount += InstrCount;
      }
    }
    OS << ']';

    // Declarations
    OS << ",\"declarations\":[";
    bool FirstDecl = true;
    for (const Function &F : *M) {
      if (shouldSkipFunction(F)) continue;
      if (!F.isDeclaration()) continue;
      
      TotalDeclarations++;
      if (Slice == SLICE_NONE || SelectedDeclarations.find(F.getName().str()) != SelectedDeclarations.end()) {
        if (!FirstDecl) OS << ',';
        FirstDecl = false;
        writeDeclaration(OS, F);
        SelectedDeclarationCount++;
      }
    }
    OS << ']';

    // Named structs and global variables
    OS << ",\"named_struct_types\":";
    writeNamedStructs(OS, *M);
    OS << ",\"global_variables\":";
    writeGlobalVariables(OS, *M);
    OS << "}\n";
  }

  // Update timing stats
  auto SerializeTime = std::chrono::high_resolution_clock::now();
  timing_stats.serialization_ms = std::chrono::duration_cast<std::chrono::milliseconds>(SerializeTime - SerializationStart).count();
  timing_stats.functions_total = TotalFunctions;
  timing_stats.functions_selected = SelectedFunctionCount;
  timing_stats.instructions_total = TotalInstructions;
  timing_stats.instructions_selected = SelectedInstructionCount;

  // For json_bytes, we need to track it differently
  // We'll estimate it or skip it for now
  timing_stats.json_bytes = 0; // Will be updated if needed
  
  // Note: For MessagePack, the output size is tracked differently
  // but we'll use json_bytes field for consistency

  auto EndTime = std::chrono::high_resolution_clock::now();
  timing_stats.total_ms = std::chrono::duration_cast<std::chrono::milliseconds>(EndTime - StartTime).count();

  // Print detailed timing information if requested
  if (Timing) {
    errs() << "[ir-timing] parse_ms: " << timing_stats.parse_ms << "\n";
    errs() << "[ir-timing] index_ms: " << timing_stats.index_ms << "\n";
    errs() << "[ir-timing] seed_detection_ms: " << timing_stats.seed_detection_ms << "\n";
    errs() << "[ir-timing] closure_computation_ms: " << timing_stats.closure_computation_ms << "\n";
    errs() << "[ir-timing] serialization_ms: " << timing_stats.serialization_ms << "\n";
    errs() << "[ir-timing] total_ms: " << timing_stats.total_ms << "\n";
    errs() << "[ir-timing] functions_total: " << timing_stats.functions_total << "\n";
    errs() << "[ir-timing] functions_selected: " << timing_stats.functions_selected << "\n";
    errs() << "[ir-timing] instructions_total: " << timing_stats.instructions_total << "\n";
    errs() << "[ir-timing] instructions_selected: " << timing_stats.instructions_selected << "\n";
    errs() << "[ir-timing] json_bytes: " << timing_stats.json_bytes << "\n";
  }

  // Print slice statistics if requested
  if (SliceStats) {
    errs() << "=== FFI Slice Statistics ===\n";
    errs() << "Total functions: " << TotalFunctions << "\n";
    errs() << "Selected functions: " << SelectedFunctionCount << "\n";
    errs() << "Total declarations: " << TotalDeclarations << "\n";
    errs() << "Selected declarations: " << SelectedDeclarationCount << "\n";
    errs() << "Total instructions: " << TotalInstructions << "\n";
    errs() << "Selected instructions: " << SelectedInstructionCount << "\n";
    errs() << "JSON bytes: " << timing_stats.json_bytes << "\n";

    if (Slice == SLICE_FFI) {
      auto Seeds = detectFfiSeeds(Index);
      errs() << "FFI seeds: " << Seeds.size() << "\n";
      errs() << "Slice hops: " << SliceHops << "\n";
      if (Seeds.empty()) {
        errs() << "NO_FFI_SEEDS: no FFI boundary functions detected\n";
      }
    }
  }

  if (Verbose) {
    errs() << "Successfully processed: " << InputFile << "\n";
    errs() << "Functions: " << SelectedFunctionCount << "\n";
    errs() << "Declarations: " << SelectedDeclarationCount << "\n";
  }

  return 0;
}