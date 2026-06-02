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

#include "llvm/Demangle/Demangle.h"
#include "llvm/IR/DebugInfoMetadata.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#include "llvm/IRReader/IRReader.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/JSON.h"
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

/// Statistics for slice filtering
struct SliceStatistics {
  size_t total_functions = 0;
  size_t selected_functions = 0;
  size_t total_declarations = 0;
  size_t selected_declarations = 0;
  size_t total_instructions = 0;
  size_t selected_instructions = 0;
  size_t total_external_edges = 0;
  size_t selected_external_edges = 0;
  
  std::chrono::milliseconds parse_time{0};
  std::chrono::milliseconds index_time{0};
  std::chrono::milliseconds slice_time{0};
  std::chrono::milliseconds serialize_time{0};
  std::chrono::milliseconds total_time{0};
  size_t json_bytes = 0;
};

// ── Helpers ─────────────────────────────────────────────────────────

/// Print an LLVM Type to a string without allocating a separate stream per call.
static std::string typeToString(const Type *T) {
  if (!T)
    return "void";
  std::string S;
  raw_string_ostream OS(S);
  T->print(OS);
  OS.flush();
  return S;
}

/// Print an LLVM Value (used for operand pretty-printing) to string.
static std::string valueToString(const Value *V) {
  if (!V)
    return "null";
  std::string S;
  raw_string_ostream OS(S);
  V->printAsOperand(OS, false);
  OS.flush();
  return S;
}

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

/// Count total instructions in selected functions.
static unsigned countInstructions(const Module &M, const std::set<std::string> &Selected) {
  unsigned Count = 0;
  for (const Function &F : M) {
    if (Selected.find(F.getName().str()) != Selected.end()) {
      for (const BasicBlock &BB : F) {
        Count += BB.size();
      }
    }
  }
  return Count;
}

// ── JSON builders ───────────────────────────────────────────────────

/// Serialize a single instruction into a JSON object.
static json::Object serializeInstruction(const Instruction &I, unsigned Id) {
  json::Object Obj;

  Obj["id"] = static_cast<int64_t>(Id);
  Obj["opcode"] = opcodeName(I.getOpcode()).str();
  Obj["result_type"] = typeToString(I.getType());

  // Operands
  json::Array Ops;
  json::Array OpTypes;
  for (unsigned OpIdx = 0; OpIdx < I.getNumOperands(); ++OpIdx) {
    const Value *Op = I.getOperand(OpIdx);
    Ops.push_back(valueToString(Op));
    OpTypes.push_back(typeToString(Op->getType()));
  }
  Obj["operands"] = std::move(Ops);
  Obj["operand_types"] = std::move(OpTypes);

  // Bitcast chain: trace back through chains of bitcasts/inttoptr/ptrtoint
  if (I.getOpcode() == Instruction::BitCast ||
      I.getOpcode() == Instruction::IntToPtr ||
      I.getOpcode() == Instruction::PtrToInt) {
    const Value *Src = I.getOperand(0);
    while (auto *BC = dyn_cast<CastInst>(Src))
      Src = BC->getOperand(0);
    Obj["source_type"] = typeToString(Src->getType());
  }

  // GEP deconstruction: expose the source element type and per-index field types
  if (const auto *GEP = dyn_cast<GetElementPtrInst>(&I)) {
    json::Object GepObj;
    Type *SourceElemTy = GEP->getSourceElementType();
    GepObj["source_type"] = typeToString(SourceElemTy);
    GepObj["in_bounds"] = GEP->isInBounds();

    json::Array Indices;
    // Use getIndexedType to compute the real field type at each nesting level
    SmallVector<Value *, 4> IdxList;
    for (unsigned OpIdx = 1; OpIdx < GEP->getNumOperands(); ++OpIdx) {
      json::Object IdxObj;
      Value *IdxVal = GEP->getOperand(OpIdx);
      IdxObj["value"] = valueToString(IdxVal);
      IdxList.push_back(IdxVal);

      const Type *CurrentFieldTy =
          GetElementPtrInst::getIndexedType(SourceElemTy, IdxList);
      IdxObj["field_type"] =
          CurrentFieldTy ? typeToString(CurrentFieldTy) : "unknown";
      Indices.push_back(std::move(IdxObj));
    }
    GepObj["indices"] = std::move(Indices);
    Obj["gep_details"] = std::move(GepObj);
  }

  // Call-specific info
  if (const auto *CI = dyn_cast<CallInst>(&I)) {
    if (const Function *Callee = CI->getCalledFunction()) {
      Obj["callee"] = Callee->getName().str();
      Obj["is_indirect"] = false;
    } else {
      Obj["callee"] = valueToString(CI->getCalledOperand());
      Obj["is_indirect"] = true;
    }
  }

  // Invoke instructions (landing-pad calls)
  if (const auto *II = dyn_cast<InvokeInst>(&I)) {
    if (const Function *Callee = II->getCalledFunction()) {
      Obj["callee"] = Callee->getName().str();
      Obj["is_indirect"] = false;
    } else {
      Obj["callee"] = valueToString(II->getCalledOperand());
      Obj["is_indirect"] = true;
    }
  }

  // Debug location
  if (const DebugLoc &DL = I.getDebugLoc()) {
    std::string Loc =
        DL->getFilename().str() + ":" + std::to_string(DL->getLine());
    if (DL->getColumn() > 0)
      Loc += ":" + std::to_string(DL->getColumn());
    Obj["debug_loc"] = Loc;
  }

  // Raw textual representation (for debugging / fallback)
  std::string Raw;
  raw_string_ostream RawOS(Raw);
  I.print(RawOS);
  RawOS.flush();
  auto Pos = Raw.find_first_not_of(" \t");
  Obj["raw"] = (Pos != std::string::npos) ? Raw.substr(Pos) : Raw;

  return Obj;
}

/// Build a label for a basic block.
static std::string blockLabel(const BasicBlock &BB, unsigned BBIndex) {
  if (!BB.getName().empty())
    return BB.getName().str();
  return "bb_" + std::to_string(BBIndex);
}

/// Serialize a basic block: label, instructions, CFG successors.
static json::Object serializeBasicBlock(
    const BasicBlock &BB, unsigned BBIndex,
    const DenseMap<const BasicBlock *, std::string> &BBIndexMap) {
  json::Object Obj;

  Obj["label"] = blockLabel(BB, BBIndex);

  // Instructions
  json::Array Instrs;
  unsigned Idx = 0;
  for (const Instruction &I : BB) {
    Instrs.push_back(serializeInstruction(I, Idx++));
  }
  Obj["instructions"] = std::move(Instrs);

  // CFG successors from the terminator — use BBIndexMap for label lookup
  json::Array Succs;
  if (const Instruction *TI = BB.getTerminator()) {
    for (unsigned i = 0; i < TI->getNumSuccessors(); ++i) {
      const BasicBlock *Succ = TI->getSuccessor(i);
      auto It = BBIndexMap.find(Succ);
      Succs.push_back(It != BBIndexMap.end() ? It->second : "unknown");
    }
  }
  Obj["successors"] = std::move(Succs);

  return Obj;
}

/// Serialize a function (with body).
static json::Object serializeFunction(const Function &F) {
  json::Object Obj;

  const std::string Name = F.getName().str();
  Obj["name"] = Name;
  Obj["demangled"] = demangle(Name);
  Obj["is_declaration"] = F.isDeclaration();
  Obj["return_type"] = typeToString(F.getReturnType());

  json::Array Params;
  for (const Argument &Arg : F.args())
    Params.push_back(typeToString(Arg.getType()));
  Obj["param_types"] = std::move(Params);

  Obj["calling_convention"] = ccName(F.getCallingConv()).str();

  // Basic blocks (only for definitions)
  if (!F.isDeclaration()) {
    DenseMap<const BasicBlock *, std::string> BBIndexMap;
    unsigned BBIdx = 0;
    for (const BasicBlock &BB : F) {
      BBIndexMap[&BB] = blockLabel(BB, BBIdx++);
    }

    json::Array Blocks;
    BBIdx = 0;
    for (const BasicBlock &BB : F)
      Blocks.push_back(serializeBasicBlock(BB, BBIdx++, BBIndexMap));
    Obj["blocks"] = std::move(Blocks);
  }

  return Obj;
}

/// Serialize a function declaration (no body — extern / intrinsics).
static json::Object serializeDeclaration(const Function &F) {
  json::Object Obj;
  const std::string Name = F.getName().str();
  Obj["name"] = Name;
  Obj["demangled"] = demangle(Name);
  Obj["return_type"] = typeToString(F.getReturnType());

  json::Array Params;
  for (const Argument &Arg : F.args())
    Params.push_back(typeToString(Arg.getType()));
  Obj["param_types"] = std::move(Params);

  return Obj;
}

/// Check if a function name matches common FFI/API patterns
static bool isFfiFunctionName(const std::string &Name) {
  static const std::vector<std::string> FfiPrefixes = {
    "sqlite3_", "malloc", "calloc", "realloc", "free", "strdup",
    "pthread_", "dlopen", "dlsym", "dlclose", "open", "close",
    "read", "write", "socket", "SSL_", "curl_", "Py_", "JNI_",
    "memcpy", "memset", "memmove", "strlen", "strcpy", "strncpy",
    "strcmp", "strncmp", "strcat", "strncat", "printf", "fprintf",
    "sprintf", "snprintf", "scanf", "sscanf"
  };
  
  for (const auto &Prefix : FfiPrefixes) {
    if (Name.find(Prefix) != std::string::npos) {
      return true;
    }
  }
  return false;
}

/// Check if a function has function pointer parameters
static bool hasFunctionPointerArg(const Function &F) {
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





/// Serialize named struct types.
static json::Object serializeNamedStructs(const Module &M) {
  json::Object Structs;
  for (const StructType *ST : M.getIdentifiedStructTypes()) {
    if (!ST->hasName())
      continue;
    if (ST->isOpaque())
      continue;

    json::Array Elems;
    for (unsigned i = 0; i < ST->getNumElements(); ++i)
      Elems.push_back(typeToString(ST->getElementType(i)));

    const std::string Key = ST->getName().str();
    Structs[Key] = std::move(Elems);
  }
  return Structs;
}

/// Serialize global variables.
static json::Array serializeGlobalVariables(const Module &M) {
  json::Array Globals;
  for (const GlobalVariable &GV : M.globals()) {
    json::Object G;
    G["name"] = GV.getName().str();
    G["type"] = typeToString(GV.getValueType());
    G["is_constant"] = GV.isConstant();
    Globals.push_back(std::move(G));
  }
  return Globals;
}

// ── Main function ───────────────────────────────────────────────────

int main(int argc, char **argv) {
  // Parse command line options
  cl::ParseCommandLineOptions(argc, argv, "LLVM IR to JSON extractor\n");

  auto StartTime = std::chrono::high_resolution_clock::now();

  // Create LLVM context and parse IR
  LLVMContext Context;
  SMDiagnostic Err;
  std::unique_ptr<Module> M = parseIRFile(InputFile, Err, Context);

  if (!M) {
    Err.print(argv[0], errs());
    return 1;
  }

  auto ParseTime = std::chrono::high_resolution_clock::now();

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

    // Detect FFI seeds
    std::set<std::string> Seeds = detectFfiSeeds(Index);

    // Compute FFI closure
    SelectedFunctions = computeFfiClosure(Index, Seeds, SliceHops);
    SliceTime = std::chrono::high_resolution_clock::now();

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

  // Serialize module to JSON
  json::Object Root;

  Root["target_triple"] = M->getTargetTriple().str();
  Root["data_layout"] = M->getDataLayoutStr();

  json::Array Functions;
  json::Array Declarations;

  // Statistics counters
  unsigned TotalFunctions = 0;
  unsigned TotalDeclarations = 0;
  unsigned TotalInstructions = 0;
  unsigned SelectedFunctionCount = 0;
  unsigned SelectedDeclarationCount = 0;
  unsigned SelectedInstructionCount = 0;

  for (const Function &F : *M) {
    if (shouldSkipFunction(F))
      continue;

    if (F.isDeclaration()) {
      TotalDeclarations++;
      if (Slice == SLICE_NONE || SelectedDeclarations.find(F.getName().str()) != SelectedDeclarations.end()) {
        Declarations.push_back(serializeDeclaration(F));
        SelectedDeclarationCount++;
      }
    } else {
      TotalFunctions++;
      // Count instructions
      unsigned InstrCount = 0;
      for (const BasicBlock &BB : F)
        InstrCount += BB.size();
      TotalInstructions += InstrCount;

      if (Slice == SLICE_NONE || SelectedFunctions.find(F.getName().str()) != SelectedFunctions.end()) {
        Functions.push_back(serializeFunction(F));
        SelectedFunctionCount++;
        SelectedInstructionCount += InstrCount;
      }
    }
  }

  Root["functions"] = std::move(Functions);
  Root["declarations"] = std::move(Declarations);
  Root["named_struct_types"] = serializeNamedStructs(*M);
  Root["global_variables"] = serializeGlobalVariables(*M);

  auto SerializeTime = std::chrono::high_resolution_clock::now();

  // Output JSON
  std::string Output;
  if (OutputFile.empty()) {
    // Output to stdout
    raw_string_ostream OS(Output);
    OS << json::Value(std::move(Root));
    OS.flush();
    outs() << Output << "\n";
  } else {
    // Output to file
    std::error_code EC;
    raw_fd_ostream FileOS(OutputFile, EC);
    if (EC) {
      errs() << "Error opening output file: " << EC.message() << "\n";
      return 1;
    }
    raw_string_ostream OS(Output);
    OS << json::Value(std::move(Root));
    OS.flush();
    FileOS << Output << "\n";
  }

  auto EndTime = std::chrono::high_resolution_clock::now();

  // Print timing information if requested
  if (Timing) {
    auto ParseDuration = std::chrono::duration_cast<std::chrono::milliseconds>(ParseTime - StartTime);
    auto SerializeDuration = std::chrono::duration_cast<std::chrono::milliseconds>(SerializeTime - SliceTime);
    auto TotalDuration = std::chrono::duration_cast<std::chrono::milliseconds>(EndTime - StartTime);

    errs() << "=== Timing Information ===\n";
    errs() << "IR Parsing:     " << ParseDuration.count() << " ms\n";
    if (Slice == SLICE_FFI) {
      auto IndexDuration = std::chrono::duration_cast<std::chrono::milliseconds>(IndexTime - ParseTime);
      auto SliceDuration = std::chrono::duration_cast<std::chrono::milliseconds>(SliceTime - IndexTime);
      errs() << "Index Building: " << IndexDuration.count() << " ms\n";
      errs() << "Slice Computation: " << SliceDuration.count() << " ms\n";
    }
    errs() << "Serialization:  " << SerializeDuration.count() << " ms\n";
    errs() << "Total:          " << TotalDuration.count() << " ms\n";
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
    errs() << "JSON bytes: " << Output.size() << "\n";

    if (Slice == SLICE_FFI) {
      errs() << "FFI seeds: " << detectFfiSeeds(Index).size() << "\n";
      errs() << "Slice hops: " << SliceHops << "\n";
    }
  }

  if (Verbose) {
    errs() << "Successfully processed: " << InputFile << "\n";
    errs() << "Functions: " << Root["functions"].getAsArray()->size() << "\n";
    errs() << "Declarations: " << Root["declarations"].getAsArray()->size() << "\n";
  }

  return 0;
}