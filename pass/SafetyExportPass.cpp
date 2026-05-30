// SafetyExportPass.cpp — LLVM pass that serializes a module to structured JSON.
//
// Designed for consumption by OmniScope-rs.  Loaded by `opt` as a plugin:
//   opt -load-pass-plugin ./libSafetyExportPass.dylib \
//       -passes='safety-export' input.ll 2>/dev/null

#include "llvm/Demangle/Demangle.h"
#include "llvm/IR/DebugInfoMetadata.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#include "llvm/Passes/PassBuilder.h"
// clang-format off — PassPlugin.h location changed across LLVM versions
#if __has_include("llvm/Plugins/PassPlugin.h")
#include "llvm/Plugins/PassPlugin.h"
#else
#include "llvm/Passes/PassPlugin.h"
#endif
// clang-format on
#include "llvm/Support/JSON.h"
#include "llvm/Support/raw_ostream.h"

#include <string>

// ── Helpers ─────────────────────────────────────────────────────────

/// Print an LLVM Type to a string without allocating a separate stream per
/// call.
static std::string typeToString(const llvm::Type *T) {
  std::string S;
  llvm::raw_string_ostream OS(S);
  T->print(OS);
  return S;
}

/// Print an LLVM Value (used for operand pretty-printing) to string.
static std::string valueToString(const llvm::Value *V) {
  std::string S;
  llvm::raw_string_ostream OS(S);
  V->print(OS);
  return S;
}

/// Return the textual opcode name for an instruction.
static llvm::StringRef opcodeName(unsigned Opcode) {
  return llvm::Instruction::getOpcodeName(Opcode);
}

/// Get calling-convention name.
static llvm::StringRef ccName(unsigned CC) {
  switch (CC) {
  case llvm::CallingConv::C:
    return "ccc";
  case llvm::CallingConv::Fast:
    return "fastcc";
  case llvm::CallingConv::Cold:
    return "coldcc";
  case llvm::CallingConv::X86_StdCall:
    return "x86_stdcallcc";
  case llvm::CallingConv::X86_FastCall:
    return "x86_fastcallcc";
  case llvm::CallingConv::AArch64_VectorCall:
    return "aarch64_vector_pcs";
  default:
    return "ccc";
  }
}

// ── JSON builders ───────────────────────────────────────────────────

/// Serialize a single instruction into a JSON object.
static llvm::json::Object serializeInstruction(const llvm::Instruction &I,
                                               unsigned Id) {
  llvm::json::Object Obj;

  Obj["id"] = static_cast<int64_t>(Id);
  Obj["opcode"] = opcodeName(I.getOpcode()).str();
  Obj["result_type"] = typeToString(I.getType());

  // Operands
  llvm::json::Array Ops;
  llvm::json::Array OpTypes;
  for (unsigned OpIdx = 0; OpIdx < I.getNumOperands(); ++OpIdx) {
    const llvm::Value *Op = I.getOperand(OpIdx);
    Ops.push_back(valueToString(Op));
    OpTypes.push_back(typeToString(Op->getType()));
  }
  Obj["operands"] = std::move(Ops);
  Obj["operand_types"] = std::move(OpTypes);

  // Bitcast chain: trace back through chains of bitcasts/inttoptr/ptrtoint
  // to recover the original source type, which is critical for FFI analysis.
  if (I.getOpcode() == llvm::Instruction::BitCast ||
      I.getOpcode() == llvm::Instruction::IntToPtr ||
      I.getOpcode() == llvm::Instruction::PtrToInt) {
    const llvm::Value *Src = I.getOperand(0);
    // Walk through chains: bitcast(bitcast(x)) → trace to original
    while (auto *BC = llvm::dyn_cast<llvm::CastInst>(Src))
      Src = BC->getOperand(0);
    Obj["source_type"] = typeToString(Src->getType());
  }

  // GEP deconstruction: expose the source element type and per-index field
  // types so the Rust side can reconstruct which struct field is being
  // accessed.
  if (const auto *GEP = llvm::dyn_cast<llvm::GetElementPtrInst>(&I)) {
    llvm::json::Object GepObj;
    GepObj["source_type"] = typeToString(GEP->getSourceElementType());
    GepObj["in_bounds"] = GEP->isInBounds();

    // Walk each index and record the type that GEP "sees" at that level
    llvm::json::Array Indices;
    for (unsigned OpIdx = 1; OpIdx < GEP->getNumOperands(); ++OpIdx) {
      llvm::json::Object IdxObj;
      IdxObj["value"] = valueToString(GEP->getOperand(OpIdx));
      // For the first index (ptr offset), type is the source element type.
      // For subsequent indices, we compute the composite type at that level.
      if (OpIdx == 1) {
        IdxObj["field_type"] = typeToString(GEP->getSourceElementType());
      } else {
        // Get the type we're indexing into at this level
        // This requires walking the GEP type chain — use the generic accessor
        auto *IdxTy = GEP->getOperand(OpIdx)->getType();
        IdxObj["field_type"] = typeToString(IdxTy);
      }
      Indices.push_back(std::move(IdxObj));
    }
    GepObj["indices"] = std::move(Indices);
    Obj["gep_details"] = std::move(GepObj);
  }

  // Call-specific info
  if (const auto *CI = llvm::dyn_cast<llvm::CallInst>(&I)) {
    if (const llvm::Function *Callee = CI->getCalledFunction()) {
      Obj["callee"] = Callee->getName().str();
      Obj["is_indirect"] = false;
    } else {
      // Indirect call — callee is a value, not a named function
      Obj["callee"] = valueToString(CI->getCalledOperand());
      Obj["is_indirect"] = true;
    }
  }

  // Invoke instructions (landing-pad calls)
  if (const auto *II = llvm::dyn_cast<llvm::InvokeInst>(&I)) {
    if (const llvm::Function *Callee = II->getCalledFunction()) {
      Obj["callee"] = Callee->getName().str();
      Obj["is_indirect"] = false;
    } else {
      Obj["callee"] = valueToString(II->getCalledOperand());
      Obj["is_indirect"] = true;
    }
  }

  // Debug location
  if (const llvm::DebugLoc &DL = I.getDebugLoc()) {
    std::string Loc =
        DL->getFilename().str() + ":" + std::to_string(DL->getLine());
    if (DL->getColumn() > 0)
      Loc += ":" + std::to_string(DL->getColumn());
    Obj["debug_loc"] = Loc;
  }

  // Raw textual representation (for debugging / fallback)
  std::string Raw;
  llvm::raw_string_ostream RawOS(Raw);
  I.print(RawOS);
  // Trim leading whitespace
  auto Pos = Raw.find_first_not_of(" \t");
  Obj["raw"] = (Pos != std::string::npos) ? Raw.substr(Pos) : Raw;

  return Obj;
}

/// Build a label for a basic block.  LLVM auto-numbered blocks (e.g. %1, %2)
/// have an empty getName(); we synthesize "bb_0", "bb_1" etc. so that
/// successors and cross-references are always non-empty.
static std::string blockLabel(const llvm::BasicBlock &BB, unsigned BBIndex) {
  if (!BB.getName().empty())
    return BB.getName().str();
  return "bb_" + std::to_string(BBIndex);
}

/// Serialize a basic block: label, instructions, CFG successors.
/// BBIndexMap maps each BasicBlock* to its synthetic label (for successor
/// refs).
static llvm::json::Object serializeBasicBlock(
    const llvm::BasicBlock &BB, unsigned BBIndex,
    const llvm::DenseMap<const llvm::BasicBlock *, std::string> &BBIndexMap) {
  llvm::json::Object Obj;

  Obj["label"] = blockLabel(BB, BBIndex);

  // Instructions
  llvm::json::Array Instrs;
  unsigned Idx = 0;
  for (const llvm::Instruction &I : BB) {
    Instrs.push_back(serializeInstruction(I, Idx++));
  }
  Obj["instructions"] = std::move(Instrs);

  // CFG successors from the terminator — use BBIndexMap for label lookup
  llvm::json::Array Succs;
  if (const llvm::Instruction *TI = BB.getTerminator()) {
    for (unsigned i = 0; i < TI->getNumSuccessors(); ++i) {
      const llvm::BasicBlock *Succ = TI->getSuccessor(i);
      auto It = BBIndexMap.find(Succ);
      Succs.push_back(It != BBIndexMap.end() ? It->second
                                             : Succ->getName().str());
    }
  }
  Obj["successors"] = std::move(Succs);

  return Obj;
}

/// Serialize a function (with body).
static llvm::json::Object serializeFunction(const llvm::Function &F) {
  llvm::json::Object Obj;

  std::string Name = F.getName().str();
  Obj["name"] = Name;
  Obj["demangled"] = llvm::demangle(Name);
  Obj["is_declaration"] = F.isDeclaration();
  Obj["return_type"] = typeToString(F.getReturnType());

  llvm::json::Array Params;
  for (const llvm::Argument &Arg : F.args())
    Params.push_back(typeToString(Arg.getType()));
  Obj["param_types"] = std::move(Params);

  Obj["calling_convention"] = ccName(F.getCallingConv()).str();

  // Basic blocks (only for definitions)
  if (!F.isDeclaration()) {
    // Build BB* → synthetic label map (fixes unnamed-BB successor refs)
    llvm::DenseMap<const llvm::BasicBlock *, std::string> BBIndexMap;
    unsigned BBIdx = 0;
    for (const llvm::BasicBlock &BB : F) {
      BBIndexMap[&BB] = blockLabel(BB, BBIdx++);
    }

    llvm::json::Array Blocks;
    BBIdx = 0;
    for (const llvm::BasicBlock &BB : F)
      Blocks.push_back(serializeBasicBlock(BB, BBIdx++, BBIndexMap));
    Obj["blocks"] = std::move(Blocks);
  }

  return Obj;
}

/// Serialize a function declaration (no body — extern / intrinsics).
static llvm::json::Object serializeDeclaration(const llvm::Function &F) {
  llvm::json::Object Obj;
  std::string Name = F.getName().str();
  Obj["name"] = Name;
  Obj["demangled"] = llvm::demangle(Name);
  Obj["return_type"] = typeToString(F.getReturnType());

  llvm::json::Array Params;
  for (const llvm::Argument &Arg : F.args())
    Params.push_back(typeToString(Arg.getType()));
  Obj["param_types"] = std::move(Params);

  return Obj;
}

/// Check whether a function should be excluded from the output.
/// Filters out LLVM intrinsics and compiler-support routines that add noise
/// without providing useful FFI analysis information.
static bool shouldSkipFunction(const llvm::Function &F) {
  llvm::StringRef Name = F.getName();

  // LLVM intrinsics: llvm.memset, llvm.lifetime, llvm.dbg, etc.
  if (Name.starts_with("llvm."))
    return true;

  // Compiler support routines that are noise for FFI analysis
  static const char *SkipList[] = {
      "__chkstk",    // stack probe (Windows)
      "__stack_chk", // stack canary (partial match covers __stack_chk_fail,
                     // etc.)
      "_GLOBAL_",    // global constructors/destructors
      "__cxa_",      // C++ ABI helpers (exception handling, atexit, etc.)
      "__gmon_",     // gprof profiling
      "__sanitizer", // sanitizer runtime (partial match)
      "__asan",      // AddressSanitizer
      "__msan",      // MemorySanitizer
      "__tsan",      // ThreadSanitizer
      "__ubsan",     // UndefinedBehaviorSanitizer
  };
  for (const char *Pfx : SkipList) {
    if (Name.starts_with(Pfx))
      return true;
  }

  return false;
}

/// Serialize named struct types.
static llvm::json::Object serializeNamedStructs(const llvm::Module &M) {
  llvm::json::Object Structs;
  for (const llvm::StructType *ST : M.getIdentifiedStructTypes()) {
    if (!ST->hasName())
      continue;

    llvm::json::Array Elems;
    for (unsigned i = 0; i < ST->getNumElements(); ++i)
      Elems.push_back(typeToString(ST->getElementType(i)));

    // Strip leading '%' from the struct name for cleaner JSON keys
    std::string Key = ST->getName().str();
    Structs[Key] = std::move(Elems);
  }
  return Structs;
}

/// Serialize global variables.
static llvm::json::Array serializeGlobalVariables(const llvm::Module &M) {
  llvm::json::Array Globals;
  for (const llvm::GlobalVariable &GV : M.globals()) {
    llvm::json::Object G;
    G["name"] = GV.getName().str();
    G["type"] = typeToString(GV.getValueType());
    G["is_constant"] = GV.isConstant();
    Globals.push_back(std::move(G));
  }
  return Globals;
}

// ── Pass implementation ─────────────────────────────────────────────

namespace {

struct SafetyExportPass : public llvm::PassInfoMixin<SafetyExportPass> {

  llvm::PreservedAnalyses run(llvm::Module &M,
                              llvm::ModuleAnalysisManager & /*MAM*/) {
    llvm::json::Object Root;

    // Module-level metadata
    Root["target_triple"] = M.getTargetTriple().str();
    Root["data_layout"] = M.getDataLayoutStr();

    // Separate declarations from definitions
    llvm::json::Array Functions;
    llvm::json::Array Declarations;

    for (const llvm::Function &F : M) {
      if (shouldSkipFunction(F))
        continue;
      if (F.isDeclaration())
        Declarations.push_back(serializeDeclaration(F));
      else
        Functions.push_back(serializeFunction(F));
    }

    Root["functions"] = std::move(Functions);
    Root["declarations"] = std::move(Declarations);
    Root["named_struct_types"] = serializeNamedStructs(M);
    Root["global_variables"] = serializeGlobalVariables(M);

    // Write JSON to stdout (not errs — stdout is for data)
    std::string Output;
    llvm::raw_string_ostream OS(Output);
    OS << llvm::json::Value(std::move(Root));
    OS.flush();
    llvm::outs() << Output << "\n";

    // We don't transform the module — preserve everything
    return llvm::PreservedAnalyses::all();
  }
};

} // anonymous namespace

// ── Plugin registration ─────────────────────────────────────────────

extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo
llvmGetPassPluginInfo() {
  return {LLVM_PLUGIN_API_VERSION, "SafetyExportPass", LLVM_VERSION_STRING,
          [](llvm::PassBuilder &PB) {
            // Register the pass so it can be invoked as "safety-export"
            PB.registerPipelineParsingCallback(
                [](llvm::StringRef Name, llvm::ModulePassManager &MPM,
                   llvm::ArrayRef<llvm::PassBuilder::PipelineElement>) {
                  if (Name == "safety-export") {
                    MPM.addPass(SafetyExportPass());
                    return true;
                  }
                  return false;
                });
          }};
}
