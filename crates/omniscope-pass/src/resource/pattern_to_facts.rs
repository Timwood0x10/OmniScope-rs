//! Pattern-to-fact mapping for IR behavior summary pass.
//!
//! Each detected BehaviorPattern is mapped to one or more SemanticFact
//! records with appropriate confidence and evidence strings.

use omniscope_semantics::{
    BehaviorPattern, EscapeType, FactConfidence, FactSource, PosixOpCategory, SemanticFact,
    SemanticKey, SemanticKind,
};

/// Maps a detected behavior pattern to semantic fact(s).
///
/// Each BehaviorPattern produces one or more SemanticFact records
/// with the appropriate SemanticKind, confidence, and evidence.
/// The key is constructed from the function name so downstream
/// consumers can look up facts by function symbol.
pub(crate) fn pattern_to_facts(
    pattern: &BehaviorPattern,
    func_name: &str,
    _func_id: u64,
) -> Vec<SemanticFact> {
    // Use Symbol key keyed by function name, NOT Resource(func_id).
    // func_id is derived from the function name hash (name_to_stable_id),
    // not from the contract graph's instance allocation IDs.
    let key = SemanticKey::Symbol(func_name.to_string());
    match pattern {
        BehaviorPattern::ConditionalRelease {
            atomic_op,
            threshold,
        } => {
            vec![SemanticFact::new(
                key,
                SemanticKind::ReleaseOnAllExitPaths,
                FactConfidence::High,
                FactSource::IRPattern,
                format!(
                    "ConditionalRelease: atomicrmw {} with threshold {} in {}",
                    atomic_op, threshold, func_name
                ),
            )]
        }
        BehaviorPattern::PureComputation => {
            vec![SemanticFact::new(
                key,
                SemanticKind::NonMemoryResource,
                FactConfidence::High,
                FactSource::IRPattern,
                format!(
                    "PureComputation: {} has no ownership side effects",
                    func_name
                ),
            )]
        }
        BehaviorPattern::OwnershipTransfer { is_acquire } => {
            let kind = if *is_acquire {
                SemanticKind::HeapProvenance
            } else {
                SemanticKind::IntoRawTransfer
            };
            vec![SemanticFact::new(
                key,
                kind,
                FactConfidence::Medium,
                FactSource::IRPattern,
                format!(
                    "OwnershipTransfer: {} (is_acquire={})",
                    func_name, is_acquire
                ),
            )]
        }
        BehaviorPattern::PointerProjection => {
            vec![SemanticFact::new(
                key,
                SemanticKind::FromParameter,
                FactConfidence::High,
                FactSource::IRPattern,
                format!(
                    "PointerProjection: {} borrows pointer without ownership change",
                    func_name
                ),
            )]
        }
        BehaviorPattern::Initialization => {
            vec![SemanticFact::new(
                key,
                SemanticKind::NonMemoryResource,
                FactConfidence::Medium,
                FactSource::IRPattern,
                format!(
                    "Initialization: {} writes to struct fields, no leak",
                    func_name
                ),
            )]
        }
        BehaviorPattern::InternalBridge => {
            vec![SemanticFact::new(
                key,
                SemanticKind::DeclaredCrossBoundary,
                FactConfidence::Medium,
                FactSource::IRPattern,
                format!(
                    "InternalBridge: {} calls only same-project functions",
                    func_name
                ),
            )]
        }
        BehaviorPattern::BorrowedReturn {
            from_readonly_param,
        } => {
            let kind = if *from_readonly_param {
                SemanticKind::ReadonlyParam
            } else {
                SemanticKind::FromParameter
            };
            vec![SemanticFact::new(
                key,
                kind,
                FactConfidence::High,
                FactSource::IRPattern,
                format!(
                    "BorrowedReturn: {} returns derived pointer (readonly={})",
                    func_name, from_readonly_param
                ),
            )]
        }
        BehaviorPattern::RAiiDropRelease { is_drop_in_place } => {
            vec![SemanticFact::new(
                key,
                SemanticKind::RaiiDropRelease,
                FactConfidence::High,
                FactSource::IRPattern,
                format!(
                    "RAiiDropRelease: {} (drop_in_place={})",
                    func_name, is_drop_in_place
                ),
            )]
        }
        BehaviorPattern::IntoRawTransfer => {
            vec![SemanticFact::new(
                key,
                SemanticKind::IntoRawTransfer,
                FactConfidence::High,
                FactSource::IRPattern,
                format!(
                    "IntoRawTransfer: {} transfers ownership via into_raw",
                    func_name
                ),
            )]
        }
        BehaviorPattern::PosixNonMemoryOp { category } => {
            let kind = match category {
                PosixOpCategory::File => SemanticKind::FileOperation,
                PosixOpCategory::Network => SemanticKind::NetworkOperation,
                PosixOpCategory::Process => SemanticKind::ProcessOperation,
                PosixOpCategory::Other => SemanticKind::NonMemoryResource,
            };
            vec![SemanticFact::new(
                key,
                kind,
                FactConfidence::High,
                FactSource::IRPattern,
                format!("PosixNonMemoryOp: {} (category={:?})", func_name, category),
            )]
        }
        BehaviorPattern::NullGuardedRelease { arg_index } => {
            vec![SemanticFact::new(
                key,
                SemanticKind::NullOnErrorPath,
                FactConfidence::High,
                FactSource::IRPattern,
                format!(
                    "NullGuardedRelease: {} checks arg {} before release",
                    func_name, arg_index
                ),
            )]
        }
        BehaviorPattern::NullStoreAfterRelease { arg_index } => {
            vec![SemanticFact::new(
                key,
                SemanticKind::AliasOfReleased,
                FactConfidence::Medium,
                FactSource::IRPattern,
                format!(
                    "NullStoreAfterRelease: {} nulls slot after releasing arg {}",
                    func_name, arg_index
                ),
            )]
        }
        BehaviorPattern::FallibleOutParamInit { out_arg_index } => {
            vec![SemanticFact::new(
                key,
                SemanticKind::FallibleOutParamInit,
                FactConfidence::Medium,
                FactSource::IRPattern,
                format!(
                    "FallibleOutParamInit: {} initializes out-param arg {}",
                    func_name, out_arg_index
                ),
            )]
        }
        BehaviorPattern::OutParamNullOnError { out_arg_index } => {
            vec![SemanticFact::new(
                key,
                SemanticKind::NullOnErrorPath,
                FactConfidence::High,
                FactSource::IRPattern,
                format!(
                    "OutParamNullOnError: {} nulls out-param arg {} on error",
                    func_name, out_arg_index
                ),
            )]
        }
        BehaviorPattern::OutParamOwnedOnSuccess { out_arg_index } => {
            vec![SemanticFact::new(
                key,
                SemanticKind::EscapedToOutParam,
                FactConfidence::Medium,
                FactSource::IRPattern,
                format!(
                    "OutParamOwnedOnSuccess: {} gives ownership via out-param arg {}",
                    func_name, out_arg_index
                ),
            )]
        }
        BehaviorPattern::StoreToOwner { owner_field } => {
            vec![SemanticFact::new(
                key,
                SemanticKind::StoredToOwner,
                FactConfidence::High,
                FactSource::IRPattern,
                format!(
                    "StoreToOwner: {} stores resource to field '{}'",
                    func_name, owner_field
                ),
            )]
        }
        BehaviorPattern::StoreToRuntime { runtime_target } => {
            vec![SemanticFact::new(
                key,
                SemanticKind::StoredToRuntime,
                FactConfidence::High,
                FactSource::IRPattern,
                format!(
                    "StoreToRuntime: {} stores resource to runtime target '{}'",
                    func_name, runtime_target
                ),
            )]
        }
        BehaviorPattern::ResourceEscape { escape_type } => {
            let kind = match escape_type {
                EscapeType::ReturnValue => SemanticKind::EscapedToCaller,
                EscapeType::OutParameter => SemanticKind::EscapedToOutParam,
            };
            vec![SemanticFact::new(
                key,
                kind,
                FactConfidence::High,
                FactSource::IRPattern,
                format!(
                    "ResourceEscape: {} escapes via {:?}",
                    func_name, escape_type
                ),
            )]
        }
        BehaviorPattern::ReleaseOnAllExitPaths { release_function } => {
            vec![SemanticFact::new(
                key,
                SemanticKind::ReleaseOnAllExitPaths,
                FactConfidence::High,
                FactSource::IRPattern,
                format!(
                    "ReleaseOnAllExitPaths: {} releases via {} on all paths",
                    func_name, release_function
                ),
            )]
        }
        BehaviorPattern::StackToGlobalEscape {
            global_target,
            alloca_reg,
        } => {
            vec![SemanticFact::new(
                key,
                SemanticKind::EscapedToCaller,
                FactConfidence::High,
                FactSource::IRPattern,
                format!(
                    "StackToGlobalEscape: {} stores alloca-derived pointer {} to global {} — use-after-return",
                    func_name, alloca_reg, global_target
                ),
            )]
        }
        BehaviorPattern::HeapToGlobalEscape {
            global_target,
            param_reg,
        } => {
            vec![SemanticFact::new(
                key,
                SemanticKind::EscapedToCaller,
                FactConfidence::High,
                FactSource::IRPattern,
                format!(
                    "HeapToGlobalEscape: {} stores parameter/heap pointer {} to global {} — potential UAF",
                    func_name, param_reg, global_target
                ),
            )]
        }
        BehaviorPattern::ReturnAlias { aliased_param } => {
            vec![SemanticFact::new(
                key,
                SemanticKind::FromParameter,
                FactConfidence::Medium,
                FactSource::IRPattern,
                format!(
                    "ReturnAlias: {} returns alias of parameter {} without ownership transfer",
                    func_name, aliased_param
                ),
            )]
        }
        BehaviorPattern::FreeThenCallbackUse {
            freed_reg,
            use_callee,
        } => {
            let callee_name = use_callee.as_deref().unwrap_or("<indirect_call>");
            vec![SemanticFact::new(
                key,
                SemanticKind::AliasOfReleased,
                FactConfidence::High,
                FactSource::IRPattern,
                format!(
                    "FreeThenCallbackUse: {} frees register {} then passes it to {} — use-after-free (CWE-416)",
                    func_name, freed_reg, callee_name
                ),
            )]
        }
        BehaviorPattern::BufferOverflow {
            callee,
            overflow_amount,
            opcode,
        } => {
            vec![SemanticFact::new(
                key,
                SemanticKind::NonMemoryResource,
                FactConfidence::High,
                FactSource::IRPattern,
                format!(
                    "BufferOverflow: {} call with size = param {} {} — overflow by {} bytes (CWE-120)",
                    callee, opcode, overflow_amount, overflow_amount
                ),
            )]
        }
    }
}
