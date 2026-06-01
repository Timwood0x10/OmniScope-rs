//! Java language adapter for semantic analysis.
//!
//! This module provides Java-specific semantic analysis, including:
//! - JNI call conventions and memory management
//! - Java garbage collection interactions
//! - Local/Global reference management
//! - Exception handling across JNI boundary
//!
//! # Java Memory Model
//!
//! Java uses a managed heap with garbage collection, but can interact with
//! native code through JNI (Java Native Interface). This creates
//! two memory domains:
//!
//! 1. **Java heap**: Managed by JVM GC, allocated via `new` or JNI functions
//! 2. **Native heap**: Managed by C/C++ malloc/free, used in JNI calls
//!
//! The key concern for JNI analysis: JNI references must be properly managed
//! to prevent memory leaks and ensure proper garbage collection.
//!
//! # JNI Call Patterns
//!
//! ```text
//! Java code ──→ JNI ──→ Native C functions
//!         ──→ (*env)->NewObject ──→ Java heap allocation
//!         ──→ (*env)->DeleteLocalRef ──→ Local reference cleanup
//!         ──→ (*env)->NewGlobalRef ──→ Global reference creation
//!         ──→ (*env)->DeleteGlobalRef ──→ Global reference cleanup
//!         ──→ (*env)->FindClass ──→ Class loading
//!         ──→ (*env)->GetMethodID ──→ Method resolution
//! ```

pub mod exception;
pub mod jni;
pub mod reference;

#[cfg(test)]
pub mod tests;

use omniscope_ir::{FunctionBody, IRInstructionKind};
use omniscope_types::Language;

/// Java-specific semantic patterns derived from IR analysis.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JavaSemanticPattern {
    /// JNI call to native function
    JNICall,
    /// JNI object creation (NewObject, NewString, etc.)
    JNIObjectCreation,
    /// JNI local reference management
    JNILocalReference,
    /// JNI global reference management
    JNIGlobalReference,
    /// JNI weak global reference management
    JNIWeakGlobalReference,
    /// JNI class loading (FindClass)
    JNIClassLoading,
    /// JNI method resolution (GetMethodID, GetStaticMethodID)
    JNIMethodResolution,
    /// JNI field access (GetFieldID, GetStaticFieldID)
    JNIFieldAccess,
    /// JNI array operations (NewArray, GetArrayElements, etc.)
    JNIArrayOperation,
    /// JNI string operations (NewStringUTF, GetStringUTFChars, etc.)
    JNIStringOperation,
    /// JNI exception handling (ExceptionOccurred, ExceptionClear, etc.)
    JNIExceptionHandling,
    /// JNI monitor operations (MonitorEnter, MonitorExit)
    JNIMonitorOperation,
    /// JNI native method registration (RegisterNatives)
    JNINativeRegistration,
    /// Java GC interaction
    GCOperation,
    /// Java reflection
    Reflection,
    /// Unknown Java pattern
    Unknown,
}

/// Analysis result for a Java function.
#[derive(Debug, Clone)]
pub struct JavaFunctionAnalysis {
    /// The function name analyzed
    pub function_name: String,
    /// Detected semantic patterns
    pub patterns: Vec<JavaSemanticPattern>,
    /// Whether this function is a JNI native method
    pub is_jni_native: bool,
    /// Whether this function manages JNI references
    pub manages_jni_references: bool,
    /// Whether this function manages native memory
    pub manages_native_memory: bool,
    /// Recommended FFI safety assessment
    pub ffi_safety: JavaFFISafety,
}

/// FFI safety assessment for Java functions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JavaFFISafety {
    /// Safe: pure Java code, no JNI concerns
    SafeJava,
    /// Safe: JNI with proper reference management
    SafeJNI,
    /// Safe: JNI native method with balanced reference handling
    SafeNativeMethod,
    /// Concern: JNI without proper reference cleanup (potential leak)
    ConcernJNIReferenceLeak,
    /// Concern: JNI without proper exception handling
    ConcernJNIException,
    /// Concern: JNI native method without proper resource management
    ConcernNativeResource,
    /// Unknown: cannot determine safety
    Unknown,
}

impl JavaFFISafety {
    /// Returns true if this assessment indicates a safe pattern.
    ///
    /// # Objective
    /// Determine whether the FFI safety assessment indicates that the analyzed
    /// Java function is safe from memory safety perspective. This is used to
    /// filter out false positives in JNI-related analysis.
    ///
    /// # Invariants
    /// - `SafeJava`, `SafeJNI`, and `SafeNativeMethod` are considered safe.
    /// - All `Concern*` variants and `Unknown` are considered unsafe.
    /// - The result is deterministic for a given variant.
    ///
    /// # Returns
    /// `true` if the assessment indicates a safe pattern, `false` otherwise.
    pub fn is_safe(&self) -> bool {
        // SafeJava: pure Java code with no JNI boundary
        // SafeJNI: JNI with proper reference management
        // SafeNativeMethod: JNI native method with balanced reference handling
        matches!(
            self,
            JavaFFISafety::SafeJava | JavaFFISafety::SafeJNI | JavaFFISafety::SafeNativeMethod
        )
    }

    /// Returns the safety score (0.0 = dangerous, 1.0 = safe).
    ///
    /// # Objective
    /// Provide a numeric safety score for risk assessment and comparison.
    /// Higher scores indicate safer patterns. The scores are calibrated based
    /// on the severity of potential memory safety issues in each category.
    ///
    /// # Invariants
    /// - Score range is always between 0.0 and 1.0.
    /// - Safe variants score >= 0.85.
    /// - Concern variants score <= 0.3.
    /// - Unknown scores exactly 0.5 (neutral).
    ///
    /// # Returns
    /// A `f32` value between 0.0 (dangerous) and 1.0 (safe).
    pub fn safety_score(&self) -> f32 {
        match self {
            // SafeJava: pure Java code, no cross-boundary concerns
            JavaFFISafety::SafeJava => 0.95,
            // SafeJNI: JNI with proper reference management
            JavaFFISafety::SafeJNI => 0.9,
            // SafeNativeMethod: JNI native method with balanced reference handling
            JavaFFISafety::SafeNativeMethod => 0.85,
            // ConcernJNIReferenceLeak: JNI references without cleanup (potential leak)
            JavaFFISafety::ConcernJNIReferenceLeak => 0.3,
            // ConcernJNIException: JNI without proper exception handling
            JavaFFISafety::ConcernJNIException => 0.2,
            // ConcernNativeResource: JNI native method without proper resource management
            JavaFFISafety::ConcernNativeResource => 0.1,
            // Unknown: insufficient information for assessment
            JavaFFISafety::Unknown => 0.5,
        }
    }
}

/// Java adapter for semantic analysis.
///
/// This adapter provides Java-specific semantic analysis by combining
/// function name pattern matching with IR body instruction analysis.
/// It detects JNI patterns, reference management, and Java GC
/// interactions.
pub struct JavaAdapter {
    /// Language hint for Java, used to identify the source language
    language: Language,
}

impl JavaAdapter {
    /// Creates a new Java adapter with Java language hint.
    ///
    /// # Objective
    /// Initialize the Java adapter with the correct language identifier
    /// so it can be used for Java-specific semantic analysis in the
    /// semantic engine pipeline.
    ///
    /// # Invariants
    /// - Language is always set to `Language::Java`.
    /// - The adapter is ready to use immediately after creation.
    ///
    /// # Returns
    /// A new `JavaAdapter` instance ready for semantic analysis.
    ///
    /// # Examples
    /// ```
    /// use omniscope_semantics::resource::java_adapter::JavaAdapter;
    /// use omniscope_types::Language;
    ///
    /// let adapter = JavaAdapter::new();
    /// assert_eq!(adapter.language(), Language::Java);
    /// ```
    pub fn new() -> Self {
        Self {
            language: Language::Java,
        }
    }

    /// Returns the language hint for this adapter.
    ///
    /// # Objective
    /// Provide the language identifier for this adapter, which is used
    /// by the semantic engine to route analysis requests to the correct
    /// language-specific adapter.
    ///
    /// # Invariants
    /// - Always returns `Language::Java`.
    /// - The value never changes after adapter creation.
    ///
    /// # Returns
    /// The `Language::Java` enum variant.
    pub fn language(&self) -> Language {
        self.language
    }

    /// Analyzes a Java function from its IR body and name.
    ///
    /// # Objective
    /// Perform comprehensive semantic analysis of a Java function by
    /// combining function name pattern matching with IR instruction
    /// analysis. This determines the function's memory management
    /// behavior and FFI safety assessment.
    ///
    /// # Invariants
    /// - The function name is always stored in the result.
    /// - Patterns from name and body are combined (not deduplicated).
    /// - JNI native method detection is always performed.
    /// - FFI safety assessment covers all detected patterns.
    ///
    /// # Arguments
    /// * `function_name` - The name of the Java function to analyze.
    /// * `body` - Optional IR body containing instruction-level analysis data.
    ///
    /// # Returns
    /// A `JavaFunctionAnalysis` containing all detected patterns and safety assessment.
    pub fn analyze_function(
        &self,
        function_name: &str,
        body: Option<&FunctionBody>,
    ) -> JavaFunctionAnalysis {
        // Collect all detected patterns from both name and IR body analysis
        let mut patterns = Vec::new();

        // Step 1: Analyze function name to detect Java JNI patterns
        // This is the primary detection mechanism for known function names
        let name_patterns = self.analyze_function_name(function_name);
        patterns.extend(name_patterns);

        // Step 2: Check if the function is a JNI native method
        // JNI native methods bridge Java and native code
        let is_jni_native = self.is_jni_native_method(function_name);

        // Step 3: Analyze IR body for instruction-level evidence
        // This complements name-based analysis with actual call targets
        if let Some(body) = body {
            let body_patterns = self.analyze_function_body(body);
            patterns.extend(body_patterns);
        }

        // Step 4: Determine memory management flags from collected patterns
        // JNI references: local/global reference management
        let manages_jni_references = patterns.iter().any(|p| {
            matches!(
                p,
                JavaSemanticPattern::JNILocalReference
                    | JavaSemanticPattern::JNIGlobalReference
                    | JavaSemanticPattern::JNIWeakGlobalReference
            )
        });
        // Native memory: JNI native method with resource management
        let manages_native_memory = patterns
            .iter()
            .any(|p| matches!(p, JavaSemanticPattern::JNICall));

        // Step 5: Compute FFI safety assessment based on all evidence
        let ffi_safety = self.determine_ffi_safety(function_name, &patterns, body);

        // Assemble final analysis result
        JavaFunctionAnalysis {
            function_name: function_name.to_string(),
            patterns,
            is_jni_native,
            manages_jni_references,
            manages_native_memory,
            ffi_safety,
        }
    }

    /// Analyzes function name to detect Java semantic patterns.
    ///
    /// # Objective
    /// Detect Java-specific semantic patterns from the function name using
    /// prefix-based pattern matching. This handles JNI patterns,
    /// Java runtime functions, and JNI native method naming conventions.
    ///
    /// # Invariants
    /// - JNI functions always get appropriate JNI pattern.
    /// - Java_ prefixed functions are always JNI native methods.
    /// - JNI environment functions are classified by their operation type.
    /// - An empty Vec is returned for unrecognized function names.
    ///
    /// # Arguments
    /// * `function_name` - The function name to analyze for Java patterns.
    ///
    /// # Returns
    /// A Vec of `JavaSemanticPattern` detected from the function name.
    fn analyze_function_name(&self, function_name: &str) -> Vec<JavaSemanticPattern> {
        let mut patterns = Vec::new();

        // JNI native method naming convention
        // Functions prefixed with "Java_" are JNI native methods
        if function_name.starts_with("Java_") {
            patterns.push(JavaSemanticPattern::JNICall);
            patterns.push(JavaSemanticPattern::JNINativeRegistration);
        }

        // JNI environment functions
        // These are called through the JNIEnv pointer
        if function_name.contains("(*env)->") || function_name.contains("JNIEnv") {
            patterns.push(JavaSemanticPattern::JNICall);

            // Classify specific JNI functions by their operation type:
            // - Object creation: NewObject, NewString, etc.
            // - Reference management: DeleteLocalRef, NewGlobalRef, etc.
            // - Class loading: FindClass
            // - Method resolution: GetMethodID, GetStaticMethodID
            // - Field access: GetFieldID, GetStaticFieldID
            // - Array operations: NewArray, GetArrayElements, etc.
            // - String operations: NewStringUTF, GetStringUTFChars, etc.
            // - Exception handling: ExceptionOccurred, ExceptionClear, etc.
            // - Monitor operations: MonitorEnter, MonitorExit
            // First check for more specific patterns before general ones
            if function_name.contains("NewStringUTF")
                || function_name.contains("GetStringUTFChars")
                || function_name.contains("ReleaseStringUTFChars")
                || function_name.contains("GetStringLength")
            {
                patterns.push(JavaSemanticPattern::JNIStringOperation);
            } else if function_name.contains("NewIntArray")
                || function_name.contains("NewBooleanArray")
                || function_name.contains("NewByteArray")
                || function_name.contains("NewCharArray")
                || function_name.contains("NewShortArray")
                || function_name.contains("NewLongArray")
                || function_name.contains("NewFloatArray")
                || function_name.contains("NewDoubleArray")
                || function_name.contains("GetArrayElements")
                || function_name.contains("ReleaseArrayElements")
                || function_name.contains("GetArrayLength")
            {
                patterns.push(JavaSemanticPattern::JNIArrayOperation);
            } else if function_name.contains("NewObject")
                || function_name.contains("NewString")
                || function_name.contains("NewObjectArray")
            {
                patterns.push(JavaSemanticPattern::JNIObjectCreation);
            } else if function_name.contains("DeleteLocalRef") {
                patterns.push(JavaSemanticPattern::JNILocalReference);
            } else if function_name.contains("DeleteWeakGlobalRef")
                || function_name.contains("NewWeakGlobalRef")
            {
                patterns.push(JavaSemanticPattern::JNIWeakGlobalReference);
            } else if function_name.contains("DeleteGlobalRef")
                || function_name.contains("NewGlobalRef")
            {
                patterns.push(JavaSemanticPattern::JNIGlobalReference);
            } else if function_name.contains("FindClass") {
                patterns.push(JavaSemanticPattern::JNIClassLoading);
            } else if function_name.contains("GetMethodID")
                || function_name.contains("GetStaticMethodID")
            {
                patterns.push(JavaSemanticPattern::JNIMethodResolution);
            } else if function_name.contains("GetFieldID")
                || function_name.contains("GetStaticFieldID")
                || function_name.contains("GetIntField")
                || function_name.contains("SetIntField")
                || function_name.contains("GetObjectField")
                || function_name.contains("SetObjectField")
            {
                patterns.push(JavaSemanticPattern::JNIFieldAccess);
            } else if function_name.contains("ExceptionOccurred")
                || function_name.contains("ExceptionClear")
                || function_name.contains("ExceptionCheck")
                || function_name.contains("Throw")
                || function_name.contains("ThrowNew")
            {
                patterns.push(JavaSemanticPattern::JNIExceptionHandling);
            } else if function_name.contains("MonitorEnter")
                || function_name.contains("MonitorExit")
            {
                patterns.push(JavaSemanticPattern::JNIMonitorOperation);
            }
        }

        // JNI function naming convention (alternative pattern)
        // Some JNI functions use "JNI" prefix
        if function_name.starts_with("JNI") {
            patterns.push(JavaSemanticPattern::JNICall);
        }

        // Java GC operations
        if function_name.contains("System.gc") || function_name.contains("Runtime.gc") {
            patterns.push(JavaSemanticPattern::GCOperation);
        }

        // Java reflection
        if function_name.contains("java.lang.reflect")
            || function_name.contains("Class.forName")
            || function_name.contains("Method.invoke")
        {
            patterns.push(JavaSemanticPattern::Reflection);
        }

        patterns
    }

    /// Analyzes function body to detect Java semantic patterns from IR instructions.
    ///
    /// # Objective
    /// Scan IR instructions within a function body to detect Java-specific
    /// semantic patterns by examining call instruction callees. This
    /// complements name-based analysis with instruction-level evidence.
    ///
    /// # Invariants
    /// - Only `Call` instructions are analyzed.
    /// - Each callee is checked against known JNI and Java runtime functions.
    /// - Multiple patterns may be detected from a single instruction.
    /// - An empty Vec is returned if no Java patterns are found.
    ///
    /// # Arguments
    /// * `body` - The IR function body containing instructions to analyze.
    ///
    /// # Returns
    /// A Vec of `JavaSemanticPattern` detected from IR instructions.
    fn analyze_function_body(&self, body: &FunctionBody) -> Vec<JavaSemanticPattern> {
        let mut patterns = Vec::new();

        // Scan all instructions for call patterns that indicate JNI or Java runtime usage
        for instruction in &body.instructions {
            if let IRInstructionKind::Call = instruction.kind {
                // Extract called function name from instruction's callee field
                if let Some(ref callee) = instruction.callee {
                    // JNI object creation
                    if callee.contains("NewObject")
                        || callee.contains("NewString")
                        || callee.contains("NewObjectArray")
                    {
                        patterns.push(JavaSemanticPattern::JNIObjectCreation);
                        patterns.push(JavaSemanticPattern::JNICall);
                    }
                    // JNI reference management
                    else if callee.contains("DeleteLocalRef")
                        || callee.contains("DeleteGlobalRef")
                        || callee.contains("NewGlobalRef")
                        || callee.contains("NewWeakGlobalRef")
                    {
                        patterns.push(JavaSemanticPattern::JNILocalReference);
                        patterns.push(JavaSemanticPattern::JNIGlobalReference);
                        patterns.push(JavaSemanticPattern::JNICall);
                    }
                    // JNI class loading
                    else if callee.contains("FindClass") {
                        patterns.push(JavaSemanticPattern::JNIClassLoading);
                        patterns.push(JavaSemanticPattern::JNICall);
                    }
                    // JNI method resolution
                    else if callee.contains("GetMethodID") || callee.contains("GetStaticMethodID")
                    {
                        patterns.push(JavaSemanticPattern::JNIMethodResolution);
                        patterns.push(JavaSemanticPattern::JNICall);
                    }
                    // JNI exception handling
                    else if callee.contains("ExceptionOccurred")
                        || callee.contains("ExceptionClear")
                        || callee.contains("ExceptionCheck")
                    {
                        patterns.push(JavaSemanticPattern::JNIExceptionHandling);
                        patterns.push(JavaSemanticPattern::JNICall);
                    }
                    // JNI native method
                    else if callee.starts_with("Java_") {
                        patterns.push(JavaSemanticPattern::JNICall);
                        patterns.push(JavaSemanticPattern::JNINativeRegistration);
                    }
                    // JNI functions
                    else if callee.contains("(*env)->") || callee.contains("JNIEnv") {
                        patterns.push(JavaSemanticPattern::JNICall);
                    }
                }
            }
        }

        patterns
    }

    /// Checks if a function is a JNI native method.
    ///
    /// # Objective
    /// Determine whether a function is a JNI native method that bridges
    /// Java code and native C/C++ functions.
    ///
    /// # Invariants
    /// - Functions prefixed with "Java_" are always JNI native methods.
    /// - Functions containing "JNI" may be JNI related.
    /// - Functions containing "(*env)->" are JNI environment calls.
    /// - Standard Java functions without JNI patterns return false.
    ///
    /// # Arguments
    /// * `function_name` - The function name to check for JNI native method patterns.
    ///
    /// # Returns
    /// `true` if the function is identified as a JNI native method, `false` otherwise.
    fn is_jni_native_method(&self, function_name: &str) -> bool {
        function_name.starts_with("Java_")
            || function_name.starts_with("JNI")
            || function_name.contains("(*env)->")
            || function_name.contains("JNIEnv")
    }

    /// Determines FFI safety for a Java function based on detected patterns.
    ///
    /// # Objective
    /// Compute the FFI safety assessment by analyzing the combination of
    /// detected patterns and function name. This determines whether the
    /// function poses memory safety risks at the Java/native boundary.
    ///
    /// # Invariants
    /// - JNI with proper reference management indicates `SafeJNI`.
    /// - JNI native method with balanced references indicates `SafeNativeMethod`.
    /// - JNI without proper exception handling indicates `ConcernJNIException`.
    /// - JNI without proper reference cleanup indicates `ConcernJNIReferenceLeak`.
    /// - Pure Java code returns `SafeJava`.
    /// - All other functions return `Unknown`.
    ///
    /// # Arguments
    /// * `function_name` - The function name for heuristic-based assessment.
    /// * `patterns` - The detected Java semantic patterns.
    /// * `_body` - Optional IR body (reserved for future analysis).
    ///
    /// # Returns
    /// A `JavaFFISafety` assessment for the function.
    fn determine_ffi_safety(
        &self,
        _function_name: &str,
        patterns: &[JavaSemanticPattern],
        _body: Option<&FunctionBody>,
    ) -> JavaFFISafety {
        // Priority 1: JNI exception handling
        // Proper exception handling is critical for JNI safety
        let has_exception_handling = patterns
            .iter()
            .any(|p| matches!(p, JavaSemanticPattern::JNIExceptionHandling));

        // Priority 2: JNI reference management
        // Balanced reference management prevents memory leaks
        let has_reference_creation = patterns.iter().any(|p| {
            matches!(
                p,
                JavaSemanticPattern::JNILocalReference | JavaSemanticPattern::JNIGlobalReference
            )
        });
        let has_reference_cleanup = patterns
            .iter()
            .any(|p| matches!(p, JavaSemanticPattern::JNILocalReference));

        // Priority 3: JNI native method analysis
        if patterns
            .iter()
            .any(|p| matches!(p, JavaSemanticPattern::JNICall))
        {
            // Check for proper exception handling
            if !has_exception_handling {
                // JNI without exception handling - potential crash
                return JavaFFISafety::ConcernJNIException;
            }

            // Check for proper reference management
            if has_reference_creation && !has_reference_cleanup {
                // JNI references without cleanup - potential leak
                return JavaFFISafety::ConcernJNIReferenceLeak;
            }

            // JNI with proper exception handling and reference management
            if has_exception_handling && (has_reference_cleanup || !has_reference_creation) {
                return JavaFFISafety::SafeJNI;
            }

            // JNI native method with balanced references
            if patterns
                .iter()
                .any(|p| matches!(p, JavaSemanticPattern::JNINativeRegistration))
            {
                return JavaFFISafety::SafeNativeMethod;
            }
        }

        // Priority 4: Pure Java code
        // If no JNI patterns detected, it's pure Java code
        if patterns.is_empty() {
            return JavaFFISafety::SafeJava;
        }

        // Default: insufficient information for assessment
        JavaFFISafety::Unknown
    }
}

impl Default for JavaAdapter {
    fn default() -> Self {
        Self::new()
    }
}
