//! Rust standard library function whitelist
//!
//! This module contains the whitelist for Rust standard library functions
//! including Vec, String, Box, Arc, Rc, HashMap, BTreeMap, HashSet,
//! thread synchronization primitives, iterators, and memory utilities.

use super::{RustStdlibWhitelist, WhitelistCategory};

impl RustStdlibWhitelist {
    /// Populates the whitelist with Rust standard library functions.
    ///
    /// # Objective
    /// Add all known safe Rust standard library functions to the whitelist.
    /// These functions are guaranteed to be safe from memory safety perspective
    /// because they operate within Rust's type system and ownership model.
    ///
    /// # Invariants
    /// - All functions use Rust mangled names (starting with "_ZN" or "_R").
    /// - Functions are organized by semantic category.
    /// - Smart pointer operations involving ownership transfer are flagged.
    /// - Container operations are all safe (no cross-family issues).
    /// - This method is called once during initialization.
    ///
    /// # Categories
    /// - Container operations (Vec, HashMap, BTreeMap, HashSet)
    /// - String operations (String, &str)
    /// - Smart pointer operations (Box, Arc, Rc)
    /// - Thread synchronization (Mutex, RwLock, Condvar)
    /// - Iterator operations
    /// - Error handling (Option, Result)
    /// - Memory utilities (std::mem, std::ptr)
    /// - Slice operations
    /// - Conversion utilities
    pub fn populate_stdlib(&mut self) {
        // ============================================================
        // Section 1: Vec operations - safe container management
        // Vec is Rust's growable array type. All operations are safe
        // because Vec manages its own heap allocation internally.
        // These functions do not transfer ownership across FFI boundaries.
        // ============================================================
        self.add_function(
            "_ZN3vec3Vec3new",
            WhitelistCategory::Container,
            false,
            "Vec::new() - Creates a new empty vector",
        );
        self.add_function(
            "_ZN3vec3Vec7with_capacity",
            WhitelistCategory::Container,
            false,
            "Vec::with_capacity() - Creates vector with pre-allocated capacity",
        );
        self.add_function(
            "_ZN3vec3Vec4push",
            WhitelistCategory::Container,
            false,
            "Vec::push() - Appends element to vector",
        );
        self.add_function(
            "_ZN3vec3Vec3pop",
            WhitelistCategory::Container,
            false,
            "Vec::pop() - Removes last element from vector",
        );
        self.add_function(
            "_ZN3vec3Vec6insert",
            WhitelistCategory::Container,
            false,
            "Vec::insert() - Inserts element at position",
        );
        self.add_function(
            "_ZN3vec3Vec6remove",
            WhitelistCategory::Container,
            false,
            "Vec::remove() - Removes element at position",
        );
        self.add_function(
            "_ZN3vec3Vec5clear",
            WhitelistCategory::Container,
            false,
            "Vec::clear() - Clears all elements",
        );
        self.add_function(
            "_ZN3vec3Vec7reserve",
            WhitelistCategory::Container,
            false,
            "Vec::reserve() - Reserves additional capacity",
        );
        self.add_function(
            "_ZN3vec3Vec13shrink_to_fit",
            WhitelistCategory::Container,
            false,
            "Vec::shrink_to_fit() - Shrinks capacity to fit length",
        );
        self.add_function(
            "_ZN3vec3Vec6as_ptr",
            WhitelistCategory::Container,
            false,
            "Vec::as_ptr() - Returns raw pointer to data",
        );
        self.add_function(
            "_ZN3vec3Vec9as_mut_ptr",
            WhitelistCategory::Container,
            false,
            "Vec::as_mut_ptr() - Returns mutable raw pointer to data",
        );

        // ============================================================
        // Section 2: String operations - safe string manipulation
        // String is Rust's growable UTF-8 string type. Operations are
        // safe because String manages its own heap allocation.
        // No cross-family memory ownership issues.
        // ============================================================
        self.add_function(
            "_ZN6string6String3new",
            WhitelistCategory::StringOps,
            false,
            "String::new() - Creates empty string",
        );
        self.add_function(
            "_ZN6string6String7with_capacity",
            WhitelistCategory::StringOps,
            false,
            "String::with_capacity() - Creates string with capacity",
        );
        self.add_function(
            "_ZN6string6String4push",
            WhitelistCategory::StringOps,
            false,
            "String::push() - Appends char to string",
        );
        self.add_function(
            "_ZN6string6String9push_str",
            WhitelistCategory::StringOps,
            false,
            "String::push_str() - Appends string slice",
        );
        self.add_function(
            "_ZN6string6String4from",
            WhitelistCategory::StringOps,
            false,
            "String::from() - Creates string from &str",
        );
        self.add_function(
            "_ZN6string6String10as_mut_ptr",
            WhitelistCategory::StringOps,
            false,
            "String::as_mut_ptr() - Returns mutable pointer",
        );

        // ============================================================
        // Section 3: Box operations - heap allocation with ownership
        // Box<T> is Rust's simplest smart pointer for heap allocation.
        // into_raw/from_raw/leak involve ownership transfer (flagged).
        // ============================================================
        self.add_function(
            "_ZN3box3Box3new",
            WhitelistCategory::SmartPointer,
            false,
            "Box::new() - Allocates on heap and initializes",
        );
        self.add_function(
            "_ZN3box3Box8into_raw",
            WhitelistCategory::SmartPointer,
            true,
            "Box::into_raw() - Consumes box, returns raw pointer",
        );
        self.add_function(
            "_ZN3box3Box9from_raw",
            WhitelistCategory::SmartPointer,
            true,
            "Box::from_raw() - Constructs box from raw pointer",
        );
        self.add_function(
            "_ZN3box3Box6leak",
            WhitelistCategory::SmartPointer,
            true,
            "Box::leak() - Consumes box, returns mutable reference",
        );

        // ============================================================
        // Section 4: Arc operations - atomic reference counting
        // Arc<T> provides thread-safe shared ownership via atomic
        // reference counting. into_raw involves ownership transfer.
        // ============================================================
        self.add_function(
            "_ZN3arc3Arc3new",
            WhitelistCategory::SmartPointer,
            false,
            "Arc::new() - Creates new atomic reference counted",
        );
        self.add_function(
            "_ZN3arc3Arc5clone",
            WhitelistCategory::SmartPointer,
            false,
            "Arc::clone() - Clones the Arc (increments refcount)",
        );
        self.add_function(
            "_ZN3arc3Arc4drop",
            WhitelistCategory::SmartPointer,
            false,
            "Arc::drop() - Decrements refcount, frees if zero",
        );
        self.add_function(
            "_ZN3arc3Arc9into_raw",
            WhitelistCategory::SmartPointer,
            true,
            "Arc::into_raw() - Consumes Arc, returns raw pointer",
        );
        self.add_function(
            "_ZN3arc3Arc10strong_count",
            WhitelistCategory::SmartPointer,
            false,
            "Arc::strong_count() - Returns strong reference count",
        );

        // ============================================================
        // Section 5: Rc operations - single-threaded reference counting
        // Rc<T> provides non-atomic shared ownership. Not thread-safe.
        // ============================================================
        self.add_function(
            "_ZN2rc2Rc3new",
            WhitelistCategory::SmartPointer,
            false,
            "Rc::new() - Creates new reference counted",
        );
        self.add_function(
            "_ZN2rc2Rc5clone",
            WhitelistCategory::SmartPointer,
            false,
            "Rc::clone() - Clones the Rc (increments refcount)",
        );
        self.add_function(
            "_ZN2rc2Rc4drop",
            WhitelistCategory::SmartPointer,
            false,
            "Rc::drop() - Decrements refcount, frees if zero",
        );

        // ============================================================
        // Section 6: HashMap operations - hash table container
        // HashMap<K,V> is Rust's hash-based associative container.
        // All operations are safe within Rust's ownership model.
        // ============================================================
        self.add_function(
            "_ZN7hashmap7HashMap3new",
            WhitelistCategory::Container,
            false,
            "HashMap::new() - Creates empty hash map",
        );
        self.add_function(
            "_ZN7hashmap7HashMap7with_capacity",
            WhitelistCategory::Container,
            false,
            "HashMap::with_capacity() - Creates with capacity",
        );
        self.add_function(
            "_ZN7hashmap7HashMap6insert",
            WhitelistCategory::Container,
            false,
            "HashMap::insert() - Inserts key-value pair",
        );
        self.add_function(
            "_ZN7hashmap7HashMap6remove",
            WhitelistCategory::Container,
            false,
            "HashMap::remove() - Removes entry by key",
        );
        self.add_function(
            "_ZN7hashmap7HashMap3get",
            WhitelistCategory::Container,
            false,
            "HashMap::get() - Gets value by key",
        );

        // ============================================================
        // Section 7: BTreeMap operations - balanced tree container
        // BTreeMap<K,V> provides ordered key-value storage.
        // All operations are safe within Rust's ownership model.
        // ============================================================
        self.add_function(
            "_ZN8btreemap8BTreeMap3new",
            WhitelistCategory::Container,
            false,
            "BTreeMap::new() - Creates empty B-tree map",
        );
        self.add_function(
            "_ZN8btreemap8BTreeMap6insert",
            WhitelistCategory::Container,
            false,
            "BTreeMap::insert() - Inserts key-value pair",
        );
        self.add_function(
            "_ZN8btreemap8BTreeMap6remove",
            WhitelistCategory::Container,
            false,
            "BTreeMap::remove() - Removes entry by key",
        );

        // ============================================================
        // Section 8: HashSet operations - hash set container
        // HashSet<T> provides hash-based set operations.
        // ============================================================
        self.add_function(
            "_ZN7hashset7HashSet3new",
            WhitelistCategory::Container,
            false,
            "HashSet::new() - Creates empty hash set",
        );
        self.add_function(
            "_ZN7hashset7HashSet6insert",
            WhitelistCategory::Container,
            false,
            "HashSet::insert() - Inserts element",
        );

        // ============================================================
        // Section 9: Thread synchronization primitives
        // These provide interior mutability for shared state.
        // Mutex, RwLock, and Condvar are safe synchronization
        // primitives that manage their own locking state.
        // ============================================================
        self.add_function(
            "_ZN3sys5mutex5Mutex3new",
            WhitelistCategory::ThreadSync,
            false,
            "Mutex::new() - Creates new mutex",
        );
        self.add_function(
            "_ZN3sys5mutex5Mutex4lock",
            WhitelistCategory::ThreadSync,
            false,
            "Mutex::lock() - Acquires mutex lock",
        );
        self.add_function(
            "_ZN3sys5mutex5Mutex6unlock",
            WhitelistCategory::ThreadSync,
            false,
            "Mutex::unlock() - Releases mutex lock",
        );
        self.add_function(
            "_ZN3sys6rwlock6RwLock3new",
            WhitelistCategory::ThreadSync,
            false,
            "RwLock::new() - Creates new read-write lock",
        );
        self.add_function(
            "_ZN3sys6rwlock6RwLock5write",
            WhitelistCategory::ThreadSync,
            false,
            "RwLock::write() - Acquires write lock",
        );
        self.add_function(
            "_ZN3sys6rwlock6RwLock4read",
            WhitelistCategory::ThreadSync,
            false,
            "RwLock::read() - Acquires read lock",
        );
        self.add_function(
            "_ZN3sys7condvar7Condvar3new",
            WhitelistCategory::ThreadSync,
            false,
            "Condvar::new() - Creates new condition variable",
        );
        self.add_function(
            "_ZN3sys7condvar7Condvar4wait",
            WhitelistCategory::ThreadSync,
            false,
            "Condvar::wait() - Waits on condition variable",
        );

        // ============================================================
        // Section 10: Iterator operations - lazy evaluation
        // Iterator methods provide lazy, composable data transformation.
        // These operations do not transfer ownership across FFI boundaries.
        // ============================================================
        self.add_function(
            "_ZN4iter8iterator8Iterator4map",
            WhitelistCategory::Iterator,
            false,
            "Iterator::map() - Transforms each element",
        );
        self.add_function(
            "_ZN4iter8iterator8Iterator6filter",
            WhitelistCategory::Iterator,
            false,
            "Iterator::filter() - Filters elements by predicate",
        );
        self.add_function(
            "_ZN4iter8iterator8Iterator7collect",
            WhitelistCategory::Iterator,
            false,
            "Iterator::collect() - Collects into collection",
        );
        self.add_function(
            "_ZN4iter8iterator8Iterator4fold",
            WhitelistCategory::Iterator,
            false,
            "Iterator::fold() - Folds elements with accumulator",
        );
        self.add_function(
            "_ZN4iter8iterator8Iterator8for_each",
            WhitelistCategory::Iterator,
            false,
            "Iterator::for_each() - Calls closure for each element",
        );

        // ============================================================
        // Section 11: Option operations - error handling
        // Option<T> represents an optional value. These operations
        // are control flow, not resource management.
        // ============================================================
        self.add_function(
            "_ZN6option6Option4unwrap",
            WhitelistCategory::ErrorHandling,
            false,
            "Option::unwrap() - Unwraps value or panics",
        );
        self.add_function(
            "_ZN6option6Option9unwrap_or",
            WhitelistCategory::ErrorHandling,
            false,
            "Option::unwrap_or() - Unwraps or returns default",
        );
        self.add_function(
            "_ZN6option6Option3map",
            WhitelistCategory::ErrorHandling,
            false,
            "Option::map() - Maps inner value",
        );
        self.add_function(
            "_ZN6option6Option7and_then",
            WhitelistCategory::ErrorHandling,
            false,
            "Option::and_then() - Chains operations",
        );

        // ============================================================
        // Section 12: Result operations - error handling
        // Result<T,E> represents success or failure. These operations
        // are control flow, not resource management.
        // ============================================================
        self.add_function(
            "_ZN6result6Result4unwrap",
            WhitelistCategory::ErrorHandling,
            false,
            "Result::unwrap() - Unwraps Ok or panics",
        );
        self.add_function(
            "_ZN6result6Result9unwrap_or",
            WhitelistCategory::ErrorHandling,
            false,
            "Result::unwrap_or() - Unwraps or returns default",
        );
        self.add_function(
            "_ZN6result6Result3map",
            WhitelistCategory::ErrorHandling,
            false,
            "Result::map() - Maps Ok value",
        );
        self.add_function(
            "_ZN6result6Result7and_then",
            WhitelistCategory::ErrorHandling,
            false,
            "Result::and_then() - Chains operations",
        );
        self.add_function(
            "_ZN6result6Result9map_err",
            WhitelistCategory::ErrorHandling,
            false,
            "Result::map_err() - Maps Err value",
        );

        // ============================================================
        // Section 13: Memory utilities - low-level operations
        // std::mem functions provide low-level memory manipulation.
        // These are safe because they operate within Rust's type system.
        // ============================================================
        self.add_function(
            "_ZN3mem4swap",
            WhitelistCategory::Utility,
            false,
            "std::mem::swap() - Swaps two values",
        );
        self.add_function(
            "_ZN3mem7replace",
            WhitelistCategory::Utility,
            false,
            "std::mem::replace() - Replaces value with new one",
        );
        self.add_function(
            "_ZN3mem6take",
            WhitelistCategory::Utility,
            false,
            "std::mem::take() - Takes value, leaves default",
        );
        self.add_function(
            "_ZN3mem4size_of",
            WhitelistCategory::Utility,
            false,
            "std::mem::size_of() - Returns size of type",
        );
        self.add_function(
            "_ZN3mem8align_of",
            WhitelistCategory::Utility,
            false,
            "std::mem::align_of() - Returns alignment of type",
        );
        self.add_function(
            "_ZN3mem7drop",
            WhitelistCategory::Utility,
            false,
            "std::mem::drop() - Drops value explicitly",
        );

        // ============================================================
        // Section 14: Pointer utilities - raw pointer operations
        // std::ptr functions provide raw pointer manipulation.
        // These are low-level utilities with known safety contracts.
        // ============================================================
        self.add_function(
            "_ZN3ptr7invalid",
            WhitelistCategory::Utility,
            false,
            "std::ptr::invalid() - Creates invalid pointer",
        );
        self.add_function(
            "_ZN3ptr5write",
            WhitelistCategory::Utility,
            false,
            "std::ptr::write() - Writes value to pointer",
        );
        self.add_function(
            "_ZN3ptr4read",
            WhitelistCategory::Utility,
            false,
            "std::ptr::read() - Reads value from pointer",
        );

        // ============================================================
        // Section 15: Slice operations - array slice operations
        // Slice indexing and access operations. These are safe
        // container operations within Rust's bounds checking.
        // ============================================================
        self.add_function(
            "_ZN5slice29SliceIndex$LT$usize$GT$3get",
            WhitelistCategory::Container,
            false,
            "slice::get() - Gets element by index",
        );
        self.add_function(
            "_ZN5slice29SliceIndex$LT$usize$GT$5index",
            WhitelistCategory::Container,
            false,
            "slice::index() - Indexes slice",
        );

        // ============================================================
        // Section 16: Conversion utilities - type conversions
        // String/byte conversion utilities. These are safe data
        // transformations that do not transfer memory ownership.
        // ============================================================
        self.add_function(
            "_ZN3str9from_utf8",
            WhitelistCategory::StringOps,
            false,
            "std::str::from_utf8() - Converts bytes to string",
        );
        self.add_function(
            "_ZN6string6String10into_bytes",
            WhitelistCategory::StringOps,
            false,
            "String::into_bytes() - Converts string to bytes",
        );
    }
}
