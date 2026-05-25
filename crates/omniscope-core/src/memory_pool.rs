//! Memory pool for OmniScope
//!
//! This module provides arena-based memory allocation for reducing allocation overhead
//! and improving cache locality during analysis.

use bumpalo::Bump;
use std::cell::UnsafeCell;

/// Thread-safe memory pool using arena allocation
pub struct MemoryPool {
    /// Inner arena allocator
    arena: UnsafeCell<Bump>,
}

impl MemoryPool {
    /// Creates a new memory pool
    pub fn new() -> Self {
        Self {
            arena: UnsafeCell::new(Bump::new()),
        }
    }

    /// Creates a new memory pool with initial capacity
    pub fn with_capacity(bytes: usize) -> Self {
        Self {
            arena: UnsafeCell::new(Bump::with_capacity(bytes)),
        }
    }

    /// Allocates a value in the arena
    ///
    /// # Safety
    /// The returned reference is valid for the lifetime of the MemoryPool.
    /// The caller must ensure the MemoryPool is not dropped while references are in use.
    pub fn alloc<T>(&self, value: T) -> &mut T {
        // SAFETY: We use UnsafeCell to allow mutable access to the arena.
        // The caller is responsible for ensuring proper lifetime management.
        unsafe { (*self.arena.get()).alloc(value) }
    }

    /// Allocates a slice of values in the arena
    ///
    /// # Safety
    /// The returned reference is valid for the lifetime of the MemoryPool.
    pub fn alloc_slice<T>(&self, slice: &[T]) -> &mut [T]
    where
        T: Copy,
    {
        unsafe { (*self.arena.get()).alloc_slice_copy(slice) }
    }

    /// Allocates a string in the arena
    ///
    /// # Safety
    /// The returned reference is valid for the lifetime of the MemoryPool.
    pub fn alloc_str(&self, s: &str) -> &mut str {
        unsafe { (*self.arena.get()).alloc_str(s) }
    }

    /// Resets the arena, deallocating all memory
    ///
    /// # Safety
    /// All references allocated from this pool become invalid after reset.
    pub unsafe fn reset(&self) {
        (*self.arena.get()).reset();
    }

    /// Returns the number of bytes currently allocated
    pub fn allocated_bytes(&self) -> usize {
        unsafe { (*self.arena.get()).allocated_bytes() }
    }
}

impl Default for MemoryPool {
    fn default() -> Self {
        Self::new()
    }
}

// SAFETY: The MemoryPool is designed to be used in a single-threaded context
// for each analysis pass. The UnsafeCell is used to allow interior mutability.
// Cross-thread sharing should be avoided.
unsafe impl Send for MemoryPool {}
unsafe impl Sync for MemoryPool {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memory_pool_basic() {
        let pool = MemoryPool::new();

        let value = pool.alloc(42);
        assert_eq!(*value, 42);

        *value = 100;
        assert_eq!(*value, 100);
    }

    #[test]
    fn test_memory_pool_slice() {
        let pool = MemoryPool::new();

        let data = [1, 2, 3, 4, 5];
        let slice = pool.alloc_slice(&data);

        assert_eq!(slice.len(), 5);
        assert_eq!(slice[0], 1);
    }

    #[test]
    fn test_memory_pool_string() {
        let pool = MemoryPool::new();

        let s = pool.alloc_str("hello world");
        assert_eq!(s, "hello world");
    }

    #[test]
    fn test_memory_pool_with_capacity() {
        let pool = MemoryPool::with_capacity(1024);
        let _ = pool.alloc(42);
        assert!(pool.allocated_bytes() > 0);
    }
}
