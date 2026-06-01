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
    pub fn alloc<T>(&mut self, value: T) -> &mut T {
        // SAFETY: We use UnsafeCell to allow mutable access to the arena.
        // The caller is responsible for ensuring proper lifetime management.
        unsafe { (*self.arena.get()).alloc(value) }
    }

    /// Allocates a slice of values in the arena
    ///
    /// # Safety
    /// The returned reference is valid for the lifetime of the MemoryPool.
    pub fn alloc_slice<T>(&mut self, slice: &[T]) -> &mut [T]
    where
        T: Copy,
    {
        unsafe { (*self.arena.get()).alloc_slice_copy(slice) }
    }

    /// Allocates a string in the arena
    ///
    /// # Safety
    /// The returned reference is valid for the lifetime of the MemoryPool.
    pub fn alloc_str(&mut self, s: &str) -> &mut str {
        unsafe { (*self.arena.get()).alloc_str(s) }
    }

    /// Resets the arena, deallocating all memory
    ///
    /// # Safety
    /// All references allocated from this pool become invalid after reset.
    /// The caller must ensure no references derived from this pool are in use.
    pub fn reset(&mut self) {
        unsafe { (*self.arena.get()).reset() };
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

// SAFETY: MemoryPool can be safely sent between threads because it has
// exclusive ownership of its arena. No shared mutable state exists when
// the pool is moved.
unsafe impl Send for MemoryPool {}

// NOTE: Sync is intentionally NOT implemented for MemoryPool.
// The inner Bump allocator is not thread-safe (it uses no synchronization
// primitives). Implementing Sync would allow &MemoryPool references to be
// shared across threads, enabling data races on the UnsafeCell<Bump>.
// Each analysis pass should use its own MemoryPool instance.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memory_pool_basic() {
        let mut pool = MemoryPool::new();

        let value = pool.alloc(42);
        assert_eq!(*value, 42, "Expected values to be equal");

        *value = 100;
        assert_eq!(*value, 100, "Expected values to be equal");
    }

    #[test]
    fn test_memory_pool_slice() {
        let mut pool = MemoryPool::new();

        let data = [1, 2, 3, 4, 5];
        let slice = pool.alloc_slice(&data);

        assert_eq!(slice.len(), 5, "Expected values to be equal");
        assert_eq!(slice[0], 1, "Expected values to be equal");
    }

    #[test]
    fn test_memory_pool_string() {
        let mut pool = MemoryPool::new();

        let s = pool.alloc_str("hello world");
        assert_eq!(s, "hello world", "Expected values to be equal");
    }

    #[test]
    fn test_memory_pool_with_capacity() {
        let mut pool = MemoryPool::with_capacity(1024);
        let _ = pool.alloc(42);
        assert!(pool.allocated_bytes() > 0, "Expected condition to be true");
    }
}
