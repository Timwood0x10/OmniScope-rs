//! OmniScope Pass - Analysis pass infrastructure

pub mod manager;
pub mod pass;

pub use manager::PassManager;
pub use pass::{Pass, PassKind, PassResult};

#[cfg(test)]
mod tests {
    #[test]
    fn test_pass_module() {
        assert!(true);
    }
}
