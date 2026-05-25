//! Pipeline manager

use omniscope_pass::PassManager;

pub struct Pipeline {
    pass_manager: PassManager,
}

impl Pipeline {
    pub fn new() -> Self {
        Self {
            pass_manager: PassManager::new(),
        }
    }
}

impl Default for Pipeline {
    fn default() -> Self {
        Self::new()
    }
}
