//! Language detection

use omniscope_types::Language;

pub struct LanguageDetector;

impl LanguageDetector {
    pub fn new() -> Self {
        Self
    }

    pub fn detect(&self) -> Language {
        Language::Unknown
    }
}
