//! ABI Layout Detector implementation.

use std::collections::HashMap;

use super::types::{AbiIssue, LanguageAbiRules, StructField, StructLayout};

/// Main detector for ABI layout issues.
///
/// This analyzer parses IR struct definitions and detects various ABI-related
/// safety issues including padding, alignment, and cross-language compatibility.
pub struct AbiLayoutDetector {
    /// Known struct layouts from IR analysis
    struct_cache: HashMap<String, StructLayout>,
    /// Language-specific ABI rules
    pub language_rules: HashMap<String, LanguageAbiRules>,
}

impl AbiLayoutDetector {
    /// Creates a new ABI layout detector.
    pub fn new() -> Self {
        Self {
            struct_cache: HashMap::new(),
            language_rules: Self::default_language_rules(),
        }
    }

    /// Creates a detector with custom language rules.
    pub fn with_language_rules(rules: HashMap<String, LanguageAbiRules>) -> Self {
        Self {
            struct_cache: HashMap::new(),
            language_rules: rules,
        }
    }

    /// Returns default language rules for common languages.
    fn default_language_rules() -> HashMap<String, LanguageAbiRules> {
        let mut rules = HashMap::new();

        // C/C++ ABI rules
        rules.insert(
            "c".to_string(),
            LanguageAbiRules {
                pointer_alignment: 8,
                default_packed: false,
                allow_field_reordering: false, // C preserves field order
            },
        );

        // Rust ABI rules
        rules.insert(
            "rust".to_string(),
            LanguageAbiRules {
                pointer_alignment: 8,
                default_packed: false,
                allow_field_reordering: true, // Rust can reorder fields
            },
        );

        // Go ABI rules
        rules.insert(
            "go".to_string(),
            LanguageAbiRules {
                pointer_alignment: 8,
                default_packed: false,
                allow_field_reordering: true, // Go can reorder fields
            },
        );

        rules
    }

    /// Detects ABI layout issues in the given IR.
    ///
    /// This is the main entry point for analysis. It parses struct definitions
    /// and checks for various ABI-related issues.
    pub fn detect_issues(&self, ir: &str) -> Vec<AbiIssue> {
        let mut issues = Vec::new();

        // Parse struct definitions from IR
        let structs = self.parse_struct_definitions(ir);

        // Analyze each struct for issues
        for layout in structs.values() {
            issues.extend(self.analyze_struct_layout(layout));
        }

        issues
    }

    /// Parses struct definitions from IR text.
    ///
    /// This method extracts struct type definitions from LLVM IR format.
    /// It handles both named structs and anonymous structs.
    pub fn parse_struct_definitions(&self, ir: &str) -> HashMap<String, StructLayout> {
        let mut structs = HashMap::new();

        for line in ir.lines() {
            let line = line.trim();

            // Match struct definition pattern: %struct.Name = type { ... }
            if let Some(layout) = self.parse_struct_definition_line(line) {
                structs.insert(layout.name.clone(), layout);
            }
        }

        structs
    }

    /// Parses a single struct definition line.
    fn parse_struct_definition_line(&self, line: &str) -> Option<StructLayout> {
        // Pattern: %struct.Name = type { field1, field2, ... }
        if !line.contains("= type {") && !line.contains("= type <{") {
            return None;
        }

        let is_packed = line.contains("= type <{");

        // Extract struct name
        let name_part = line.split('=').next()?;
        let name = name_part.trim().trim_start_matches('%').to_string();

        // Extract fields part
        let fields_start = line.find('{')?;
        let fields_end = line.rfind('}')?;
        if fields_start >= fields_end {
            return None;
        }

        let fields_str = &line[fields_start + 1..fields_end];
        let fields = self.parse_struct_fields(fields_str);

        // Calculate alignment and size
        let alignment = if is_packed {
            1
        } else {
            self.calculate_struct_alignment(&fields)
        };
        let total_size = self.calculate_struct_size(&fields, alignment, is_packed);

        Some(StructLayout {
            name,
            fields,
            total_size,
            alignment,
            packed: is_packed,
        })
    }

    /// Parses field types from a struct definition.
    fn parse_struct_fields(&self, fields_str: &str) -> Vec<StructField> {
        let mut fields = Vec::new();
        let mut depth = 0;
        let mut current_field = String::new();

        for ch in fields_str.chars() {
            match ch {
                '{' | '[' | '(' => {
                    depth += 1;
                    current_field.push(ch);
                }
                '}' | ']' | ')' => {
                    depth -= 1;
                    current_field.push(ch);
                }
                ',' if depth == 0 => {
                    if let Some(field) = self.create_field_from_type(current_field.trim()) {
                        fields.push(field);
                    }
                    current_field.clear();
                }
                _ => {
                    current_field.push(ch);
                }
            }
        }

        // Don't forget the last field
        if let Some(field) = self.create_field_from_type(current_field.trim()) {
            fields.push(field);
        }

        fields
    }

    /// Creates a StructField from a type string.
    fn create_field_from_type(&self, type_str: &str) -> Option<StructField> {
        if type_str.is_empty() {
            return None;
        }

        let (size, alignment) = self.get_type_info(type_str);

        Some(StructField {
            name: format!("field_{}", type_str), // Use type as name for now
            type_str: type_str.to_string(),
            size,
            alignment,
            offset: None, // Will be calculated later
        })
    }

    /// Gets size and alignment information for a type.
    pub fn get_type_info(&self, type_str: &str) -> (usize, usize) {
        match type_str {
            // Integer types
            "i1" => (1, 1),
            "i8" => (1, 1),
            "i16" => (2, 2),
            "i32" => (4, 4),
            "i64" => (8, 8),
            "i128" => (16, 16),

            // Floating point types
            "float" => (4, 4),
            "double" => (8, 8),
            "fp128" | "ppc_fp128" => (16, 16),

            // Pointer types
            "ptr" | "i8*" | "i32*" | "i64*" => (8, 8),

            // Array types: [N x type]
            _ if type_str.starts_with('[') && type_str.ends_with(']') => {
                self.parse_array_type(type_str)
            }

            // Struct types: %struct.Name or { ... }
            _ if type_str.starts_with('%') || type_str.starts_with('{') => {
                // For nested structs, we'd need recursive analysis
                // For now, return a conservative estimate
                (0, 1) // Unknown size
            }

            // Vector types: <N x type>
            _ if type_str.starts_with('<') && type_str.ends_with('>') => {
                self.parse_vector_type(type_str)
            }

            // Unknown type
            _ => (0, 1),
        }
    }

    /// Parses array type information.
    fn parse_array_type(&self, type_str: &str) -> (usize, usize) {
        // Format: [N x type]
        let inner = &type_str[1..type_str.len() - 1]; // Remove brackets
        let parts: Vec<&str> = inner.splitn(2, " x ").collect();
        if parts.len() != 2 {
            return (0, 1);
        }

        let count: usize = parts[0].trim().parse().unwrap_or(0);
        let (elem_size, elem_align) = self.get_type_info(parts[1].trim());

        (count * elem_size, elem_align)
    }

    /// Parses vector type information.
    fn parse_vector_type(&self, type_str: &str) -> (usize, usize) {
        // Format: <N x type>
        let inner = &type_str[1..type_str.len() - 1]; // Remove brackets
        let parts: Vec<&str> = inner.splitn(2, " x ").collect();
        if parts.len() != 2 {
            return (0, 1);
        }

        let count: usize = parts[0].trim().parse().unwrap_or(0);
        let (elem_size, _elem_align) = self.get_type_info(parts[1].trim());

        // Vectors are typically aligned to their total size
        let total_size = count * elem_size;
        let alignment = std::cmp::min(total_size, 16); // Cap at 16 bytes

        (total_size, alignment)
    }

    /// Calculates the alignment requirement for a struct.
    pub fn calculate_struct_alignment(&self, fields: &[StructField]) -> usize {
        fields.iter().map(|f| f.alignment).max().unwrap_or(1)
    }

    /// Calculates the total size of a struct including padding.
    pub fn calculate_struct_size(
        &self,
        fields: &[StructField],
        alignment: usize,
        packed: bool,
    ) -> Option<usize> {
        if fields.is_empty() {
            return Some(0);
        }

        let mut current_offset = 0;
        for field in fields {
            if !packed && field.alignment > 0 {
                // Add padding for alignment
                let padding =
                    (field.alignment - (current_offset % field.alignment)) % field.alignment;
                current_offset += padding;
            }
            current_offset += field.size;
        }

        // Add final padding to align struct size
        if !packed && alignment > 0 {
            let final_padding = (alignment - (current_offset % alignment)) % alignment;
            current_offset += final_padding;
        }

        Some(current_offset)
    }

    /// Analyzes a struct layout for ABI issues.
    pub fn analyze_struct_layout(&self, layout: &StructLayout) -> Vec<AbiIssue> {
        let mut issues = Vec::new();

        // Check for empty struct
        if layout.fields.is_empty() {
            issues.push(AbiIssue::EmptyStruct {
                struct_name: layout.name.clone(),
            });
            return issues;
        }

        // Check for padding issues
        issues.extend(self.detect_padding_issues(layout));

        // Check for field ordering issues
        if let Some(ordering_issue) = self.detect_field_ordering_issues(layout) {
            issues.push(ordering_issue);
        }

        // Check for excessive padding
        if let Some(excessive_issue) = self.detect_excessive_padding(layout) {
            issues.push(excessive_issue);
        }

        // Detect endianness issues
        issues.extend(self.detect_endianness_issues(layout));

        // Detect bitfield layout issues
        issues.extend(self.detect_bitfield_layout_issues(layout));

        issues
    }

    /// Detects padding issues in a struct.
    fn detect_padding_issues(&self, layout: &StructLayout) -> Vec<AbiIssue> {
        let mut issues = Vec::new();

        if layout.packed {
            return issues; // No padding in packed structs
        }

        let mut current_offset = 0;
        for i in 0..layout.fields.len() {
            let field = &layout.fields[i];

            // Calculate required padding
            let required_padding =
                (field.alignment - (current_offset % field.alignment)) % field.alignment;

            if required_padding > 0 {
                let field_before = if i > 0 {
                    layout.fields[i - 1].name.clone()
                } else {
                    "struct_start".to_string()
                };

                issues.push(AbiIssue::StructPadding {
                    struct_name: layout.name.clone(),
                    padding_bytes: required_padding,
                    field_before,
                    field_after: field.name.clone(),
                    offset: current_offset,
                });
            }

            current_offset += required_padding + field.size;
        }

        issues
    }

    /// Detects field ordering issues that could reduce padding.
    fn detect_field_ordering_issues(&self, layout: &StructLayout) -> Option<AbiIssue> {
        if layout.packed || layout.fields.len() < 2 {
            return None;
        }

        // Sort fields by alignment (largest first) to minimize padding
        let mut sorted_fields: Vec<usize> = (0..layout.fields.len()).collect();
        sorted_fields.sort_by(|&a, &b| {
            layout.fields[b]
                .alignment
                .cmp(&layout.fields[a].alignment)
                .then_with(|| layout.fields[b].size.cmp(&layout.fields[a].size))
        });

        // Check if current order is already optimal
        let is_optimal = sorted_fields.iter().enumerate().all(|(i, &idx)| idx == i);

        if is_optimal {
            return None;
        }

        // Calculate current size
        let current_size = self
            .calculate_struct_size(&layout.fields, layout.alignment, layout.packed)
            .unwrap_or(0);

        // Calculate optimized size
        let optimized_fields: Vec<StructField> = sorted_fields
            .iter()
            .map(|&idx| layout.fields[idx].clone())
            .collect();

        let optimized_size = self
            .calculate_struct_size(&optimized_fields, layout.alignment, layout.packed)
            .unwrap_or(0);

        if optimized_size < current_size {
            let current_order: Vec<String> = layout.fields.iter().map(|f| f.name.clone()).collect();

            let suggested_order: Vec<String> = sorted_fields
                .iter()
                .map(|&idx| layout.fields[idx].name.clone())
                .collect();

            Some(AbiIssue::FieldOrdering {
                struct_name: layout.name.clone(),
                current_order,
                suggested_order,
                wasted_bytes: current_size - optimized_size,
            })
        } else {
            None
        }
    }

    /// Detects excessive padding (more than 50% of total size).
    fn detect_excessive_padding(&self, layout: &StructLayout) -> Option<AbiIssue> {
        let total_size = layout.total_size?;
        if total_size == 0 {
            return None;
        }

        // Calculate data size (sum of field sizes)
        let data_size: usize = layout.fields.iter().map(|f| f.size).sum();
        let padding_bytes = total_size.saturating_sub(data_size);
        let padding_ratio = padding_bytes as f64 / total_size as f64;

        if padding_ratio > 0.5 {
            Some(AbiIssue::ExcessivePadding {
                struct_name: layout.name.clone(),
                total_size,
                padding_bytes,
                padding_ratio,
            })
        } else {
            None
        }
    }

    /// Detects endianness issues in a struct.
    fn detect_endianness_issues(&self, layout: &StructLayout) -> Vec<AbiIssue> {
        let mut issues = Vec::new();

        // Check for fields that may have endianness issues
        for field in &layout.fields {
            // Check for multi-byte integer fields that may have endianness issues
            if field.size > 1
                && (field.type_str.starts_with('i')
                    || field.type_str == "float"
                    || field.type_str == "double")
            {
                // Check if the field is in a packed struct (may have alignment issues)
                if layout.packed && field.alignment > 1 {
                    issues.push(AbiIssue::EndiannessIssue {
                        struct_name: layout.name.clone(),
                        field_name: field.name.clone(),
                        field_type: field.type_str.clone(),
                        issue_details: format!(
                            "Packed struct field '{}' ({}) may have alignment issues on strict-alignment platforms",
                            field.name, field.type_str
                        ),
                    });
                }

                // Check for potential endianness issues in cross-platform code
                if field.size >= 2 {
                    issues.push(AbiIssue::EndiannessIssue {
                        struct_name: layout.name.clone(),
                        field_name: field.name.clone(),
                        field_type: field.type_str.clone(),
                        issue_details: format!(
                            "Multi-byte field '{}' ({}) may have endianness issues in cross-platform code",
                            field.name, field.type_str
                        ),
                    });
                }
            }
        }

        issues
    }

    /// Detects bitfield layout issues in a struct.
    fn detect_bitfield_layout_issues(&self, layout: &StructLayout) -> Vec<AbiIssue> {
        let mut issues = Vec::new();

        // Check for potential bitfield layout issues
        for field in &layout.fields {
            // Check for small integer types that may be used as bitfields
            if field.type_str.starts_with('i') && field.size == 1 {
                // Check if the field is in a packed struct
                if layout.packed {
                    // Check for potential bitfield alignment issues
                    if field.alignment > 1 {
                        issues.push(AbiIssue::BitfieldLayoutIssue {
                            struct_name: layout.name.clone(),
                            field_name: field.name.clone(),
                            bit_width: 8, // Assuming 8-bit bitfield
                            issue_details: format!(
                                "Packed bitfield '{}' may have alignment issues",
                                field.name
                            ),
                        });
                    }
                }

                // Check for potential bitfield ordering issues
                // In packed structs, bitfield ordering may be compiler-specific
                if layout.packed && layout.fields.len() > 1 {
                    issues.push(AbiIssue::BitfieldLayoutIssue {
                        struct_name: layout.name.clone(),
                        field_name: field.name.clone(),
                        bit_width: 8,
                        issue_details:
                            "Bitfield ordering in packed struct may be compiler-specific"
                                .to_string(),
                    });
                }
            }
        }

        issues
    }

    /// Analyzes cross-language ABI compatibility.
    pub fn analyze_cross_language_abi(
        &self,
        layout: &StructLayout,
        language1: &str,
        language2: &str,
    ) -> Option<AbiIssue> {
        let rules1 = self.language_rules.get(language1)?;
        let rules2 = self.language_rules.get(language2)?;

        // Check for alignment differences
        let alignment1 = if rules1.default_packed {
            1
        } else {
            layout.alignment
        };

        let alignment2 = if rules2.default_packed {
            1
        } else {
            layout.alignment
        };

        if alignment1 != alignment2 {
            return Some(AbiIssue::CrossLanguageMismatch {
                struct_name: layout.name.clone(),
                language1: language1.to_string(),
                language2: language2.to_string(),
                mismatch_details: format!("Alignment mismatch: {} vs {}", alignment1, alignment2),
            });
        }

        // Check for field ordering differences
        if rules1.allow_field_reordering != rules2.allow_field_reordering {
            return Some(AbiIssue::CrossLanguageMismatch {
                struct_name: layout.name.clone(),
                language1: language1.to_string(),
                language2: language2.to_string(),
                mismatch_details: "Field ordering rules differ".to_string(),
            });
        }

        None
    }

    /// Adds a struct layout to the cache for later analysis.
    pub fn cache_struct_layout(&mut self, layout: StructLayout) {
        self.struct_cache.insert(layout.name.clone(), layout);
    }

    /// Gets a cached struct layout by name.
    pub fn get_cached_layout(&self, name: &str) -> Option<&StructLayout> {
        self.struct_cache.get(name)
    }

    /// Clears the struct cache.
    pub fn clear_cache(&mut self) {
        self.struct_cache.clear();
    }
}

impl Default for AbiLayoutDetector {
    fn default() -> Self {
        Self::new()
    }
}
