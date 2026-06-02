//! Index-based edge grouping for the issue candidate builder.
//!
//! Groups contract edges by their target resource instance ID using
//! indices into the `ContractGraph::edges` Vec, avoiding expensive
//! `ContractEdge` clones.

use std::collections::HashMap;

use omniscope_types::Effect;

use crate::resource::contract_graph_builder::ContractGraph;

/// Zero-clone edge grouping: maps instance IDs to indices in
/// `graph.edges` rather than cloning the edges themselves.
pub struct InstanceEdgeGroups {
    /// instance_id → Vec<edge index in graph.edges>
    groups: HashMap<u64, Vec<usize>>,
    /// Ordered list of unique instance IDs for deterministic iteration.
    instance_ids: Vec<u64>,
}

impl InstanceEdgeGroups {
    /// Builds index-based edge groups from the contract graph.
    ///
    /// Each edge is classified by its effect kind and assigned to the
    /// appropriate instance group via index (no `ContractEdge` clone).
    pub fn new(graph: &ContractGraph) -> Self {
        let mut groups: HashMap<u64, Vec<usize>> = HashMap::new();
        let mut seen_order: Vec<u64> = Vec::new();
        let mut seen_set: std::collections::HashSet<u64> = std::collections::HashSet::new();

        for (idx, edge) in graph.edges.iter().enumerate() {
            let key = match edge.effect {
                // Acquire: source=0 → target=instance_id
                Effect::Acquire { result, .. } => result,

                // Reclaim: group by `result` (the fresh reclaim instance ID).
                // Also group by `edge.source` (the escaped instance ID) so the
                // OwnershipEscapeLeak check can find the reclaim in the same
                // group as the escape edge.
                Effect::OwnershipReclaim { result, .. } => {
                    // Insert into result group
                    insert_edge(&mut groups, &mut seen_order, &mut seen_set, result, idx);
                    // Also insert into source group if different from result
                    if edge.source != 0 && edge.source != result {
                        insert_edge(
                            &mut groups,
                            &mut seen_order,
                            &mut seen_set,
                            edge.source,
                            idx,
                        );
                    }
                    continue;
                }

                // Release: source=instance_id → target=0
                Effect::Release { .. } | Effect::ConditionalRelease { .. } => edge.source,

                // OwnershipEscape: source=instance_id → target=0
                Effect::OwnershipEscape { .. } => edge.source,

                // EscapesToCallback: may have source=0 when no explicit source.
                Effect::EscapesToCallback { .. } => {
                    if edge.source != 0 {
                        edge.source
                    } else {
                        u64::MAX
                    }
                }

                // ReturnsBorrowed: similar to EscapesToCallback.
                Effect::ReturnsBorrowed => {
                    if edge.source != 0 {
                        edge.source
                    } else {
                        u64::MAX
                    }
                }

                // Other effects: attach to source instance
                _ => {
                    if edge.source != 0 {
                        edge.source
                    } else {
                        continue;
                    }
                }
            };

            insert_edge(&mut groups, &mut seen_order, &mut seen_set, key, idx);
        }

        Self {
            groups,
            instance_ids: seen_order,
        }
    }

    /// Returns the ordered list of instance IDs in this group.
    pub fn instance_ids(&self) -> &[u64] {
        &self.instance_ids
    }

    /// Returns the edge indices for a given instance ID.
    pub fn edges_of(&self, instance_id: u64) -> &[usize] {
        self.groups.get(&instance_id).map_or(&[], |v| v)
    }
}

/// Helper to insert an edge index into the groups and track insertion order.
fn insert_edge(
    groups: &mut HashMap<u64, Vec<usize>>,
    seen_order: &mut Vec<u64>,
    seen_set: &mut std::collections::HashSet<u64>,
    key: u64,
    idx: usize,
) {
    if groups.entry(key).or_default().is_empty() && !seen_set.contains(&key) {
        seen_set.insert(key);
        seen_order.push(key);
    }
    groups.get_mut(&key)
        .expect("grouping: key should exist after or_default insert")
        .push(idx);
}
