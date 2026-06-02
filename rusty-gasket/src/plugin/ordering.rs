//! Topological sorting of plugins based on ordering constraints.
//!
//! Plugins declare their relative execution order via [`PluginOrdering`].
//! The framework converts those declarations into a directed graph and
//! produces a valid topological order, rejecting cycles and dangling
//! references at startup rather than producing surprising runtime behavior.

use std::collections::{BTreeSet, HashMap, VecDeque};

use crate::BoxError;

use super::PluginHandle;

/// Ordering constraints for a plugin relative to other plugins.
///
/// - `before` — this plugin must run before the named plugins
/// - `after` — this plugin must run after the named plugins
/// - `first` — request earliest possible execution (priority 0)
/// - `last` — request latest possible execution
///
/// Constraints are normalized to directed edges and topologically
/// sorted. References to non-existent plugins are a hard error
/// (unlike JS gasket which silently ignores them).
///
/// Construct directly with field assignment, or use the builder-style
/// helpers ([`Self::before`], [`Self::after`], [`Self::first`],
/// [`Self::last`]) to chain constraints from a `Plugin::ordering` impl.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct PluginOrdering {
    /// Plugin names that this plugin must execute before.
    pub before: Vec<&'static str>,
    /// Plugin names that this plugin must execute after.
    pub after: Vec<&'static str>,
    /// Request earliest possible execution (overrides all non-`first` plugins).
    pub first: bool,
    /// Request latest possible execution (overrides all non-`last` plugins).
    pub last: bool,
}

impl PluginOrdering {
    /// Create an empty ordering. Equivalent to [`Self::default`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Append plugin names that this plugin must execute before.
    #[must_use]
    pub fn before(mut self, names: impl IntoIterator<Item = &'static str>) -> Self {
        self.before.extend(names);
        self
    }

    /// Append plugin names that this plugin must execute after.
    #[must_use]
    pub fn after(mut self, names: impl IntoIterator<Item = &'static str>) -> Self {
        self.after.extend(names);
        self
    }

    /// Mark this plugin to run as early as possible.
    #[must_use]
    pub const fn first(mut self) -> Self {
        self.first = true;
        self
    }

    /// Mark this plugin to run as late as possible.
    #[must_use]
    pub const fn last(mut self) -> Self {
        self.last = true;
        self
    }
}

/// Sort plugins into a valid execution order based on their ordering constraints.
///
/// Returns indices into the original slice. Detects cycles and references
/// to non-existent plugins, returning an error in both cases.
///
/// # Errors
/// Returns an error if a plugin sets both `first` and `last`, declares a
/// `before`/`after` dependency on a name that is not registered, or if the
/// declared constraints form a cycle.
pub fn topological_sort(plugins: &[PluginHandle]) -> Result<Vec<usize>, BoxError> {
    let n = plugins.len();
    let mut name_to_idx: HashMap<&str, usize> = HashMap::with_capacity(n);
    for (i, plugin) in plugins.iter().enumerate() {
        let name = plugin.name();
        if let Some(prev) = name_to_idx.insert(name, i) {
            return Err(format!(
                "Duplicate plugin name '{name}' registered at indices {prev} and {i}; \
                 plugin names must be unique"
            )
            .into());
        }
    }

    let mut adj: Vec<BTreeSet<usize>> = vec![BTreeSet::new(); n];
    let mut in_degree: Vec<usize> = vec![0; n];

    for (i, plugin) in plugins.iter().enumerate() {
        let ordering = plugin.ordering();

        if ordering.first && ordering.last {
            return Err(format!(
                "Plugin '{}' declares both first=true and last=true, which is contradictory",
                plugin.name()
            )
            .into());
        }

        if ordering.first {
            for (j, other) in plugins.iter().enumerate() {
                if j != i && !other.ordering().first {
                    adj[i].insert(j);
                }
            }
        }

        if ordering.last {
            for (j, other) in plugins.iter().enumerate() {
                if j != i && !other.ordering().last {
                    adj[j].insert(i);
                }
            }
        }

        for target_name in &ordering.before {
            if let Some(&j) = name_to_idx.get(target_name) {
                adj[i].insert(j);
            } else {
                return Err(format!(
                    "Plugin '{}' declares before='{}', but no such plugin is registered",
                    plugin.name(),
                    target_name
                )
                .into());
            }
        }

        for dep_name in &ordering.after {
            if let Some(&j) = name_to_idx.get(dep_name) {
                adj[j].insert(i);
            } else {
                return Err(format!(
                    "Plugin '{}' declares after='{}', but no such plugin is registered",
                    plugin.name(),
                    dep_name
                )
                .into());
            }
        }
    }

    for (i, neighbors) in adj.iter().enumerate() {
        for &j in neighbors {
            if i != j {
                in_degree[j] += 1;
            }
        }
    }

    let mut queue: VecDeque<usize> = VecDeque::new();
    for (i, &deg) in in_degree.iter().enumerate() {
        if deg == 0 {
            queue.push_back(i);
        }
    }

    let mut sorted = Vec::with_capacity(n);
    while let Some(node) = queue.pop_front() {
        sorted.push(node);
        for &neighbor in &adj[node] {
            in_degree[neighbor] -= 1;
            if in_degree[neighbor] == 0 {
                queue.push_back(neighbor);
            }
        }
    }

    if sorted.len() != n {
        let cycle_nodes: Vec<&str> = (0..n)
            .filter(|i| in_degree[*i] > 0)
            .map(|i| plugins[i].name())
            .collect();
        return Err(format!(
            "Cycle detected in plugin ordering involving: {}",
            cycle_nodes.join(", ")
        )
        .into());
    }

    Ok(sorted)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugin::Plugin;

    struct TestPlugin {
        name: &'static str,
        ordering: PluginOrdering,
        deps: Vec<&'static str>,
    }

    impl Plugin for TestPlugin {
        fn name(&self) -> &'static str {
            self.name
        }
        fn ordering(&self) -> PluginOrdering {
            self.ordering.clone()
        }
        fn dependencies(&self) -> Vec<&str> {
            self.deps.clone()
        }
    }

    fn make_plugin(name: &'static str) -> PluginHandle {
        PluginHandle::new(TestPlugin {
            name,
            ordering: PluginOrdering::default(),
            deps: Vec::new(),
        })
    }

    fn make_ordered_plugin(name: &'static str, ordering: PluginOrdering) -> PluginHandle {
        PluginHandle::new(TestPlugin {
            name,
            ordering,
            deps: Vec::new(),
        })
    }

    #[test]
    fn basic_sort_preserves_insertion_order() {
        let plugins = vec![make_plugin("a"), make_plugin("b"), make_plugin("c")];
        let sorted = topological_sort(&plugins).expect("should sort");
        assert_eq!(sorted, vec![0, 1, 2]);
    }

    #[test]
    fn before_after_ordering() {
        let plugins = vec![
            make_ordered_plugin(
                "auth",
                PluginOrdering {
                    after: vec!["logging"],
                    ..Default::default()
                },
            ),
            make_plugin("logging"),
        ];
        let sorted = topological_sort(&plugins).expect("should sort");
        assert_eq!(sorted, vec![1, 0]);
    }

    #[test]
    fn first_last_ordering() {
        let plugins = vec![
            make_plugin("middle"),
            make_ordered_plugin(
                "last",
                PluginOrdering {
                    last: true,
                    ..Default::default()
                },
            ),
            make_ordered_plugin(
                "first",
                PluginOrdering {
                    first: true,
                    ..Default::default()
                },
            ),
        ];
        let sorted = topological_sort(&plugins).expect("should sort");
        assert_eq!(plugins[sorted[0]].name(), "first");
        assert_eq!(plugins[sorted[2]].name(), "last");
    }

    #[test]
    fn cycle_detection() {
        let plugins = vec![
            make_ordered_plugin(
                "a",
                PluginOrdering {
                    after: vec!["b"],
                    ..Default::default()
                },
            ),
            make_ordered_plugin(
                "b",
                PluginOrdering {
                    after: vec!["a"],
                    ..Default::default()
                },
            ),
        ];
        let result = topological_sort(&plugins);
        assert!(result.is_err());
        let err_msg = result.expect_err("should detect cycle").to_string();
        assert!(err_msg.contains("Cycle detected"));
    }

    #[test]
    fn duplicate_plugin_name_is_error() {
        let plugins = vec![make_plugin("a"), make_plugin("a")];
        let err = topological_sort(&plugins)
            .expect_err("duplicate plugin names should be rejected")
            .to_string();
        assert!(
            err.contains("Duplicate plugin name 'a'"),
            "expected duplicate-name error, got: {err}"
        );
    }

    #[test]
    fn ordering_builder_is_equivalent_to_struct_literal() {
        let built = PluginOrdering::new()
            .before(["downstream"])
            .after(["upstream"])
            .first();
        let literal = PluginOrdering {
            before: vec!["downstream"],
            after: vec!["upstream"],
            first: true,
            ..Default::default()
        };
        assert_eq!(built.before, literal.before);
        assert_eq!(built.after, literal.after);
        assert_eq!(built.first, literal.first);
        assert_eq!(built.last, literal.last);
    }

    #[test]
    fn ordering_builder_appends_repeatedly() {
        // Multiple .before() calls accumulate rather than overwrite, so a
        // plugin can spread its constraint declaration across helper
        // methods or extension traits.
        let built = PluginOrdering::new().before(["a"]).before(["b", "c"]);
        assert_eq!(built.before, vec!["a", "b", "c"]);
    }

    #[test]
    fn missing_before_ref_is_error() {
        let plugins = vec![make_ordered_plugin(
            "a",
            PluginOrdering {
                before: vec!["nonexistent"],
                ..Default::default()
            },
        )];
        let result = topological_sort(&plugins);
        assert!(result.is_err());
        assert!(
            result
                .expect_err("should error on missing ref")
                .to_string()
                .contains("nonexistent")
        );
    }
}
