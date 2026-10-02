use std::borrow::Cow;
use std::collections::{HashSet, VecDeque};
use std::fmt;
use std::sync::Arc;

use aho_corasick::{AhoCorasick, AhoCorasickKind, StartKind};
use regex::Regex;
use thiserror::Error;

use crate::{DomainMatcher, DomainNameMode};

/// Flat contiguous reversed-label domain trie.
/// Domains are traversed by labels in reverse order (e.g., `com` -> `example` -> `api`),
/// allowing all subdomains to naturally share parent nodes.
/// Stored in a single flat contiguous array of nodes with an underlying string arena.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct ReversedDomainTrie {
    arena: Box<str>,
    nodes: Box<[FlatTrieNode]>,
    pub full_count: usize,
    pub suffix_count: usize,
    pub pattern_bytes: usize,
}

#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
pub struct FlatTrieNode {
    pub label_offset: u32,
    pub first_child: u32,
    pub num_children: u32,
    pub label_len: u16,
    pub flags: u16, // bit 0: is_suffix, bit 1: is_full
}

#[derive(Debug, Default)]
pub struct TrieBuilderNode {
    label: String,
    flags: u16,
    children: Vec<TrieBuilderNode>,
}

impl TrieBuilderNode {
    fn insert<'a>(&mut self, mut labels: impl Iterator<Item = &'a str>, flag: u16) {
        let Some(label) = labels.next() else {
            self.flags |= flag;
            return;
        };

        if let Some(child) = self.children.iter_mut().find(|c| c.label == label) {
            child.insert(labels, flag);
        } else {
            let mut child = TrieBuilderNode {
                label: label.to_owned(),
                flags: 0,
                children: Vec::new(),
            };
            child.insert(labels, flag);
            self.children.push(child);
        }
    }
}

impl ReversedDomainTrie {
    pub fn build(
        mut root: TrieBuilderNode,
        full_count: usize,
        suffix_count: usize,
        pattern_bytes: usize,
    ) -> Self {
        if root.children.is_empty() && root.flags == 0 {
            return Self {
                arena: Box::default(),
                nodes: Box::default(),
                full_count,
                suffix_count,
                pattern_bytes,
            };
        }

        let mut arena = String::new();
        let mut flat_nodes = Vec::new();

        root.children.sort_unstable_by(|a, b| a.label.cmp(&b.label));

        // Node 0: Root node
        flat_nodes.push(FlatTrieNode {
            label_offset: 0,
            first_child: 0,
            num_children: root.children.len() as u32,
            label_len: 0,
            flags: root.flags,
        });

        let mut queue = VecDeque::new();
        if !root.children.is_empty() {
            queue.push_back((0usize, root.children));
        }

        while let Some((parent_idx, mut children)) = queue.pop_front() {
            let first_child_idx = flat_nodes.len() as u32;
            flat_nodes[parent_idx].first_child = first_child_idx;

            for child in &mut children {
                child.children.sort_unstable_by(|a, b| a.label.cmp(&b.label));
            }

            let start = flat_nodes.len();
            for child in &children {
                let label_offset = arena.len() as u32;
                let label_len = child.label.len() as u16;
                arena.push_str(&child.label);

                flat_nodes.push(FlatTrieNode {
                    label_offset,
                    first_child: 0,
                    num_children: child.children.len() as u32,
                    label_len,
                    flags: child.flags,
                });
            }

            for (i, child) in children.into_iter().enumerate() {
                if !child.children.is_empty() {
                    queue.push_back((start + i, child.children));
                }
            }
        }

        Self {
            arena: arena.into_boxed_str(),
            nodes: flat_nodes.into_boxed_slice(),
            full_count,
            suffix_count,
            pattern_bytes,
        }
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.full_count + self.suffix_count
    }

    #[inline]
    pub fn pattern_bytes(&self) -> usize {
        self.pattern_bytes
    }

    pub fn total_memory_bytes(&self) -> usize {
        self.arena.len() + self.nodes.len() * std::mem::size_of::<FlatTrieNode>()
    }

    pub fn matches(&self, domain: &str) -> bool {
        if self.nodes.is_empty() {
            return false;
        }

        let mut current_idx = 0;

        for label in domain.rsplit('.') {
            let current = &self.nodes[current_idx];
            if current.num_children == 0 {
                return false;
            }
            let children_start = current.first_child as usize;
            let children_end = children_start + current.num_children as usize;
            let children = &self.nodes[children_start..children_end];

            let found = children.binary_search_by(|child| {
                let start = child.label_offset as usize;
                let end = start + child.label_len as usize;
                let child_label = &self.arena[start..end];
                child_label.cmp(label)
            });

            match found {
                Ok(child_offset) => {
                    let next_idx = children_start + child_offset;
                    let next_node = &self.nodes[next_idx];
                    if (next_node.flags & 1) != 0 {
                        // Suffix matched
                        return true;
                    }
                    current_idx = next_idx;
                }
                Err(_) => return false,
            }
        }

        // Reached end of all labels: check full match flag (bit 1)
        (self.nodes[current_idx].flags & 2) != 0
    }
}

impl fmt::Debug for ReversedDomainTrie {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReversedDomainTrie")
            .field("nodes", &self.nodes.len())
            .field("full_count", &self.full_count)
            .field("suffix_count", &self.suffix_count)
            .field("arena_bytes", &self.arena.len())
            .finish()
    }
}

/// Small routing rules are more common than geosite-sized matcher sets. A
/// linear scan avoids a hash lookup (and an ASCII-case normalization pass) for
/// each rule while the indexed representation still handles large sets.
const LINEAR_MATCHER_LIMIT: usize = 8;

/// Query-ready set of `full:`, `domain:`, `keyword:` and `regexp:` matchers
/// belonging to one rule.
///
/// Names are matched per label and ASCII case-insensitively: `domain:a.test`
/// matches `a.test` and `b.a.test` but not `ba.test`. Trailing dots are kept
/// as-is on both sides, so DNS callers normalize names before matching.
///
/// The compiled state is immutable and shared behind an `Arc`, so cloning a
/// set only bumps a reference count instead of copying its hash tables,
/// automaton and regexes.
#[derive(Clone, Default)]
pub struct DomainMatcherSet {
    inner: Option<Arc<DomainMatcherSetInner>>,
    matcher_count: usize,
}

struct DomainMatcherSetInner {
    linear: Option<Box<[DomainMatcher]>>,
    trie: ReversedDomainTrie,
    keywords: Vec<Box<str>>,
    keyword_automaton: Option<AhoCorasick>,
    regex: Vec<Regex>,
}

impl DomainMatcherSet {
    pub fn builder() -> DomainMatcherSetBuilder {
        DomainMatcherSetBuilder::default()
    }

    /// Compiles `matchers` in one pass; `mode` picks the `full:`/`domain:`
    /// pattern normalization.
    pub fn compile(
        matchers: &[DomainMatcher],
        mode: DomainNameMode,
    ) -> Result<Self, DomainMatcherSetError> {
        let mut builder = Self::builder();
        for matcher in matchers {
            builder.insert(matcher, mode);
        }
        builder.build()
    }

    pub fn is_empty(&self) -> bool {
        self.matcher_count == 0
    }

    /// Returns the number of source matchers inserted, duplicates included.
    pub fn matcher_count(&self) -> usize {
        self.matcher_count
    }

    pub fn full_count(&self) -> usize {
        self.inner.as_ref().map_or(0, |inner| inner.full_count())
    }

    pub fn suffix_count(&self) -> usize {
        self.inner.as_ref().map_or(0, |inner| inner.suffix_count())
    }

    /// Returns the retained pattern payload in bytes, excluding hash-table,
    /// automaton and regex-engine overhead.
    pub fn pattern_bytes(&self) -> usize {
        self.inner.as_ref().map_or(0, |inner| inner.pattern_bytes())
    }

    pub fn matches(&self, domain: &str) -> bool {
        let Some(inner) = &self.inner else {
            return false;
        };
        if let Some(matchers) = &inner.linear {
            return matchers.iter().any(|matcher| matcher.matches(domain));
        }
        let domain = lowercase_ascii(domain);
        inner.trie.matches(&domain)
            || inner.matches_keyword(&domain)
            || inner.matches_regex(&domain)
    }
}

impl DomainMatcherSetInner {
    fn pattern_bytes(&self) -> usize {
        if let Some(matchers) = &self.linear {
            return matchers.iter().map(matcher_pattern_bytes).sum();
        }
        self.trie.pattern_bytes()
            + self
                .keywords
                .iter()
                .map(|keyword| keyword.len())
                .sum::<usize>()
            + self
                .regex
                .iter()
                .map(|regex| regex.as_str().len())
                .sum::<usize>()
    }

    fn full_count(&self) -> usize {
        self.trie.full_count
            + self.matcher_kind_count(|matcher| matches!(matcher, DomainMatcher::Full(_)))
    }

    fn suffix_count(&self) -> usize {
        self.trie.suffix_count
            + self.matcher_kind_count(|matcher| matches!(matcher, DomainMatcher::Suffix(_)))
    }

    fn matches_keyword(&self, domain: &str) -> bool {
        self.keyword_automaton
            .as_ref()
            .is_some_and(|automaton| automaton.is_match(domain))
    }

    fn matches_regex(&self, domain: &str) -> bool {
        self.regex.iter().any(|regex| regex.is_match(domain))
    }

    fn matcher_kind_count(&self, select: fn(&DomainMatcher) -> bool) -> usize {
        self.linear.as_deref().map_or(0, |matchers| {
            matchers.iter().filter(|matcher| select(matcher)).count()
        })
    }
}

impl fmt::Debug for DomainMatcherSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let counts = |select: fn(&DomainMatcherSetInner) -> usize| {
            self.inner.as_ref().map_or(0, |inner| select(inner))
        };
        f.debug_struct("DomainMatcherSet")
            .field("full", &counts(|inner| inner.full_count()))
            .field("suffix", &counts(|inner| inner.suffix_count()))
            .field(
                "keyword",
                &counts(|inner| {
                    inner.keywords.len()
                        + inner.matcher_kind_count(|matcher| {
                            matches!(matcher, DomainMatcher::Keyword(_))
                        })
                }),
            )
            .field(
                "regex",
                &counts(|inner| {
                    inner.regex.len()
                        + inner.matcher_kind_count(|matcher| {
                            matches!(matcher, DomainMatcher::Regex(_))
                        })
                }),
            )
            .field("matcher_count", &self.matcher_count)
            .finish()
    }
}

impl PartialEq for DomainMatcherSet {
    fn eq(&self, other: &Self) -> bool {
        self.matcher_count == other.matcher_count
            && match (&self.inner, &other.inner) {
                (None, None) => true,
                (Some(a), Some(b)) => {
                    a.linear == b.linear
                        && a.trie == b.trie
                        && a.keywords == b.keywords
                        && a.regex
                            .iter()
                            .map(Regex::as_str)
                            .eq(b.regex.iter().map(Regex::as_str))
                }
                (Some(_), None) | (None, Some(_)) => false,
            }
    }
}

impl Eq for DomainMatcherSet {}

#[derive(Debug, Error)]
pub enum DomainMatcherSetError {
    #[error("keyword matchers exceed the automaton limits: {0}")]
    Keyword(#[from] aho_corasick::BuildError),
}

#[derive(Debug)]
pub struct DomainMatcherSetBuilder {
    linear: Option<Vec<DomainMatcher>>,
    trie_root: TrieBuilderNode,
    seen_full: HashSet<Box<str>>,
    seen_suffix: HashSet<Box<str>>,
    full_count: usize,
    suffix_count: usize,
    pattern_bytes: usize,
    keywords: Vec<Box<str>>,
    regex: Vec<Regex>,
    matcher_count: usize,
}

impl Default for DomainMatcherSetBuilder {
    fn default() -> Self {
        Self {
            linear: Some(Vec::new()),
            trie_root: TrieBuilderNode::default(),
            seen_full: HashSet::new(),
            seen_suffix: HashSet::new(),
            full_count: 0,
            suffix_count: 0,
            pattern_bytes: 0,
            keywords: Vec::new(),
            regex: Vec::new(),
            matcher_count: 0,
        }
    }
}

impl DomainMatcherSetBuilder {
    /// Adds one matcher; the already compiled regex of a `regexp:` matcher is
    /// shared, not recompiled.
    pub fn insert(&mut self, matcher: &DomainMatcher, mode: DomainNameMode) {
        if let Some(linear) = &mut self.linear {
            if self.matcher_count < LINEAR_MATCHER_LIMIT {
                let matcher = normalize_linear_matcher(matcher, mode);
                if !linear.contains(&matcher) {
                    linear.push(matcher);
                }
            } else {
                self.linear = None;
            }
        }
        match matcher {
            DomainMatcher::Keyword(keyword) => self.keywords.push(lowercase_boxed(keyword)),
            DomainMatcher::Full(domain) => {
                let pattern = lowercase_ascii(mode.pattern(domain));
                if self.seen_full.insert(pattern.as_ref().into()) {
                    self.pattern_bytes += pattern.len();
                    self.full_count += 1;
                }
                self.trie_root.insert(pattern.rsplit('.'), 2);
            }
            DomainMatcher::Suffix(suffix) => {
                let pattern = lowercase_ascii(mode.pattern(suffix));
                if self.seen_suffix.insert(pattern.as_ref().into()) {
                    self.pattern_bytes += pattern.len();
                    self.suffix_count += 1;
                }
                self.trie_root.insert(pattern.rsplit('.'), 1);
            }
            DomainMatcher::Regex(matcher) => self.regex.push(matcher.regex().clone()),
        }
        self.matcher_count += 1;
    }

    pub fn matcher_count(&self) -> usize {
        self.matcher_count
    }

    pub fn build(self) -> Result<DomainMatcherSet, DomainMatcherSetError> {
        if self.matcher_count == 0 {
            return Ok(DomainMatcherSet::default());
        }
        let matcher_count = self.matcher_count;
        let (linear, trie, keywords, keyword_automaton, regex) =
            if let Some(linear) = self.linear {
                (
                    Some(linear.into_boxed_slice()),
                    ReversedDomainTrie::default(),
                    Vec::new(),
                    None,
                    Vec::new(),
                )
            } else {
                let keyword_automaton = if self.keywords.is_empty() {
                    None
                } else {
                    Some(
                        AhoCorasick::builder()
                            .kind(Some(AhoCorasickKind::ContiguousNFA))
                            .start_kind(StartKind::Unanchored)
                            .build(self.keywords.iter().map(|keyword| keyword.as_bytes()))?,
                    )
                };
                (
                    None,
                    ReversedDomainTrie::build(
                        self.trie_root,
                        self.full_count,
                        self.suffix_count,
                        self.pattern_bytes,
                    ),
                    self.keywords,
                    keyword_automaton,
                    self.regex,
                )
            };
        Ok(DomainMatcherSet {
            inner: Some(Arc::new(DomainMatcherSetInner {
                linear,
                trie,
                keywords,
                keyword_automaton,
                regex,
            })),
            matcher_count,
        })
    }
}

fn lowercase_boxed(value: &str) -> Box<str> {
    value.to_ascii_lowercase().into_boxed_str()
}

fn normalize_linear_matcher(matcher: &DomainMatcher, mode: DomainNameMode) -> DomainMatcher {
    match matcher {
        DomainMatcher::Keyword(keyword) => DomainMatcher::Keyword(keyword.to_ascii_lowercase()),
        DomainMatcher::Full(domain) => {
            DomainMatcher::Full(mode.pattern(domain).to_ascii_lowercase())
        }
        DomainMatcher::Suffix(suffix) => {
            DomainMatcher::Suffix(mode.pattern(suffix).to_ascii_lowercase())
        }
        DomainMatcher::Regex(matcher) => DomainMatcher::Regex(matcher.clone()),
    }
}

fn matcher_pattern_bytes(matcher: &DomainMatcher) -> usize {
    match matcher {
        DomainMatcher::Keyword(pattern)
        | DomainMatcher::Full(pattern)
        | DomainMatcher::Suffix(pattern) => pattern.len(),
        DomainMatcher::Regex(matcher) => matcher.pattern().len(),
    }
}

fn lowercase_ascii(value: &str) -> Cow<'_, str> {
    if value.bytes().any(|byte| byte.is_ascii_uppercase()) {
        Cow::Owned(value.to_ascii_lowercase())
    } else {
        Cow::Borrowed(value)
    }
}

#[cfg(test)]
mod tests {
    use std::mem::size_of;

    use super::*;
    use crate::RegexMatcher;

    fn matchers(
        full: &[&str],
        suffix: &[&str],
        keyword: &[&str],
        regex: &[&str],
    ) -> Vec<DomainMatcher> {
        full.iter()
            .map(|name| DomainMatcher::Full((*name).to_owned()))
            .chain(
                suffix
                    .iter()
                    .map(|name| DomainMatcher::Suffix((*name).to_owned())),
            )
            .chain(
                keyword
                    .iter()
                    .map(|name| DomainMatcher::Keyword((*name).to_owned())),
            )
            .chain(
                regex
                    .iter()
                    .map(|pattern| DomainMatcher::Regex(RegexMatcher::new(*pattern).unwrap())),
            )
            .collect()
    }

    fn compile(
        full: &[&str],
        suffix: &[&str],
        keyword: &[&str],
        regex: &[&str],
    ) -> DomainMatcherSet {
        DomainMatcherSet::compile(
            &matchers(full, suffix, keyword, regex),
            DomainNameMode::Routing,
        )
        .unwrap()
    }

    fn table_bytes(trie: &ReversedDomainTrie) -> usize {
        trie.nodes.len() * size_of::<FlatTrieNode>()
    }

    fn heap_bytes(trie: &ReversedDomainTrie) -> usize {
        trie.arena.len()
    }

    #[test]
    fn clone_shares_compiled_state() {
        let set = compile(&["a.test"], &[], &[], &[]);
        let cloned = set.clone();
        assert!(Arc::ptr_eq(
            set.inner.as_ref().unwrap(),
            cloned.inner.as_ref().unwrap()
        ));
        assert_eq!(cloned, set);
        assert!(cloned.matches("a.test"));
    }

    #[test]
    fn small_sets_use_the_linear_fast_path_without_retaining_indexes() {
        let set = compile(&["a.test", "b.test"], &["suffix.test"], &["kw"], &["^rx$"]);
        let inner = set.inner.as_deref().unwrap();

        assert_eq!(inner.linear.as_deref().unwrap().len(), 5);
        assert!(inner.trie.is_empty());
        assert!(inner.keywords.is_empty());
        assert!(inner.keyword_automaton.is_none());
        assert!(inner.regex.is_empty());
        assert!(set.matches("B.TEST"));
        assert!(set.matches("deep.SUFFIX.test"));
        assert!(set.matches("prefix-KW-suffix"));
        assert!(set.matches("RX"));
    }

    #[test]
    fn sets_above_the_linear_limit_use_the_compiled_indexes() {
        let full = (0..=LINEAR_MATCHER_LIMIT)
            .map(|index| format!("host-{index}.test"))
            .collect::<Vec<_>>();
        let matchers = full
            .iter()
            .map(|name| DomainMatcher::Full(name.clone()))
            .collect::<Vec<_>>();
        let set = DomainMatcherSet::compile(&matchers, DomainNameMode::Routing).unwrap();
        let inner = set.inner.as_deref().unwrap();

        assert!(inner.linear.is_none());
        assert_eq!(inner.full_count(), LINEAR_MATCHER_LIMIT + 1);
        assert!(set.matches("HOST-8.TEST"));
        assert!(!set.matches("missing.test"));
    }

    #[test]
    fn empty_set_matches_nothing_and_reports_zero_sizes() {
        let empty = DomainMatcherSet::default();
        assert!(empty.is_empty());
        assert_eq!(empty.matcher_count(), 0);
        assert_eq!(empty.pattern_bytes(), 0);
        assert!(!empty.matches(""));
        assert!(!empty.matches("example.com"));
        assert_eq!(DomainMatcherSet::builder().build().unwrap(), empty);
        assert_eq!(
            format!("{empty:?}"),
            "DomainMatcherSet { full: 0, suffix: 0, keyword: 0, regex: 0, matcher_count: 0 }"
        );
    }

    #[test]
    fn full_names_match_exactly_and_case_insensitively() {
        let set = compile(&["Example.COM", "exact.test."], &[], &[], &[]);
        assert_eq!(set.matcher_count(), 2);
        assert!(set.matches("example.com"));
        assert!(set.matches("EXAMPLE.com"));
        assert!(!set.matches("www.example.com"));
        assert!(!set.matches("example.com."));
        assert!(set.matches("exact.test."));
        assert!(!set.matches("exact.test"));
        assert!(!set.matches("notexample.com"));
    }

    #[test]
    fn suffixes_match_on_label_boundaries_only() {
        let set = compile(&[], &["Example.com", "corp", ".lead.test", ""], &[], &[]);
        assert!(set.matches("example.com"));
        assert!(set.matches("a.b.EXAMPLE.com"));
        assert!(!set.matches("notexample.com"));
        assert!(!set.matches("example.com.evil"));
        assert!(set.matches("corp"));
        assert!(set.matches("intranet.corp"));
        assert!(!set.matches("corp.example"));
        assert!(set.matches(".lead.test"));
        assert!(set.matches("x..lead.test"));
        assert!(!set.matches("www.lead.test"));
        assert!(set.matches(""));
        assert!(set.matches("trailing.dot."));
        assert!(!set.matches("nodot"));
    }

    #[test]
    fn full_and_suffix_rules_for_the_same_name_are_kept_apart() {
        let set = compile(&["shared.test"], &["shared.test"], &[], &[]);
        assert_eq!(set.matcher_count(), 2);
        assert!(set.matches("shared.test"));
        assert!(set.matches("deep.shared.test"));

        let full_only = compile(&["only.test"], &[], &[], &[]);
        assert!(!full_only.matches("deep.only.test"));

        let duplicated = compile(&["dup.test", "DUP.test"], &[], &[], &[]);
        assert_eq!(duplicated.matcher_count(), 2);
        assert_eq!(duplicated.pattern_bytes(), "dup.test".len());
    }

    #[test]
    fn keywords_match_anywhere_case_insensitively_including_empty() {
        let set = compile(&[], &[], &["Ample", "zz"], &[]);
        assert!(set.matches("EXAMPLE.com"));
        assert!(set.matches("sample"));
        assert!(set.matches("buzz.test"));
        assert!(!set.matches("other.test"));
        assert!(!set.matches(""));

        let empty_keyword = compile(&[], &[], &[""], &[]);
        assert!(empty_keyword.matches(""));
        assert!(empty_keyword.matches("anything"));
    }

    #[test]
    fn regexes_match_the_lowercased_name() {
        let set = compile(
            &[],
            &[],
            &[],
            &[r"^[^.]*local[^.]*$", r"^api\.[a-z]+\.test$"],
        );
        assert!(set.matches("MyLocalHost"));
        assert!(!set.matches("local.host"));
        assert!(set.matches("API.svc.test"));
        assert!(!set.matches("api.svc.test."));
    }

    #[test]
    fn dns_mode_trims_trailing_dots_from_full_and_suffix_patterns() {
        let matchers = matchers(&["dotted.test."], &["trailing.example."], &[], &[]);
        let routing = DomainMatcherSet::compile(&matchers, DomainNameMode::Routing).unwrap();
        let dns = DomainMatcherSet::compile(&matchers, DomainNameMode::Dns).unwrap();

        assert!(routing.matches("dotted.test."));
        assert!(!routing.matches("dotted.test"));
        assert!(routing.matches("a.trailing.example."));
        assert!(!routing.matches("a.trailing.example"));

        assert!(dns.matches("dotted.test"));
        assert!(!dns.matches("dotted.test."));
        assert!(dns.matches("a.trailing.example"));
        assert!(!dns.matches("a.trailing.example."));
        assert_eq!(dns.matcher_count(), 2);
    }

    #[test]
    fn regex_matchers_share_the_prevalidated_regex() {
        let matcher = RegexMatcher::new(r"^cdn[0-9]+\.example$").unwrap();
        let mut builder = DomainMatcherSet::builder();
        builder.insert(
            &DomainMatcher::Regex(matcher.clone()),
            DomainNameMode::Routing,
        );
        let set = builder.build().unwrap();
        assert_eq!(set.matcher_count(), 1);
        assert_eq!(set.pattern_bytes(), matcher.pattern().len());
        assert!(set.matches("CDN7.example"));
        assert!(!set.matches("cdn.example"));
    }

    #[test]
    fn equality_debug_and_pattern_bytes_cover_all_kinds() {
        let left = compile(&["a.test"], &["b.test"], &["kw"], &["^c$"]);
        let right = compile(&["A.TEST"], &["B.test"], &["KW"], &["^c$"]);
        assert_eq!(left, right);
        assert_ne!(left, compile(&["a.test"], &["b.test"], &["kw"], &["^d$"]));
        assert_ne!(left, compile(&["a.test"], &["b.test"], &[], &["^c$"]));
        assert_ne!(
            left,
            compile(&["a.test", "a.test"], &["b.test"], &["kw"], &["^c$"])
        );
        assert_eq!(left.pattern_bytes(), 6 + 6 + 2 + 3);
        assert_eq!(
            format!("{left:?}"),
            "DomainMatcherSet { full: 1, suffix: 1, keyword: 1, regex: 1, matcher_count: 4 }"
        );
        let cloned = left.clone();
        assert!(cloned.matches("x.b.test") && cloned.matches("c") && cloned.matches("akwz"));
    }

    #[test]
    fn geosite_sized_mix_stays_within_the_memory_budget() {
        let mut builder = DomainMatcherSet::builder();
        for index in 0..100_000 {
            builder.insert(
                &DomainMatcher::Suffix(format!("site-{index}.geosite-suffix.example")),
                DomainNameMode::Routing,
            );
        }
        for index in 0..20_000 {
            builder.insert(
                &DomainMatcher::Full(format!("host-{index}.geosite-full.example")),
                DomainNameMode::Routing,
            );
        }
        for index in 0..2_000 {
            builder.insert(
                &DomainMatcher::Keyword(format!("keyword-{index:04}")),
                DomainNameMode::Routing,
            );
        }
        for index in 0..200 {
            builder.insert(
                &DomainMatcher::Regex(
                    RegexMatcher::new(format!(r"^ad[0-9]*-{index}\.[a-z]+\.example$")).unwrap(),
                ),
                DomainNameMode::Routing,
            );
        }
        let set = builder.build().unwrap();
        assert_eq!(set.matcher_count(), 122_200);
        let inner = set.inner.as_deref().unwrap();

        let name_table_bytes = table_bytes(&inner.trie);
        let name_heap_bytes = heap_bytes(&inner.trie);
        let keyword_list_bytes = inner.keywords.capacity() * size_of::<Box<str>>()
            + inner
                .keywords
                .iter()
                .map(|keyword| keyword.len())
                .sum::<usize>();
        let automaton_bytes = inner
            .keyword_automaton
            .as_ref()
            .map_or(0, AhoCorasick::memory_usage);
        let regex_pattern_bytes = inner
            .regex
            .iter()
            .map(|regex| regex.as_str().len())
            .sum::<usize>();
        eprintln!(
            "names: tables {name_table_bytes} B + heap {name_heap_bytes} B; keywords: list {keyword_list_bytes} B + automaton {automaton_bytes} B; regex patterns {regex_pattern_bytes} B"
        );

        let flat_vec_name_bytes = 120_000 * 32 + name_heap_bytes;
        assert!(name_table_bytes + name_heap_bytes <= flat_vec_name_bytes);
        assert!(automaton_bytes <= 1024 * 1024);

        assert!(set.matches("www.site-77777.geosite-suffix.example"));
        assert!(set.matches("host-19999.geosite-full.example"));
        assert!(!set.matches("www.host-19999.geosite-full.example"));
        assert!(set.matches("cdn.keyword-1999.test"));
        assert!(set.matches("ad42-199.tracker.example"));
        assert!(!set.matches("clean.example"));
    }
}
