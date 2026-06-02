use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use uuid::Uuid;

pub const DEFAULT_MAX_RESULTS: usize = 20;

#[derive(Debug, Clone)]
pub struct SearchHit {
    pub id: Uuid,
    /// Higher is better. Sum of per-term scores weighted by IDF.
    pub score: f32,
    pub matched_terms: Vec<String>,
}

/// Trigram-based fuzzy inverted index.
///
/// Three structures work together:
///   inverted    — exact token → record IDs (the posting list)
///   trigrams    — 3-char gram → token strings (candidate lookup; append-only)
///   rec_tokens  — record ID → tokens it owns (fast O(k) deletion)
///
/// Search: query tokens → trigram lookup → candidate tokens → Levenshtein filter
///         → merge posting lists → IDF-weighted score → rank → truncate
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct SearchIndex {
    inverted: HashMap<String, HashSet<Uuid>>,
    trigrams: HashMap<String, HashSet<String>>,
    rec_tokens: HashMap<Uuid, HashSet<String>>,
    /// Total number of indexed records (for IDF denominator).
    doc_count: usize,
}

impl SearchIndex {
    pub fn index_record(&mut self, id: Uuid, text: &str) {
        let tokens = tokenize(text);
        let mut owned: HashSet<String> = HashSet::new();
        for token in tokens {
            self.inverted.entry(token.clone()).or_default().insert(id);
            for tg in trigrams_of(&token) {
                self.trigrams.entry(tg).or_default().insert(token.clone());
            }
            owned.insert(token);
        }
        self.rec_tokens.insert(id, owned);
        self.doc_count += 1;
    }

    pub fn remove_record(&mut self, id: &Uuid) {
        if let Some(tokens) = self.rec_tokens.remove(id) {
            for token in &tokens {
                if let Some(ids) = self.inverted.get_mut(token) {
                    ids.remove(id);
                    if ids.is_empty() {
                        self.inverted.remove(token);
                    }
                }
            }
            if self.doc_count > 0 {
                self.doc_count -= 1;
            }
        }
        // trigrams are append-only — empty inverted entries are skipped at query time
    }

    /// Fuzzy search. Returns hits sorted by descending score.
    ///
    /// Multi-word queries use AND semantics: all terms must match at least one token
    /// in the record (with fuzzy tolerance). Single-word queries return ranked results.
    pub fn search(&self, query: &str, max_results: usize) -> Vec<SearchHit> {
        let query_tokens = tokenize(query);
        if query_tokens.is_empty() {
            return Vec::new();
        }

        // per-term candidate match: record_id → (score contribution, matched_query_term)
        let mut record_scores: HashMap<Uuid, f32> = HashMap::new();
        // track which query terms each record matched (for AND filter)
        let mut term_hits: HashMap<Uuid, HashSet<usize>> = HashMap::new();

        for (qi, qtoken) in query_tokens.iter().enumerate() {
            let max_dist = fuzzy_distance(qtoken.len());
            let idf = self.idf(qtoken, max_dist);

            for (token, dist) in self.candidates(qtoken, max_dist) {
                let tf_score = token_score(dist) * idf;
                if let Some(ids) = self.inverted.get(&token) {
                    for &id in ids {
                        *record_scores.entry(id).or_default() += tf_score;
                        term_hits.entry(id).or_default().insert(qi);
                    }
                }
            }
        }

        let n_terms = query_tokens.len();

        let mut hits: Vec<SearchHit> = record_scores
            .into_iter()
            .filter(|(id, _)| {
                // AND: every query term must be satisfied by at least one matched token
                term_hits.get(id).map_or(false, |qs| qs.len() == n_terms)
            })
            .map(|(id, score)| {
                let matched_terms: Vec<String> = term_hits
                    .get(&id)
                    .map(|qs| qs.iter().map(|&i| query_tokens[i].clone()).collect())
                    .unwrap_or_default();
                SearchHit { id, score, matched_terms }
            })
            .collect();

        hits.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal));
        hits.truncate(max_results);
        hits
    }

    /// Collect all indexed tokens within `max_dist` of `query_token` using the trigram index.
    /// Returns (token, edit_distance) pairs.
    fn candidates(&self, query_token: &str, max_dist: usize) -> Vec<(String, usize)> {
        let qgrams: HashSet<String> = trigrams_of(query_token).into_iter().collect();

        let mut seen: HashSet<&String> = HashSet::new();
        let mut out: Vec<(String, usize)> = Vec::new();

        for tg in &qgrams {
            if let Some(tokens) = self.trigrams.get(tg) {
                for token in tokens {
                    if seen.insert(token) {
                        // Early length filter before paying for Levenshtein
                        let len_diff = (token.len() as isize - query_token.len() as isize).unsigned_abs();
                        if len_diff > max_dist {
                            continue;
                        }
                        let dist = levenshtein(query_token, token);
                        if dist <= max_dist && self.inverted.contains_key(token) {
                            out.push((token.clone(), dist));
                        }
                    }
                }
            }
        }

        // Ensure exact match is always included even with no shared trigrams
        if self.inverted.contains_key(query_token) && !out.iter().any(|(t, _)| t == query_token) {
            out.push((query_token.to_string(), 0));
        }

        out
    }

    /// Inverse document frequency for a query token (log-dampened).
    /// Rare tokens get higher weight; falls back gracefully for unknown terms.
    fn idf(&self, query_token: &str, max_dist: usize) -> f32 {
        let df = self
            .candidates(query_token, max_dist)
            .iter()
            .filter_map(|(t, _)| self.inverted.get(t))
            .map(|ids| ids.len())
            .sum::<usize>()
            .max(1);
        let n = self.doc_count.max(1) as f32;
        ((n / df as f32) + 1.0).ln() + 1.0
    }

    pub fn stats(&self) -> (usize, usize, usize) {
        (self.inverted.len(), self.trigrams.len(), self.doc_count)
    }
}

// ── Token scoring ──────────────────────────────────────────────────────────

fn fuzzy_distance(len: usize) -> usize {
    match len {
        0..=4 => 0,
        5..=8 => 1,
        _ => 2,
    }
}

fn token_score(edit_dist: usize) -> f32 {
    match edit_dist {
        0 => 1.0,
        1 => 0.7,
        _ => 0.4,
    }
}

// ── Text processing ────────────────────────────────────────────────────────

fn tokenize(text: &str) -> Vec<String> {
    text.split(|c: char| !c.is_alphanumeric())
        .filter(|t| t.len() >= 2)
        .map(|t| t.to_lowercase())
        .collect()
}

/// Padded trigrams: " hello " → [" he", "hel", "ell", "llo", "lo "]
fn trigrams_of(token: &str) -> Vec<String> {
    let padded = format!(" {} ", token);
    let chars: Vec<char> = padded.chars().collect();
    chars.windows(3).map(|w| w.iter().collect()).collect()
}

// ── Levenshtein distance ───────────────────────────────────────────────────

/// Space-optimized Levenshtein. Bails early if delta > 2 (max fuzzy distance).
fn levenshtein(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let (n, m) = (a.len(), b.len());

    if n == 0 { return m; }
    if m == 0 { return n; }
    // Length difference already guarantees distance ≥ diff; bail early.
    if (n as isize - m as isize).unsigned_abs() > 2 {
        return 3;
    }

    let mut prev: Vec<usize> = (0..=m).collect();
    let mut curr = vec![0usize; m + 1];

    for i in 1..=n {
        curr[0] = i;
        let mut row_min = i;
        for j in 1..=m {
            curr[j] = if a[i - 1] == b[j - 1] {
                prev[j - 1]
            } else {
                1 + prev[j - 1].min(prev[j]).min(curr[j - 1])
            };
            row_min = row_min.min(curr[j]);
        }
        // If entire row is already > 2, this pair can't match.
        if row_min > 2 {
            return 3;
        }
        std::mem::swap(&mut prev, &mut curr);
    }
    prev[m]
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn idx_with(records: &[(&str, &str)]) -> (SearchIndex, Vec<Uuid>) {
        let mut idx = SearchIndex::default();
        let ids: Vec<Uuid> = records
            .iter()
            .map(|(_, text)| {
                let id = Uuid::new_v4();
                idx.index_record(id, text);
                id
            })
            .collect();
        (idx, ids)
    }

    #[test]
    fn exact_search() {
        let (idx, ids) = idx_with(&[("a", "buy groceries today"), ("b", "read the rust book")]);
        let r = idx.search("groceries", 10);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].id, ids[0]);
    }

    #[test]
    fn fuzzy_typo() {
        let (idx, ids) = idx_with(&[("a", "buy groceries"), ("b", "unrelated content")]);
        // "grocereis" is 2 edits from "groceries" (same length, 2 substitutions)
        let r = idx.search("grocereis", 10);
        assert!(!r.is_empty(), "expected fuzzy match for 'grocereis' → 'groceries'");
        assert_eq!(r[0].id, ids[0]);
    }

    #[test]
    fn multi_word_and_semantics() {
        let (idx, ids) = idx_with(&[
            ("a", "read the rust book"),
            ("b", "rust programming language"),
            ("c", "book recommendations"),
        ]);
        // both "rust" and "book" → only record a
        let r = idx.search("rust book", 10);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].id, ids[0]);
    }

    #[test]
    fn remove_cleans_up() {
        let mut idx = SearchIndex::default();
        let id = Uuid::new_v4();
        idx.index_record(id, "hello world");
        idx.remove_record(&id);
        assert!(idx.search("hello", 10).is_empty());
        assert_eq!(idx.stats().0, 0); // inverted index empty
    }

    #[test]
    fn idf_ranks_rare_first() {
        let mut idx = SearchIndex::default();
        // "special" appears in 1 doc; "common" appears in 4
        let rare = Uuid::new_v4();
        idx.index_record(rare, "special common topic");
        for _ in 0..4 {
            idx.index_record(Uuid::new_v4(), "common topic here");
        }
        // Searching "special" → only the rare doc matches
        let r = idx.search("special", 10);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].id, rare);

        // Searching "common" → multiple docs; rare doc included and scored
        let r2 = idx.search("common", 10);
        assert_eq!(r2.len(), 5);

        // Searching "special common" (AND) → only rare doc has both
        let r3 = idx.search("special common", 10);
        assert_eq!(r3.len(), 1);
        assert_eq!(r3[0].id, rare);
    }

    #[test]
    fn levenshtein_correctness() {
        assert_eq!(levenshtein("kitten", "sitting"), 3);
        assert_eq!(levenshtein("rust", "rust"), 0);
        assert_eq!(levenshtein("book", "boo"), 1);
        assert_eq!(levenshtein("", "abc"), 3);
    }
}
