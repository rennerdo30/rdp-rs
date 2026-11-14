//! Fuzzy matching for the command palette: the query's characters must
//! appear in the text in order (a subsequence), and the best alignment is
//! scored so that prefixes, word starts and consecutive runs win.
//!
//! Matching works on `char`s, never bytes, so any Unicode text is safe;
//! positions are char indices into the text (for highlighting).

/// A successful match: higher scores are better.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Match {
    pub score: i32,
    /// Char indices of the matched characters in the text, ascending.
    pub positions: Vec<usize>,
}

/// Every matched character.
const MATCH: i32 = 16;
/// The text's first character.
const FIRST: i32 = 24;
/// The start of a word (after a separator, or a lower-to-upper case step).
const WORD_START: i32 = 18;
/// Right after the previous matched character.
const CONSECUTIVE: i32 = 14;
/// The query character has exactly the text's case.
const SAME_CASE: i32 = 1;
/// A gap between two matched characters: opening it, and each further char.
const GAP_OPEN: i32 = 3;
const GAP_EXTEND: i32 = 1;
/// Each unmatched char before the first match (capped).
const LEADING: i32 = 1;
const LEADING_MAX: i32 = 12;

fn lower(c: char) -> char {
    c.to_lowercase().next().unwrap_or(c)
}

fn is_sep(c: char) -> bool {
    !c.is_alphanumeric()
}

/// Bonus for matching the text char at `j`.
fn position_bonus(text: &[char], j: usize) -> i32 {
    if j == 0 {
        return FIRST;
    }
    let (prev, cur) = (text[j - 1], text[j]);
    let start = (is_sep(prev) && !is_sep(cur))
        || (prev.is_lowercase() && cur.is_uppercase())
        || (prev.is_alphabetic() && cur.is_numeric())
        || (prev.is_numeric() && cur.is_alphabetic());
    if start { WORD_START } else { 0 }
}

/// Matches `query` against `text`. Whitespace in the query is ignored, so
/// "office ws" finds "Office workstation". An empty query matches
/// everything with score 0 and no positions.
pub fn fuzzy(query: &str, text: &str) -> Option<Match> {
    let q: Vec<char> = query.chars().filter(|c| !c.is_whitespace()).collect();
    if q.is_empty() {
        return Some(Match {
            score: 0,
            positions: Vec::new(),
        });
    }
    let t: Vec<char> = text.chars().collect();
    let (m, n) = (q.len(), t.len());
    if m > n {
        return None;
    }
    let ql: Vec<char> = q.iter().map(|&c| lower(c)).collect();
    let tl: Vec<char> = t.iter().map(|&c| lower(c)).collect();

    // Quick reject: is it a subsequence at all?
    let mut qi = 0;
    for &c in &tl {
        if qi < m && c == ql[qi] {
            qi += 1;
        }
    }
    if qi < m {
        return None;
    }

    const NONE: i32 = i32::MIN / 2;
    // score[i][j]: best score with query[i] matched at text[j];
    // back[i][j]: where query[i - 1] was matched on that best path.
    let mut score = vec![NONE; m * n];
    let mut back = vec![usize::MAX; m * n];
    let bonus: Vec<i32> = (0..n).map(|j| position_bonus(&t, j)).collect();
    for i in 0..m {
        // Best predecessor that leaves a gap before j: (score, index).
        let mut gap: (i32, usize) = (NONE, usize::MAX);
        for j in i..n {
            if i > 0 && j >= 2 {
                // Extend the running gap by one, or open one after j - 2.
                let k = j - 2;
                let open = score[(i - 1) * n + k];
                let extended = gap.0 - GAP_EXTEND;
                gap = if open > NONE && open - GAP_OPEN >= extended {
                    (open - GAP_OPEN, k)
                } else {
                    (extended, gap.1)
                };
            }
            if tl[j] != ql[i] {
                continue;
            }
            let here = MATCH + bonus[j] + if t[j] == q[i] { SAME_CASE } else { 0 };
            let (prev, from) = if i == 0 {
                let lead = (j as i32 * LEADING).min(LEADING_MAX);
                (-lead, usize::MAX)
            } else {
                let mut best = (NONE, usize::MAX);
                if j >= 1 {
                    let s = score[(i - 1) * n + j - 1];
                    if s > NONE {
                        // A run keeps the word-start bonus of its first char.
                        best = (s + CONSECUTIVE, j - 1);
                    }
                }
                if gap.1 != usize::MAX && gap.0 > best.0 {
                    best = gap;
                }
                best
            };
            if prev <= NONE {
                continue;
            }
            score[i * n + j] = prev + here;
            back[i * n + j] = from;
        }
    }
    let row = (m - 1) * n;
    let (mut j, mut best) = (usize::MAX, NONE);
    for k in 0..n {
        if score[row + k] > best {
            best = score[row + k];
            j = k;
        }
    }
    if j == usize::MAX {
        return None;
    }
    let mut positions = vec![0; m];
    for i in (0..m).rev() {
        positions[i] = j;
        j = back[i * n + j];
    }
    // Shorter texts win ties ("Excel" before "Excel (old)").
    let length = (n - m).min(40) as i32 / 4;
    Some(Match {
        score: best - length,
        positions,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn score(q: &str, t: &str) -> i32 {
        fuzzy(q, t).map_or(i32::MIN, |m| m.score)
    }

    /// The texts matching `q`, best first.
    fn rank<'a>(q: &str, texts: &[&'a str]) -> Vec<&'a str> {
        let mut v: Vec<(i32, &str)> = texts
            .iter()
            .filter_map(|t| fuzzy(q, t).map(|m| (m.score, *t)))
            .collect();
        v.sort_by_key(|x| std::cmp::Reverse(x.0));
        v.into_iter().map(|x| x.1).collect()
    }

    #[test]
    fn subsequence_or_nothing() {
        assert!(fuzzy("bsv", "Build server").is_some());
        assert!(fuzzy("svb", "Build server").is_none(), "order matters");
        assert!(fuzzy("buildx", "Build").is_none(), "longer than the text");
        assert!(fuzzy("z", "Office workstation").is_none());
    }

    #[test]
    fn empty_query_matches_everything_without_marks() {
        let m = fuzzy("", "Office workstation").unwrap();
        assert_eq!(m.score, 0);
        assert!(m.positions.is_empty());
        assert_eq!(fuzzy("   ", "x").unwrap().positions, Vec::<usize>::new());
    }

    #[test]
    fn positions_mark_word_starts_and_runs() {
        // "ow" takes the two word starts, not the "o" and "w" inside words.
        assert_eq!(fuzzy("ow", "Office workstation").unwrap().positions, [0, 7]);
        // A run in the middle of the text.
        assert_eq!(
            fuzzy("serv", "Build server").unwrap().positions,
            [6, 7, 8, 9]
        );
        // Spaces in the query are ignored.
        assert_eq!(
            fuzzy("test vm", "Test VM (Windows 11)").unwrap().positions,
            [0, 1, 2, 3, 5, 6]
        );
        // camelCase and digits count as word starts.
        assert_eq!(fuzzy("rd", "openRdpLog").unwrap().positions, [4, 5]);
        assert_eq!(fuzzy("b01", "build-01.lab").unwrap().positions, [0, 6, 7]);
        // A whole word start beats the text's first letter plus a stray one.
        assert_eq!(fuzzy("sa", "shared sales").unwrap().positions, [7, 8]);
    }

    #[test]
    fn realistic_names_rank_sensibly() {
        let names = [
            "Office workstation",
            "Office apps",
            "Build server",
            "Test VM (Windows 11)",
            "Disconnect",
            "Show panel",
            "Smart cards",
            "Sound",
        ];
        // A prefix beats letters scattered inside words.
        assert_eq!(
            rank("off", &names)[..2],
            ["Office apps", "Office workstation"]
        );
        // Word starts beat an inner letter run.
        assert_eq!(rank("ow", &names)[0], "Office workstation");
        assert_eq!(rank("sc", &names)[0], "Smart cards");
        assert_eq!(rank("bs", &names)[0], "Build server");
        // "vm" as a word beats v...m spread out.
        assert_eq!(rank("vm", &names)[0], "Test VM (Windows 11)");
        // "so": prefix "Sound" over "Show panel" (s...o gap) and "Disconnect".
        assert_eq!(rank("so", &names)[0], "Sound");
    }

    #[test]
    fn consecutive_beats_scattered() {
        assert!(score("serv", "Build server") > score("serv", "Smart cards everywhere v"));
        assert!(score("disc", "Disconnect") > score("disc", "Display scale"));
    }

    #[test]
    fn exact_case_breaks_ties_only() {
        assert!(score("VM", "Test VM") > score("vm", "Test VM"));
        assert!(score("vm", "Test VM") > score("vm", "Test vbox m"));
    }

    #[test]
    fn unicode_is_safe() {
        // Multi-byte text: positions are char indices.
        let m = fuzzy("zr", "Büro Zürich").unwrap();
        assert_eq!(m.positions, [5, 7]);
        assert!(fuzzy("ü", "Büro").is_some());
        assert!(fuzzy("Ü", "büro").is_some(), "case folds beyond ASCII");
        // Characters whose lower case is longer, and emoji, never panic.
        assert!(fuzzy("i", "İstanbul").is_some());
        assert!(fuzzy("🚀", "Launch 🚀 now").unwrap().positions == [7]);
        assert!(fuzzy("x", "日本語サーバー").is_none());
        assert_eq!(fuzzy("サバ", "日本語サーバー").unwrap().positions, [3, 5]);
    }
}
