//! Single-line text field state: caret, select-all, secret (password) display.

#[derive(Clone, Default)]
pub struct TextField {
    pub text: String,
    /// Caret position in chars.
    pub caret: usize,
    /// Ctrl+A: the next edit replaces everything.
    pub all: bool,
    pub secret: bool,
}

impl TextField {
    #[cfg(test)]
    pub fn new(text: &str) -> Self {
        Self {
            text: text.into(),
            caret: text.chars().count(),
            all: false,
            secret: false,
        }
    }

    pub fn secret() -> Self {
        Self {
            secret: true,
            ..Default::default()
        }
    }

    pub fn set(&mut self, text: &str) {
        self.text = text.into();
        self.caret = text.chars().count();
        self.all = false;
    }

    /// What is drawn: bullets for secrets.
    pub fn display(&self) -> String {
        if self.secret {
            "•".repeat(self.text.chars().count())
        } else {
            self.text.clone()
        }
    }

    fn byte(&self, char_idx: usize) -> usize {
        self.text
            .char_indices()
            .nth(char_idx)
            .map_or(self.text.len(), |(b, _)| b)
    }

    fn take_all(&mut self) -> bool {
        if std::mem::take(&mut self.all) {
            self.text.clear();
            self.caret = 0;
            true
        } else {
            false
        }
    }

    pub fn insert(&mut self, s: &str) {
        self.take_all();
        let clean: String = s.chars().filter(|c| !c.is_control()).collect();
        let at = self.byte(self.caret);
        self.text.insert_str(at, &clean);
        self.caret += clean.chars().count();
    }

    pub fn backspace(&mut self) {
        if self.take_all() || self.caret == 0 {
            return;
        }
        let at = self.byte(self.caret - 1);
        self.text.remove(at);
        self.caret -= 1;
    }

    pub fn delete(&mut self) {
        if self.take_all() || self.caret >= self.text.chars().count() {
            return;
        }
        let at = self.byte(self.caret);
        self.text.remove(at);
    }

    pub fn left(&mut self) {
        self.all = false;
        self.caret = self.caret.saturating_sub(1);
    }

    pub fn right(&mut self) {
        self.all = false;
        self.caret = (self.caret + 1).min(self.text.chars().count());
    }

    pub fn home(&mut self) {
        self.all = false;
        self.caret = 0;
    }

    pub fn end(&mut self) {
        self.all = false;
        self.caret = self.text.chars().count();
    }

    pub fn select_all(&mut self) {
        self.all = !self.text.is_empty();
        self.caret = self.text.chars().count();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn editing_respects_multibyte_chars() {
        let mut f = TextField::new("aé");
        f.left();
        f.insert("ü");
        assert_eq!(f.text, "aüé");
        f.backspace();
        f.delete();
        assert_eq!(f.text, "a");
    }

    #[test]
    fn select_all_then_type_replaces() {
        let mut f = TextField::new("old");
        f.select_all();
        f.insert("new");
        assert_eq!(f.text, "new");
        f.select_all();
        f.backspace();
        assert!(f.text.is_empty());
    }

    #[test]
    fn secret_display_hides_text() {
        let mut f = TextField::secret();
        f.insert("hunter2");
        assert_eq!(f.display(), "•••••••");
    }
}
