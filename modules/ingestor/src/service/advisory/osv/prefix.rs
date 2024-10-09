use std::sync::OnceLock;

pub struct PrefixMatcher {
    prefixes: Vec<PrefixMapping>,
}

impl PrefixMatcher {
    fn new() -> Self {
        Self { prefixes: vec![] }
    }

    fn add(&mut self, prefix: impl Into<String>, name: impl Into<String>) {
        self.prefixes.push(PrefixMapping {
            prefix: prefix.into(),
            name: name.into(),
        })
    }

    pub fn detect(&self, input: &str) -> Option<String> {
        self.prefixes
            .iter()
            .find(|each| input.starts_with(&each.prefix))
            .map(|inner| inner.name.clone())
    }
}

struct PrefixMapping {
    prefix: String,
    name: String,
}

pub fn get_well_known_prefixes() -> &'static PrefixMatcher {
    WELL_KNOWN_PREFIXES.get_or_init(|| {
        let mut matcher = PrefixMatcher::new();

        matcher.add(
            "https://rustsec.org/advisories/RUSTSEC",
            "Rust Security Advisory Database",
        );

        matcher
    })
}

static WELL_KNOWN_PREFIXES: OnceLock<PrefixMatcher> = OnceLock::new();
