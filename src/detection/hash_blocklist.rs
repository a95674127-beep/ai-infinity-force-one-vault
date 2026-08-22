use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs;

pub enum BlocklistVerdict {
    Match(String),
    Clean,
    Error(String),
}

pub struct HashBlocklist {
    known_bad: HashSet<String>,
}

impl HashBlocklist {
    pub fn load(path: &str) -> std::io::Result<Self> {
        let content = fs::read_to_string(path)?;
        let known_bad = content
            .lines()
            .map(|l| l.trim().to_lowercase())
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .collect();
        Ok(Self { known_bad })
    }

    pub fn scan_payload(&self, data: &[u8]) -> BlocklistVerdict {
        let mut hasher = Sha256::new();
        hasher.update(data);
        let hash = format!("{:x}", hasher.finalize());

        if self.known_bad.contains(&hash) {
            BlocklistVerdict::Match(hash)
        } else {
            BlocklistVerdict::Clean
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_known_hash() {
        let mut set = HashSet::new();
        let mut hasher = Sh
        }
    }
}
