pub enum EntropyVerdict {
    Suspicious(f64),
    Normal(f64),
}

const SUSPICION_THRESHOLD: f64 = 7.2;

pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut counts = [0u32; 256];
    for &byte in data {
        counts[byte as usize] += 1;
    }

    let len = data.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

pub fn scan_payload(data: &[u8]) -> EntropyVerdict {
    let score = shannon_entropy(data);
    if score >= SUSPICION_THRESHOLD {
        EntropyVerdict::Suspicious(score)
    } else {
        EntropyVerdict::Normal(score)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn low_entropy_text_is_normal() {
        let data = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        matches!(scan_payload(data), EntropyVerdict::Normal(_));
    }

    #[test]
    fn random_bytes_are_suspicious() {
        let data: Vec<u8> = (0..=255).cycle().take(2048).collect();
        let score = shannon_entropy(&data);
        assert!(score > 7.0);
    }
}
