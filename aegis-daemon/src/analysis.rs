use std::collections::HashMap;

pub struct ThreatAnalyzer {
    // Stores the 'Normal' entropy baseline for specific agent roles
    pub role_baselines: HashMap<String, f64>,
}

impl ThreatAnalyzer {
    pub fn new() -> Self {
        Self {
            role_baselines: HashMap::new(),
        }
    }

    /// Shannon Entropy: Detects encrypted data or packed payloads (0.0 to 8.0)
    pub fn calculate_entropy(data: &[u8]) -> f64 {
        if data.is_empty() { return 0.0; }
        let mut counts = [0usize; 256];
        for &byte in data { counts[byte as usize] += 1; }
        
        counts.iter().filter(|&&c| c > 0).map(|&c| {
            let p = c as f64 / data.len() as f64;
            -p * p.log2()
        }).sum()
    }

    /// Adaptive Anomaly Detection: Compares current entropy against a role's baseline.
    /// If the deviation is too high, it signals a potential behavioral drift.
    pub fn assess_anomaly(&self, role: &str, current_entropy: f64) -> f64 {
        if let Some(&baseline) = self.role_baselines.get(role) {
            let drift = (current_entropy - baseline).abs();
            // A drift > 1.5 in entropy usually indicates a shift from text to encrypted/binary data
            return (drift / 2.0).clamp(0.0, 1.0);
        }
        0.0 // No baseline yet, assume safe
    }

    /// Intent Heuristics: Scans raw buffers for unauthorized command patterns.
    pub fn calculate_risk_score(data: &[u8]) -> f64 {
        let mut score = 0.0;
        let patterns = [
            (b"/etc/shadow", 0.9),
            (b"/bin/sh", 0.8),
            (b"curl ", 0.5),
            (b"base64", 0.4),
        ];

        for (pattern, risk) in patterns {
            if data.windows(pattern.len()).any(|w| w == *pattern) {
                score += risk;
            }
        }
        
        score.clamp(0.0, 1.0)
    }
}
