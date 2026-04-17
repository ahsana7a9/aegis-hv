use std::collections::HashMap;

pub struct ThreatAnalyzer {
    /// Maps Agent Roles to their learned 'Normal' entropy (e.g., "Hornet-Scout" -> 4.2)
    pub role_baselines: HashMap<String, f64>,
}

impl ThreatAnalyzer {
    pub fn new() -> Self {
        let mut role_baselines = HashMap::new();
        // Default baseline for general intelligence tasks
        role_baselines.insert("default".to_string(), 4.5);
        Self { role_baselines }
    }

    /// Shannon Entropy Calculation (H)
    /// Detects if the agent is exfiltrating compressed or encrypted data.
    /// Range: 0.0 (Uniform/Low Info) to 8.0 (High Complexity/Encrypted)
    pub fn calculate_entropy(data: &[u8]) -> f64 {
        if data.is_empty() { return 0.0; }
        let mut counts = [0usize; 256];
        for &byte in data { counts[byte as usize] += 1; }
        
        counts.iter().filter(|&&c| c > 0).map(|&c| {
            let p = c as f64 / data.len() as f64;
            -p * p.log2()
        }).sum()
    }

    /// Adaptive Anomaly Detection
    /// Measures "Behavioral Drift" from the established baseline.
    pub fn assess_anomaly(&self, role: &str, current_entropy: f64) -> f64 {
        let baseline = self.role_baselines.get(role).unwrap_or(&4.5);
        let drift = (current_entropy - baseline).abs();
        
        // Critical Threshold: A drift > 1.5 suggests a transition from 
        // human-readable text to encrypted binary streams.
        (drift / 2.0).clamp(0.0, 1.0)
    }

    /// Intent Heuristics
    /// Scans the binary buffers for "Red Line" strings that indicate OS subversion.
    pub fn calculate_risk_score(data: &[u8]) -> f64 {
        let mut score = 0.0;
        let patterns = [
            (b"/etc/shadow", 0.95), // Direct credential theft attempt
            (b"/bin/sh", 0.85),     // Shell escape attempt
            (b"curl ", 0.60),       // Unauthorized external egress
            (b"base64", 0.50),     // Obfuscation technique
            (b"chmod", 0.70),      // Permission tampering
        ];

        for (pattern, risk) in patterns {
            if data.windows(pattern.len()).any(|w| w == *pattern) {
                score += risk;
            }
        }
        
        score.clamp(0.0, 1.0)
    }
}
