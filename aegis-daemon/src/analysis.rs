use aegis_common::Severity;

pub struct ThreatAnalyzer;

impl ThreatAnalyzer {
    /// Calculates Shannon Entropy (0.0 to 8.0).
    /// ~4.5 is typical text/code. ~7.5+ is likely encrypted exfiltration.
    pub fn calculate_entropy(data: &[u8]) -> f64 {
        if data.is_empty() {
            return 0.0;
        }
        
        let mut counts = [0usize; 256];
        for &byte in data {
            counts[byte as usize] += 1;
        }
        
        counts.iter()
            .filter(|&&c| c > 0)
            .map(|&c| {
                let p = c as f64 / data.len() as f64;
                -p * p.log2()
            })
            .sum()
    }

    /// Evaluates a data packet and returns a recommended Severity
    pub fn assess_risk(data: &[u8]) -> Severity {
        let entropy = Self::calculate_entropy(data);
        
        // Thresholds based on 2026 exfiltration patterns
        if entropy > 7.8 {
            Severity::Critical // Almost certainly encrypted data or binary exfiltration
        } else if entropy > 7.0 {
            Severity::High     // Highly compressed or suspicious pattern
        } else if entropy > 5.5 {
            Severity::Medium   // Unusually high for standard JSON/Text
        } else {
            Severity::Low      // Normal traffic
        }
    }
}
