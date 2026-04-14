pub struct ThreatAnalyzer;

impl ThreatAnalyzer {
    /// Calculates Shannon Entropy (0.0 to 8.0).
    /// ~4.5 is typical text/code. ~7.5+ is likely encrypted exfiltration.
    pub fn calculate_entropy(data: &[u8]) -> f64 {
        if data.is_empty() { return 0.0; }
        let mut counts = [0usize; 256];
        for &byte in data { counts[byte as usize] += 1; }
        
        counts.iter().filter(|&&c| c > 0).map(|&c| {
            let p = c as f64 / data.len() as f64;
            -p * p.log2()
        }).sum()
    }

    /// Evaluates a data packet and returns a recommended Severity
    pub fn assess_risk(data: &[u8]) -> aegis_common::Severity {
        let entropy = Self::calculate_entropy(data);
        
        if entropy > 7.8 {
            aegis_common::Severity::Critical // Almost certainly encrypted data
        } else if entropy > 7.0 {
            aegis_common::Severity::High     // Highly compressed or suspicious
        } else {
            aegis_common::Severity::Low      // Normal traffic (text/JSON)
        }
    }
}
