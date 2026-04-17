// Binary Integrity Verification Implementation

use std::fs;
use std::io::{self, Read};
use sha2::{Sha256, Digest};

/// Function to verify the integrity of a binary file using SHA-256 hashing.
/// Returns true if the hash of the file matches the expected hash.
fn verify_binary_integrity(file_path: &str, expected_hash: &str) -> io::Result<bool> {
    // Read the binary file
    let mut file = fs::File::open(file_path)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;

    // Compute the SHA-256 hash of the binary file
    let mut hasher = Sha256::new();
    hasher.update(&buffer);
    let result = hasher.finalize();

    // Convert hash result to hex string
    let computed_hash = format!("{:x}", result);

    // Compare computed hash with the expected hash
    Ok(computed_hash == expected_hash)
}

// Example usage (you can remove this in the final implementation):
// fn main() {
//     let file_path = "path/to/your/binary/file";
//     let expected_hash = "expected_hash_here";
//     match verify_binary_integrity(file_path, expected_hash) {
//         Ok(is_valid) => println!("Binary integrity valid: {}", is_valid),
//         Err(e) => eprintln!("Error: {}", e),
//     }
// }