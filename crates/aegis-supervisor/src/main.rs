use std::env;

fn load_master_key() -> [u8; 32] {
    let key_hex = env::var("AEGIS_REGISTRY_KEY")
        .expect("AEGIS_REGISTRY_KEY not set");

    let bytes = hex::decode(key_hex)
        .expect("Invalid hex key");

    bytes.try_into().expect("Key must be 32 bytes")
}
