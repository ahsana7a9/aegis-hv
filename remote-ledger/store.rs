use anyhow::{Result, anyhow};
use rusqlite::{Connection, params};

pub struct LedgerStore {
    conn: Connection,
}

impl LedgerStore {
    pub fn new(path: &str) -> Result<Self> {
        let conn = Connection::open(path)?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS ledger (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                data TEXT NOT NULL
            )",
            [],
        )?;

        Ok(Self { conn })
    }

    pub fn append(&self, data: serde_json::Value) -> Result<()> {

        // 🚨 STRICT APPEND ONLY (no overwrite)
        self.conn.execute(
            "INSERT INTO ledger (data) VALUES (?1)",
            params![data.to_string()],
        )?;

        Ok(())
    }
}
