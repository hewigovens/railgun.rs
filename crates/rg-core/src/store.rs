//! Durable chain data. Replaying it rebuilds [`rg_sync::SyncState`] in about
//! two seconds for Arbitrum, so the store keeps inputs, not derived trees, and
//! the mobile cost of a real database can wait until it is measured.

use std::fs;
use std::io::Write;
use std::path::PathBuf;

use rg_sync::RawLog;

use crate::Error;

pub trait ChainStore {
    /// Leaf hashes from the indexer, in `seed_from_text` form.
    fn seed(&self) -> Result<Option<String>, Error>;
    fn save_seed(&mut self, text: &str) -> Result<(), Error>;
    /// The next block to fetch logs from.
    fn cursor(&self) -> Result<Option<u64>, Error>;
    fn set_cursor(&mut self, block: u64) -> Result<(), Error>;
    fn logs(&self) -> Result<Vec<RawLog>, Error>;
    fn append_logs(&mut self, logs: &[RawLog]) -> Result<(), Error>;
    /// Drops logs at or after `block`. Returns how many went.
    fn truncate_logs(&mut self, block: u64) -> Result<usize, Error>;
}

/// One directory per network: `leaves.txt`, `logs.jsonl`, `cursor`.
pub struct FileStore {
    dir: PathBuf,
}

impl FileStore {
    pub fn open(dir: impl Into<PathBuf>) -> Result<Self, Error> {
        let dir = dir.into();
        fs::create_dir_all(&dir)?;
        Ok(FileStore { dir })
    }

    fn read(&self, name: &str) -> Result<Option<String>, Error> {
        match fs::read_to_string(self.dir.join(name)) {
            Ok(text) => Ok(Some(text)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Whole-file replacement that a crash cannot leave half written.
    fn replace(&self, name: &str, text: &str) -> Result<(), Error> {
        let tmp = self.dir.join(format!("{name}.tmp"));
        fs::write(&tmp, text)?;
        fs::rename(tmp, self.dir.join(name))?;
        Ok(())
    }

    /// Complete lines only: a crash during an append can leave a partial one.
    fn log_lines(&self) -> Result<Vec<String>, Error> {
        let text = self.read("logs.jsonl")?.unwrap_or_default();
        let end = text.rfind('\n').map_or(0, |i| i + 1);
        Ok(text[..end].lines().map(str::to_string).collect())
    }
}

impl ChainStore for FileStore {
    fn seed(&self) -> Result<Option<String>, Error> {
        self.read("leaves.txt")
    }

    fn save_seed(&mut self, text: &str) -> Result<(), Error> {
        self.replace("leaves.txt", text)
    }

    fn cursor(&self) -> Result<Option<u64>, Error> {
        self.read("cursor")?
            .map(|s| s.trim().parse().map_err(|_| Error::Corrupt("cursor")))
            .transpose()
    }

    fn set_cursor(&mut self, block: u64) -> Result<(), Error> {
        self.replace("cursor", &block.to_string())
    }

    fn logs(&self) -> Result<Vec<RawLog>, Error> {
        Ok(RawLog::parse_jsonl(&self.log_lines()?.join("\n"))?)
    }

    fn append_logs(&mut self, logs: &[RawLog]) -> Result<(), Error> {
        let mut text = String::new();
        for log in logs {
            text.push_str(&log.to_json().to_string());
            text.push('\n');
        }
        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.dir.join("logs.jsonl"))?;
        file.write_all(text.as_bytes())?;
        Ok(())
    }

    fn truncate_logs(&mut self, block: u64) -> Result<usize, Error> {
        let lines = self.log_lines()?;
        let logs = RawLog::parse_jsonl(&lines.join("\n"))?;
        let mut kept = String::new();
        let mut dropped = 0;
        for (line, log) in lines.iter().zip(&logs) {
            if log.block_number < block {
                kept.push_str(line);
                kept.push('\n');
            } else {
                dropped += 1;
            }
        }
        // Also rewrites away any partial last line.
        self.replace("logs.jsonl", &kept)?;
        Ok(dropped)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store(name: &str) -> FileStore {
        let dir = std::env::temp_dir().join(format!("rg-core-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        FileStore::open(dir).unwrap()
    }

    fn log(block: u64) -> RawLog {
        RawLog {
            address: [1; 20],
            topics: vec![[2; 32]],
            data: vec![3],
            block_number: block,
            transaction_hash: [4; 32],
            log_index: 0,
        }
    }

    #[test]
    fn logs_round_trip_and_truncate_from_a_block() {
        let mut s = store("truncate");
        s.append_logs(&[log(1), log(2), log(3)]).unwrap();
        assert_eq!(s.logs().unwrap(), vec![log(1), log(2), log(3)]);
        assert_eq!(s.truncate_logs(2).unwrap(), 2);
        assert_eq!(s.logs().unwrap(), vec![log(1)]);
    }

    #[test]
    fn a_partial_last_line_from_a_crash_is_ignored_and_removed() {
        let mut s = store("partial");
        s.append_logs(&[log(1)]).unwrap();
        let mut f = fs::OpenOptions::new()
            .append(true)
            .open(s.dir.join("logs.jsonl"))
            .unwrap();
        f.write_all(b"{\"address\":\"0x01").unwrap();
        assert_eq!(s.logs().unwrap(), vec![log(1)]);
        assert_eq!(s.truncate_logs(5).unwrap(), 0);
        s.append_logs(&[log(6)]).unwrap();
        assert_eq!(s.logs().unwrap(), vec![log(1), log(6)]);
    }

    #[test]
    fn missing_files_read_as_empty() {
        let s = store("empty");
        assert_eq!(s.cursor().unwrap(), None);
        assert_eq!(s.seed().unwrap(), None);
        assert!(s.logs().unwrap().is_empty());
    }
}
