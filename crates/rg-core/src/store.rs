//! Durable chain data. Replaying it rebuilds [`rg_sync::SyncState`] in about two seconds for Arbitrum, so the store keeps inputs, not derived trees, and the mobile cost of a real database can wait until it is measured.

use std::fs;
use std::io::Write;
use std::path::PathBuf;

use rg_sync::RawLog;

use crate::Error;
use crate::pending_spends::Spend;

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
    /// Txid tree leaves past the reorg window, with the squid id of the last one.
    fn txid_leaves(&self) -> Result<(Vec<[u8; 32]>, Option<String>), Error>;
    fn append_txid_leaves(&mut self, leaves: &[(String, [u8; 32])]) -> Result<(), Error>;
    /// The notes of each batch handed to a broadcaster and not yet seen spent.
    fn pending_spends(&self) -> Result<Vec<Vec<Spend>>, Error>;
    fn save_pending_spends(&mut self, batches: &[Vec<Spend>]) -> Result<(), Error>;
}

/// One directory per network: `leaves.txt`, `logs.jsonl`, `cursor`, `txid-leaves.txt`, `pending-spends.txt`.
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
    fn lines(&self, name: &str) -> Result<Vec<String>, Error> {
        let text = self.read(name)?.unwrap_or_default();
        let end = text.rfind('\n').map_or(0, |i| i + 1);
        Ok(text[..end].lines().map(str::to_string).collect())
    }

    fn append(&self, name: &str, text: &str) -> Result<(), Error> {
        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.dir.join(name))?;
        file.write_all(text.as_bytes())?;
        Ok(())
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
        Ok(RawLog::parse_jsonl(&self.lines("logs.jsonl")?.join("\n"))?)
    }

    fn append_logs(&mut self, logs: &[RawLog]) -> Result<(), Error> {
        let mut text = String::new();
        for log in logs {
            text.push_str(&log.to_json().to_string());
            text.push('\n');
        }
        self.append("logs.jsonl", &text)
    }

    fn truncate_logs(&mut self, block: u64) -> Result<usize, Error> {
        let lines = self.lines("logs.jsonl")?;
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

    fn txid_leaves(&self) -> Result<(Vec<[u8; 32]>, Option<String>), Error> {
        let corrupt = || Error::Corrupt("txid leaves");
        let mut leaves = Vec::new();
        let mut last = None;
        for line in self.lines("txid-leaves.txt")? {
            let (id, leaf) = line.split_once(' ').ok_or_else(corrupt)?;
            let leaf = hex::decode(leaf).map_err(|_| corrupt())?;
            leaves.push(leaf.try_into().map_err(|_| corrupt())?);
            last = Some(id.to_string());
        }
        Ok((leaves, last))
    }

    fn append_txid_leaves(&mut self, leaves: &[(String, [u8; 32])]) -> Result<(), Error> {
        let mut text = String::new();
        for (id, leaf) in leaves {
            text.push_str(&format!("{id} {}\n", hex::encode(leaf)));
        }
        self.append("txid-leaves.txt", &text)
    }

    fn pending_spends(&self) -> Result<Vec<Vec<Spend>>, Error> {
        let corrupt = || Error::Corrupt("pending spends");
        let spend = |s: &str| {
            let (tree, nullifier) = s.split_once(':')?;
            let nullifier = hex::decode(nullifier).ok()?.try_into().ok()?;
            Some((tree.parse().ok()?, nullifier))
        };
        self.lines("pending-spends.txt")?
            .iter()
            .map(|line| line.split(' ').map(spend).collect::<Option<Vec<_>>>())
            .collect::<Option<_>>()
            .ok_or_else(corrupt)
    }

    fn save_pending_spends(&mut self, batches: &[Vec<Spend>]) -> Result<(), Error> {
        let mut text = String::new();
        for batch in batches {
            let spends: Vec<String> = batch
                .iter()
                .map(|(tree, n)| format!("{tree}:{}", hex::encode(n)))
                .collect();
            text.push_str(&spends.join(" "));
            text.push('\n');
        }
        self.replace("pending-spends.txt", &text)
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
    fn txid_leaves_resume_after_the_last_complete_line() {
        let mut s = store("txid");
        s.append_txid_leaves(&[("a".into(), [1; 32]), ("b".into(), [2; 32])])
            .unwrap();
        s.append("txid-leaves.txt", "c 03").unwrap();
        assert_eq!(
            s.txid_leaves().unwrap(),
            (vec![[1; 32], [2; 32]], Some("b".into()))
        );
    }

    #[test]
    fn missing_files_read_as_empty() {
        let s = store("empty");
        assert_eq!(s.cursor().unwrap(), None);
        assert_eq!(s.seed().unwrap(), None);
        assert!(s.logs().unwrap().is_empty());
    }
}
