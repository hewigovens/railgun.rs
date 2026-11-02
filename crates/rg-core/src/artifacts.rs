//! Circuit artifacts: downloaded when first needed and checked by hash every time they load. They are not redistributed here (see scope.md), only their hashes, from the wallet SDK's `artifact-v2-hashes.json` (MIT).

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;

use sha2::{Digest, Sha256};

use crate::Error;

const GATEWAY: &str = "https://ipfs-lb.com/ipfs";
const TRANSACT_ROOT: &str = "QmUsmnK4PFc7zDp2cmC4wBZxYLjNyRgWfs5GNcJJ2uLcpU";
/// Newer than the engine's: the live aggregator rejects proofs from older keys.
const POI_ROOT: &str = "QmZ2MyM6TKxffkv6stuo2hFwmUfs3q4xgMYN164Sje8new";
const HASHES: &str = include_str!("artifact-v2-hashes.json");
const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(600);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Circuit {
    Transact {
        inputs: usize,
        outputs: usize,
    },
    /// n inputs and n outputs: 3 or 13.
    Poi(usize),
}

impl Circuit {
    /// The name in the hash list and on disk.
    fn variant(&self) -> String {
        match self {
            Circuit::Transact { inputs, outputs } => format!("{inputs:02}x{outputs:02}"),
            Circuit::Poi(n) => format!("POI_{n}x{n}"),
        }
    }

    fn remote_name(&self) -> String {
        match self {
            Circuit::Transact { inputs, outputs } => format!("{inputs:02}x{outputs:02}"),
            Circuit::Poi(n) => format!("{n:02}x{n:02}"),
        }
    }

    fn url(&self, kind: Kind) -> String {
        let root = match self {
            Circuit::Transact { .. } => TRANSACT_ROOT,
            Circuit::Poi(_) => POI_ROOT,
        };
        let name = self.remote_name();
        match kind {
            Kind::Zkey => format!("{GATEWAY}/{root}/circuits/{name}/zkey.br"),
            Kind::Wasm => format!("{GATEWAY}/{root}/prover/snarkjs/{name}.wasm.br"),
        }
    }

    fn expected_hash(&self, kind: Kind) -> Result<String, Error> {
        let hashes: serde_json::Value = serde_json::from_str(HASHES).expect("bundled json");
        hashes[self.variant()][kind.name()]
            .as_str()
            .map(str::to_string)
            .ok_or_else(|| Error::UnknownCircuit(self.variant()))
    }
}

#[derive(Clone, Copy, Debug)]
enum Kind {
    Zkey,
    Wasm,
}

impl Kind {
    fn name(self) -> &'static str {
        match self {
            Kind::Zkey => "zkey",
            Kind::Wasm => "wasm",
        }
    }
}

fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

/// The file's bytes, if it exists and has the expected hash.
fn stored(path: &Path, expected: &str) -> Result<Option<Vec<u8>>, Error> {
    match fs::read(path) {
        Ok(data) => Ok((sha256_hex(&data) == expected).then_some(data)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// Witness wasm and proving key of one circuit.
pub(crate) struct Loaded {
    pub wasm: Vec<u8>,
    pub zkey: Vec<u8>,
}

/// A directory of artifacts, one subdirectory per circuit.
pub struct Artifacts {
    dir: PathBuf,
}

impl Artifacts {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Artifacts { dir: dir.into() }
    }

    fn fetch(&self, circuit: Circuit, kind: Kind) -> Result<Vec<u8>, Error> {
        let expected = circuit.expected_hash(kind)?;
        let dir = self.dir.join(circuit.variant());
        let path = dir.join(kind.name());
        if let Some(data) = stored(&path, &expected)? {
            return Ok(data);
        }

        let url = circuit.url(kind);
        let download = |e: reqwest::Error| Error::Download(url.clone(), e.to_string());
        let compressed = reqwest::blocking::Client::builder()
            .timeout(DOWNLOAD_TIMEOUT)
            .build()
            .map_err(download)?
            .get(&url)
            .send()
            .and_then(reqwest::blocking::Response::error_for_status)
            .and_then(|r| r.bytes())
            .map_err(download)?;
        let mut data = Vec::new();
        brotli::Decompressor::new(compressed.as_ref(), 4096).read_to_end(&mut data)?;
        if sha256_hex(&data) != expected {
            return Err(Error::ArtifactHash(url));
        }

        fs::create_dir_all(&dir)?;
        let tmp = dir.join(format!("{}.tmp", kind.name()));
        fs::write(&tmp, &data)?;
        fs::rename(tmp, path)?;
        Ok(data)
    }

    pub(crate) fn load(&self, circuit: Circuit) -> Result<Loaded, Error> {
        Ok(Loaded {
            wasm: self.fetch(circuit, Kind::Wasm)?,
            zkey: self.fetch(circuit, Kind::Zkey)?,
        })
    }

    /// Fetches a circuit ahead of time, so the first proof is not the slow one.
    pub fn prepare(&self, circuit: Circuit) -> Result<(), Error> {
        self.load(circuit).map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashes_cover_exactly_the_circuits_rg_tx_accepts() {
        for inputs in 1..=14 {
            for outputs in 1..=14 {
                let circuit = Circuit::Transact { inputs, outputs };
                let hashed = circuit.expected_hash(Kind::Zkey).is_ok();
                assert_eq!(
                    hashed,
                    rg_tx::circuit_exists(inputs, outputs),
                    "{inputs}x{outputs}"
                );
            }
        }
        for n in [rg_poi::MINI_CIRCUIT, rg_poi::FULL_CIRCUIT] {
            Circuit::Poi(n).expected_hash(Kind::Zkey).unwrap();
        }
    }

    #[test]
    fn only_a_file_with_the_right_hash_is_used() {
        let path = std::env::temp_dir().join(format!("rg-core-art-{}", std::process::id()));
        fs::write(&path, b"tampered").unwrap();
        let right = sha256_hex(b"tampered");
        assert_eq!(stored(&path, &right).unwrap().unwrap(), b"tampered");
        assert_eq!(stored(&path, &sha256_hex(b"original")).unwrap(), None);
        fs::remove_file(&path).unwrap();
        assert_eq!(stored(&path, &right).unwrap(), None);
    }
}
