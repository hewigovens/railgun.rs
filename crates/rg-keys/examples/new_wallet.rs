//! Make a fresh test wallet: 12-word mnemonic from /dev/urandom, written to the
//! file given as the first argument (refuses to overwrite), and its 0zk address
//! (all chains, index 0) printed to stdout.

use std::io::Read;

use rg_keys::address::{encode_address, AddressData, ADDRESS_VERSION};
use rg_keys::keys::WalletKeys;

fn main() {
    let path = std::env::args()
        .nth(1)
        .expect("usage: new_wallet <mnemonic-file>");
    if std::path::Path::new(&path).exists() {
        panic!("{path} exists; not overwriting");
    }
    let mut entropy = [0u8; 16];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut entropy))
        .expect("read /dev/urandom");
    let mnemonic = bip39::Mnemonic::from_entropy(&entropy).expect("16 bytes");
    let words = mnemonic.to_string();
    let keys = WalletKeys::from_mnemonic(&words, "", 0).expect("valid mnemonic");
    let address = encode_address(&AddressData {
        master_public_key: keys.master_public_key,
        viewing_public_key: keys.viewing_public_key,
        chain: None,
        version: ADDRESS_VERSION,
    })
    .expect("encode");
    std::fs::write(&path, format!("{words}\n")).expect("write mnemonic");
    println!("{address}");
}
