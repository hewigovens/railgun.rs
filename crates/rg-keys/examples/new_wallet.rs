//! Make a fresh test wallet: writes a 12-word mnemonic to the file given as the first argument (refuses to overwrite) and prints its 0zk address.

use rg_keys::{WalletKeys, generate_mnemonic};

fn main() {
    let path = std::env::args()
        .nth(1)
        .expect("usage: new_wallet <mnemonic-file>");
    if std::path::Path::new(&path).exists() {
        panic!("{path} exists; not overwriting");
    }
    let words = generate_mnemonic();
    let keys = WalletKeys::from_mnemonic(&words, "", 0).expect("valid mnemonic");
    std::fs::write(&path, format!("{words}\n")).expect("write mnemonic");
    println!("{}", keys.address().expect("encode"));
}
