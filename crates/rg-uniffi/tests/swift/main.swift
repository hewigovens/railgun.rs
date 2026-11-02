// Drives the generated bindings from Swift. Without RG_MNEMONIC_FILE it stays offline. With it, RG_RPC, RG_DATA, RG_FROM, RG_RECIPIENT and RG_TOKEN exercise a live client; nothing is sent.
import Foundation

func require(_ condition: Bool, _ message: String) {
  guard condition else {
    print("FAILED: \(message)")
    exit(1)
  }
}

let words = generateMnemonic()
require(words.split(separator: " ").count == 12, "mnemonic has 12 words")
let wallet = try Wallet.fromMnemonic(mnemonic: words, index: 0)
require(try wallet.address().hasPrefix("0zk"), "address is 0zk")

do {
  _ = try Wallet.fromMnemonic(mnemonic: "not a mnemonic", index: 0)
  require(false, "a bad mnemonic must throw")
} catch RailgunError.InvalidInput {
  print("bad mnemonic: InvalidInput")
}

let empty = NSTemporaryDirectory() + "rg-smoke-\(UUID().uuidString)"
do {
  _ = try RailgunClient.open(network: "mars", rpcUrl: "http://localhost:1", dataDir: empty)
  require(false, "an unknown network must throw")
} catch RailgunError.InvalidInput {
  print("unknown network: InvalidInput")
}
let offline = try RailgunClient.open(network: "arbitrum", rpcUrl: "http://localhost:1", dataDir: empty)
require(offline.balances(wallet: wallet).isEmpty, "a new wallet has no balance")
do {
  _ = try offline.sync()
  require(false, "sync with no node must throw")
} catch RailgunError.Network {
  print("no node: Network")
}

let env = ProcessInfo.processInfo.environment
guard let file = env["RG_MNEMONIC_FILE"] else {
  print("offline checks passed")
  exit(0)
}
let mnemonic = try String(contentsOfFile: file, encoding: .utf8).trimmingCharacters(in: .whitespacesAndNewlines)
let live = try Wallet.fromMnemonic(mnemonic: mnemonic, index: 0)
print("address: \(try live.address())")
let client = try RailgunClient.open(network: "arbitrum", rpcUrl: env["RG_RPC"]!, dataDir: env["RG_DATA"]!)
print("sync: \(try client.sync())")
let balances = client.balances(wallet: live)
print("balances: \(balances)")
require(!balances.isEmpty, "the test wallet has a balance")
do {
  _ = try client.buildTransfer(wallet: live, recipient: env["RG_RECIPIENT"]!, token: env["RG_TOKEN"]!, value: "999999999999999999999", memo: nil)
  require(false, "too large a transfer must throw")
} catch RailgunError.InsufficientFunds {
  print("too much: InsufficientFunds")
}
let tx = try client.buildTransfer(wallet: live, recipient: env["RG_RECIPIENT"]!, token: env["RG_TOKEN"]!, value: "1000000000000", memo: "from swift")
print("transfer: \(tx.data.count) bytes to \(tx.to) on chain \(tx.chainId)")
print("gas: \(try client.estimateGas(from: env["RG_FROM"]!, tx: tx))")
if let hash = env["RG_POI_TX"] {
  let proof = try client.provePoi(wallet: live, txHash: hash)
  print("poi valid: \(try client.poiIsValid(submission: proof))")
}
print("live checks passed")
