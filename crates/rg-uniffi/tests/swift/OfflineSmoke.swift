import Foundation

struct OfflineSmoke {
    func run() throws {
        let words = generateMnemonic()
        Check.that(words.split(separator: " ").count == 12, "mnemonic has 12 words")
        let wallet = try Wallet.fromMnemonic(mnemonic: words, index: 0)
        try Check.that(wallet.address().hasPrefix("0zk"), "address is 0zk")

        try Check.raises(RailgunError.self, where: \.isInvalidInput, "bad mnemonic") {
            try Wallet.fromMnemonic(mnemonic: "not a mnemonic", index: 0)
        }

        let dataDir = NSTemporaryDirectory() + "rg-smoke-\(UUID().uuidString)"
        try Check.raises(RailgunError.self, where: \.isInvalidInput, "unknown network") {
            try RailgunClient.open(network: "mars", rpcUrl: "http://localhost:1", dataDir: dataDir)
        }

        let client = try RailgunClient.open(network: "arbitrum", rpcUrl: "http://localhost:1", dataDir: dataDir)
        Check.that(client.balances(wallet: wallet).isEmpty, "a new wallet has no balance")
        try Check.raises(RailgunError.self, where: \.isNetwork, "no node") {
            try client.sync()
        }
        print("offline checks passed")
    }
}
