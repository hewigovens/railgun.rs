import Foundation

struct OfflineSmoke {
    func run() throws {
        var words = generateMnemonic()
        Check.that(String(bytes: words, encoding: .utf8)?.split(separator: " ").count == 12, "mnemonic has 12 words")
        let wallet = try Wallet.fromMnemonic(mnemonic: words, index: 0)
        words.wipe()
        Check.that(words.allSatisfy { $0 == 0 }, "buffer is wiped")
        try Check.that(wallet.address().hasPrefix("0zk"), "address is 0zk")

        try Check.raises(RailgunError.self, where: \.isInvalidInput, "bad mnemonic") {
            try Wallet.fromMnemonic(mnemonic: Data("not a mnemonic".utf8), index: 0)
        }
        try Check.raises(RailgunError.self, where: \.isInvalidInput, "mnemonic not UTF-8") {
            try Wallet.fromMnemonic(mnemonic: Data([0xFF]), index: 0)
        }

        let test = Data("test test test test test test test test test test test junk".utf8)
        let account = try EvmAccount.fromMnemonic(mnemonic: test, index: 0)
        Check.that(account.address() == "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266", "standard EVM account")

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
