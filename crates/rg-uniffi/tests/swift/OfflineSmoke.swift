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
        Check.that(account.address() == "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266", "standard EVM account, checksummed")

        Check.that(isValidMnemonic(mnemonic: test), "valid mnemonic")
        Check.that(!isValidMnemonic(mnemonic: Data("test test test test test test test test test test test test".utf8)), "bad checksum")
        try Check.that(isValidRailgunAddress(address: wallet.address()), "valid 0zk address")
        Check.that(!isValidRailgunAddress(address: "0zk1qy"), "truncated 0zk address")
        Check.that(isValidEvmAddress(address: account.address()), "valid EVM address")
        Check.that(isValidEvmAddress(address: account.address().lowercased()), "lowercase EVM address")
        Check.that(!isValidEvmAddress(address: account.address().replacingOccurrences(of: "F", with: "f")), "bad EIP-55 checksum")

        var viewingKey = wallet.shareableViewingKey()
        let viewOnly = try Wallet.fromShareableViewingKey(key: viewingKey)
        viewingKey.wipe()
        try Check.that(viewOnly.address() == wallet.address() && viewOnly.isViewOnly() && !wallet.isViewOnly(), "view-only wallet has the same address")
        try Check.raises(RailgunError.self, where: \.isInvalidInput, "bad viewing key") {
            try Wallet.fromShareableViewingKey(key: Data("82a5".utf8))
        }

        let dataDir = NSTemporaryDirectory() + "rg-smoke-\(UUID().uuidString)"
        try Check.raises(RailgunError.self, where: \.isInvalidInput, "unknown network") {
            try RailgunClient.open(network: "mars", rpcUrl: "http://localhost:1", dataDir: dataDir)
        }

        let client = try RailgunClient.open(network: "arbitrum", rpcUrl: "http://localhost:1", dataDir: dataDir)
        try Check.that(client.balances(wallet: wallet).isEmpty, "a new wallet has no balance")
        Check.that(client.history(wallet: wallet).isEmpty, "a new wallet has no history")
        try Check.that(client.balances(wallet: viewOnly).isEmpty, "a view-only wallet scans")
        try Check.raises(RailgunError.self, where: \.isInvalidInput, "a view-only wallet cannot spend") {
            try client.buildTransfer(wallet: viewOnly, recipient: wallet.address(), token: account.address(), value: "1", memo: nil)
        }
        try Check.raises(RailgunError.self, where: \.isNetwork, "no node") {
            try client.sync()
        }
        print("offline checks passed")
    }
}
