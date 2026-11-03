import Foundation

/// Runs against a live node when `RG_MNEMONIC_FILE` is set. Sends only with `RG_SEND_KEY_FILE`, so point `RG_RPC` at a fork for that.
struct LiveSmoke {
    private let mnemonicFile: String
    private let rpcUrl: String
    private let dataDir: String
    private let sender: String
    private let recipient: String
    private let token: String
    private let poiTransaction: String?
    private let sendKeyFile: String?

    init?(environment: [String: String]) {
        guard let mnemonicFile = environment["RG_MNEMONIC_FILE"], !mnemonicFile.isEmpty else {
            return nil
        }
        self.mnemonicFile = mnemonicFile
        rpcUrl = environment["RG_RPC", default: ""]
        dataDir = environment["RG_DATA", default: ""]
        sender = environment["RG_FROM", default: ""]
        recipient = environment["RG_RECIPIENT", default: ""]
        token = environment["RG_TOKEN", default: ""]
        poiTransaction = environment["RG_POI_TX"]
        sendKeyFile = environment["RG_SEND_KEY_FILE"]
    }

    func run() throws {
        var mnemonic = try Data(contentsOf: URL(fileURLWithPath: mnemonicFile))
        defer { mnemonic.wipe() }
        let wallet = try Wallet.fromMnemonic(mnemonic: mnemonic, index: 0)
        let client = try RailgunClient.open(network: "arbitrum", rpcUrl: rpcUrl, dataDir: dataDir)
        try print("sync: \(client.sync())")

        let balances = try client.balances(wallet: wallet)
        print("balances: \(balances)")
        Check.that(balances.contains { $0.spendable != "0" }, "the test wallet has a spendable balance")
        let history = client.history(wallet: wallet)
        print("history: \(history.count) items, latest \(String(describing: history.first))")
        Check.that(!history.isEmpty, "the test wallet has history")

        try Check.raises(RailgunError.self, where: \.isInsufficientFunds, "too much") {
            try transfer("999999999999999999999", with: client, wallet: wallet)
        }
        let transaction = try transfer("1000000000000", with: client, wallet: wallet)
        print("transfer: \(transaction.data.count) bytes on chain \(transaction.chainId)")
        let fee = try client.quoteFee(from: sender, tx: transaction)
        print("fee: gas limit \(fee.gasLimit()), expected \(fee.expectedCost()) wei, at most \(fee.maxCost()) wei")

        let offer = try RailgunBroadcasters.connect(network: "arbitrum").bestOffer(token: token)
        Check.that(offer != nil, "a broadcaster takes the token")
        if let offer {
            try print("broadcaster: \(offer.railgunAddress()) at \(offer.feePerUnitGas(token: token) ?? "none") per unit gas")
        }

        if let poiTransaction {
            let proof = try client.provePoi(wallet: wallet, txHash: poiTransaction)
            try print("poi valid: \(client.poiIsValid(submission: proof))")
        }
        print("live checks passed")

        if let sendKeyFile {
            try send(transaction, with: client, wallet: wallet, keyFile: sendKeyFile)
        }
    }

    private func send(_ transfer: UnsignedTx, with client: RailgunClient, wallet: Wallet, keyFile: String) throws {
        var key = try Data(hex: String(contentsOfFile: keyFile, encoding: .utf8))
        defer { key.wipe() }
        let account = try EvmAccount.fromPrivateKey(privateKey: key)
        let value = "1000000000000"
        if try (Decimal(string: client.allowance(owner: account.address(), token: token)) ?? 0) < (Decimal(string: value) ?? 0) {
            try sendAndWait(client.buildApprove(token: token, value: value), from: account, with: client)
        }
        try sendAndWait(client.buildShield(receiver: wallet.address(), token: token, value: value), from: account, with: client)
        _ = try client.sync()
        let balance = try client.balances(wallet: wallet).first { $0.token == token }
        Check.that(balance?.shieldPending != "0", "the new shield waits for POI")
        let beyondSpendable = ((Decimal(string: balance?.spendable ?? "") ?? 0) + 1).description
        try Check.raises(RailgunError.self, where: \.isPendingPoi, "pending notes are not spent") {
            try self.transfer(beyondSpendable, with: client, wallet: wallet)
        }
        try sendAndWait(transfer, from: account, with: client)
        print("send checks passed")
    }

    private func sendAndWait(_ transaction: UnsignedTx, from account: EvmAccount, with client: RailgunClient) throws {
        let fee = try client.quoteFee(from: account.address(), tx: transaction)
        let hash = try client.send(account: account, tx: transaction, fee: fee)
        var receipt: Receipt?
        for _ in 0 ..< 120 {
            receipt = try client.receipt(txHash: hash)
            if receipt != nil {
                break
            }
            Thread.sleep(forTimeInterval: 1)
        }
        print("\(hash): \(String(describing: receipt))")
        Check.that(receipt?.success == true, "transaction succeeded")
    }

    private func transfer(_ value: String, with client: RailgunClient, wallet: Wallet) throws -> UnsignedTx {
        try client.buildTransfer(wallet: wallet, recipient: recipient, token: token, value: value, memo: "from swift")
    }
}
