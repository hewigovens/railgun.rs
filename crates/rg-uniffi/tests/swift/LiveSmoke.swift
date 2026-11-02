import Foundation

/// Runs against a live node when `RG_MNEMONIC_FILE` is set, and sends nothing.
struct LiveSmoke {
    private let mnemonicFile: String
    private let rpcUrl: String
    private let dataDir: String
    private let sender: String
    private let recipient: String
    private let token: String
    private let poiTransaction: String?

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
    }

    func run() throws {
        let mnemonic = try String(contentsOfFile: mnemonicFile, encoding: .utf8)
            .trimmingCharacters(in: .whitespacesAndNewlines)
        let wallet = try Wallet.fromMnemonic(mnemonic: mnemonic, index: 0)
        let client = try RailgunClient.open(network: "arbitrum", rpcUrl: rpcUrl, dataDir: dataDir)
        try print("sync: \(client.sync())")

        let balances = client.balances(wallet: wallet)
        print("balances: \(balances)")
        Check.that(!balances.isEmpty, "the test wallet has a balance")

        try Check.raises(RailgunError.self, where: \.isInsufficientFunds, "too much") {
            try transfer("999999999999999999999", with: client, wallet: wallet)
        }
        let transaction = try transfer("1000000000000", with: client, wallet: wallet)
        print("transfer: \(transaction.data.count) bytes on chain \(transaction.chainId)")
        try print("gas: \(client.estimateGas(from: sender, tx: transaction))")

        if let poiTransaction {
            let proof = try client.provePoi(wallet: wallet, txHash: poiTransaction)
            try print("poi valid: \(client.poiIsValid(submission: proof))")
        }
        print("live checks passed")
    }

    private func transfer(_ value: String, with client: RailgunClient, wallet: Wallet) throws -> UnsignedTx {
        try client.buildTransfer(wallet: wallet, recipient: recipient, token: token, value: value, memo: "from swift")
    }
}
