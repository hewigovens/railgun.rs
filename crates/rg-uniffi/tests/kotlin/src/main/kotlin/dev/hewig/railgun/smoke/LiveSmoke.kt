package dev.hewig.railgun.smoke

import dev.hewig.railgun.EvmAccount
import dev.hewig.railgun.RailgunClient
import dev.hewig.railgun.RailgunException
import dev.hewig.railgun.UnsignedTx
import dev.hewig.railgun.Wallet
import java.io.File

/** Runs against a live node when `RG_MNEMONIC_FILE` is set. Sends only with `RG_SEND_KEY_FILE`, so point `RG_RPC` at a fork for that. */
class LiveSmoke private constructor(
    private val mnemonicFile: String,
    private val environment: Map<String, String>,
) {
    private val recipient = environment.getValue("RG_RECIPIENT")
    private val token = environment.getValue("RG_TOKEN")

    fun run() {
        val wallet = File(mnemonicFile).readBytes().toSecretBuffer().useOnce { Wallet.fromMnemonic(it, 0u) }
        val client = RailgunClient.open(
            "arbitrum",
            environment.getValue("RG_RPC"),
            environment.getValue("RG_DATA"),
        )
        println("sync: ${client.sync()}")

        val balances = client.balances(wallet)
        println("balances: $balances")
        Check.that(balances.isNotEmpty(), "the test wallet has a balance")

        Check.raises<RailgunException.InsufficientFunds>("too much") {
            client.transfer(wallet, "999999999999999999999")
        }
        val transaction = client.transfer(wallet, "1000000000000")
        println("transfer: ${transaction.data.size} bytes on chain ${transaction.chainId}")
        println("gas: ${client.estimateGas(environment.getValue("RG_FROM"), transaction)}")

        environment["RG_SEND_KEY_FILE"]?.let { send(client, wallet, transaction, it) }
        println("live checks passed")
    }

    private fun send(client: RailgunClient, wallet: Wallet, transfer: UnsignedTx, keyFile: String) {
        val account = File(keyFile).readText().trim().removePrefix("0x").hexToByteArray()
            .toSecretBuffer().useOnce { EvmAccount.fromPrivateKey(it) }
        val value = "1000000000000"
        if (client.allowance(account.address(), token).toBigInteger() < value.toBigInteger()) {
            client.sendAndWait(account, client.buildApprove(token, value))
        }
        client.sendAndWait(account, client.buildShield(wallet.address(), token, value))
        client.sendAndWait(account, transfer)
        println("send checks passed")
    }

    private fun RailgunClient.sendAndWait(account: EvmAccount, transaction: UnsignedTx) {
        val hash = send(account, transaction)
        val receipt = (1..120).firstNotNullOfOrNull { receipt(hash) ?: null.also { Thread.sleep(1000) } }
        println("$hash: $receipt")
        Check.that(receipt?.success == true, "transaction succeeded")
    }

    private fun RailgunClient.transfer(wallet: Wallet, value: String): UnsignedTx =
        buildTransfer(wallet, recipient, token, value, "from kotlin")

    companion object {
        fun fromEnvironment(environment: Map<String, String>): LiveSmoke? =
            environment["RG_MNEMONIC_FILE"]
                ?.takeIf(String::isNotEmpty)
                ?.let { LiveSmoke(it, environment) }
    }
}
