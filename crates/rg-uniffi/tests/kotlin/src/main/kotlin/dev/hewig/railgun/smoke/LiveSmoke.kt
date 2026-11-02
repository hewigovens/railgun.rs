package dev.hewig.railgun.smoke

import dev.hewig.railgun.RailgunClient
import dev.hewig.railgun.RailgunException
import dev.hewig.railgun.UnsignedTx
import dev.hewig.railgun.Wallet
import java.io.File

/** Runs against a live node when `RG_MNEMONIC_FILE` is set, and sends nothing. */
class LiveSmoke private constructor(
    private val mnemonicFile: String,
    private val environment: Map<String, String>,
) {
    private val recipient = environment.getValue("RG_RECIPIENT")
    private val token = environment.getValue("RG_TOKEN")

    fun run() {
        val wallet = Wallet.fromMnemonic(File(mnemonicFile).readText().trim(), 0u)
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
        println("live checks passed")
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
