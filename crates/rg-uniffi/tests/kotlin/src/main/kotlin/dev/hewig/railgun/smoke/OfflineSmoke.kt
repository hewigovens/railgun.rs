package dev.hewig.railgun.smoke

import dev.hewig.railgun.RailgunClient
import dev.hewig.railgun.RailgunException
import dev.hewig.railgun.Wallet
import dev.hewig.railgun.generateMnemonic
import java.nio.file.Files

class OfflineSmoke {
    fun run() {
        val words = generateMnemonic()
        Check.that(words.decodeToString().split(" ").size == 12, "mnemonic has 12 words")

        val secret = words.toSecretBuffer()
        val wallet = secret.useOnce { Wallet.fromMnemonic(it, 0u) }
        Check.that(wallet.address().startsWith("0zk"), "address is 0zk")
        Check.that(secret.position(0).let { (0 until it.limit()).all { i -> it.get(i) == 0.toByte() } }, "buffer is wiped")
        wallet.close()

        Check.raises<RailgunException.InvalidInput>("bad mnemonic") {
            "not a mnemonic".toByteArray().toSecretBuffer().useOnce { Wallet.fromMnemonic(it, 0u) }
        }
        Check.raises<RailgunException.InvalidInput>("mnemonic not UTF-8") {
            byteArrayOf(-1).toSecretBuffer().useOnce { Wallet.fromMnemonic(it, 0u) }
        }

        val dataDir = Files.createTempDirectory("rg-smoke").toString()
        Check.raises<RailgunException.InvalidInput>("unknown network") {
            RailgunClient.open("mars", "http://localhost:1", dataDir)
        }

        val client = RailgunClient.open("arbitrum", "http://localhost:1", dataDir)
        Check.raises<RailgunException.Network>("no node") {
            client.sync()
        }
        println("offline checks passed")
    }
}
