package dev.hewig.railgun.smoke

import dev.hewig.railgun.RailgunClient
import dev.hewig.railgun.RailgunException
import dev.hewig.railgun.Wallet
import dev.hewig.railgun.generateMnemonic
import java.nio.file.Files

class OfflineSmoke {
    fun run() {
        val words = generateMnemonic()
        Check.that(words.split(" ").size == 12, "mnemonic has 12 words")
        Check.that(Wallet.fromMnemonic(words, 0u).address().startsWith("0zk"), "address is 0zk")

        Check.raises<RailgunException.InvalidInput>("bad mnemonic") {
            Wallet.fromMnemonic("not a mnemonic", 0u)
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
