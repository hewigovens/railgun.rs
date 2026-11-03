package dev.hewig.railgun.smoke

import dev.hewig.railgun.EvmAccount
import dev.hewig.railgun.RailgunClient
import dev.hewig.railgun.RailgunException
import dev.hewig.railgun.Wallet
import dev.hewig.railgun.generateMnemonic
import dev.hewig.railgun.isValidEvmAddress
import dev.hewig.railgun.isValidMnemonic
import dev.hewig.railgun.isValidRailgunAddress
import java.nio.file.Files

class OfflineSmoke {
    fun run() {
        val words = generateMnemonic()
        Check.that(words.decodeToString().split(" ").size == 12, "mnemonic has 12 words")

        val secret = words.toSecretBuffer()
        val wallet = secret.useOnce { Wallet.fromMnemonic(it, 0u) }
        val address = wallet.address()
        Check.that(address.startsWith("0zk"), "address is 0zk")
        Check.that(secret.position(0).let { (0 until it.limit()).all { i -> it.get(i) == 0.toByte() } }, "buffer is wiped")

        Check.raises<RailgunException.InvalidInput>("bad mnemonic") {
            "not a mnemonic".toByteArray().toSecretBuffer().useOnce { Wallet.fromMnemonic(it, 0u) }
        }
        Check.raises<RailgunException.InvalidInput>("mnemonic not UTF-8") {
            byteArrayOf(-1).toSecretBuffer().useOnce { Wallet.fromMnemonic(it, 0u) }
        }

        val test = "test test test test test test test test test test test junk"
        val account = test.toByteArray().toSecretBuffer().useOnce { EvmAccount.fromMnemonic(it, 0u) }
        Check.that(account.address() == "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266", "standard EVM account, checksummed")

        Check.that(test.toByteArray().toSecretBuffer().useOnce { isValidMnemonic(it) }, "valid mnemonic")
        val badChecksum = "test test test test test test test test test test test test"
        Check.that(!badChecksum.toByteArray().toSecretBuffer().useOnce { isValidMnemonic(it) }, "bad checksum")
        Check.that(isValidRailgunAddress(address), "valid 0zk address")
        Check.that(!isValidRailgunAddress("0zk1qy"), "truncated 0zk address")
        Check.that(isValidEvmAddress(account.address()), "valid EVM address")
        Check.that(isValidEvmAddress(account.address().lowercase()), "lowercase EVM address")
        Check.that(!isValidEvmAddress(account.address().replace('F', 'f')), "bad EIP-55 checksum")

        val viewOnly = wallet.shareableViewingKey().toSecretBuffer().useOnce { Wallet.fromShareableViewingKey(it) }
        Check.that(viewOnly.address() == address && viewOnly.isViewOnly() && !wallet.isViewOnly(), "view-only wallet has the same address")
        Check.raises<RailgunException.InvalidInput>("bad viewing key") {
            "82a5".toByteArray().toSecretBuffer().useOnce { Wallet.fromShareableViewingKey(it) }
        }

        val dataDir = Files.createTempDirectory("rg-smoke").toString()
        Check.raises<RailgunException.InvalidInput>("unknown network") {
            RailgunClient.open("mars", "http://localhost:1", dataDir)
        }

        val client = RailgunClient.open("arbitrum", "http://localhost:1", dataDir)
        Check.that(client.balances(wallet).isEmpty(), "a new wallet has no balance")
        Check.that(client.history(wallet).isEmpty(), "a new wallet has no history")
        Check.that(client.balances(viewOnly).isEmpty(), "a view-only wallet scans")
        Check.raises<RailgunException.InvalidInput>("a view-only wallet cannot spend") {
            client.buildTransfer(viewOnly, address, account.address(), "1", null)
        }
        viewOnly.close()
        wallet.close()
        Check.raises<RailgunException.Network>("no node") {
            client.sync()
        }
        println("offline checks passed")
    }
}
