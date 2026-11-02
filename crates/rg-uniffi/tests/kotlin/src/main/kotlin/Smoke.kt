// Drives the generated Kotlin bindings on the JVM. Without RG_MNEMONIC_FILE it stays offline; with it, the same variables as the Swift smoke test run a live client that sends nothing.
import com.hewigovens.railgun.RailgunClient
import com.hewigovens.railgun.RailgunException
import com.hewigovens.railgun.Wallet
import com.hewigovens.railgun.generateMnemonic
import java.io.File
import java.nio.file.Files
import kotlin.system.exitProcess

fun require(condition: Boolean, message: String) {
    if (!condition) {
        println("FAILED: $message")
        exitProcess(1)
    }
}

fun main() {
    val words = generateMnemonic()
    require(words.split(" ").size == 12, "mnemonic has 12 words")
    require(Wallet.fromMnemonic(words, 0u).address().startsWith("0zk"), "address is 0zk")

    try {
        Wallet.fromMnemonic("not a mnemonic", 0u)
        require(false, "a bad mnemonic must throw")
    } catch (e: RailgunException.InvalidInput) {
        println("bad mnemonic: InvalidInput")
    }

    val empty = Files.createTempDirectory("rg-smoke").toString()
    val offline = RailgunClient.open("arbitrum", "http://localhost:1", empty)
    try {
        offline.sync()
        require(false, "sync with no node must throw")
    } catch (e: RailgunException.Network) {
        println("no node: Network")
    }

    val env = System.getenv()
    val file = env["RG_MNEMONIC_FILE"]
    if (file == null) {
        println("offline checks passed")
        return
    }
    val live = Wallet.fromMnemonic(File(file).readText().trim(), 0u)
    val client = RailgunClient.open("arbitrum", env.getValue("RG_RPC"), env.getValue("RG_DATA"))
    println("sync: ${client.sync()}")
    println("balances: ${client.balances(live)}")
    val tx = client.buildTransfer(live, env.getValue("RG_RECIPIENT"), env.getValue("RG_TOKEN"), "1000000000000", "from kotlin")
    println("transfer: ${tx.data.size} bytes on chain ${tx.chainId}")
    println("gas: ${client.estimateGas(env.getValue("RG_FROM"), tx)}")
    println("live checks passed")
}
