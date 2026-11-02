package dev.hewig.railgun.smoke

fun main() {
    OfflineSmoke().run()
    LiveSmoke.fromEnvironment(System.getenv())?.run()
}
