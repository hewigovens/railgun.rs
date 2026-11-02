package dev.hewig.railgun.smoke

import kotlin.system.exitProcess

object Check {
    fun that(condition: Boolean, message: String) {
        if (!condition) {
            fail(message)
        }
    }

    fun fail(message: String): Nothing {
        println("FAILED: $message")
        exitProcess(1)
    }

    inline fun <reified Failure : Throwable> raises(message: String, body: () -> Any?) {
        try {
            body()
        } catch (error: Throwable) {
            if (error is Failure) {
                println("$message: ${error::class.simpleName}")
                return
            }
            throw error
        }
        fail("$message must throw")
    }
}
