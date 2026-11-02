package dev.hewig.railgun.smoke

import java.nio.ByteBuffer

/** Copies into a direct buffer, the only kind that crosses to Rust by reference, and wipes the source. */
fun ByteArray.toSecretBuffer(): ByteBuffer {
    val buffer = ByteBuffer.allocateDirect(size).put(this)
    fill(0)
    buffer.flip()
    return buffer
}

fun <T> ByteBuffer.useOnce(block: (ByteBuffer) -> T): T =
    try {
        block(this)
    } finally {
        (0 until limit()).forEach { put(it, 0) }
    }
