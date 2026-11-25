package com.android.niapsec.encryption.internal

import com.android.niapsec.encryption.tools.CleanSecretKeySpec
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec

class ZeroizingStreamsTest {

    @Test
    fun zeroizingByteArrayOutputStreamWipesOldBuffersOnGrowthAndClose() {
        val out = ZeroizingByteArrayOutputStream(initialCapacity = 32)
        val firstBuf = out.backingBuffer()
        val payload = ByteArray(100) { (0x41 + (it % 26)).toByte() }
        out.write(payload)

        // Old 32-byte buffer must be zeroed immediately when grown
        assertTrue(firstBuf.all { it == 0.toByte() })
        val grownBuf = out.backingBuffer()
        assertArrayEquals(payload, out.toByteArrayCopy())

        out.close()
        assertEquals(0, out.size)
        assertTrue(grownBuf.all { it == 0.toByte() })
    }

    @Test
    fun zeroizingByteArrayInputStreamProgressivelyZeroesAndWipesOnClose() {
        val raw = "SENSITIVE_SECRET_PAYLOAD_1234567890".toByteArray(Charsets.UTF_8)
        val expected = raw.copyOf()
        val input = ZeroizingByteArrayInputStream(raw)

        val chunk = ByteArray(10)
        val read1 = input.read(chunk)
        assertEquals(10, read1)
        assertArrayEquals(expected.copyOfRange(0, 10), chunk)
        // First 10 bytes must already be zeroed in backing array
        assertTrue((0 until 10).all { raw[it] == 0.toByte() })

        // Close before EOF must still wipe all remaining unread bytes
        input.close()
        assertTrue(raw.all { it == 0.toByte() })
        assertEquals(-1, input.read())
    }

    @Test
    fun zeroizingCipherStreamsRoundTripMultiChunkAndDestroyKey() {
        val keyBytes = ByteArray(32).also { SecureRandom().nextBytes(it) }
        val encKey = CleanSecretKeySpec(keyBytes, "AES")
        val decKey = CleanSecretKeySpec(keyBytes, "AES")
        val aad = "EHBR".toByteArray(Charsets.US_ASCII)
        val plaintext = ByteArray(4096) { (it and 0xFF).toByte() }

        val encCipher = Cipher.getInstance("AES/GCM/NoPadding")
        encCipher.init(Cipher.ENCRYPT_MODE, encKey)
        encCipher.updateAAD(aad)
        val iv = encCipher.iv

        val wire = ByteArrayOutputStream()
        ZeroizingCipherEncryptOutputStream(wire, encCipher, encKey).use { out ->
            out.write(plaintext, 0, 1000)
            out.write(plaintext, 1000, 3096)
        }
        assertTrue(encKey.isDestroyed)

        val decCipher = Cipher.getInstance("AES/GCM/NoPadding")
        decCipher.init(Cipher.DECRYPT_MODE, decKey, GCMParameterSpec(128, iv))
        decCipher.updateAAD(aad)

        val recovered = ByteArrayOutputStream()
        ZeroizingCipherDecryptInputStream(ByteArrayInputStream(wire.toByteArray()), decCipher, decKey).use { input ->
            val buf = ByteArray(512)
            while (true) {
                val n = input.read(buf)
                if (n <= 0) break
                recovered.write(buf, 0, n)
            }
        }
        assertTrue(decKey.isDestroyed)
        assertArrayEquals(plaintext, recovered.toByteArray())
    }
}
