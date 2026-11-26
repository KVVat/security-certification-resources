/*
 * Copyright (C) 2026 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.android.niapsec.encryption.tools

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Test
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

class SafeHkdfTest {

    private fun referenceHkdfSha512(ikm: ByteArray, salt: ByteArray?, info: ByteArray, length: Int): ByteArray {
        val mac = Mac.getInstance("HmacSHA512")
        val actualSalt = if (salt == null || salt.isEmpty()) ByteArray(64) else salt
        mac.init(SecretKeySpec(actualSalt, "HmacSHA512"))
        val prk = mac.doFinal(ikm)

        val out = ByteArray(length)
        var t = ByteArray(0)
        var offset = 0
        var counter = 1
        while (offset < length) {
            mac.init(SecretKeySpec(prk, "HmacSHA512"))
            mac.update(t)
            mac.update(info)
            mac.update(counter.toByte())
            t = mac.doFinal()
            val n = minOf(t.size, length - offset)
            System.arraycopy(t, 0, out, offset, n)
            offset += n
            counter++
        }
        return out
    }

    @Test
    fun matchesReferenceHmacSha512For32ByteAesKek() {
        val ikm = ByteArray(66) { (it * 7 + 3).toByte() }
        val salt = "mail_raw_hybrid_key_symmetric_ec".toByteArray(Charsets.UTF_8)
        val info = ByteArray(158) { (it xor 0x3C).toByte() }

        val actual = SafeHkdf.computeHkdf(ikm, salt, info, 32)
        val expected = referenceHkdfSha512(ikm, salt, info, 32)

        assertEquals(32, actual.size)
        assertArrayEquals(expected, actual)
    }

    @Test
    fun matchesReferenceForMultiBlockAndEmptySalt() {
        val ikm = ByteArray(140) { (it + 11).toByte() } // > SHA-512 block size (128B)
        val info = "multi-block-info".toByteArray(Charsets.UTF_8)

        val actual = SafeHkdf.computeHkdf(ikm, null, info, 100) // spans 2 SHA-512 iterations
        val expected = referenceHkdfSha512(ikm, null, info, 100)

        assertEquals(100, actual.size)
        assertArrayEquals(expected, actual)
    }

    @Test
    fun handlesZeroLengthOutput() {
        val actual = SafeHkdf.computeHkdf(byteArrayOf(1, 2, 3), byteArrayOf(4), byteArrayOf(5), 0)
        assertEquals(0, actual.size)
    }
}
