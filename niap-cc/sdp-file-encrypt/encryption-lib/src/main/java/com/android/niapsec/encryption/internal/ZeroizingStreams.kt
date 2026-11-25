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
package com.android.niapsec.encryption.internal

import com.android.niapsec.encryption.tools.CleanSecretKeySpec
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Memory-zeroizing [OutputStream] replacement for [java.io.ByteArrayOutputStream].
 *
 * Standard [java.io.ByteArrayOutputStream] leaves both its internal backing array and every
 * intermediate array allocated during capacity growth unzeroed on the ART heap until GC.
 * This class zeroes old backing arrays immediately on resize and zeroes the active backing
 * array on [zeroize] / [close].
 */
internal class ZeroizingByteArrayOutputStream(initialCapacity: Int = 256) : OutputStream() {
    private var buf: ByteArray = ByteArray(initialCapacity.coerceAtLeast(32))
    private var count: Int = 0

    val size: Int get() = count

    private fun ensureCapacity(minCapacity: Int) {
        if (minCapacity <= buf.size) return
        var newCap = buf.size shl 1
        if (newCap < minCapacity) newCap = minCapacity
        val next = ByteArray(newCap)
        buf.copyInto(next, destinationOffset = 0, startIndex = 0, endIndex = count)
        buf.fill(0)
        buf = next
    }

    override fun write(b: Int) {
        ensureCapacity(count + 1)
        buf[count++] = b.toByte()
    }

    override fun write(b: ByteArray, off: Int, len: Int) {
        if (off < 0 || len < 0 || off + len > b.size) {
            throw IndexOutOfBoundsException("off=$off, len=$len, size=${b.size}")
        }
        if (len == 0) return
        ensureCapacity(count + len)
        b.copyInto(buf, destinationOffset = count, startIndex = off, endIndex = off + len)
        count += len
    }

    /** Returns the internal backing buffer (valid range `0 until size`) without copying. */
    fun backingBuffer(): ByteArray = buf

    /** Returns an exact-length copy (caller is responsible for zeroizing the returned array). */
    fun toByteArrayCopy(): ByteArray = buf.copyOf(count)

    fun zeroize() {
        buf.fill(0)
        count = 0
    }

    override fun close() {
        zeroize()
    }
}

/**
 * Memory-zeroizing [InputStream] replacement for [java.io.ByteArrayInputStream].
 *
 * Progressively overwrites consumed bytes with zeros as [read] advances and unconditionally
 * zeroes the entire backing array on [close].
 */
internal class ZeroizingByteArrayInputStream(
    private val buf: ByteArray,
    private val length: Int = buf.size
) : InputStream() {
    private var pos: Int = 0
    private var closed: Boolean = false

    override fun read(): Int {
        if (closed || pos >= length) return -1
        val value = buf[pos].toInt() and 0xFF
        buf[pos] = 0
        pos++
        return value
    }

    override fun read(b: ByteArray, off: Int, len: Int): Int {
        if (off < 0 || len < 0 || off + len > b.size) {
            throw IndexOutOfBoundsException("off=$off, len=$len, size=${b.size}")
        }
        if (len == 0) return 0
        if (closed || pos >= length) return -1
        val toCopy = minOf(len, length - pos)
        buf.copyInto(b, destinationOffset = off, startIndex = pos, endIndex = pos + toCopy)
        buf.fill(0, pos, pos + toCopy)
        pos += toCopy
        return toCopy
    }

    override fun available(): Int = if (closed) 0 else (length - pos).coerceAtLeast(0)

    override fun close() {
        if (!closed) {
            closed = true
            buf.fill(0)
            pos = length
        }
    }
}

/**
 * Zeroizing AEAD encrypting [OutputStream] that avoids [javax.crypto.CipherOutputStream] and
 * Conscrypt's unzeroed `OpenSSLAeadCipher.buf` (which is allocated whenever `cipher.update()`
 * is called before `doFinal()`).
 *
 * Buffers plaintext into a [ZeroizingByteArrayOutputStream], calls `cipher.doFinal(buf, 0, len)`
 * directly on [close] (keeping 100% wire compatibility with AES-256-GCM), wipes all plaintext
 * buffers, destroys [keySpec], and overwrites internal cipher key state in `finally`.
 */
internal class ZeroizingCipherEncryptOutputStream(
    private val downstream: OutputStream,
    private val dataCipher: Cipher,
    private val keySpec: CleanSecretKeySpec?
) : OutputStream() {
    private val plainBuffer = ZeroizingByteArrayOutputStream(256)
    private var closed = false

    override fun write(b: Int) {
        if (closed) throw IOException("Stream already closed")
        plainBuffer.write(b)
    }

    override fun write(b: ByteArray, off: Int, len: Int) {
        if (closed) throw IOException("Stream already closed")
        plainBuffer.write(b, off, len)
    }

    override fun close() {
        if (closed) return
        closed = true
        try {
            val plaintext = plainBuffer.backingBuffer()
            val plainLen = plainBuffer.size
            val ciphertext = dataCipher.doFinal(plaintext, 0, plainLen)
            downstream.write(ciphertext)
            downstream.flush()
        } finally {
            plainBuffer.zeroize()
            keySpec?.let { if (!it.isDestroyed) it.destroy() }
            clearCipherState(dataCipher)
            downstream.close()
        }
    }
}

/**
 * Zeroizing AEAD decrypting [InputStream] that replaces [javax.crypto.CipherInputStream].
 *
 * Standard [javax.crypto.CipherInputStream] allocates an internal 512-byte `ibuffer` and an
 * unzeroed `obuffer` on the ART heap that persists after `close()`. This stream reads the
 * ciphertext into memory, calls `cipher.doFinal(ct, 0, ctLen, plainBuf, 0)` directly into an
 * owned `plainBuf`, immediately destroys [keySpec] and clears cipher state, zeroes consumed
 * slices as [read] advances, and unconditionally zeroes `plainBuf` on [close].
 */
internal class ZeroizingCipherDecryptInputStream(
    private val upstream: InputStream,
    private val dataCipher: Cipher,
    private val keySpec: CleanSecretKeySpec?
) : InputStream() {
    private var plainBuf: ByteArray? = null
    private var plainLen: Int = 0
    private var pos: Int = 0
    private var decrypted: Boolean = false
    private var closed: Boolean = false

    private fun ensureDecrypted() {
        if (decrypted) return
        decrypted = true
        var outBuf: ByteArray? = null
        try {
            val ctBytes = upstream.readBytes()
            val maxOut = dataCipher.getOutputSize(ctBytes.size).coerceAtLeast(0)
            outBuf = ByteArray(maxOut)
            val actualLen = dataCipher.doFinal(ctBytes, 0, ctBytes.size, outBuf, 0)
            plainBuf = outBuf
            plainLen = actualLen
            pos = 0
        } catch (e: Exception) {
            outBuf?.fill(0)
            plainBuf = null
            plainLen = 0
            if (e is IOException) throw e
            throw IOException("Decryption failed: ${e.message}", e)
        } finally {
            keySpec?.let { if (!it.isDestroyed) it.destroy() }
            clearCipherState(dataCipher)
        }
    }

    override fun read(): Int {
        if (closed) return -1
        ensureDecrypted()
        val buf = plainBuf ?: return -1
        if (pos >= plainLen) return -1
        val v = buf[pos].toInt() and 0xFF
        buf[pos] = 0
        pos++
        return v
    }

    override fun read(b: ByteArray, off: Int, len: Int): Int {
        if (off < 0 || len < 0 || off + len > b.size) {
            throw IndexOutOfBoundsException("off=$off, len=$len, size=${b.size}")
        }
        if (len == 0) return 0
        if (closed) return -1
        ensureDecrypted()
        val buf = plainBuf ?: return -1
        if (pos >= plainLen) return -1
        val toCopy = minOf(len, plainLen - pos)
        buf.copyInto(b, destinationOffset = off, startIndex = pos, endIndex = pos + toCopy)
        buf.fill(0, pos, pos + toCopy)
        pos += toCopy
        return toCopy
    }

    override fun available(): Int {
        if (closed || !decrypted) return 0
        return (plainLen - pos).coerceAtLeast(0)
    }

    override fun close() {
        if (closed) return
        closed = true
        try {
            plainBuf?.fill(0)
            plainBuf = null
            plainLen = 0
            pos = 0
            keySpec?.let { if (!it.isDestroyed) it.destroy() }
            clearCipherState(dataCipher)
        } finally {
            upstream.close()
        }
    }
}

internal fun clearCipherState(cipher: Cipher) {
    try {
        val dummyKey = SecretKeySpec(ByteArray(32), "AES")
        val dummyIv = ByteArray(12).also { SecureRandom().nextBytes(it) }
        cipher.init(Cipher.ENCRYPT_MODE, dummyKey, GCMParameterSpec(128, dummyIv))
    } catch (_: Exception) {
        // Best-effort internal cipher state overwrite
    }
}
