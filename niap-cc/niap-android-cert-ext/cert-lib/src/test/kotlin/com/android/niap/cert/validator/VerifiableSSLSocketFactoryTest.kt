/*
 * Copyright 2026 Google LLC
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

package com.android.niap.cert.validator

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.InputStream
import javax.net.ssl.SSLHandshakeException

class VerifiableSSLSocketFactoryTest {

    private fun buildServerHelloBody(
        legacyVersion: Int = 0x0303,
        random: ByteArray = ByteArray(32) { (it + 1).toByte() },
        sessionId: ByteArray = ByteArray(32) { 0xAA.toByte() },
        cipherSuite: Int = 0xC02C,
        extensions: List<Pair<Int, ByteArray>>? = emptyList()
    ): ByteArray {
        val out = ByteArrayOutputStream()
        out.write((legacyVersion ushr 8) and 0xFF)
        out.write(legacyVersion and 0xFF)
        out.write(random)
        out.write(sessionId.size)
        out.write(sessionId)
        out.write((cipherSuite ushr 8) and 0xFF)
        out.write(cipherSuite and 0xFF)
        out.write(0x00)

        if (extensions != null) {
            val extBuf = ByteArrayOutputStream()
            for ((extType, extData) in extensions) {
                extBuf.write((extType ushr 8) and 0xFF)
                extBuf.write(extType and 0xFF)
                extBuf.write((extData.size ushr 8) and 0xFF)
                extBuf.write(extData.size and 0xFF)
                extBuf.write(extData)
            }
            val extBytes = extBuf.toByteArray()
            out.write((extBytes.size ushr 8) and 0xFF)
            out.write(extBytes.size and 0xFF)
            out.write(extBytes)
        }
        return out.toByteArray()
    }

    private fun wrapHandshake(hsType: Int, body: ByteArray): ByteArray =
        ByteArrayOutputStream().apply {
            write(hsType and 0xFF)
            write((body.size ushr 16) and 0xFF)
            write((body.size ushr 8) and 0xFF)
            write(body.size and 0xFF)
            write(body)
        }.toByteArray()

    private fun wrapRecord(contentType: Int, payload: ByteArray): ByteArray =
        ByteArrayOutputStream().apply {
            write(contentType and 0xFF)
            write(0x03); write(0x03)
            write((payload.size ushr 8) and 0xFF)
            write(payload.size and 0xFF)
            write(payload)
        }.toByteArray()

    @Test
    fun tls12WithEms_isAcceptedAndReplayedIntact() {
        val sh = buildServerHelloBody(
            extensions = listOf(0xFF01 to byteArrayOf(0x00), 0x0017 to ByteArray(0))
        )
        val wire = wrapRecord(0x16, wrapHandshake(0x02, sh)) +
            byteArrayOf(0x17, 0x03, 0x03, 0x00, 0x02, 0x11, 0x22)

        var rejected = false
        val readBack = EmsVerifyingInputStream(ByteArrayInputStream(wire)) { rejected = true }.readBytes()

        assertFalse(rejected)
        assertArrayEquals(wire, readBack)
    }

    @Test
    fun tls12OmittingEms_isRejectedWithSSLHandshakeException() {
        val sh = buildServerHelloBody(
            extensions = listOf(0xFF01 to byteArrayOf(0x00), 0x000B to byteArrayOf(0x01, 0x00))
        )
        val wire = wrapRecord(0x16, wrapHandshake(0x02, sh))

        var rejectedCount = 0
        val stream = EmsVerifyingInputStream(ByteArrayInputStream(wire)) { rejectedCount++ }

        try {
            stream.read(ByteArray(256))
            fail("Expected SSLHandshakeException when TLS 1.2 ServerHello omits EMS")
        } catch (e: SSLHandshakeException) {
            assertTrue(e.message!!.contains("extended_master_secret"))
        }
        assertEquals(1, rejectedCount)
    }

    @Test
    fun tls12WithNoExtensionsBlock_isRejected() {
        val wire = wrapRecord(0x16, wrapHandshake(0x02, buildServerHelloBody(extensions = null)))
        assertTrue(ServerHelloValidator.inspect(wire) is ServerHelloValidator.Result.Reject)
    }

    @Test
    fun tls12WithNonEmptyEms_isRejected() {
        val sh = buildServerHelloBody(extensions = listOf(0x0017 to byteArrayOf(0x01)))
        val wire = wrapRecord(0x16, wrapHandshake(0x02, sh))
        assertTrue(ServerHelloValidator.inspect(wire) is ServerHelloValidator.Result.Reject)
    }

    @Test
    fun tls13WithoutEms_isAccepted() {
        val sh = buildServerHelloBody(
            cipherSuite = 0x1302,
            extensions = listOf(0x002B to byteArrayOf(0x03, 0x04))
        )
        val wire = wrapRecord(0x16, wrapHandshake(0x02, sh))
        assertEquals(ServerHelloValidator.Result.PassThrough, ServerHelloValidator.inspect(wire))
    }

    @Test
    fun fragmentedRecords_reassemblesAndEnforcesEms() {
        val hs = wrapHandshake(0x02, buildServerHelloBody(extensions = listOf(0x0017 to ByteArray(0))))
        val fullWire = wrapRecord(0x16, hs.copyOfRange(0, 20)) + wrapRecord(0x16, hs.copyOfRange(20, hs.size))

        val drip = object : InputStream() {
            var pos = 0
            override fun read(): Int = if (pos < fullWire.size) fullWire[pos++].toInt() and 0xFF else -1
            override fun read(b: ByteArray, off: Int, len: Int): Int {
                if (pos >= fullWire.size) return -1
                val n = minOf(3, len, fullWire.size - pos)
                System.arraycopy(fullWire, pos, b, off, n)
                pos += n
                return n
            }
        }

        val out = EmsVerifyingInputStream(drip) { fail("Unexpected rejection") }.readBytes()
        assertArrayEquals(fullWire, out)
    }
}
