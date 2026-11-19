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

import android.util.Log
import java.io.ByteArrayOutputStream
import java.io.FilterInputStream
import java.io.FilterOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.net.InetAddress
import java.net.Socket
import java.net.SocketAddress
import java.nio.channels.SocketChannel
import javax.net.ssl.SSLHandshakeException
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

/**
 * [SSLSocketFactory] wrapper that applies cipher suite constraints and verifies mandatory
 * TLS handshake extensions such as Extended Master Secret (EMS, RFC 7627 / FCS_TLSC_EXT.1)
 * on the underlying socket stream while keeping platform Conscrypt [SSLSocket] instances intact.
 */
class VerifiableSSLSocketFactory(
    private val delegate: SSLSocketFactory,
    private val allowedCipherSuites: Array<String>? = null,
    private val requireExtendedMasterSecret: Boolean = true
) : SSLSocketFactory() {

    override fun getDefaultCipherSuites(): Array<String> =
        allowedCipherSuites ?: delegate.defaultCipherSuites

    override fun getSupportedCipherSuites(): Array<String> =
        allowedCipherSuites ?: delegate.supportedCipherSuites

    override fun createSocket(s: Socket?, host: String?, port: Int, autoClose: Boolean): Socket {
        requireNotNull(s) { "Underlying socket must not be null" }
        val raw = if (requireExtendedMasterSecret && s !is VerifiableRawSocket) {
            VerifiableRawSocket(s)
        } else {
            s
        }
        return (delegate.createSocket(raw, host, port, autoClose) as SSLSocket).also(::applyCiphers)
    }

    override fun createSocket(host: String?, port: Int): Socket =
        createFromRawSocket({ Socket(host, port) }, host, port) { delegate.createSocket(host, port) }

    override fun createSocket(host: String?, port: Int, localHost: InetAddress?, localPort: Int): Socket =
        createFromRawSocket({ Socket(host, port, localHost, localPort) }, host, port) {
            delegate.createSocket(host, port, localHost, localPort)
        }

    override fun createSocket(host: InetAddress?, port: Int): Socket =
        createFromRawSocket({ Socket(host, port) }, host?.hostAddress, port) {
            delegate.createSocket(host, port)
        }

    override fun createSocket(address: InetAddress?, port: Int, localAddress: InetAddress?, localPort: Int): Socket =
        createFromRawSocket({ Socket(address, port, localAddress, localPort) }, address?.hostAddress, port) {
            delegate.createSocket(address, port, localAddress, localPort)
        }

    private inline fun createFromRawSocket(
        rawFactory: () -> Socket,
        host: String?,
        port: Int,
        fallback: () -> Socket
    ): Socket {
        if (!requireExtendedMasterSecret) {
            return (fallback() as SSLSocket).also(::applyCiphers)
        }
        val raw = rawFactory()
        return try {
            createSocket(raw, host, port, true)
        } catch (t: Throwable) {
            runCatching { raw.close() }
            throw t
        }
    }

    private fun applyCiphers(sslSocket: SSLSocket) {
        if (allowedCipherSuites != null) {
            sslSocket.enabledCipherSuites = allowedCipherSuites
        }
    }
}

internal object ServerHelloValidator {
    internal const val MAX_PRE_HELLO_BYTES = 32768
    private const val MAX_RECORD_LEN = 18432
    private const val EXT_EMS = 0x0017
    private const val EXT_SUPPORTED_VERSIONS = 0x002B
    private const val TLS_1_3 = 0x0304

    // RFC 8446 SHA-256("HelloRetryRequest")
    private val HRR_RANDOM = byteArrayOf(
        0xCF.toByte(), 0x21, 0xAD.toByte(), 0x74, 0xE5.toByte(), 0x9A.toByte(), 0x61, 0x11,
        0xBE.toByte(), 0x1D, 0x8C.toByte(), 0x02, 0x1E, 0x65, 0xB8.toByte(), 0x91.toByte(),
        0xC2.toByte(), 0xA2.toByte(), 0x11, 0x16, 0x7A, 0xBB.toByte(), 0x8C.toByte(), 0x5E,
        0x07, 0x9E.toByte(), 0x09, 0xE2.toByte(), 0xC8.toByte(), 0xA8.toByte(), 0x33, 0x9C.toByte()
    )

    sealed interface Result {
        data object NeedMoreBytes : Result
        data object HelloRetryRequest : Result
        data object PassThrough : Result
        data class Reject(val reason: String) : Result
    }

    fun inspect(wire: ByteArray, allowCcs: Boolean = false): Result {
        if (wire.size > MAX_PRE_HELLO_BYTES) {
            return Result.Reject("Pre-ServerHello data exceeded $MAX_PRE_HELLO_BYTES bytes")
        }
        val hsBuf = ByteArrayOutputStream()
        var off = 0
        while (off + 5 <= wire.size) {
            val type = wire[off].toInt() and 0xFF
            val len = u16(wire, off + 3)
            if (len !in 1..MAX_RECORD_LEN) return Result.Reject("Invalid TLS record length: $len")
            val avail = minOf(len, wire.size - (off + 5))
            when (type) {
                0x16 -> { // Handshake
                    if (avail > 0) hsBuf.write(wire, off + 5, avail)
                    if (hasCompleteFirstMessage(hsBuf) || avail < len) break
                }
                0x15 -> { // Alert
                    if (avail < 2) return Result.NeedMoreBytes
                    if ((wire[off + 5].toInt() and 0xFF) == 2) return Result.PassThrough
                    if (avail < len) return Result.NeedMoreBytes
                }
                0x14 -> { // ChangeCipherSpec (allowed after TLS 1.3 HRR)
                    if (!allowCcs || len != 1) return Result.Reject("Unexpected ChangeCipherSpec")
                    if (avail < 1) return Result.NeedMoreBytes
                }
                else -> return Result.Reject("Unexpected TLS record type 0x${type.toString(16)}")
            }
            off += 5 + len
        }

        val hs = hsBuf.toByteArray()
        if (hs.size < 4) return Result.NeedMoreBytes
        val hsType = hs[0].toInt() and 0xFF
        val hsLen = ((hs[1].toInt() and 0xFF) shl 16) or u16(hs, 2)
        if (hsType != 0x02) return Result.Reject("Expected ServerHello (0x02), got 0x${hsType.toString(16)}")
        if (hsLen > MAX_PRE_HELLO_BYTES) return Result.Reject("Excessive ServerHello length: $hsLen")
        if (hs.size < 4 + hsLen) return Result.NeedMoreBytes

        return checkServerHello(hs.copyOfRange(4, 4 + hsLen))
    }

    private fun checkServerHello(body: ByteArray): Result {
        if (body.size < 38) return Result.Reject("Malformed ServerHello: length=${body.size}")
        val legacyVer = u16(body, 0)
        val isHrr = body.copyOfRange(2, 34).contentEquals(HRR_RANDOM)
        val sidLen = body[34].toInt() and 0xFF
        var pos = 35 + sidLen + 3
        if (sidLen > 32 || pos > body.size) return Result.Reject("Malformed ServerHello session_id")

        var hasEms = false
        var supportedVer: Int? = null
        if (pos < body.size) {
            if (pos + 2 > body.size) return Result.Reject("Truncated ServerHello extensions length")
            val extTotal = u16(body, pos)
            pos += 2
            if (pos + extTotal != body.size) return Result.Reject("ServerHello extensions length mismatch")
            val seen = HashSet<Int>()
            while (pos < body.size) {
                if (pos + 4 > body.size) return Result.Reject("Truncated ServerHello extension header")
                val extType = u16(body, pos)
                val extLen = u16(body, pos + 2)
                pos += 4
                if (pos + extLen > body.size || !seen.add(extType)) {
                    return Result.Reject("Invalid or duplicate extension 0x${extType.toString(16)}")
                }
                when (extType) {
                    EXT_EMS -> {
                        if (extLen != 0) return Result.Reject("Non-empty EMS extension")
                        hasEms = true
                    }
                    EXT_SUPPORTED_VERSIONS -> {
                        if (extLen != 2) return Result.Reject("Invalid supported_versions length")
                        supportedVer = u16(body, pos)
                    }
                }
                pos += extLen
            }
        }

        val negotiatedVer = supportedVer ?: legacyVer
        if (negotiatedVer >= TLS_1_3) {
            return if (isHrr) Result.HelloRetryRequest else Result.PassThrough
        }
        return if (hasEms) {
            Result.PassThrough
        } else {
            Result.Reject(
                "TLS ServerHello (0x${negotiatedVer.toString(16)}) omitted mandatory extended_master_secret (EMS) extension"
            )
        }
    }

    private fun hasCompleteFirstMessage(buf: ByteArrayOutputStream): Boolean {
        if (buf.size() < 4) return false
        val b = buf.toByteArray()
        val len = ((b[1].toInt() and 0xFF) shl 16) or u16(b, 2)
        return b.size >= 4 + len
    }

    private fun u16(b: ByteArray, off: Int): Int =
        ((b[off].toInt() and 0xFF) shl 8) or (b[off + 1].toInt() and 0xFF)
}

internal class VerifiableRawSocket(private val delegate: Socket) : Socket() {
    @Volatile private var rejected = false

    private val verifiedIn: InputStream by lazy {
        EmsVerifyingInputStream(delegate.getInputStream(), ::sendFatalAlertAndAbort)
    }
    private val guardedOut: OutputStream by lazy {
        object : FilterOutputStream(delegate.getOutputStream()) {
            override fun write(b: Int) { if (!rejected) out.write(b) }
            override fun write(b: ByteArray, off: Int, len: Int) { if (!rejected) out.write(b, off, len) }
            override fun flush() { if (!rejected) out.flush() }
        }
    }

    private fun sendFatalAlertAndAbort() {
        if (rejected) return
        rejected = true
        runCatching {
            delegate.getOutputStream().apply {
                write(byteArrayOf(0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28)) // fatal handshake_failure
                flush()
            }
        }
        runCatching { delegate.shutdownOutput() }
    }

    override fun getInputStream(): InputStream = verifiedIn
    override fun getOutputStream(): OutputStream = guardedOut
    override fun getChannel(): SocketChannel? = null

    override fun connect(endpoint: SocketAddress?) = delegate.connect(endpoint)
    override fun connect(endpoint: SocketAddress?, timeout: Int) = delegate.connect(endpoint, timeout)
    override fun bind(bindpoint: SocketAddress?) = delegate.bind(bindpoint)
    override fun getInetAddress(): InetAddress? = delegate.inetAddress
    override fun getLocalAddress(): InetAddress = delegate.localAddress
    override fun getPort(): Int = delegate.port
    override fun getLocalPort(): Int = delegate.localPort
    override fun getRemoteSocketAddress(): SocketAddress? = delegate.remoteSocketAddress
    override fun getLocalSocketAddress(): SocketAddress? = delegate.localSocketAddress
    override fun setTcpNoDelay(on: Boolean) { delegate.tcpNoDelay = on }
    override fun getTcpNoDelay(): Boolean = delegate.tcpNoDelay
    override fun setSoLinger(on: Boolean, linger: Int) = delegate.setSoLinger(on, linger)
    override fun getSoLinger(): Int = delegate.soLinger
    override fun sendUrgentData(data: Int) = delegate.sendUrgentData(data)
    override fun setOOBInline(on: Boolean) { delegate.oobInline = on }
    override fun getOOBInline(): Boolean = delegate.oobInline
    override fun setSoTimeout(timeout: Int) { delegate.soTimeout = timeout }
    override fun getSoTimeout(): Int = delegate.soTimeout
    override fun setSendBufferSize(size: Int) { delegate.sendBufferSize = size }
    override fun getSendBufferSize(): Int = delegate.sendBufferSize
    override fun setReceiveBufferSize(size: Int) { delegate.receiveBufferSize = size }
    override fun getReceiveBufferSize(): Int = delegate.receiveBufferSize
    override fun setKeepAlive(on: Boolean) { delegate.keepAlive = on }
    override fun getKeepAlive(): Boolean = delegate.keepAlive
    override fun setTrafficClass(tc: Int) { delegate.trafficClass = tc }
    override fun getTrafficClass(): Int = delegate.trafficClass
    override fun setReuseAddress(on: Boolean) { delegate.reuseAddress = on }
    override fun getReuseAddress(): Boolean = delegate.reuseAddress
    @Synchronized override fun close() = delegate.close()
    override fun shutdownInput() = delegate.shutdownInput()
    override fun shutdownOutput() = delegate.shutdownOutput()
    override fun isConnected(): Boolean = delegate.isConnected
    override fun isBound(): Boolean = delegate.isBound
    override fun isClosed(): Boolean = delegate.isClosed
    override fun isInputShutdown(): Boolean = delegate.isInputShutdown
    override fun isOutputShutdown(): Boolean = delegate.isOutputShutdown
    override fun setPerformancePreferences(c: Int, l: Int, b: Int) = delegate.setPerformancePreferences(c, l, b)
}

internal class EmsVerifyingInputStream(
    delegateIn: InputStream,
    private val onReject: () -> Unit
) : FilterInputStream(delegateIn) {
    private val pending = ByteArrayOutputStream()
    private var replay: ByteArray? = null
    private var replayPos = 0
    private var verified = false
    private var seenHrr = false
    private var failure: String? = null

    override fun read(): Int {
        val one = ByteArray(1)
        return if (read(one, 0, 1) == -1) -1 else (one[0].toInt() and 0xFF)
    }

    override fun read(b: ByteArray, off: Int, len: Int): Int {
        if (off < 0 || len < 0 || len > b.size - off) throw IndexOutOfBoundsException()
        if (len == 0) return 0
        failure?.let { throw SSLHandshakeException(it) }

        replay?.let { buf ->
            val n = minOf(len, buf.size - replayPos)
            System.arraycopy(buf, replayPos, b, off, n)
            replayPos += n
            if (replayPos >= buf.size) { replay = null; replayPos = 0 }
            return n
        }
        if (verified) return `in`.read(b, off, len)

        val chunk = ByteArray(4096)
        while (true) {
            if (pending.size() > 0) {
                val wire = pending.toByteArray()
                when (val res = ServerHelloValidator.inspect(wire, allowCcs = seenHrr)) {
                    ServerHelloValidator.Result.PassThrough -> {
                        verified = true
                        pending.reset()
                        replay = wire
                        return read(b, off, len)
                    }
                    ServerHelloValidator.Result.HelloRetryRequest -> {
                        seenHrr = true
                        pending.reset()
                        replay = wire
                        return read(b, off, len)
                    }
                    is ServerHelloValidator.Result.Reject -> failHandshake(res.reason)
                    ServerHelloValidator.Result.NeedMoreBytes -> Unit
                }
            }
            val n = `in`.read(chunk)
            if (n == -1) {
                if (pending.size() == 0) { verified = true; return -1 }
                failHandshake("TLS connection closed before ServerHello completed")
            }
            if (pending.size() + n > ServerHelloValidator.MAX_PRE_HELLO_BYTES) {
                failHandshake("TLS pre-ServerHello buffer limit exceeded")
            }
            pending.write(chunk, 0, n)
        }
    }

    override fun available(): Int = (replay?.let { it.size - replayPos } ?: 0) + `in`.available()

    private fun failHandshake(reason: String): Nothing {
        runCatching { Log.e("VerifiableSSLSocket", reason) }
        failure = reason
        onReject()
        throw SSLHandshakeException(reason)
    }
}
