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

package com.android.niapsec.encryption.internal.keymanagement

import com.google.crypto.tink.Aead
import com.google.crypto.tink.StreamingAead
import java.io.FilterInputStream
import java.io.FilterOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.nio.channels.ReadableByteChannel
import java.nio.channels.SeekableByteChannel
import java.nio.channels.WritableByteChannel

/**
 * INSECURE / DEMO COMPARISON ONLY.
 *
 * A pass-through [KeyProvider] that performs NO encryption and enforces NO device lock
 * requirement. Exists strictly to visually contrast unencrypted storage against SDP-compliant
 * providers (such as [RawHybridKeyProvider]) when switching implementations inside
 * `encryption-lib`.
 *
 * TODO(security): Do NOT use in production builds; intended strictly for side-by-side security
 * demonstrations illustrating the exposure of unencrypted locked-state data at rest.
 */
class NoOpKeyProvider : KeyProvider {

    private val passthroughAead: Aead = object : Aead {
        override fun encrypt(plaintext: ByteArray, associatedData: ByteArray): ByteArray {
            return plaintext.copyOf()
        }

        override fun decrypt(ciphertext: ByteArray, associatedData: ByteArray): ByteArray {
            return ciphertext.copyOf()
        }
    }

    private val passthroughStreamingAead: StreamingAead = object : StreamingAead {
        override fun newEncryptingChannel(
            ciphertextDestination: WritableByteChannel,
            associatedData: ByteArray
        ): WritableByteChannel = ciphertextDestination

        override fun newSeekableDecryptingChannel(
            ciphertextSource: SeekableByteChannel,
            associatedData: ByteArray
        ): SeekableByteChannel = ciphertextSource

        override fun newDecryptingChannel(
            ciphertextSource: ReadableByteChannel,
            associatedData: ByteArray
        ): ReadableByteChannel = ciphertextSource

        override fun newEncryptingStream(
            ciphertextDestination: OutputStream,
            associatedData: ByteArray
        ): OutputStream = object : FilterOutputStream(ciphertextDestination) {
            override fun write(b: ByteArray, off: Int, len: Int) {
                out.write(b, off, len)
            }
        }

        override fun newDecryptingStream(
            ciphertextSource: InputStream,
            associatedData: ByteArray
        ): InputStream = object : FilterInputStream(ciphertextSource) {}
    }

    override fun getAead(): Aead = passthroughAead

    override fun getStreamingAead(): StreamingAead = passthroughStreamingAead

    override fun getUnlockDeviceRequired(): Boolean = false

    override fun rewrapKeyToSymmetricUdr(encryptedDek: ByteArray): ByteArray = encryptedDek

    override fun isSymmetricallyWrapped(encryptedDek: ByteArray): Boolean = true

    override fun destroy() {
        // No cryptographic keys are allocated in Keystore or preferences.
    }
}
