/* Copyright 2019, The Android Open Source Project, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.google.android.attestation

import com.google.android.attestation.RootOfTrust.Companion.createRootOfTrust
import com.google.common.truth.Truth
import com.google.protobuf.ByteString
import org.bouncycastle.asn1.ASN1Sequence
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.JUnit4
import java.io.IOException
import java.util.*

/** Test for [RootOfTrust].  */
@RunWith(JUnit4::class)
class RootOfTrustTest {
    @Test
    @Throws(IOException::class)
    fun testCreateRootOfTrust() {
        val rootOfTrustSequence = getRootOfTrustSequence()
        val rootOfTrust = createRootOfTrust(rootOfTrustSequence, ATTESTATION_VERSION)

        Truth.assertThat(rootOfTrust).isNotNull()
        Truth.assertThat(rootOfTrust.verifiedBootKey).isEqualTo(EXPECTED_VERIFIED_BOOT_KEY)
        Truth.assertThat(rootOfTrust.deviceLocked).isEqualTo(EXPECTED_DEVICE_LOCKED)
        Truth.assertThat(rootOfTrust.verifiedBootState).isEqualTo(EXPECTED_VERIFIED_BOOT_STATE)
        Truth.assertThat(rootOfTrust.verifiedBootHash).isEqualTo(EXPECTED_VERIFIED_BOOT_HASH)
    }

    companion object {
        // Generated from certificate with EC Algorithm and StrongBox Security Level
        private const val ROOT_OF_TRUST =
            ("MEoEIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQEACgECBCByjbEnTx8c8Vcd5DgLBIpVSsSjgOdvU1UI" + "NSkISpN4AQ==")
        private const val ATTESTATION_VERSION = 3

        private val EXPECTED_VERIFIED_BOOT_KEY: ByteString =
            ByteString.copyFrom(Base64.getDecoder().decode("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="))
        private const val EXPECTED_DEVICE_LOCKED = false
        private val EXPECTED_VERIFIED_BOOT_STATE = RootOfTrust.VerifiedBootState.UNVERIFIED
        private val EXPECTED_VERIFIED_BOOT_HASH: ByteString =
            ByteString.copyFrom(Base64.getDecoder().decode("co2xJ08fHPFXHeQ4CwSKVUrEo4Dnb1NVCDUpCEqTeAE="))

        @Throws(IOException::class)
        private fun getRootOfTrustSequence(): ASN1Sequence {
            val rootOfTrustBytes = Base64.getDecoder().decode(ROOT_OF_TRUST)
            return ASN1Sequence.fromByteArray(rootOfTrustBytes) as ASN1Sequence
        }
    }
}
