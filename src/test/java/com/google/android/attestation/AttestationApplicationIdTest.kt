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

import com.google.android.attestation.AttestationApplicationId.Companion.createAttestationApplicationId
import com.google.common.collect.ImmutableSet
import com.google.common.truth.Truth
import com.google.protobuf.ByteString
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.JUnit4
import java.util.*

/** Test for [AttestationApplicationId].  */
@RunWith(JUnit4::class)
class AttestationApplicationIdTest {
    @Test
    fun testCreateAttestationApplicationId() {
        val attestationApplicationId = createAttestationApplicationId(ATTESTATION_APPLICATION_ID)
        Truth.assertThat(attestationApplicationId).isEqualTo(EXPECTED_ATTESTATION_APPLICATION_ID)
    }

    companion object {
        // Generated from certificate with RSA Algorithm and StrongBox Security Level
        private val ATTESTATION_APPLICATION_ID: ByteArray = Base64.getDecoder().decode(
            "MIIBszGCAYswDAQHYW5kcm9pZAIBHTAZBBRjb20uYW5kcm9pZC5rZXljaGFpbgIBHTAZBBRjb20uYW5kcm9p" + "ZC5zZXR0aW5ncwIBHTAZBBRjb20ucXRpLmRpYWdzZXJ2aWNlcwIBHTAaBBVjb20uYW5kcm9pZC5keW" + "5zeXN0ZW0CAR0wHQQYY29tLmFuZHJvaWQuaW5wdXRkZXZpY2VzAgEdMB8EGmNvbS5hbmRyb2lkLmxv" + "Y2FsdHJhbnNwb3J0AgEdMB8EGmNvbS5hbmRyb2lkLmxvY2F0aW9uLmZ1c2VkAgEdMB8EGmNvbS5hbm" + "Ryb2lkLnNlcnZlci50ZWxlY29tAgEdMCAEG2NvbS5hbmRyb2lkLndhbGxwYXBlcmJhY2t1cAIBHTAh" + "BBxjb20uZ29vZ2xlLlNTUmVzdGFydERldGVjdG9yAgEdMCIEHWNvbS5nb29nbGUuYW5kcm9pZC5oaW" + "RkZW5tZW51AgEBMCMEHmNvbS5hbmRyb2lkLnByb3ZpZGVycy5zZXR0aW5ncwIBHTEiBCAwGqPLCBE0" + "UBxF8UIqvGbCQiT9Xe1f3I8X5pcXb9hmqg=="
        )

        private val EXPECTED_ATTESTATION_APPLICATION_ID = AttestationApplicationId(
            ImmutableSet.of(
                AttestationApplicationId.AttestationPackageInfo("android", 29),
                AttestationApplicationId.AttestationPackageInfo("com.android.keychain", 29),
                AttestationApplicationId.AttestationPackageInfo("com.android.settings", 29),
                AttestationApplicationId.AttestationPackageInfo("com.qti.diagservices", 29),
                AttestationApplicationId.AttestationPackageInfo("com.android.dynsystem", 29),
                AttestationApplicationId.AttestationPackageInfo("com.android.inputdevices", 29),
                AttestationApplicationId.AttestationPackageInfo("com.android.localtransport", 29),
                AttestationApplicationId.AttestationPackageInfo("com.android.location.fused", 29),
                AttestationApplicationId.AttestationPackageInfo("com.android.server.telecom", 29),
                AttestationApplicationId.AttestationPackageInfo("com.android.wallpaperbackup", 29),
                AttestationApplicationId.AttestationPackageInfo("com.google.SSRestartDetector", 29),
                AttestationApplicationId.AttestationPackageInfo("com.google.android.hiddenmenu", 1),
                AttestationApplicationId.AttestationPackageInfo("com.android.providers.settings", 29),
            ),
            ImmutableSet.of(
                ByteString.copyFrom(
                    Base64.getDecoder().decode("MBqjywgRNFAcRfFCKrxmwkIk/V3tX9yPF+aXF2/YZqo=")
                )
            )
        )
    }
}
