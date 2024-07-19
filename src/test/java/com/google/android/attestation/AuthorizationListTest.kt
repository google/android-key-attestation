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
import com.google.android.attestation.AuthorizationList.Companion.createAuthorizationList
import org.bouncycastle.asn1.ASN1Encodable
import org.bouncycastle.asn1.ASN1Sequence
import java.io.IOException
import java.util.*
import kotlin.test.*


/** Test for [AuthorizationList].  */
class AuthorizationListTest {
    @Test
    @Throws(IOException::class)
    fun testCanParseAuthorizationListFromSwEnforced() {
        val authorizationList = createAuthorizationList(
            getEncodableAuthorizationList(SW_ENFORCED_EXTENSION_DATA), ATTESTATION_VERSION
        )

        assertEquals(authorizationList.creationDateTime, EXPECTED_SW_CREATION_DATETIME)
        assertNull(authorizationList.rootOfTrust)
        assertEquals(authorizationList.attestationApplicationId, EXPECTED_SW_ATTESTATION_APPLICATION_ID)
        assertFalse(authorizationList.deviceUniqueAttestation)
    }

    @Test
    @Throws(IOException::class)
    fun testCanParseAuthorizationListFromTeeEnforced() {
        val authorizationList = createAuthorizationList(
            getEncodableAuthorizationList(TEE_ENFORCED_EXTENSION_DATA), ATTESTATION_VERSION
        )

        assertEquals(authorizationList.purpose, EXPECTED_TEE_PURPOSE)
        assertEquals(authorizationList.algorithm, EXPECTED_TEE_ALGORITHM)
        assertEquals(authorizationList.keySize, EXPECTED_TEE_KEY_SIZE)
        assertEquals(authorizationList.digest, EXPECTED_TEE_DIGEST)
        assertEquals(authorizationList.padding, EXPECTED_TEE_PADDING)
        assertEquals(authorizationList.rsaPublicExponent, EXPECTED_TEE_RSA_PUBLIC_COMPONENT)
        assertTrue(authorizationList.noAuthRequired)
        assertEquals(authorizationList.origin, EXPECTED_TEE_ORIGIN)
        assertNotNull(authorizationList.rootOfTrust)
        assertEquals(authorizationList.osVersion, EXPECTED_TEE_OS_VERSION)
        assertEquals(authorizationList.osPatchLevel, EXPECTED_TEE_OS_PATCH_LEVEL)
        assertEquals(authorizationList.vendorPatchLevel, EXPECTED_TEE_VENDOR_PATCH_LEVEL)
        assertEquals(authorizationList.bootPatchLevel, EXPECTED_TEE_BOOT_PATCH_LEVEL)
        assertFalse(authorizationList.deviceUniqueAttestation)
    }

    @Test
    @Throws(IOException::class)
    fun testCanParseIndividualAttestation() {
        val authorizationList = createAuthorizationList(
            getEncodableAuthorizationList(EXTENTION_DATA_WITH_INDIVIDUAL_ATTESTATION), ATTESTATION_VERSION
        )

        assertTrue(authorizationList.deviceUniqueAttestation)
    }

    companion object {
        // Generated from certificate with RSA Algorithm and StrongBox Security Level
        private const val SW_ENFORCED_EXTENSION_DATA =
            ("MIIBzb+FPQgCBgFr9iKgzL+FRYIBuwSCAbcwggGzMYIBizAMBAdhbmRyb2lkAgEdMBkEFGNvbS5hbmRyb2lkLmtleWNo" + "YWluAgEdMBkEFGNvbS5hbmRyb2lkLnNldHRpbmdzAgEdMBkEFGNvbS5xdGkuZGlhZ3NlcnZpY2VzAgEdMBoEFW" + "NvbS5hbmRyb2lkLmR5bnN5c3RlbQIBHTAdBBhjb20uYW5kcm9pZC5pbnB1dGRldmljZXMCAR0wHwQaY29tLmFu" + "ZHJvaWQubG9jYWx0cmFuc3BvcnQCAR0wHwQaY29tLmFuZHJvaWQubG9jYXRpb24uZnVzZWQCAR0wHwQaY29tLm" + "FuZHJvaWQuc2VydmVyLnRlbGVjb20CAR0wIAQbY29tLmFuZHJvaWQud2FsbHBhcGVyYmFja3VwAgEdMCEEHGNv" + "bS5nb29nbGUuU1NSZXN0YXJ0RGV0ZWN0b3ICAR0wIgQdY29tLmdvb2dsZS5hbmRyb2lkLmhpZGRlbm1lbnUCAQ" + "EwIwQeY29tLmFuZHJvaWQucHJvdmlkZXJzLnNldHRpbmdzAgEdMSIEIDAao8sIETRQHEXxQiq8ZsJCJP1d7V/c" + "jxfmlxdv2Gaq")
        private const val TEE_ENFORCED_EXTENSION_DATA =
            ("MIGwoQgxBgIBAgIBA6IDAgEBowQCAggApQUxAwIBBKYIMQYCAQMCAQW/gUgFAgMBAAG/g3cCBQC/hT4DAgEAv4VATDBK" + "BCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEBAAoBAgQgco2xJ08fHPFXHeQ4CwSKVUrEo4Dnb1" + "NVCDUpCEqTeAG/hUEDAgEAv4VCBQIDAxSzv4VOBgIEATQV8b+FTwYCBAE0Few=")
        private const val ATTESTATION_VERSION = 3

        private const val EXPECTED_SW_CREATION_DATETIME = 1563202592972L
        private val EXPECTED_SW_ATTESTATION_APPLICATION_ID = createAttestationApplicationId(
            Base64.getDecoder().decode(
                "MIIBszGCAYswDAQHYW5kcm9pZAIBHTAZBBRjb20uYW5kcm9pZC5rZXljaGFpbgIBHTAZBBRjb20uYW5k" + "cm9pZC5zZXR0aW5ncwIBHTAZBBRjb20ucXRpLmRpYWdzZXJ2aWNlcwIBHTAaBBVjb20uYW5kcm" + "9pZC5keW5zeXN0ZW0CAR0wHQQYY29tLmFuZHJvaWQuaW5wdXRkZXZpY2VzAgEdMB8EGmNvbS5h" + "bmRyb2lkLmxvY2FsdHJhbnNwb3J0AgEdMB8EGmNvbS5hbmRyb2lkLmxvY2F0aW9uLmZ1c2VkAg" + "EdMB8EGmNvbS5hbmRyb2lkLnNlcnZlci50ZWxlY29tAgEdMCAEG2NvbS5hbmRyb2lkLndhbGxw" + "YXBlcmJhY2t1cAIBHTAhBBxjb20uZ29vZ2xlLlNTUmVzdGFydERldGVjdG9yAgEdMCIEHWNvbS" + "5nb29nbGUuYW5kcm9pZC5oaWRkZW5tZW51AgEBMCMEHmNvbS5hbmRyb2lkLnByb3ZpZGVycy5z" + "ZXR0aW5ncwIBHTEiBCAwGqPLCBE0UBxF8UIqvGbCQiT9Xe1f3I8X5pcXb9hmqg=="
            )
        )
        private val EXPECTED_TEE_PURPOSE: Set<Int> = setOf(2, 3)
        private const val EXPECTED_TEE_ALGORITHM = 1
        private const val EXPECTED_TEE_KEY_SIZE = 2048
        private val EXPECTED_TEE_DIGEST: Set<Int> = setOf(4)
        private val EXPECTED_TEE_PADDING: Set<Int> = setOf(3, 5)
        private const val EXPECTED_TEE_RSA_PUBLIC_COMPONENT = 65537L
        private const val EXPECTED_TEE_ORIGIN = 0
        private const val EXPECTED_TEE_OS_VERSION = 0
        private const val EXPECTED_TEE_OS_PATCH_LEVEL = 201907
        private const val EXPECTED_TEE_VENDOR_PATCH_LEVEL = 20190705
        private const val EXPECTED_TEE_BOOT_PATCH_LEVEL = 20190700

        @Throws(IOException::class)
        private fun getEncodableAuthorizationList(extensionData: String): Array<ASN1Encodable> {
            val extensionDataBytes = Base64.getDecoder().decode(extensionData)
            return ASN1Sequence.getInstance(extensionDataBytes).toArray()
        }

        private const val EXTENTION_DATA_WITH_INDIVIDUAL_ATTESTATION =
            ("MIH0oQgxBgIBAgIBA6IDAgEBowQCAggApQUxAwIBBKYIMQYCAQMCAQW/gUgFAgMBAAG/g3cCBQC/hT4DAgEAv4VATDBK" + "BCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEBAAoBAgQgEvR7Lf1t9nD6P2qyUmgiQ0mG+RixYn" + "glj2TaAMZmHn2/hUEFAgMBrbC/hUIFAgMDFRi/hUYIBAZnb29nbGW/hUcHBAVzYXJnb7+FSAcEBXNhcmdvv4VM" + "CAQGR29vZ2xlv4VNCgQIUGl4ZWwgM2G/hU4GAgQBND1lv4VPBgIEATQ9Zb+FUAIFAA==")
    }
}
