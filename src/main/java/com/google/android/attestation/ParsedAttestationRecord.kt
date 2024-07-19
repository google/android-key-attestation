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

import com.google.android.attestation.ASN1Parsing.getIntegerFromAsn1
import com.google.android.attestation.Constants.ATTESTATION_CHALLENGE_INDEX
import com.google.android.attestation.Constants.ATTESTATION_SECURITY_LEVEL_INDEX
import com.google.android.attestation.Constants.ATTESTATION_VERSION_INDEX
import com.google.android.attestation.Constants.KEYMASTER_SECURITY_LEVEL_INDEX
import com.google.android.attestation.Constants.KEYMASTER_VERSION_INDEX
import com.google.android.attestation.Constants.KEY_DESCRIPTION_OID
import com.google.android.attestation.Constants.KM_SECURITY_LEVEL_SOFTWARE
import com.google.android.attestation.Constants.KM_SECURITY_LEVEL_STRONG_BOX
import com.google.android.attestation.Constants.KM_SECURITY_LEVEL_TRUSTED_ENVIRONMENT
import com.google.android.attestation.Constants.SW_ENFORCED_INDEX
import com.google.android.attestation.Constants.TEE_ENFORCED_INDEX
import com.google.android.attestation.Constants.UNIQUE_ID_INDEX
import com.google.errorprone.annotations.Immutable
import org.bouncycastle.asn1.ASN1InputStream
import org.bouncycastle.asn1.ASN1OctetString
import org.bouncycastle.asn1.ASN1Sequence
import java.io.IOException
import java.security.cert.X509Certificate

/** Java representation of Key Attestation extension data.  */
@Immutable
data class ParsedAttestationRecord(
    val attestationVersion: Int,
    val attestationSecurityLevel: SecurityLevel,
    val keymasterVersion: Int,
    val keymasterSecurityLevel: SecurityLevel,
    val attestationChallenge: ByteArray,
    val uniqueId: ByteArray,
    val softwareEnforced: AuthorizationList,
    val teeEnforced: AuthorizationList,
) {

    /**
     * This indicates the extent to which a software feature, such as a key pair, is protected based
     * on its location within the device.
     */
    enum class SecurityLevel {
        SOFTWARE, TRUSTED_ENVIRONMENT, STRONG_BOX
    }

    companion object {

        @JvmStatic
        @Throws(IOException::class)
        fun createParsedAttestationRecord(cert: X509Certificate): ParsedAttestationRecord {
            val attestationExtensionBytes = cert.getExtensionValue(KEY_DESCRIPTION_OID)
            return create(extractAttestationSequence(attestationExtensionBytes))
        }

        fun create(extensionData: ASN1Sequence): ParsedAttestationRecord {
            val attestationVersion = getIntegerFromAsn1(extensionData.getObjectAt(ATTESTATION_VERSION_INDEX))
            val atttestationSecurityLevel = securityLevelToEnum(
                getIntegerFromAsn1(
                    extensionData.getObjectAt(ATTESTATION_SECURITY_LEVEL_INDEX)
                )
            )
            val keymasterVersion = getIntegerFromAsn1(extensionData.getObjectAt(KEYMASTER_VERSION_INDEX))
            val keymasterSecurityLevel = securityLevelToEnum(
                getIntegerFromAsn1(
                    extensionData.getObjectAt(KEYMASTER_SECURITY_LEVEL_INDEX)
                )
            )
            val attestationChallenge =
                ASN1OctetString.getInstance(extensionData.getObjectAt(ATTESTATION_CHALLENGE_INDEX)).octets
            val uniqueId = ASN1OctetString.getInstance(extensionData.getObjectAt(UNIQUE_ID_INDEX)).octets
            val softwareEnforced = AuthorizationList.createAuthorizationList(
                ASN1Sequence.getInstance(extensionData.getObjectAt(SW_ENFORCED_INDEX)).toArray(), attestationVersion
            )
            val teeEnforced = AuthorizationList.createAuthorizationList(
                ASN1Sequence.getInstance(extensionData.getObjectAt(TEE_ENFORCED_INDEX)).toArray(), attestationVersion
            )
            return ParsedAttestationRecord(
                attestationVersion,
                atttestationSecurityLevel,
                keymasterVersion,
                keymasterSecurityLevel,
                attestationChallenge,
                uniqueId,
                softwareEnforced,
                teeEnforced
            )
        }

        private fun securityLevelToEnum(securityLevel: Int): SecurityLevel {
            return when (securityLevel) {
                KM_SECURITY_LEVEL_SOFTWARE -> SecurityLevel.SOFTWARE
                KM_SECURITY_LEVEL_TRUSTED_ENVIRONMENT -> SecurityLevel.TRUSTED_ENVIRONMENT
                KM_SECURITY_LEVEL_STRONG_BOX -> SecurityLevel.STRONG_BOX
                else -> throw IllegalArgumentException("Invalid security level.")
            }
        }

        @Throws(IOException::class)
        private fun extractAttestationSequence(attestationExtensionBytes: ByteArray): ASN1Sequence {
            var decodedSequence: ASN1Sequence
            ASN1InputStream(attestationExtensionBytes).use { asn1InputStream ->
                // The extension contains one object, a sequence, in the
                // Distinguished Encoding Rules (DER)-encoded form. Get the DER
                // bytes.
                val derSequenceBytes = (asn1InputStream.readObject() as ASN1OctetString).octets
                ASN1InputStream(derSequenceBytes).use { seqInputStream ->
                    decodedSequence = seqInputStream.readObject() as ASN1Sequence
                }
            }
            return decodedSequence
        }
    }
}
