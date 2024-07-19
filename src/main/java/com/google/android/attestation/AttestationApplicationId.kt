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

import com.google.android.attestation.Constants.ATTESTATION_APPLICATION_ID_PACKAGE_INFOS_INDEX
import com.google.android.attestation.Constants.ATTESTATION_APPLICATION_ID_SIGNATURE_DIGESTS_INDEX
import com.google.android.attestation.Constants.ATTESTATION_PACKAGE_INFO_PACKAGE_NAME_INDEX
import com.google.android.attestation.Constants.ATTESTATION_PACKAGE_INFO_VERSION_INDEX
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.ASN1OctetString
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.ASN1Set
import java.nio.charset.StandardCharsets

/**
 * This data structure reflects the Android platform's belief as to which apps are allowed to use
 * the secret key material under attestation. The ID can comprise multiple packages if and only if
 * multiple packages share the same UID.
 *
 *
 * The Attestation Application ID data from KeyMint will not exceed 1K bytes.
 */
data class AttestationApplicationId(
    val packageInfos: Set<AttestationPackageInfo>, val signatureDigests: Set<ByteArray>
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is AttestationApplicationId) return false

        if (packageInfos != other.packageInfos) return false
        if (!signatureDigests.zip(other.signatureDigests).all { (it1, it2) -> it1.contentEquals(it2) }) return false

        return true
    }

    override fun hashCode(): Int {
        var result = packageInfos.hashCode()
        result = 31 * result + signatureDigests.hashCode()
        return result
    }

    /** Provides package's name and version number.  */
    data class AttestationPackageInfo(
        val packageName: String, val version: Long
    ) {
        companion object {
            internal fun create(packageInfo: ASN1Sequence): AttestationPackageInfo {
                val packageName = String(
                    (packageInfo.getObjectAt(ATTESTATION_PACKAGE_INFO_PACKAGE_NAME_INDEX) as ASN1OctetString).octets,
                    StandardCharsets.UTF_8
                )
                val version =
                    (packageInfo.getObjectAt(ATTESTATION_PACKAGE_INFO_VERSION_INDEX) as ASN1Integer).value.toLong()
                return AttestationPackageInfo(packageName, version)
            }
        }
    }

    companion object {
        @JvmStatic
        fun createAttestationApplicationId(attestationApplicationId: ByteArray): AttestationApplicationId {
            val attestationApplicationIdSequence = ASN1Sequence.getInstance(attestationApplicationId)
            val attestationPackageInfos =
                (attestationApplicationIdSequence.getObjectAt(ATTESTATION_APPLICATION_ID_PACKAGE_INFOS_INDEX) as ASN1Set).map {
                    it as ASN1Sequence
                }.map { AttestationPackageInfo.create(it) }.toSet()
            val digests = (attestationApplicationIdSequence.getObjectAt(
                ATTESTATION_APPLICATION_ID_SIGNATURE_DIGESTS_INDEX
            ) as ASN1Set).map { it as ASN1OctetString }.map { it.octets }.toSet()
            return AttestationApplicationId(attestationPackageInfos, digests)
        }
    }
}
