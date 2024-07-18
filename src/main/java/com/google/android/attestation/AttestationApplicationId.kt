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
import com.google.auto.value.AutoValue
import com.google.common.collect.ImmutableSet
import com.google.common.collect.Streams
import com.google.errorprone.annotations.CanIgnoreReturnValue
import com.google.errorprone.annotations.Immutable
import com.google.protobuf.ByteString
import org.bouncycastle.asn1.*
import java.nio.charset.StandardCharsets

/**
 * This data structure reflects the Android platform's belief as to which apps are allowed to use
 * the secret key material under attestation. The ID can comprise multiple packages if and only if
 * multiple packages share the same UID.
 *
 *
 * The Attestation Application ID data from KeyMint will not exceed 1K bytes.
 */
@AutoValue
@Immutable
abstract class AttestationApplicationId {
    abstract fun packageInfos(): ImmutableSet<AttestationPackageInfo>

    abstract fun signatureDigests(): ImmutableSet<ByteString>

    /** Builder for [AttestationApplicationId].  */
    @AutoValue.Builder
    abstract class Builder {
        abstract fun setPackageInfos(value: Set<AttestationPackageInfo>): Builder

        abstract fun packageInfosBuilder(): ImmutableSet.Builder<AttestationPackageInfo>

        @CanIgnoreReturnValue
        fun addPackageInfo(value: AttestationPackageInfo): Builder {
            packageInfosBuilder().add(value)
            return this
        }

        abstract fun setSignatureDigests(value: Set<ByteString>): Builder

        abstract fun signatureDigestsBuilder(): ImmutableSet.Builder<ByteString>

        @CanIgnoreReturnValue
        fun addSignatureDigest(value: ByteString): Builder {
            signatureDigestsBuilder().add(value)
            return this
        }

        @CanIgnoreReturnValue
        fun addSignatureDigest(value: ByteArray): Builder {
            return addSignatureDigest(ByteString.copyFrom(value))
        }

        abstract fun build(): AttestationApplicationId
    }

    /** Provides package's name and version number.  */
    @AutoValue
    @Immutable
    abstract class AttestationPackageInfo {
        abstract fun packageName(): String

        abstract fun version(): Long

        /** Builder for [AttestationPackageInfo].  */
        @AutoValue.Builder
        abstract class Builder {
            abstract fun setPackageName(packageName: String): Builder

            abstract fun setVersion(version: Long): Builder

            abstract fun build(): AttestationPackageInfo
        }

        companion object {
            @JvmStatic
            fun builder(): Builder = AutoValue_AttestationApplicationId_AttestationPackageInfo.Builder()

            internal fun create(packageInfo: ASN1Sequence): AttestationPackageInfo {
                val packageName = String(
                    (packageInfo.getObjectAt(ATTESTATION_PACKAGE_INFO_PACKAGE_NAME_INDEX) as ASN1OctetString).octets,
                    StandardCharsets.UTF_8
                )
                val version =
                    (packageInfo.getObjectAt(ATTESTATION_PACKAGE_INFO_VERSION_INDEX) as ASN1Integer).value.toLong()
                return builder().setPackageName(packageName).setVersion(version).build()
            }
        }
    }

    companion object {
        @JvmStatic
        fun builder(): Builder = AutoValue_AttestationApplicationId.Builder()

        @JvmStatic
        fun createAttestationApplicationId(attestationApplicationId: ByteArray): AttestationApplicationId {
            val builder = builder()
            val attestationApplicationIdSequence = ASN1Sequence.getInstance(attestationApplicationId)
            val attestationPackageInfos = attestationApplicationIdSequence.getObjectAt(
                ATTESTATION_APPLICATION_ID_PACKAGE_INFOS_INDEX
            ) as ASN1Set
            Streams.stream(attestationPackageInfos.iterator()).map { obj -> ASN1Sequence::class.java.cast(obj) }
                .map { packageInfo -> AttestationPackageInfo.create(packageInfo) }
                .forEach { value -> builder.addPackageInfo(value) }

            val digests = attestationApplicationIdSequence.getObjectAt(
                ATTESTATION_APPLICATION_ID_SIGNATURE_DIGESTS_INDEX
            ) as ASN1Set
            Streams.stream(digests.iterator()).map { obj -> ASN1OctetString::class.java.cast(obj) }
                .map { obj: ASN1OctetString -> obj.octets }.map { bytes -> ByteString.copyFrom(bytes) }
                .forEach { value -> builder.addSignatureDigest(value) }
            return builder.build()
        }
    }
}
