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

import com.google.android.attestation.ASN1Parsing.getBooleanFromAsn1
import com.google.android.attestation.ASN1Parsing.getIntegerFromAsn1
import com.google.android.attestation.Constants.KM_VERIFIED_BOOT_STATE_FAILED
import com.google.android.attestation.Constants.KM_VERIFIED_BOOT_STATE_SELF_SIGNED
import com.google.android.attestation.Constants.KM_VERIFIED_BOOT_STATE_UNVERIFIED
import com.google.android.attestation.Constants.KM_VERIFIED_BOOT_STATE_VERIFIED
import com.google.android.attestation.Constants.ROOT_OF_TRUST_DEVICE_LOCKED_INDEX
import com.google.android.attestation.Constants.ROOT_OF_TRUST_VERIFIED_BOOT_HASH_INDEX
import com.google.android.attestation.Constants.ROOT_OF_TRUST_VERIFIED_BOOT_KEY_INDEX
import com.google.android.attestation.Constants.ROOT_OF_TRUST_VERIFIED_BOOT_STATE_INDEX
import com.google.auto.value.AutoValue
import com.google.errorprone.annotations.CanIgnoreReturnValue
import com.google.protobuf.ByteString
import org.bouncycastle.asn1.ASN1OctetString
import org.bouncycastle.asn1.ASN1Sequence


/** This collection of values defines key information about the device's status.  */
@AutoValue
abstract class RootOfTrust {
    abstract fun verifiedBootKey(): ByteString

    abstract fun deviceLocked(): Boolean

    abstract fun verifiedBootState(): VerifiedBootState

    abstract fun verifiedBootHash(): ByteString

    /** Builder for [RootOfTrust].  */
    @AutoValue.Builder
    abstract class Builder {
        abstract fun setVerifiedBootKey(value: ByteString): Builder

        @CanIgnoreReturnValue
        fun setVerifiedBootKey(value: ByteArray): Builder {
            return setVerifiedBootKey(ByteString.copyFrom(value))
        }

        abstract fun setDeviceLocked(value: Boolean): Builder

        abstract fun setVerifiedBootState(value: VerifiedBootState): Builder

        abstract fun setVerifiedBootHash(value: ByteString): Builder

        @CanIgnoreReturnValue
        fun setVerifiedBootHash(value: ByteArray): Builder {
            setVerifiedBootHash(ByteString.copyFrom(value))
            return this
        }

        abstract fun build(): RootOfTrust
    }

    /**
     * This provides the device's current boot state, which represents the level of protection
     * provided to the user and to apps after the device finishes booting.
     */
    enum class VerifiedBootState {
        VERIFIED, SELF_SIGNED, UNVERIFIED, FAILED
    }

    companion object {
        @JvmStatic
        fun builder(): Builder {
            return AutoValue_RootOfTrust.Builder().setVerifiedBootKey(ByteString.EMPTY)
                .setVerifiedBootHash(ByteString.EMPTY)
        }

        @JvmStatic
        fun createRootOfTrust(rootOfTrust: ASN1Sequence, attestationVersion: Int): RootOfTrust {
            val builder = builder()
            builder.setVerifiedBootKey(
                ASN1OctetString.getInstance(rootOfTrust.getObjectAt(ROOT_OF_TRUST_VERIFIED_BOOT_KEY_INDEX)).octets
            )
            builder.setDeviceLocked(
                getBooleanFromAsn1(rootOfTrust.getObjectAt(ROOT_OF_TRUST_DEVICE_LOCKED_INDEX))
            )
            builder.setVerifiedBootState(
                verifiedBootStateToEnum(
                    getIntegerFromAsn1(
                        rootOfTrust.getObjectAt(ROOT_OF_TRUST_VERIFIED_BOOT_STATE_INDEX)
                    )
                )
            )
            if (attestationVersion >= 3) {
                builder.setVerifiedBootHash(
                    ASN1OctetString.getInstance(
                        rootOfTrust.getObjectAt(ROOT_OF_TRUST_VERIFIED_BOOT_HASH_INDEX)
                    ).octets
                )
            }
            return builder.build()
        }

        private fun verifiedBootStateToEnum(securityLevel: Int): VerifiedBootState {
            return when (securityLevel) {
                KM_VERIFIED_BOOT_STATE_VERIFIED -> VerifiedBootState.VERIFIED
                KM_VERIFIED_BOOT_STATE_SELF_SIGNED -> VerifiedBootState.SELF_SIGNED
                KM_VERIFIED_BOOT_STATE_UNVERIFIED -> VerifiedBootState.UNVERIFIED
                KM_VERIFIED_BOOT_STATE_FAILED -> VerifiedBootState.FAILED
                else -> throw IllegalArgumentException("Invalid verified boot state.")
            }
        }
    }
}
