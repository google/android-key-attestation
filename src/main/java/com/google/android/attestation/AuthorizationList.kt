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

import com.google.android.attestation.Constants.KM_TAG_ACTIVE_DATE_TIME
import com.google.android.attestation.Constants.KM_TAG_ALGORITHM
import com.google.android.attestation.Constants.KM_TAG_ALLOW_WHILE_ON_BODY
import com.google.android.attestation.Constants.KM_TAG_ATTESTATION_APPLICATION_ID
import com.google.android.attestation.Constants.KM_TAG_ATTESTATION_ID_BRAND
import com.google.android.attestation.Constants.KM_TAG_ATTESTATION_ID_DEVICE
import com.google.android.attestation.Constants.KM_TAG_ATTESTATION_ID_IMEI
import com.google.android.attestation.Constants.KM_TAG_ATTESTATION_ID_MANUFACTURER
import com.google.android.attestation.Constants.KM_TAG_ATTESTATION_ID_MEID
import com.google.android.attestation.Constants.KM_TAG_ATTESTATION_ID_MODEL
import com.google.android.attestation.Constants.KM_TAG_ATTESTATION_ID_PRODUCT
import com.google.android.attestation.Constants.KM_TAG_ATTESTATION_ID_SECOND_IMEI
import com.google.android.attestation.Constants.KM_TAG_ATTESTATION_ID_SERIAL
import com.google.android.attestation.Constants.KM_TAG_AUTH_TIMEOUT
import com.google.android.attestation.Constants.KM_TAG_BOOT_PATCH_LEVEL
import com.google.android.attestation.Constants.KM_TAG_CREATION_DATE_TIME
import com.google.android.attestation.Constants.KM_TAG_DEVICE_UNIQUE_ATTESTATION
import com.google.android.attestation.Constants.KM_TAG_DIGEST
import com.google.android.attestation.Constants.KM_TAG_EC_CURVE
import com.google.android.attestation.Constants.KM_TAG_KEY_SIZE
import com.google.android.attestation.Constants.KM_TAG_NO_AUTH_REQUIRED
import com.google.android.attestation.Constants.KM_TAG_ORIGIN
import com.google.android.attestation.Constants.KM_TAG_ORIGINATION_EXPIRE_DATE_TIME
import com.google.android.attestation.Constants.KM_TAG_OS_PATCH_LEVEL
import com.google.android.attestation.Constants.KM_TAG_OS_VERSION
import com.google.android.attestation.Constants.KM_TAG_PADDING
import com.google.android.attestation.Constants.KM_TAG_PURPOSE
import com.google.android.attestation.Constants.KM_TAG_ROLLBACK_RESISTANCE
import com.google.android.attestation.Constants.KM_TAG_ROOT_OF_TRUST
import com.google.android.attestation.Constants.KM_TAG_RSA_OAEP_MGF_DIGEST
import com.google.android.attestation.Constants.KM_TAG_RSA_PUBLIC_EXPONENT
import com.google.android.attestation.Constants.KM_TAG_TRUSTED_CONFIRMATION_REQUIRED
import com.google.android.attestation.Constants.KM_TAG_TRUSTED_USER_PRESENCE_REQUIRED
import com.google.android.attestation.Constants.KM_TAG_UNLOCKED_DEVICE_REQUIRED
import com.google.android.attestation.Constants.KM_TAG_USAGE_EXPIRE_DATE_TIME
import com.google.android.attestation.Constants.KM_TAG_USER_AUTH_TYPE
import com.google.android.attestation.Constants.KM_TAG_VENDOR_PATCH_LEVEL
import com.google.android.attestation.RootOfTrust.Companion.createRootOfTrust
import com.google.auto.value.AutoValue
import com.google.common.collect.ImmutableMap
import com.google.common.collect.ImmutableSet
import com.google.common.collect.Streams
import com.google.errorprone.annotations.CanIgnoreReturnValue
import com.google.errorprone.annotations.Immutable
import com.google.protobuf.ByteString
import org.bouncycastle.asn1.*
import java.util.*

/**
 * This data structure contains the key pair's properties themselves, as defined in the Keymaster
 * hardware abstraction layer (HAL). You compare these values to the device's current state or to a
 * set of expected values to verify that a key pair is still valid for use in your app.
 */
@AutoValue
@Immutable
abstract class AuthorizationList {
    abstract fun purpose(): ImmutableSet<Int>

    abstract fun algorithm(): Optional<Int>

    abstract fun keySize(): Optional<Int>

    abstract fun digest(): ImmutableSet<Int>

    abstract fun padding(): ImmutableSet<Int>

    abstract fun ecCurve(): Optional<Int>

    abstract fun rsaPublicExponent(): Optional<Long>

    abstract fun mgfDigest(): ImmutableSet<Int>

    abstract fun rollbackResistance(): Boolean

    // TODO earlyBootOnly

    abstract fun activeDateTime(): Optional<Int>

    abstract fun originationExpireDateTime(): Optional<Int>

    abstract fun usageExpireDateTime(): Optional<Int>

    // TODO usageCountLimit

    abstract fun noAuthRequired(): Boolean

    abstract fun userAuthType(): Optional<Long>

    abstract fun authTimeout(): Optional<Int>

    abstract fun allowWhileOnBody(): Boolean

    abstract fun trustedUserPresenceRequired(): Boolean

    abstract fun trustedConfirmationRequired(): Boolean

    abstract fun unlockedDeviceRequired(): Boolean

    abstract fun creationDateTime(): Optional<Long>

    abstract fun origin(): Optional<Int>

    abstract fun rootOfTrust(): Optional<RootOfTrust>

    abstract fun osVersion(): Optional<Int>

    abstract fun osPatchLevel(): Optional<Int>

    abstract fun attestationApplicationId(): Optional<AttestationApplicationId>

    abstract fun attestationIdBrand(): Optional<ByteString>

    abstract fun attestationIdDevice(): Optional<ByteString>

    abstract fun attestationIdProduct(): Optional<ByteString>

    abstract fun attestationIdSerial(): Optional<ByteString>

    abstract fun attestationIdImei(): Optional<ByteString>

    abstract fun attestationIdMeid(): Optional<ByteString>

    abstract fun attestationIdManufacturer(): Optional<ByteString>

    abstract fun attestationIdModel(): Optional<ByteString>

    abstract fun vendorPatchLevel(): Optional<Int>

    abstract fun bootPatchLevel(): Optional<Int>

    abstract fun deviceUniqueAttestation(): Boolean

    abstract fun attestationIdSecondImei(): Optional<ByteString>

    /**
     * Builder for an AuthorizationList. Any field not set will be made an Optional.empty or set with
     * the default value.
     */
    @AutoValue.Builder
    abstract class Builder {
        abstract fun purposeBuilder(): ImmutableSet.Builder<Int>

        @CanIgnoreReturnValue
        fun addPurpose(value: Int): Builder {
            purposeBuilder().add(value)
            return this
        }

        abstract fun setAlgorithm(value: Int): Builder

        abstract fun setKeySize(keySize: Int): Builder

        abstract fun digestBuilder(): ImmutableSet.Builder<Int>

        @CanIgnoreReturnValue
        fun addDigest(value: Int): Builder {
            digestBuilder().add(value)
            return this
        }

        abstract fun paddingBuilder(): ImmutableSet.Builder<Int>

        @CanIgnoreReturnValue
        fun addPadding(value: Int): Builder {
            paddingBuilder().add(value)
            return this
        }

        abstract fun setEcCurve(ecCurve: Int): Builder

        abstract fun setRsaPublicExponent(value: Long): Builder

        abstract fun mgfDigestBuilder(): ImmutableSet.Builder<Int>

        @CanIgnoreReturnValue
        fun addMgfDigest(value: Int): Builder {
            mgfDigestBuilder().add(value)
            return this
        }

        abstract fun setRollbackResistance(value: Boolean): Builder

        abstract fun setActiveDateTime(value: Int): Builder

        abstract fun setOriginationExpireDateTime(value: Int): Builder

        abstract fun setUsageExpireDateTime(value: Int): Builder

        abstract fun setNoAuthRequired(value: Boolean): Builder

        abstract fun setUserAuthType(value: Long): Builder

        abstract fun setAuthTimeout(value: Int): Builder

        abstract fun setAllowWhileOnBody(value: Boolean): Builder

        abstract fun setTrustedUserPresenceRequired(value: Boolean): Builder

        abstract fun setTrustedConfirmationRequired(value: Boolean): Builder

        abstract fun setUnlockedDeviceRequired(value: Boolean): Builder

        abstract fun setCreationDateTime(value: Long): Builder

        abstract fun setOrigin(value: Int): Builder

        abstract fun setRootOfTrust(rootOfTrust: RootOfTrust): Builder

        abstract fun setOsVersion(osVersion: Int): Builder

        abstract fun setOsPatchLevel(value: Int): Builder

        abstract fun setAttestationApplicationId(
            attestationApplicationId: AttestationApplicationId?
        ): Builder

        abstract fun setAttestationIdBrand(attestationIdBrand: ByteString): Builder

        @CanIgnoreReturnValue
        fun setAttestationIdBrand(value: String): Builder {
            return setAttestationIdBrand(ByteString.copyFromUtf8(value))
        }

        abstract fun setAttestationIdDevice(attestationIdDevice: ByteString): Builder

        @CanIgnoreReturnValue
        fun setAttestationIdDevice(value: String): Builder {
            return setAttestationIdDevice(ByteString.copyFromUtf8(value))
        }

        abstract fun setAttestationIdProduct(attestationIdProduct: ByteString): Builder

        @CanIgnoreReturnValue
        fun setAttestationIdProduct(value: String): Builder {
            return setAttestationIdProduct(ByteString.copyFromUtf8(value))
        }

        abstract fun setAttestationIdSerial(attestationIdSerial: ByteString): Builder

        @CanIgnoreReturnValue
        fun setAttestationIdSerial(value: String): Builder {
            return setAttestationIdSerial(ByteString.copyFromUtf8(value))
        }

        abstract fun setAttestationIdImei(attestationIdImei: ByteString): Builder

        @CanIgnoreReturnValue
        fun setAttestationIdImei(value: String): Builder {
            return setAttestationIdImei(ByteString.copyFromUtf8(value))
        }

        abstract fun setAttestationIdSecondImei(attestationIdSecondImei: ByteString): Builder

        @CanIgnoreReturnValue
        fun setAttestationIdSecondImei(value: String): Builder {
            return setAttestationIdSecondImei(ByteString.copyFromUtf8(value))
        }

        abstract fun setAttestationIdMeid(attestationIdMeid: ByteString): Builder

        @CanIgnoreReturnValue
        fun setAttestationIdMeid(value: String): Builder {
            return setAttestationIdMeid(ByteString.copyFromUtf8(value))
        }

        abstract fun setAttestationIdManufacturer(attestationIdManufacturer: ByteString): Builder

        @CanIgnoreReturnValue
        fun setAttestationIdManufacturer(value: String): Builder {
            return setAttestationIdManufacturer(ByteString.copyFromUtf8(value))
        }

        abstract fun setAttestationIdModel(attestationIdModel: ByteString): Builder

        @CanIgnoreReturnValue
        fun setAttestationIdModel(value: String): Builder {
            return setAttestationIdModel(ByteString.copyFromUtf8(value))
        }

        abstract fun setVendorPatchLevel(vendorPatchLevel: Int): Builder

        abstract fun setBootPatchLevel(bootPatchLevel: Int): Builder

        abstract fun setDeviceUniqueAttestation(value: Boolean): Builder

        abstract fun build(): AuthorizationList
    }

    /**
     * This data structure holds the parsed attest record authorizations mapped to their authorization
     * tags.
     */
    private class ParsedAuthorizationMap(private val authorizationMap: ImmutableMap<Int, ASN1Object>) {
        fun findAuthorizationListEntry(tag: Int): Optional<ASN1Object> {
            return Optional.ofNullable(authorizationMap[tag])
        }

        fun findIntegerSetAuthorizationListEntry(tag: Int): ImmutableSet<Int> {
            val asn1Set = findAuthorizationListEntry(tag).map { obj -> ASN1Set::class.java.cast(obj) }.orElse(null)
            if (asn1Set == null) {
                return ImmutableSet.of()
            }
            return Streams.stream<ASN1Encodable>(asn1Set).map { obj -> ASN1Parsing.getIntegerFromAsn1(obj) }.collect(
                ImmutableSet.toImmutableSet()
            )
        }

        fun findOptionalIntegerAuthorizationListEntry(tag: Int): Optional<Int> {
            return findAuthorizationListEntry(tag).map { obj -> ASN1Integer::class.java.cast(obj) }
                .map { obj -> ASN1Parsing.getIntegerFromAsn1(obj) }
        }

        fun findOptionalLongAuthorizationListEntry(tag: Int): Optional<Long> {
            return findAuthorizationListEntry(tag).map { obj -> ASN1Integer::class.java.cast(obj) }
                .map { value: ASN1Integer -> value.value.toLong() }
        }

        fun findBooleanAuthorizationListEntry(tag: Int): Boolean {
            return findAuthorizationListEntry(tag).isPresent
        }

        fun findOptionalByteArrayAuthorizationListEntry(tag: Int): Optional<ByteString> {
            return findAuthorizationListEntry(tag).map { obj -> ASN1OctetString::class.java.cast(obj) }
                .map { obj -> obj.octets }.map { bytes -> ByteString.copyFrom(bytes) }
        }
    }

    companion object {
        @JvmStatic
        fun builder(): Builder {
            return AutoValue_AuthorizationList.Builder().setRollbackResistance(false).setNoAuthRequired(false)
                .setAllowWhileOnBody(false).setTrustedUserPresenceRequired(false).setTrustedConfirmationRequired(false)
                .setUnlockedDeviceRequired(false).setDeviceUniqueAttestation(false)
        }

        @JvmStatic
        fun createAuthorizationList(
            authorizationList: Array<ASN1Encodable>, attestationVersion: Int
        ): AuthorizationList {
            val builder = builder()
            val parsedAuthorizationMap = getAuthorizationMap(authorizationList)
            parsedAuthorizationMap.findIntegerSetAuthorizationListEntry(KM_TAG_PURPOSE).stream()
                .forEach { value -> builder.addPurpose(value) }
            parsedAuthorizationMap.findOptionalIntegerAuthorizationListEntry(KM_TAG_ALGORITHM)
                .ifPresent { value -> builder.setAlgorithm(value) }

            parsedAuthorizationMap.findOptionalIntegerAuthorizationListEntry(KM_TAG_KEY_SIZE)
                .ifPresent { keySize -> builder.setKeySize(keySize) }
            parsedAuthorizationMap.findIntegerSetAuthorizationListEntry(KM_TAG_DIGEST).stream()
                .forEach { value -> builder.addDigest(value) }
            parsedAuthorizationMap.findIntegerSetAuthorizationListEntry(KM_TAG_PADDING).stream()
                .forEach { value -> builder.addPadding(value) }
            parsedAuthorizationMap.findOptionalIntegerAuthorizationListEntry(KM_TAG_EC_CURVE)
                .ifPresent { ecCurve -> builder.setEcCurve(ecCurve) }
            parsedAuthorizationMap.findOptionalLongAuthorizationListEntry(KM_TAG_RSA_PUBLIC_EXPONENT)
                .ifPresent { value -> builder.setRsaPublicExponent(value) }
            parsedAuthorizationMap.findIntegerSetAuthorizationListEntry(KM_TAG_RSA_OAEP_MGF_DIGEST).stream()
                .forEach { value -> builder.addMgfDigest(value) }
            builder.setRollbackResistance(
                parsedAuthorizationMap.findBooleanAuthorizationListEntry(KM_TAG_ROLLBACK_RESISTANCE)
            )
            parsedAuthorizationMap.findOptionalIntegerAuthorizationListEntry(KM_TAG_ACTIVE_DATE_TIME)
                .ifPresent { value -> builder.setActiveDateTime(value) }
            parsedAuthorizationMap.findOptionalIntegerAuthorizationListEntry(KM_TAG_ORIGINATION_EXPIRE_DATE_TIME)
                .ifPresent { value -> builder.setOriginationExpireDateTime(value) }
            parsedAuthorizationMap.findOptionalIntegerAuthorizationListEntry(KM_TAG_USAGE_EXPIRE_DATE_TIME)
                .ifPresent { value -> builder.setUsageExpireDateTime(value) }
            builder.setNoAuthRequired(
                parsedAuthorizationMap.findBooleanAuthorizationListEntry(KM_TAG_NO_AUTH_REQUIRED)
            )
            parsedAuthorizationMap.findOptionalLongAuthorizationListEntry(KM_TAG_USER_AUTH_TYPE)
                .ifPresent { value -> builder.setUserAuthType(value) }
            parsedAuthorizationMap.findOptionalIntegerAuthorizationListEntry(KM_TAG_AUTH_TIMEOUT)
                .ifPresent { value -> builder.setAuthTimeout(value) }
            builder.setAllowWhileOnBody(
                parsedAuthorizationMap.findBooleanAuthorizationListEntry(KM_TAG_ALLOW_WHILE_ON_BODY)
            )
            builder.setTrustedUserPresenceRequired(
                parsedAuthorizationMap.findBooleanAuthorizationListEntry(
                    KM_TAG_TRUSTED_USER_PRESENCE_REQUIRED
                )
            )
            builder.setTrustedConfirmationRequired(
                parsedAuthorizationMap.findBooleanAuthorizationListEntry(
                    KM_TAG_TRUSTED_CONFIRMATION_REQUIRED
                )
            )
            builder.setUnlockedDeviceRequired(
                parsedAuthorizationMap.findBooleanAuthorizationListEntry(KM_TAG_UNLOCKED_DEVICE_REQUIRED)
            )
            parsedAuthorizationMap.findOptionalLongAuthorizationListEntry(KM_TAG_CREATION_DATE_TIME)
                .ifPresent { value -> builder.setCreationDateTime(value) }
            parsedAuthorizationMap.findOptionalIntegerAuthorizationListEntry(KM_TAG_ORIGIN)
                .ifPresent { value -> builder.setOrigin(value) }
            parsedAuthorizationMap.findAuthorizationListEntry(KM_TAG_ROOT_OF_TRUST)
                .map { obj -> ASN1Sequence::class.java.cast(obj) }.map { rootOfTrust ->
                    createRootOfTrust(
                        rootOfTrust!!, attestationVersion
                    )
                }.ifPresent { rootOfTrust -> builder.setRootOfTrust(rootOfTrust) }
            parsedAuthorizationMap.findOptionalIntegerAuthorizationListEntry(KM_TAG_OS_VERSION)
                .ifPresent { osVersion -> builder.setOsVersion(osVersion) }
            parsedAuthorizationMap.findOptionalIntegerAuthorizationListEntry(KM_TAG_OS_PATCH_LEVEL)
                .ifPresent { value -> builder.setOsPatchLevel(value) }
            parsedAuthorizationMap.findAuthorizationListEntry(KM_TAG_ATTESTATION_APPLICATION_ID)
                .map { obj -> ASN1OctetString::class.java.cast(obj) }.map { obj -> obj.octets }
                .map { obj -> AttestationApplicationId.createAttestationApplicationId(obj) }
                .ifPresent { attestationApplicationId: AttestationApplicationId? ->
                    builder.setAttestationApplicationId(
                        attestationApplicationId
                    )
                }
            parsedAuthorizationMap.findOptionalByteArrayAuthorizationListEntry(KM_TAG_ATTESTATION_ID_BRAND)
                .ifPresent { attestationIdBrand -> builder.setAttestationIdBrand(attestationIdBrand) }
            parsedAuthorizationMap.findOptionalByteArrayAuthorizationListEntry(KM_TAG_ATTESTATION_ID_DEVICE)
                .ifPresent { attestationIdDevice -> builder.setAttestationIdDevice(attestationIdDevice) }
            parsedAuthorizationMap.findOptionalByteArrayAuthorizationListEntry(KM_TAG_ATTESTATION_ID_PRODUCT)
                .ifPresent { attestationIdProduct -> builder.setAttestationIdProduct(attestationIdProduct) }
            parsedAuthorizationMap.findOptionalByteArrayAuthorizationListEntry(KM_TAG_ATTESTATION_ID_SERIAL)
                .ifPresent { attestationIdSerial -> builder.setAttestationIdSerial(attestationIdSerial) }
            parsedAuthorizationMap.findOptionalByteArrayAuthorizationListEntry(KM_TAG_ATTESTATION_ID_IMEI)
                .ifPresent { attestationIdImei -> builder.setAttestationIdImei(attestationIdImei) }
            parsedAuthorizationMap.findOptionalByteArrayAuthorizationListEntry(KM_TAG_ATTESTATION_ID_SECOND_IMEI)
                .ifPresent { attestationIdSecondImei ->
                    builder.setAttestationIdSecondImei(
                        attestationIdSecondImei
                    )
                }
            parsedAuthorizationMap.findOptionalByteArrayAuthorizationListEntry(KM_TAG_ATTESTATION_ID_MEID)
                .ifPresent { attestationIdMeid -> builder.setAttestationIdMeid(attestationIdMeid) }
            parsedAuthorizationMap.findOptionalByteArrayAuthorizationListEntry(KM_TAG_ATTESTATION_ID_MANUFACTURER)
                .ifPresent { attestationIdManufacturer ->
                    builder.setAttestationIdManufacturer(
                        attestationIdManufacturer
                    )
                }
            parsedAuthorizationMap.findOptionalByteArrayAuthorizationListEntry(KM_TAG_ATTESTATION_ID_MODEL)
                .ifPresent { attestationIdModel -> builder.setAttestationIdModel(attestationIdModel) }
            parsedAuthorizationMap.findOptionalIntegerAuthorizationListEntry(KM_TAG_VENDOR_PATCH_LEVEL)
                .ifPresent { vendorPatchLevel -> builder.setVendorPatchLevel(vendorPatchLevel) }
            parsedAuthorizationMap.findOptionalIntegerAuthorizationListEntry(KM_TAG_BOOT_PATCH_LEVEL)
                .ifPresent { bootPatchLevel -> builder.setBootPatchLevel(bootPatchLevel) }
            builder.setDeviceUniqueAttestation(
                parsedAuthorizationMap.findBooleanAuthorizationListEntry(KM_TAG_DEVICE_UNIQUE_ATTESTATION)
            )

            return builder.build()
        }

        private fun getAuthorizationMap(authorizationList: Array<ASN1Encodable>): ParsedAuthorizationMap {
            // authorizationMap must retain the order of authorizationList, otherwise
            // the code searching for out of order tags below will break. Helpfully
            // a ImmutableMap preserves insertion order.
            //
            // https://guava.dev/releases/23.0/api/docs/com/google/common/collect/ImmutableCollection.html
            val authorizationMap = Arrays.stream(authorizationList).map { o -> ASN1TaggedObject.getInstance(o) }
                .collect(ImmutableMap.toImmutableMap({ obj: ASN1TaggedObject -> obj.tagNo },
                    { obj: ASN1TaggedObject -> obj.explicitBaseObject })
                )
            return ParsedAuthorizationMap(authorizationMap)
        }
    }
}
