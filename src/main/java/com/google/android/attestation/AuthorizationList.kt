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
import com.google.common.collect.ImmutableMap
import com.google.common.collect.ImmutableSet
import com.google.common.collect.Streams
import com.google.errorprone.annotations.Immutable
import com.google.protobuf.ByteString
import org.bouncycastle.asn1.*
import java.util.*

/**
 * This data structure contains the key pair's properties themselves, as defined in the Keymaster
 * hardware abstraction layer (HAL). You compare these values to the device's current state or to a
 * set of expected values to verify that a key pair is still valid for use in your app.
 */
@Immutable
data class AuthorizationList(
    val purpose: ImmutableSet<Int>,
    val algorithm: Int?,
    val keySize: Int?,
    val digest: ImmutableSet<Int>,
    val padding: ImmutableSet<Int>,
    val ecCurve: Int?,
    val rsaPublicExponent: Long?,
    val mgfDigest: ImmutableSet<Int>,
    val rollbackResistance: Boolean,
    // TODO earlyBootOnly
    val activeDateTime: Int?,
    val originationExpireDateTime: Int?,
    val usageExpireDateTime: Int?,
    // TODO usageCountLimit
    val noAuthRequired: Boolean,
    val userAuthType: Long?,
    val authTimeout: Int?,
    val allowWhileOnBody: Boolean,
    val trustedUserPresenceRequired: Boolean,
    val trustedConfirmationRequired: Boolean,
    val unlockedDeviceRequired: Boolean,
    val creationDateTime: Long?,
    val origin: Int?,
    val rootOfTrust: RootOfTrust?,
    val osVersion: Int?,
    val osPatchLevel: Int?,
    val attestationApplicationId: AttestationApplicationId?,
    val attestationIdBrand: ByteString?,
    val attestationIdDevice: ByteString?,
    val attestationIdProduct: ByteString?,
    val attestationIdSerial: ByteString?,
    val attestationIdImei: ByteString?,
    val attestationIdMeid: ByteString?,
    val attestationIdManufacturer: ByteString?,
    val attestationIdModel: ByteString?,
    val vendorPatchLevel: Int?,
    val bootPatchLevel: Int?,
    val deviceUniqueAttestation: Boolean,
    val attestationIdSecondImei: ByteString?,
) {
    /**
     * This data structure holds the parsed attest record authorizations mapped to their authorization
     * tags.
     */
    private class ParsedAuthorizationMap(private val authorizationMap: ImmutableMap<Int, ASN1Object>) {
        // TODO remove Optional<>
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

        fun findOptionalIntegerAuthorizationListEntry(tag: Int): Int? {
            return findAuthorizationListEntry(tag).map { obj -> ASN1Parsing.getIntegerFromAsn1(obj as ASN1Integer) }
                .orElse(null)
        }

        fun findOptionalLongAuthorizationListEntry(tag: Int): Long? {
            return findAuthorizationListEntry(tag).map { obj -> (obj as ASN1Integer).value.toLong() }.orElse(null)
        }

        fun findBooleanAuthorizationListEntry(tag: Int): Boolean {
            return findAuthorizationListEntry(tag).isPresent
        }

        fun findOptionalByteArrayAuthorizationListEntry(tag: Int): ByteString? {
            return findAuthorizationListEntry(tag).map { obj -> ByteString.copyFrom((obj as ASN1OctetString).octets) }
                .orElse(null)
        }
    }

    companion object {
        @JvmStatic
        fun createAuthorizationList(
            authorizationList: Array<ASN1Encodable>, attestationVersion: Int
        ): AuthorizationList {
            val parsedAuthorizationMap = getAuthorizationMap(authorizationList)
            val rootOfTrust = parsedAuthorizationMap.findAuthorizationListEntry(KM_TAG_ROOT_OF_TRUST)
                .map { obj -> createRootOfTrust((obj as ASN1Sequence), attestationVersion) }.orElse(null)
            val attestationApplicationId =
                parsedAuthorizationMap.findAuthorizationListEntry(KM_TAG_ATTESTATION_APPLICATION_ID)
                    .map { obj -> AttestationApplicationId.createAttestationApplicationId((obj as ASN1OctetString).octets) }
                    .orElse(null)
            return AuthorizationList(
                parsedAuthorizationMap.findIntegerSetAuthorizationListEntry(KM_TAG_PURPOSE),
                parsedAuthorizationMap.findOptionalIntegerAuthorizationListEntry(KM_TAG_ALGORITHM),
                parsedAuthorizationMap.findOptionalIntegerAuthorizationListEntry(KM_TAG_KEY_SIZE),
                parsedAuthorizationMap.findIntegerSetAuthorizationListEntry(KM_TAG_DIGEST),
                parsedAuthorizationMap.findIntegerSetAuthorizationListEntry(KM_TAG_PADDING),
                parsedAuthorizationMap.findOptionalIntegerAuthorizationListEntry(KM_TAG_EC_CURVE),
                parsedAuthorizationMap.findOptionalLongAuthorizationListEntry(KM_TAG_RSA_PUBLIC_EXPONENT),
                parsedAuthorizationMap.findIntegerSetAuthorizationListEntry(KM_TAG_RSA_OAEP_MGF_DIGEST),
                parsedAuthorizationMap.findBooleanAuthorizationListEntry(KM_TAG_ROLLBACK_RESISTANCE),
                parsedAuthorizationMap.findOptionalIntegerAuthorizationListEntry(KM_TAG_ACTIVE_DATE_TIME),
                parsedAuthorizationMap.findOptionalIntegerAuthorizationListEntry(
                    KM_TAG_ORIGINATION_EXPIRE_DATE_TIME
                ),
                parsedAuthorizationMap.findOptionalIntegerAuthorizationListEntry(KM_TAG_USAGE_EXPIRE_DATE_TIME),
                parsedAuthorizationMap.findBooleanAuthorizationListEntry(KM_TAG_NO_AUTH_REQUIRED),
                parsedAuthorizationMap.findOptionalLongAuthorizationListEntry(KM_TAG_USER_AUTH_TYPE),
                parsedAuthorizationMap.findOptionalIntegerAuthorizationListEntry(KM_TAG_AUTH_TIMEOUT),
                parsedAuthorizationMap.findBooleanAuthorizationListEntry(KM_TAG_ALLOW_WHILE_ON_BODY),
                parsedAuthorizationMap.findBooleanAuthorizationListEntry(KM_TAG_TRUSTED_USER_PRESENCE_REQUIRED),
                parsedAuthorizationMap.findBooleanAuthorizationListEntry(KM_TAG_TRUSTED_CONFIRMATION_REQUIRED),
                parsedAuthorizationMap.findBooleanAuthorizationListEntry(KM_TAG_UNLOCKED_DEVICE_REQUIRED),
                parsedAuthorizationMap.findOptionalLongAuthorizationListEntry(KM_TAG_CREATION_DATE_TIME),
                parsedAuthorizationMap.findOptionalIntegerAuthorizationListEntry(KM_TAG_ORIGIN),
                rootOfTrust,
                parsedAuthorizationMap.findOptionalIntegerAuthorizationListEntry(KM_TAG_OS_VERSION),
                parsedAuthorizationMap.findOptionalIntegerAuthorizationListEntry(KM_TAG_OS_PATCH_LEVEL),
                attestationApplicationId,
                parsedAuthorizationMap.findOptionalByteArrayAuthorizationListEntry(KM_TAG_ATTESTATION_ID_BRAND),
                parsedAuthorizationMap.findOptionalByteArrayAuthorizationListEntry(KM_TAG_ATTESTATION_ID_DEVICE),
                parsedAuthorizationMap.findOptionalByteArrayAuthorizationListEntry(KM_TAG_ATTESTATION_ID_PRODUCT),
                parsedAuthorizationMap.findOptionalByteArrayAuthorizationListEntry(KM_TAG_ATTESTATION_ID_SERIAL),
                parsedAuthorizationMap.findOptionalByteArrayAuthorizationListEntry(KM_TAG_ATTESTATION_ID_IMEI),
                parsedAuthorizationMap.findOptionalByteArrayAuthorizationListEntry(KM_TAG_ATTESTATION_ID_MEID),
                parsedAuthorizationMap.findOptionalByteArrayAuthorizationListEntry(KM_TAG_ATTESTATION_ID_MANUFACTURER),
                parsedAuthorizationMap.findOptionalByteArrayAuthorizationListEntry(KM_TAG_ATTESTATION_ID_MODEL),
                parsedAuthorizationMap.findOptionalIntegerAuthorizationListEntry(KM_TAG_VENDOR_PATCH_LEVEL),
                parsedAuthorizationMap.findOptionalIntegerAuthorizationListEntry(KM_TAG_BOOT_PATCH_LEVEL),
                parsedAuthorizationMap.findBooleanAuthorizationListEntry(KM_TAG_DEVICE_UNIQUE_ATTESTATION),
                parsedAuthorizationMap.findOptionalByteArrayAuthorizationListEntry(KM_TAG_ATTESTATION_ID_SECOND_IMEI)
            )
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
