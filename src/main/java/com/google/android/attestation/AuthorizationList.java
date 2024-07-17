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

package com.google.android.attestation;

import static com.google.android.attestation.Constants.KM_TAG_ACTIVE_DATE_TIME;
import static com.google.android.attestation.Constants.KM_TAG_ALGORITHM;
import static com.google.android.attestation.Constants.KM_TAG_ALLOW_WHILE_ON_BODY;
import static com.google.android.attestation.Constants.KM_TAG_ATTESTATION_APPLICATION_ID;
import static com.google.android.attestation.Constants.KM_TAG_ATTESTATION_ID_BRAND;
import static com.google.android.attestation.Constants.KM_TAG_ATTESTATION_ID_DEVICE;
import static com.google.android.attestation.Constants.KM_TAG_ATTESTATION_ID_IMEI;
import static com.google.android.attestation.Constants.KM_TAG_ATTESTATION_ID_MANUFACTURER;
import static com.google.android.attestation.Constants.KM_TAG_ATTESTATION_ID_MEID;
import static com.google.android.attestation.Constants.KM_TAG_ATTESTATION_ID_MODEL;
import static com.google.android.attestation.Constants.KM_TAG_ATTESTATION_ID_PRODUCT;
import static com.google.android.attestation.Constants.KM_TAG_ATTESTATION_ID_SECOND_IMEI;
import static com.google.android.attestation.Constants.KM_TAG_ATTESTATION_ID_SERIAL;
import static com.google.android.attestation.Constants.KM_TAG_AUTH_TIMEOUT;
import static com.google.android.attestation.Constants.KM_TAG_BOOT_PATCH_LEVEL;
import static com.google.android.attestation.Constants.KM_TAG_CREATION_DATE_TIME;
import static com.google.android.attestation.Constants.KM_TAG_DEVICE_UNIQUE_ATTESTATION;
import static com.google.android.attestation.Constants.KM_TAG_DIGEST;
import static com.google.android.attestation.Constants.KM_TAG_EC_CURVE;
import static com.google.android.attestation.Constants.KM_TAG_KEY_SIZE;
import static com.google.android.attestation.Constants.KM_TAG_NO_AUTH_REQUIRED;
import static com.google.android.attestation.Constants.KM_TAG_ORIGIN;
import static com.google.android.attestation.Constants.KM_TAG_ORIGINATION_EXPIRE_DATE_TIME;
import static com.google.android.attestation.Constants.KM_TAG_OS_PATCH_LEVEL;
import static com.google.android.attestation.Constants.KM_TAG_OS_VERSION;
import static com.google.android.attestation.Constants.KM_TAG_PADDING;
import static com.google.android.attestation.Constants.KM_TAG_PURPOSE;
import static com.google.android.attestation.Constants.KM_TAG_ROLLBACK_RESISTANCE;
import static com.google.android.attestation.Constants.KM_TAG_ROOT_OF_TRUST;
import static com.google.android.attestation.Constants.KM_TAG_RSA_OAEP_MGF_DIGEST;
import static com.google.android.attestation.Constants.KM_TAG_RSA_PUBLIC_EXPONENT;
import static com.google.android.attestation.Constants.KM_TAG_TRUSTED_CONFIRMATION_REQUIRED;
import static com.google.android.attestation.Constants.KM_TAG_TRUSTED_USER_PRESENCE_REQUIRED;
import static com.google.android.attestation.Constants.KM_TAG_UNLOCKED_DEVICE_REQUIRED;
import static com.google.android.attestation.Constants.KM_TAG_USAGE_EXPIRE_DATE_TIME;
import static com.google.android.attestation.Constants.KM_TAG_USER_AUTH_TYPE;
import static com.google.android.attestation.Constants.KM_TAG_VENDOR_PATCH_LEVEL;
import static com.google.common.collect.ImmutableMap.toImmutableMap;
import static com.google.common.collect.ImmutableSet.toImmutableSet;
import static com.google.common.collect.Streams.stream;
import static java.util.Arrays.stream;

import com.google.auto.value.AutoValue;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import com.google.errorprone.annotations.CanIgnoreReturnValue;
import com.google.errorprone.annotations.Immutable;
import com.google.protobuf.ByteString;
import java.util.Optional;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1TaggedObject;

/**
 * This data structure contains the key pair's properties themselves, as defined in the Keymaster
 * hardware abstraction layer (HAL). You compare these values to the device's current state or to a
 * set of expected values to verify that a key pair is still valid for use in your app.
 */
@AutoValue
@Immutable
public abstract class AuthorizationList {
  public abstract ImmutableSet<Integer> purpose();

  public abstract Optional<Integer> algorithm();

  public abstract Optional<Integer> keySize();

  public abstract ImmutableSet<Integer> digest();

  public abstract ImmutableSet<Integer> padding();

  public abstract Optional<Integer> ecCurve();

  public abstract Optional<Long> rsaPublicExponent();

  public abstract ImmutableSet<Integer> mgfDigest();

  public abstract boolean rollbackResistance();

  // TODO earlyBootOnly

  public abstract Optional<Integer> activeDateTime();

  public abstract Optional<Integer> originationExpireDateTime();

  public abstract Optional<Integer> usageExpireDateTime();

  // TODO usageCountLimit

  public abstract boolean noAuthRequired();

  public abstract Optional<Long> userAuthType();

  public abstract Optional<Integer> authTimeout();

  public abstract boolean allowWhileOnBody();

  public abstract boolean trustedUserPresenceRequired();

  public abstract boolean trustedConfirmationRequired();

  public abstract boolean unlockedDeviceRequired();

  public abstract Optional<Long> creationDateTime();

  public abstract Optional<Integer> origin();

  public abstract Optional<RootOfTrust> rootOfTrust();

  public abstract Optional<Integer> osVersion();

  public abstract Optional<Integer> osPatchLevel();

  public abstract Optional<AttestationApplicationId> attestationApplicationId();

  public abstract Optional<ByteString> attestationIdBrand();

  public abstract Optional<ByteString> attestationIdDevice();

  public abstract Optional<ByteString> attestationIdProduct();

  public abstract Optional<ByteString> attestationIdSerial();

  public abstract Optional<ByteString> attestationIdImei();

  public abstract Optional<ByteString> attestationIdMeid();

  public abstract Optional<ByteString> attestationIdManufacturer();

  public abstract Optional<ByteString> attestationIdModel();

  public abstract Optional<Integer> vendorPatchLevel();

  public abstract Optional<Integer> bootPatchLevel();

  public abstract boolean deviceUniqueAttestation();

  public abstract Optional<ByteString> attestationIdSecondImei();

  public static Builder builder() {
    return new AutoValue_AuthorizationList.Builder()
        .setRollbackResistance(false)
        .setNoAuthRequired(false)
        .setAllowWhileOnBody(false)
        .setTrustedUserPresenceRequired(false)
        .setTrustedConfirmationRequired(false)
        .setUnlockedDeviceRequired(false)
        .setDeviceUniqueAttestation(false);
  }

  /**
   * Builder for an AuthorizationList. Any field not set will be made an Optional.empty or set with
   * the default value.
   */
  @AutoValue.Builder
  public abstract static class Builder {
    abstract ImmutableSet.Builder<Integer> purposeBuilder();

    @CanIgnoreReturnValue
    public final Builder addPurpose(Integer value) {
      purposeBuilder().add(value);
      return this;
    }

    public abstract Builder setAlgorithm(Integer value);

    public abstract Builder setKeySize(Integer keySize);

    abstract ImmutableSet.Builder<Integer> digestBuilder();

    @CanIgnoreReturnValue
    public final Builder addDigest(Integer value) {
      digestBuilder().add(value);
      return this;
    }

    abstract ImmutableSet.Builder<Integer> paddingBuilder();

    @CanIgnoreReturnValue
    public final Builder addPadding(Integer value) {
      paddingBuilder().add(value);
      return this;
    }

    public abstract Builder setEcCurve(Integer ecCurve);

    public abstract Builder setRsaPublicExponent(Long value);

    abstract ImmutableSet.Builder<Integer> mgfDigestBuilder();

    @CanIgnoreReturnValue
    public final Builder addMgfDigest(Integer value) {
      mgfDigestBuilder().add(value);
      return this;
    }

    public abstract Builder setRollbackResistance(boolean value);

    public abstract Builder setActiveDateTime(Integer value);

    public abstract Builder setOriginationExpireDateTime(Integer value);

    public abstract Builder setUsageExpireDateTime(Integer value);

    public abstract Builder setNoAuthRequired(boolean value);

    public abstract Builder setUserAuthType(Long value);

    public abstract Builder setAuthTimeout(Integer value);

    public abstract Builder setAllowWhileOnBody(boolean value);

    public abstract Builder setTrustedUserPresenceRequired(boolean value);

    public abstract Builder setTrustedConfirmationRequired(boolean value);

    public abstract Builder setUnlockedDeviceRequired(boolean value);

    public abstract Builder setCreationDateTime(Long value);

    public abstract Builder setOrigin(Integer value);

    public abstract Builder setRootOfTrust(RootOfTrust rootOfTrust);

    public abstract Builder setOsVersion(Integer osVersion);

    public abstract Builder setOsPatchLevel(Integer value);

    public abstract Builder setAttestationApplicationId(
        AttestationApplicationId attestationApplicationId);

    public abstract Builder setAttestationIdBrand(ByteString attestationIdBrand);

    @CanIgnoreReturnValue
    public final Builder setAttestationIdBrand(String value) {
      return setAttestationIdBrand(ByteString.copyFromUtf8(value));
    }

    public abstract Builder setAttestationIdDevice(ByteString attestationIdDevice);

    @CanIgnoreReturnValue
    public final Builder setAttestationIdDevice(String value) {
      return setAttestationIdDevice(ByteString.copyFromUtf8(value));
    }

    public abstract Builder setAttestationIdProduct(ByteString attestationIdProduct);

    @CanIgnoreReturnValue
    public final Builder setAttestationIdProduct(String value) {
      return setAttestationIdProduct(ByteString.copyFromUtf8(value));
    }

    public abstract Builder setAttestationIdSerial(ByteString attestationIdSerial);

    @CanIgnoreReturnValue
    public final Builder setAttestationIdSerial(String value) {
      return setAttestationIdSerial(ByteString.copyFromUtf8(value));
    }

    public abstract Builder setAttestationIdImei(ByteString attestationIdImei);

    @CanIgnoreReturnValue
    public final Builder setAttestationIdImei(String value) {
      return setAttestationIdImei(ByteString.copyFromUtf8(value));
    }

    public abstract Builder setAttestationIdSecondImei(ByteString attestationIdSecondImei);

    @CanIgnoreReturnValue
    public final Builder setAttestationIdSecondImei(String value) {
      return setAttestationIdSecondImei(ByteString.copyFromUtf8(value));
    }

    public abstract Builder setAttestationIdMeid(ByteString attestationIdMeid);

    @CanIgnoreReturnValue
    public final Builder setAttestationIdMeid(String value) {
      return setAttestationIdMeid(ByteString.copyFromUtf8(value));
    }

    public abstract Builder setAttestationIdManufacturer(ByteString attestationIdManufacturer);

    @CanIgnoreReturnValue
    public final Builder setAttestationIdManufacturer(String value) {
      return setAttestationIdManufacturer(ByteString.copyFromUtf8(value));
    }

    public abstract Builder setAttestationIdModel(ByteString attestationIdModel);

    @CanIgnoreReturnValue
    public final Builder setAttestationIdModel(String value) {
      return setAttestationIdModel(ByteString.copyFromUtf8(value));
    }

    public abstract Builder setVendorPatchLevel(Integer vendorPatchLevel);

    public abstract Builder setBootPatchLevel(Integer bootPatchLevel);

    public abstract Builder setDeviceUniqueAttestation(boolean value);

    public abstract AuthorizationList build();
  }

  static AuthorizationList createAuthorizationList(
      ASN1Encodable[] authorizationList, int attestationVersion) {
    Builder builder = AuthorizationList.builder();
    ParsedAuthorizationMap parsedAuthorizationMap = getAuthorizationMap(authorizationList);
    parsedAuthorizationMap.findIntegerSetAuthorizationListEntry(KM_TAG_PURPOSE).stream()
        .forEach(builder::addPurpose);
    parsedAuthorizationMap
        .findOptionalIntegerAuthorizationListEntry(KM_TAG_ALGORITHM)
        .ifPresent(builder::setAlgorithm);

    parsedAuthorizationMap
        .findOptionalIntegerAuthorizationListEntry(KM_TAG_KEY_SIZE)
        .ifPresent(builder::setKeySize);
    parsedAuthorizationMap.findIntegerSetAuthorizationListEntry(KM_TAG_DIGEST).stream()
        .forEach(builder::addDigest);
    parsedAuthorizationMap.findIntegerSetAuthorizationListEntry(KM_TAG_PADDING).stream()
        .forEach(builder::addPadding);
    parsedAuthorizationMap
        .findOptionalIntegerAuthorizationListEntry(KM_TAG_EC_CURVE)
        .ifPresent(builder::setEcCurve);
    parsedAuthorizationMap
        .findOptionalLongAuthorizationListEntry(KM_TAG_RSA_PUBLIC_EXPONENT)
        .ifPresent(builder::setRsaPublicExponent);
    parsedAuthorizationMap.findIntegerSetAuthorizationListEntry(KM_TAG_RSA_OAEP_MGF_DIGEST).stream()
        .forEach(builder::addMgfDigest);
    builder.setRollbackResistance(
        parsedAuthorizationMap.findBooleanAuthorizationListEntry(KM_TAG_ROLLBACK_RESISTANCE));
    parsedAuthorizationMap
        .findOptionalIntegerAuthorizationListEntry(KM_TAG_ACTIVE_DATE_TIME)
        .ifPresent(builder::setActiveDateTime);
    parsedAuthorizationMap
        .findOptionalIntegerAuthorizationListEntry(KM_TAG_ORIGINATION_EXPIRE_DATE_TIME)
        .ifPresent(builder::setOriginationExpireDateTime);
    parsedAuthorizationMap
        .findOptionalIntegerAuthorizationListEntry(KM_TAG_USAGE_EXPIRE_DATE_TIME)
        .ifPresent(builder::setUsageExpireDateTime);
    builder.setNoAuthRequired(
        parsedAuthorizationMap.findBooleanAuthorizationListEntry(KM_TAG_NO_AUTH_REQUIRED));
    parsedAuthorizationMap
        .findOptionalLongAuthorizationListEntry(KM_TAG_USER_AUTH_TYPE)
        .ifPresent(builder::setUserAuthType);
    parsedAuthorizationMap
        .findOptionalIntegerAuthorizationListEntry(KM_TAG_AUTH_TIMEOUT)
        .ifPresent(builder::setAuthTimeout);
    builder.setAllowWhileOnBody(
        parsedAuthorizationMap.findBooleanAuthorizationListEntry(KM_TAG_ALLOW_WHILE_ON_BODY));
    builder.setTrustedUserPresenceRequired(
        parsedAuthorizationMap.findBooleanAuthorizationListEntry(
            KM_TAG_TRUSTED_USER_PRESENCE_REQUIRED));
    builder.setTrustedConfirmationRequired(
        parsedAuthorizationMap.findBooleanAuthorizationListEntry(
            KM_TAG_TRUSTED_CONFIRMATION_REQUIRED));
    builder.setUnlockedDeviceRequired(
        parsedAuthorizationMap.findBooleanAuthorizationListEntry(KM_TAG_UNLOCKED_DEVICE_REQUIRED));
    parsedAuthorizationMap
        .findOptionalLongAuthorizationListEntry(KM_TAG_CREATION_DATE_TIME)
        .ifPresent(builder::setCreationDateTime);
    parsedAuthorizationMap
        .findOptionalIntegerAuthorizationListEntry(KM_TAG_ORIGIN)
        .ifPresent(builder::setOrigin);
    parsedAuthorizationMap
        .findAuthorizationListEntry(KM_TAG_ROOT_OF_TRUST)
        .map(ASN1Sequence.class::cast)
        .map(rootOfTrust -> RootOfTrust.createRootOfTrust(rootOfTrust, attestationVersion))
        .ifPresent(builder::setRootOfTrust);
    parsedAuthorizationMap
        .findOptionalIntegerAuthorizationListEntry(KM_TAG_OS_VERSION)
        .ifPresent(builder::setOsVersion);
    parsedAuthorizationMap
        .findOptionalIntegerAuthorizationListEntry(KM_TAG_OS_PATCH_LEVEL)
        .ifPresent(builder::setOsPatchLevel);
    parsedAuthorizationMap
        .findAuthorizationListEntry(KM_TAG_ATTESTATION_APPLICATION_ID)
        .map(ASN1OctetString.class::cast)
        .map(ASN1OctetString::getOctets)
        .map(AttestationApplicationId::createAttestationApplicationId)
        .ifPresent(builder::setAttestationApplicationId);
    parsedAuthorizationMap
        .findOptionalByteArrayAuthorizationListEntry(KM_TAG_ATTESTATION_ID_BRAND)
        .ifPresent(builder::setAttestationIdBrand);
    parsedAuthorizationMap
        .findOptionalByteArrayAuthorizationListEntry(KM_TAG_ATTESTATION_ID_DEVICE)
        .ifPresent(builder::setAttestationIdDevice);
    parsedAuthorizationMap
        .findOptionalByteArrayAuthorizationListEntry(KM_TAG_ATTESTATION_ID_PRODUCT)
        .ifPresent(builder::setAttestationIdProduct);
    parsedAuthorizationMap
        .findOptionalByteArrayAuthorizationListEntry(KM_TAG_ATTESTATION_ID_SERIAL)
        .ifPresent(builder::setAttestationIdSerial);
    parsedAuthorizationMap
        .findOptionalByteArrayAuthorizationListEntry(KM_TAG_ATTESTATION_ID_IMEI)
        .ifPresent(builder::setAttestationIdImei);
    parsedAuthorizationMap
        .findOptionalByteArrayAuthorizationListEntry(KM_TAG_ATTESTATION_ID_SECOND_IMEI)
        .ifPresent(builder::setAttestationIdSecondImei);
    parsedAuthorizationMap
        .findOptionalByteArrayAuthorizationListEntry(KM_TAG_ATTESTATION_ID_MEID)
        .ifPresent(builder::setAttestationIdMeid);
    parsedAuthorizationMap
        .findOptionalByteArrayAuthorizationListEntry(KM_TAG_ATTESTATION_ID_MANUFACTURER)
        .ifPresent(builder::setAttestationIdManufacturer);
    parsedAuthorizationMap
        .findOptionalByteArrayAuthorizationListEntry(KM_TAG_ATTESTATION_ID_MODEL)
        .ifPresent(builder::setAttestationIdModel);
    parsedAuthorizationMap
        .findOptionalIntegerAuthorizationListEntry(KM_TAG_VENDOR_PATCH_LEVEL)
        .ifPresent(builder::setVendorPatchLevel);
    parsedAuthorizationMap
        .findOptionalIntegerAuthorizationListEntry(KM_TAG_BOOT_PATCH_LEVEL)
        .ifPresent(builder::setBootPatchLevel);
    builder.setDeviceUniqueAttestation(
        parsedAuthorizationMap.findBooleanAuthorizationListEntry(KM_TAG_DEVICE_UNIQUE_ATTESTATION));

    return builder.build();
  }

  private static ParsedAuthorizationMap getAuthorizationMap(ASN1Encodable[] authorizationList) {
    // authorizationMap must retain the order of authorizationList, otherwise
    // the code searching for out of order tags below will break. Helpfully
    // a ImmutableMap preserves insertion order.
    //
    // https://guava.dev/releases/23.0/api/docs/com/google/common/collect/ImmutableCollection.html
    ImmutableMap<Integer, ASN1Object> authorizationMap =
        stream(authorizationList)
            .map(ASN1TaggedObject::getInstance)
            .collect(
                toImmutableMap(
                    ASN1TaggedObject::getTagNo, ASN1TaggedObject::getExplicitBaseObject));
    return new ParsedAuthorizationMap(authorizationMap);
  }

  /**
   * This data structure holds the parsed attest record authorizations mapped to their authorization
   * tags.
   */
  private static class ParsedAuthorizationMap {
    private final ImmutableMap<Integer, ASN1Object> authorizationMap;

    private ParsedAuthorizationMap(ImmutableMap<Integer, ASN1Object> authorizationMap) {
      this.authorizationMap = authorizationMap;
    }

    private Optional<ASN1Object> findAuthorizationListEntry(int tag) {
      return Optional.ofNullable(authorizationMap.get(tag));
    }

    private ImmutableSet<Integer> findIntegerSetAuthorizationListEntry(int tag) {
      ASN1Set asn1Set = findAuthorizationListEntry(tag).map(ASN1Set.class::cast).orElse(null);
      if (asn1Set == null) {
        return ImmutableSet.of();
      }
      return stream(asn1Set).map(ASN1Parsing::getIntegerFromAsn1).collect(toImmutableSet());
    }

    private Optional<Integer> findOptionalIntegerAuthorizationListEntry(int tag) {
      return findAuthorizationListEntry(tag)
          .map(ASN1Integer.class::cast)
          .map(ASN1Parsing::getIntegerFromAsn1);
    }

    private Optional<Long> findOptionalLongAuthorizationListEntry(int tag) {
      return findAuthorizationListEntry(tag)
          .map(ASN1Integer.class::cast)
          .map(value -> value.getValue().longValue());
    }

    private boolean findBooleanAuthorizationListEntry(int tag) {
      return findAuthorizationListEntry(tag).isPresent();
    }

    private Optional<ByteString> findOptionalByteArrayAuthorizationListEntry(int tag) {
      return findAuthorizationListEntry(tag)
          .map(ASN1OctetString.class::cast)
          .map(ASN1OctetString::getOctets)
          .map(ByteString::copyFrom);
    }
  }
}
