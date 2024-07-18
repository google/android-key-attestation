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

import static com.google.android.attestation.AuthorizationList.UserAuthType.FINGERPRINT;
import static com.google.android.attestation.AuthorizationList.UserAuthType.PASSWORD;
import static com.google.android.attestation.AuthorizationList.UserAuthType.USER_AUTH_TYPE_ANY;
import static com.google.android.attestation.AuthorizationList.UserAuthType.USER_AUTH_TYPE_NONE;
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
import static com.google.android.attestation.Constants.KM_TAG_ROLLBACK_RESISTANT;
import static com.google.android.attestation.Constants.KM_TAG_ROOT_OF_TRUST;
import static com.google.android.attestation.Constants.KM_TAG_RSA_PUBLIC_EXPONENT;
import static com.google.android.attestation.Constants.KM_TAG_TRUSTED_CONFIRMATION_REQUIRED;
import static com.google.android.attestation.Constants.KM_TAG_TRUSTED_USER_PRESENCE_REQUIRED;
import static com.google.android.attestation.Constants.KM_TAG_UNLOCKED_DEVICE_REQUIRED;
import static com.google.android.attestation.Constants.KM_TAG_USAGE_EXPIRE_DATE_TIME;
import static com.google.android.attestation.Constants.KM_TAG_USER_AUTH_TYPE;
import static com.google.android.attestation.Constants.KM_TAG_VENDOR_PATCH_LEVEL;
import static com.google.android.attestation.Constants.UINT32_MAX;
import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.collect.ImmutableMap.toImmutableMap;
import static com.google.common.collect.ImmutableSet.toImmutableSet;
import static com.google.common.collect.Streams.stream;
import static java.util.Arrays.stream;

import com.google.auto.value.AutoValue;
import com.google.common.annotations.VisibleForTesting;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import com.google.errorprone.annotations.CanIgnoreReturnValue;
import com.google.errorprone.annotations.Immutable;
import com.google.protobuf.ByteString;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDate;
import java.time.YearMonth;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.ASN1Util;

/**
 * This data structure contains the key pair's properties themselves, as defined in the Keymaster
 * hardware abstraction layer (HAL). You compare these values to the device's current state or to a
 * set of expected values to verify that a key pair is still valid for use in your app.
 */
@AutoValue
@Immutable
public abstract class AuthorizationList {
  /** Specifies the types of user authenticators that may be used to authorize this key. */
  public enum UserAuthType {
    USER_AUTH_TYPE_NONE,
    PASSWORD,
    FINGERPRINT,
    USER_AUTH_TYPE_ANY
  }

  /**
   * Asymmetric algorithms from
   * https://cs.android.com/android/platform/superproject/+/master:hardware/interfaces/security/keymint/aidl/android/hardware/security/keymint/Algorithm.aidl
   */
  public enum Algorithm {
    RSA,
    EC,
  }

  private static final ImmutableMap<Integer, Algorithm> ASN1_TO_ALGORITHM =
      ImmutableMap.of(1, Algorithm.RSA, 3, Algorithm.EC);

  /**
   * From
   * https://cs.android.com/android/platform/superproject/+/master:hardware/interfaces/security/keymint/aidl/android/hardware/security/keymint/EcCurve.aidl
   */
  public enum EcCurve {
    P_224,
    P_256,
    P_384,
    P_521,
    CURVE_25519
  }

  private static final ImmutableMap<Integer, EcCurve> ASN1_TO_EC_CURVE =
      ImmutableMap.of(
          0,
          EcCurve.P_224,
          1,
          EcCurve.P_256,
          2,
          EcCurve.P_384,
          3,
          EcCurve.P_521,
          4,
          EcCurve.CURVE_25519);

  /**
   * From
   * https://cs.android.com/android/platform/superproject/+/master:hardware/interfaces/security/keymint/aidl/android/hardware/security/keymint/PaddingMode.aidl
   */
  public enum PaddingMode {
    NONE,
    RSA_OAEP,
    RSA_PSS,
    RSA_PKCS1_1_5_ENCRYPT,
    RSA_PKCS1_1_5_SIGN,
    PKCS7
  }

  static final ImmutableMap<PaddingMode, Integer> PADDING_MODE_TO_ASN1 =
      ImmutableMap.of(
          PaddingMode.NONE,
          1,
          PaddingMode.RSA_OAEP,
          2,
          PaddingMode.RSA_PSS,
          3,
          PaddingMode.RSA_PKCS1_1_5_ENCRYPT,
          4,
          PaddingMode.RSA_PKCS1_1_5_SIGN,
          5,
          PaddingMode.PKCS7,
          64);
  static final ImmutableMap<Integer, PaddingMode> ASN1_TO_PADDING_MODE =
      ImmutableMap.of(
          1,
          PaddingMode.NONE,
          2,
          PaddingMode.RSA_OAEP,
          3,
          PaddingMode.RSA_PSS,
          4,
          PaddingMode.RSA_PKCS1_1_5_ENCRYPT,
          5,
          PaddingMode.RSA_PKCS1_1_5_SIGN,
          64,
          PaddingMode.PKCS7);

  /**
   * From
   * https://cs.android.com/android/platform/superproject/+/master:hardware/interfaces/security/keymint/aidl/android/hardware/security/keymint/Digest.aidl
   */
  public enum DigestMode {
    NONE,
    MD5,
    SHA1,
    SHA_2_224,
    SHA_2_256,
    SHA_2_384,
    SHA_2_512
  }

  static final ImmutableMap<DigestMode, Integer> DIGEST_MODE_TO_ASN1 =
      ImmutableMap.of(
          DigestMode.NONE,
          0,
          DigestMode.MD5,
          1,
          DigestMode.SHA1,
          2,
          DigestMode.SHA_2_224,
          3,
          DigestMode.SHA_2_256,
          4,
          DigestMode.SHA_2_384,
          5,
          DigestMode.SHA_2_512,
          6);
  static final ImmutableMap<Integer, DigestMode> ASN1_TO_DIGEST_MODE =
      ImmutableMap.of(
          0,
          DigestMode.NONE,
          1,
          DigestMode.MD5,
          2,
          DigestMode.SHA1,
          3,
          DigestMode.SHA_2_224,
          4,
          DigestMode.SHA_2_256,
          5,
          DigestMode.SHA_2_384,
          6,
          DigestMode.SHA_2_512);

  /**
   * From
   * https://cs.android.com/android/platform/superproject/+/master:hardware/interfaces/security/keymint/aidl/android/hardware/security/keymint/KeyOrigin.aidl
   */
  public enum KeyOrigin {
    GENERATED,
    DERIVED,
    IMPORTED,
    RESERVED,
    SECURELY_IMPORTED
  }

  static final ImmutableMap<KeyOrigin, Integer> KEY_ORIGIN_TO_ASN1 =
      ImmutableMap.of(
          KeyOrigin.GENERATED,
          0,
          KeyOrigin.IMPORTED,
          1,
          KeyOrigin.DERIVED,
          2,
          KeyOrigin.RESERVED,
          3,
          KeyOrigin.SECURELY_IMPORTED,
          4);
  static final ImmutableMap<Integer, KeyOrigin> ASN1_TO_KEY_ORIGIN =
      ImmutableMap.of(
          0,
          KeyOrigin.GENERATED,
          1,
          KeyOrigin.IMPORTED,
          2,
          KeyOrigin.DERIVED,
          3,
          KeyOrigin.RESERVED,
          4,
          KeyOrigin.SECURELY_IMPORTED);

  /**
   * From
   * https://cs.android.com/android/platform/superproject/+/master:hardware/interfaces/security/keymint/aidl/android/hardware/security/keymint/KeyPurpose.aidl
   */
  public enum OperationPurpose {
    ENCRYPT,
    DECRYPT,
    SIGN,
    VERIFY,
    WRAP_KEY,
    AGREE_KEY,
    ATTEST_KEY
  }

  static final ImmutableMap<OperationPurpose, Integer> OPERATION_PURPOSE_TO_ASN1 =
      ImmutableMap.of(
          OperationPurpose.ENCRYPT,
          0,
          OperationPurpose.DECRYPT,
          1,
          OperationPurpose.SIGN,
          2,
          OperationPurpose.VERIFY,
          3,
          OperationPurpose.WRAP_KEY,
          5,
          OperationPurpose.AGREE_KEY,
          6,
          OperationPurpose.ATTEST_KEY,
          7);
  static final ImmutableMap<Integer, OperationPurpose> ASN1_TO_OPERATION_PURPOSE =
      ImmutableMap.of(
          0,
          OperationPurpose.ENCRYPT,
          1,
          OperationPurpose.DECRYPT,
          2,
          OperationPurpose.SIGN,
          3,
          OperationPurpose.VERIFY,
          5,
          OperationPurpose.WRAP_KEY,
          6,
          OperationPurpose.AGREE_KEY,
          7,
          OperationPurpose.ATTEST_KEY);

  public abstract ImmutableSet<OperationPurpose> purpose();

  public abstract Optional<Algorithm> algorithm();

  public abstract Optional<Integer> keySize();

  public abstract ImmutableSet<DigestMode> digest();

  public abstract ImmutableSet<PaddingMode> padding();

  public abstract Optional<EcCurve> ecCurve();

  public abstract Optional<Long> rsaPublicExponent();

  public abstract boolean rollbackResistance();

  public abstract Optional<Instant> activeDateTime();

  public abstract Optional<Instant> originationExpireDateTime();

  public abstract Optional<Instant> usageExpireDateTime();

  public abstract boolean noAuthRequired();

  public abstract ImmutableSet<UserAuthType> userAuthType();

  public abstract Optional<Duration> authTimeout();

  public abstract boolean allowWhileOnBody();

  public abstract boolean trustedUserPresenceRequired();

  public abstract boolean trustedConfirmationRequired();

  public abstract boolean unlockedDeviceRequired();

  public abstract Optional<Instant> creationDateTime();

  public abstract Optional<KeyOrigin> origin();

  public abstract boolean rollbackResistant();

  public abstract Optional<RootOfTrust> rootOfTrust();

  public abstract Optional<Integer> osVersion();

  public abstract Optional<YearMonth> osPatchLevel();

  public abstract Optional<AttestationApplicationId> attestationApplicationId();

  public abstract Optional<ByteString> attestationIdBrand();

  public abstract Optional<ByteString> attestationIdDevice();

  public abstract Optional<ByteString> attestationIdProduct();

  public abstract Optional<ByteString> attestationIdSerial();

  public abstract Optional<ByteString> attestationIdImei();

  public abstract Optional<ByteString> attestationIdSecondImei();

  public abstract Optional<ByteString> attestationIdMeid();

  public abstract Optional<ByteString> attestationIdManufacturer();

  public abstract Optional<ByteString> attestationIdModel();

  public abstract Optional<LocalDate> vendorPatchLevel();

  public abstract Optional<LocalDate> bootPatchLevel();

  public abstract boolean individualAttestation();


  public abstract ImmutableList<Integer> unorderedTags();

  public static Builder builder() {
    return new AutoValue_AuthorizationList.Builder()
        .setRollbackResistance(false)
        .setNoAuthRequired(false)
        .setAllowWhileOnBody(false)
        .setTrustedUserPresenceRequired(false)
        .setTrustedConfirmationRequired(false)
        .setUnlockedDeviceRequired(false)
        .setRollbackResistant(false)
        .setIndividualAttestation(false);
  }

  /**
   * Builder for an AuthorizationList. Any field not set will be made an Optional.empty or set with
   * the default value.
   */
  @AutoValue.Builder
  public abstract static class Builder {
    abstract ImmutableSet.Builder<OperationPurpose> purposeBuilder();

    @CanIgnoreReturnValue
    public final Builder addPurpose(OperationPurpose value) {
      purposeBuilder().add(value);
      return this;
    }

    public abstract Builder setAlgorithm(Algorithm algorithm);

    public abstract Builder setKeySize(Integer keySize);

    abstract ImmutableSet.Builder<DigestMode> digestBuilder();

    @CanIgnoreReturnValue
    public final Builder addDigest(DigestMode value) {
      digestBuilder().add(value);
      return this;
    }

    abstract ImmutableSet.Builder<PaddingMode> paddingBuilder();

    @CanIgnoreReturnValue
    public final Builder addPadding(PaddingMode value) {
      paddingBuilder().add(value);
      return this;
    }

    public abstract Builder setEcCurve(EcCurve ecCurve);

    public abstract Builder setRsaPublicExponent(Long rsaPublicExponent);

    public abstract Builder setRollbackResistance(boolean rollbackResistance);

    public abstract Builder setActiveDateTime(Instant activeDateTime);

    public abstract Builder setOriginationExpireDateTime(Instant originationExpireDateTime);

    public abstract Builder setUsageExpireDateTime(Instant usageExpireDateTime);

    public abstract Builder setNoAuthRequired(boolean noAuthRequired);

    abstract ImmutableSet.Builder<UserAuthType> userAuthTypeBuilder();

    @CanIgnoreReturnValue
    public final Builder addUserAuthType(UserAuthType value) {
      userAuthTypeBuilder().add(value);
      return this;
    }

    public abstract Builder setAuthTimeout(Duration authTimeout);

    public abstract Builder setAllowWhileOnBody(boolean allowWhileOnBody);

    public abstract Builder setTrustedUserPresenceRequired(boolean trustedUserPresenceRequired);

    public abstract Builder setTrustedConfirmationRequired(boolean trustedConfirmationRequired);

    public abstract Builder setUnlockedDeviceRequired(boolean unlockedDeviceRequired);

    public abstract Builder setCreationDateTime(Instant creationDateTime);

    public abstract Builder setOrigin(KeyOrigin origin);

    public abstract Builder setRollbackResistant(boolean rollbackResistant);

    public abstract Builder setRootOfTrust(RootOfTrust rootOfTrust);

    public abstract Builder setOsVersion(Integer osVersion);

    public abstract Builder setOsPatchLevel(YearMonth osPatchLevel);

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

    public abstract Builder setVendorPatchLevel(LocalDate vendorPatchLevel);

    public abstract Builder setBootPatchLevel(LocalDate bootPatchLevel);

    public abstract Builder setIndividualAttestation(boolean individualAttestation);

    abstract ImmutableList.Builder<Integer> unorderedTagsBuilder();

    @CanIgnoreReturnValue
    public final Builder addUnorderedTag(Integer value) {
      unorderedTagsBuilder().add(value);
      return this;
    }

    public abstract AuthorizationList build();
  }

  static AuthorizationList createAuthorizationList(
      ASN1Encodable[] authorizationList, int attestationVersion) {
    Builder builder = AuthorizationList.builder();
    ParsedAuthorizationMap parsedAuthorizationMap = getAuthorizationMap(authorizationList);
    parsedAuthorizationMap.findIntegerSetAuthorizationListEntry(KM_TAG_PURPOSE).stream()
        .map(ASN1_TO_OPERATION_PURPOSE::get)
        .forEach(builder::addPurpose);
    parsedAuthorizationMap
        .findOptionalIntegerAuthorizationListEntry(KM_TAG_ALGORITHM)
        .map(ASN1_TO_ALGORITHM::get)
        .ifPresent(builder::setAlgorithm);

    parsedAuthorizationMap
        .findOptionalIntegerAuthorizationListEntry(KM_TAG_KEY_SIZE)
        .ifPresent(builder::setKeySize);
    parsedAuthorizationMap.findIntegerSetAuthorizationListEntry(KM_TAG_DIGEST).stream()
        .map(ASN1_TO_DIGEST_MODE::get)
        .forEach(builder::addDigest);
    parsedAuthorizationMap.findIntegerSetAuthorizationListEntry(KM_TAG_PADDING).stream()
        .map(ASN1_TO_PADDING_MODE::get)
        .forEach(builder::addPadding);
    parsedAuthorizationMap
        .findOptionalIntegerAuthorizationListEntry(KM_TAG_EC_CURVE)
        .map(ASN1_TO_EC_CURVE::get)
        .ifPresent(builder::setEcCurve);
    parsedAuthorizationMap
        .findOptionalLongAuthorizationListEntry(KM_TAG_RSA_PUBLIC_EXPONENT)
        .ifPresent(builder::setRsaPublicExponent);
    builder.setRollbackResistance(
        parsedAuthorizationMap.findBooleanAuthorizationListEntry(KM_TAG_ROLLBACK_RESISTANCE));
    parsedAuthorizationMap
        .findOptionalInstantMillisAuthorizationListEntry(KM_TAG_ACTIVE_DATE_TIME)
        .ifPresent(builder::setActiveDateTime);
    parsedAuthorizationMap
        .findOptionalInstantMillisAuthorizationListEntry(KM_TAG_ORIGINATION_EXPIRE_DATE_TIME)
        .ifPresent(builder::setOriginationExpireDateTime);
    parsedAuthorizationMap
        .findOptionalInstantMillisAuthorizationListEntry(KM_TAG_USAGE_EXPIRE_DATE_TIME)
        .ifPresent(builder::setUsageExpireDateTime);
    builder.setNoAuthRequired(
        parsedAuthorizationMap.findBooleanAuthorizationListEntry(KM_TAG_NO_AUTH_REQUIRED));
    parsedAuthorizationMap
        .findOptionalLongAuthorizationListEntry(KM_TAG_USER_AUTH_TYPE)
        .map(AuthorizationList::userAuthTypeToEnum)
        .ifPresent(it -> it.forEach(builder::addUserAuthType));
    parsedAuthorizationMap
        .findOptionalIntegerAuthorizationListEntry(KM_TAG_AUTH_TIMEOUT)
        .map(Duration::ofSeconds)
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
        .findOptionalInstantMillisAuthorizationListEntry(KM_TAG_CREATION_DATE_TIME)
        .ifPresent(builder::setCreationDateTime);
    parsedAuthorizationMap
        .findOptionalIntegerAuthorizationListEntry(KM_TAG_ORIGIN)
        .map(ASN1_TO_KEY_ORIGIN::get)
        .ifPresent(builder::setOrigin);
    builder.setRollbackResistant(
        parsedAuthorizationMap.findBooleanAuthorizationListEntry(KM_TAG_ROLLBACK_RESISTANT));
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
        .map(String::valueOf)
        .map(AuthorizationList::toYearMonth)
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
        .map(String::valueOf)
        .map(AuthorizationList::toLocalDate)
        .ifPresent(builder::setVendorPatchLevel);
    parsedAuthorizationMap
        .findOptionalIntegerAuthorizationListEntry(KM_TAG_BOOT_PATCH_LEVEL)
        .map(String::valueOf)
        .map(AuthorizationList::toLocalDate)
        .ifPresent(builder::setBootPatchLevel);
    builder.setIndividualAttestation(
        parsedAuthorizationMap.findBooleanAuthorizationListEntry(KM_TAG_DEVICE_UNIQUE_ATTESTATION));
    parsedAuthorizationMap.getUnorderedTags().forEach(builder::addUnorderedTag);

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
                    ASN1TaggedObject::getTagNo,
                    obj -> ASN1Util.getExplicitContextBaseObject(obj, obj.getTagNo())));

    List<Integer> unorderedTags = new ArrayList<>();
    int previousTag = 0;
    for (int currentTag : authorizationMap.keySet()) {
      if (previousTag > currentTag) {
        unorderedTags.add(previousTag);
      }
      previousTag = currentTag;
    }
    return new ParsedAuthorizationMap(authorizationMap, ImmutableList.copyOf(unorderedTags));
  }

  @VisibleForTesting
  static LocalDate toLocalDate(String value) {
    checkArgument(value.length() == 6 || value.length() == 8);
    int year = Integer.parseInt(value.substring(0, 4));
    int month =
        Integer.parseInt(value.substring(4, 6)) == 0 ? 1 : Integer.parseInt(value.substring(4, 6));
    int day =
        value.length() == 8 && !value.substring(6, 8).equals("00")
            ? Integer.parseInt(value.substring(6, 8))
            : 1;
    return LocalDate.of(year, month, day);
  }

  private static YearMonth toYearMonth(String value) {
    checkArgument(value.length() == 6);
    try {
      return YearMonth.parse(value, DateTimeFormatter.ofPattern("yyyyMM"));
    } catch (DateTimeParseException e) {
      throw new IllegalArgumentException(e);
    }
  }

  @VisibleForTesting
  static ImmutableSet<UserAuthType> userAuthTypeToEnum(long userAuthType) {
    if (userAuthType == 0) {
      return ImmutableSet.of(USER_AUTH_TYPE_NONE);
    }

    ImmutableSet.Builder<UserAuthType> builder = ImmutableSet.builder();

    if ((userAuthType & 1L) == 1L) {
      builder.add(PASSWORD);
    }
    if ((userAuthType & 2L) == 2L) {
      builder.add(FINGERPRINT);
    }
    if (userAuthType == UINT32_MAX) {
      builder.add(USER_AUTH_TYPE_ANY);
    }

    ImmutableSet<UserAuthType> result = builder.build();
    if (result.isEmpty()) {
      throw new IllegalArgumentException("Invalid User Auth Type.");
    }

    return result;
  }

  /**
   * This data structure holds the parsed attest record authorizations mapped to their authorization
   * tags and a list of unordered authorization tags found in this authorization list.
   */
  private static class ParsedAuthorizationMap {
    private final ImmutableMap<Integer, ASN1Object> authorizationMap;
    private final ImmutableList<Integer> unorderedTags;

    private ParsedAuthorizationMap(
        ImmutableMap<Integer, ASN1Object> authorizationMap, ImmutableList<Integer> unorderedTags) {
      this.authorizationMap = authorizationMap;
      this.unorderedTags = unorderedTags;
    }

    private ImmutableList<Integer> getUnorderedTags() {
      return unorderedTags;
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

    private Optional<Instant> findOptionalInstantMillisAuthorizationListEntry(int tag) {
      Optional<Long> millis = findOptionalLongAuthorizationListEntry(tag);
      return millis.map(Instant::ofEpochMilli);
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
