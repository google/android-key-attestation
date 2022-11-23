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
import static com.google.android.attestation.Constants.KM_TAG_ALL_APPLICATIONS;
import static com.google.android.attestation.Constants.KM_TAG_APPLICATION_ID;
import static com.google.android.attestation.Constants.KM_TAG_ATTESTATION_APPLICATION_ID;
import static com.google.android.attestation.Constants.KM_TAG_ATTESTATION_ID_BRAND;
import static com.google.android.attestation.Constants.KM_TAG_ATTESTATION_ID_DEVICE;
import static com.google.android.attestation.Constants.KM_TAG_ATTESTATION_ID_IMEI;
import static com.google.android.attestation.Constants.KM_TAG_ATTESTATION_ID_MANUFACTURER;
import static com.google.android.attestation.Constants.KM_TAG_ATTESTATION_ID_MEID;
import static com.google.android.attestation.Constants.KM_TAG_ATTESTATION_ID_MODEL;
import static com.google.android.attestation.Constants.KM_TAG_ATTESTATION_ID_PRODUCT;
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

import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERTaggedObject;

/**
 * This data structure contains the key pair's properties themselves, as defined in the Keymaster
 * hardware abstraction layer (HAL). You compare these values to the device's current state or to a
 * set of expected values to verify that a key pair is still valid for use in your app.
 */
@SuppressWarnings("OptionalUsedAsFieldOrParameterType")
public class AuthorizationList {
  /** Specifies the types of user authenticators that may be used to authorize this key. */
  public enum UserAuthType {
    USER_AUTH_TYPE_NONE,
    PASSWORD,
    FINGERPRINT,
    USER_AUTH_TYPE_ANY
  }

  public final Optional<Set<Integer>> purpose;
  public final Optional<Integer> algorithm;
  public final Optional<Integer> keySize;
  public final Optional<Set<Integer>> digest;
  public final Optional<Set<Integer>> padding;
  public final Optional<Integer> ecCurve;
  public final Optional<Long> rsaPublicExponent;
  public final boolean rollbackResistance;
  public final Optional<Instant> activeDateTime;
  public final Optional<Instant> originationExpireDateTime;
  public final Optional<Instant> usageExpireDateTime;
  public final boolean noAuthRequired;
  public final Optional<Set<UserAuthType>> userAuthType;
  public final Optional<Duration> authTimeout;
  public final boolean allowWhileOnBody;
  public final boolean trustedUserPresenceRequired;
  public final boolean trustedConfirmationRequired;
  public final boolean unlockedDeviceRequired;
  public final boolean allApplications;
  public final Optional<byte[]> applicationId;
  public final Optional<Instant> creationDateTime;
  public final Optional<Integer> origin;
  public final boolean rollbackResistant;
  public final Optional<RootOfTrust> rootOfTrust;
  public final Optional<Integer> osVersion;
  public final Optional<Integer> osPatchLevel;
  public final Optional<AttestationApplicationId> attestationApplicationId;
  public final Optional<byte[]> attestationApplicationIdBytes;
  public final Optional<byte[]> attestationIdBrand;
  public final Optional<byte[]> attestationIdDevice;
  public final Optional<byte[]> attestationIdProduct;
  public final Optional<byte[]> attestationIdSerial;
  public final Optional<byte[]> attestationIdImei;
  public final Optional<byte[]> attestationIdMeid;
  public final Optional<byte[]> attestationIdManufacturer;
  public final Optional<byte[]> attestationIdModel;
  public final Optional<Integer> vendorPatchLevel;
  public final Optional<Integer> bootPatchLevel;
  public final boolean individualAttestation;

  private AuthorizationList(ASN1Encodable[] authorizationList, int attestationVersion) {
    Map<Integer, ASN1Primitive> authorizationMap = getAuthorizationMap(authorizationList);
    this.purpose = findOptionalIntegerSetAuthorizationListEntry(authorizationMap, KM_TAG_PURPOSE);
    this.algorithm = findOptionalIntegerAuthorizationListEntry(authorizationMap, KM_TAG_ALGORITHM);
    this.keySize = findOptionalIntegerAuthorizationListEntry(authorizationMap, KM_TAG_KEY_SIZE);
    this.digest = findOptionalIntegerSetAuthorizationListEntry(authorizationMap, KM_TAG_DIGEST);
    this.padding = findOptionalIntegerSetAuthorizationListEntry(authorizationMap, KM_TAG_PADDING);
    this.ecCurve = findOptionalIntegerAuthorizationListEntry(authorizationMap, KM_TAG_EC_CURVE);
    this.rsaPublicExponent =
        findOptionalLongAuthorizationListEntry(authorizationMap, KM_TAG_RSA_PUBLIC_EXPONENT);
    this.rollbackResistance =
        findBooleanAuthorizationListEntry(authorizationMap, KM_TAG_ROLLBACK_RESISTANCE);
    this.activeDateTime =
        findOptionalInstantMillisAuthorizationListEntry(authorizationMap, KM_TAG_ACTIVE_DATE_TIME);
    this.originationExpireDateTime =
        findOptionalInstantMillisAuthorizationListEntry(
            authorizationMap, KM_TAG_ORIGINATION_EXPIRE_DATE_TIME);
    this.usageExpireDateTime =
        findOptionalInstantMillisAuthorizationListEntry(
            authorizationMap, KM_TAG_USAGE_EXPIRE_DATE_TIME);
    this.noAuthRequired =
        findBooleanAuthorizationListEntry(authorizationMap, KM_TAG_NO_AUTH_REQUIRED);
    this.userAuthType = findOptionalUserAuthType(authorizationMap, KM_TAG_USER_AUTH_TYPE);
    this.authTimeout =
        findOptionalDurationSecondsAuthorizationListEntry(authorizationMap, KM_TAG_AUTH_TIMEOUT);
    this.allowWhileOnBody =
        findBooleanAuthorizationListEntry(authorizationMap, KM_TAG_ALLOW_WHILE_ON_BODY);
    this.trustedUserPresenceRequired =
        findBooleanAuthorizationListEntry(authorizationMap, KM_TAG_TRUSTED_USER_PRESENCE_REQUIRED);
    this.trustedConfirmationRequired =
        findBooleanAuthorizationListEntry(authorizationMap, KM_TAG_TRUSTED_CONFIRMATION_REQUIRED);
    this.unlockedDeviceRequired =
        findBooleanAuthorizationListEntry(authorizationMap, KM_TAG_UNLOCKED_DEVICE_REQUIRED);
    this.allApplications =
        findBooleanAuthorizationListEntry(authorizationMap, KM_TAG_ALL_APPLICATIONS);
    this.applicationId =
        findOptionalByteArrayAuthorizationListEntry(authorizationMap, KM_TAG_APPLICATION_ID);
    this.creationDateTime =
        findOptionalInstantMillisAuthorizationListEntry(
            authorizationMap, KM_TAG_CREATION_DATE_TIME);
    this.origin = findOptionalIntegerAuthorizationListEntry(authorizationMap, KM_TAG_ORIGIN);
    this.rollbackResistant =
        findBooleanAuthorizationListEntry(authorizationMap, KM_TAG_ROLLBACK_RESISTANT);
    this.rootOfTrust =
        Optional.ofNullable(
            RootOfTrust.createRootOfTrust(
                (ASN1Sequence) findAuthorizationListEntry(authorizationMap, KM_TAG_ROOT_OF_TRUST),
                attestationVersion));
    this.osVersion = findOptionalIntegerAuthorizationListEntry(authorizationMap, KM_TAG_OS_VERSION);
    this.osPatchLevel =
        findOptionalIntegerAuthorizationListEntry(authorizationMap, KM_TAG_OS_PATCH_LEVEL);
    this.attestationApplicationId =
        Optional.ofNullable(
            AttestationApplicationId.createAttestationApplicationId(
                (DEROctetString)
                    findAuthorizationListEntry(
                        authorizationMap, KM_TAG_ATTESTATION_APPLICATION_ID)));
    this.attestationApplicationIdBytes =
        findOptionalByteArrayAuthorizationListEntry(
            authorizationMap, KM_TAG_ATTESTATION_APPLICATION_ID);
    this.attestationIdBrand =
        findOptionalByteArrayAuthorizationListEntry(authorizationMap, KM_TAG_ATTESTATION_ID_BRAND);
    this.attestationIdDevice =
        findOptionalByteArrayAuthorizationListEntry(authorizationMap, KM_TAG_ATTESTATION_ID_DEVICE);
    this.attestationIdProduct =
        findOptionalByteArrayAuthorizationListEntry(
            authorizationMap, KM_TAG_ATTESTATION_ID_PRODUCT);
    this.attestationIdSerial =
        findOptionalByteArrayAuthorizationListEntry(authorizationMap, KM_TAG_ATTESTATION_ID_SERIAL);
    this.attestationIdImei =
        findOptionalByteArrayAuthorizationListEntry(authorizationMap, KM_TAG_ATTESTATION_ID_IMEI);
    this.attestationIdMeid =
        findOptionalByteArrayAuthorizationListEntry(authorizationMap, KM_TAG_ATTESTATION_ID_MEID);
    this.attestationIdManufacturer =
        findOptionalByteArrayAuthorizationListEntry(
            authorizationMap, KM_TAG_ATTESTATION_ID_MANUFACTURER);
    this.attestationIdModel =
        findOptionalByteArrayAuthorizationListEntry(authorizationMap, KM_TAG_ATTESTATION_ID_MODEL);
    this.vendorPatchLevel =
        findOptionalIntegerAuthorizationListEntry(authorizationMap, KM_TAG_VENDOR_PATCH_LEVEL);
    this.bootPatchLevel =
        findOptionalIntegerAuthorizationListEntry(authorizationMap, KM_TAG_BOOT_PATCH_LEVEL);
    this.individualAttestation =
        findBooleanAuthorizationListEntry(authorizationMap, KM_TAG_DEVICE_UNIQUE_ATTESTATION);
  }

  private AuthorizationList(Builder builder) {
    this.purpose = Optional.ofNullable(builder.purpose);
    this.algorithm = Optional.ofNullable(builder.algorithm);
    this.keySize = Optional.ofNullable(builder.keySize);
    this.digest = Optional.ofNullable(builder.digest);
    this.padding = Optional.ofNullable(builder.padding);
    this.ecCurve = Optional.ofNullable(builder.ecCurve);
    this.rsaPublicExponent = Optional.ofNullable(builder.rsaPublicExponent);
    this.rollbackResistance = builder.rollbackResistance;
    this.activeDateTime = Optional.ofNullable(builder.activeDateTime);
    this.originationExpireDateTime = Optional.ofNullable(builder.originationExpireDateTime);
    this.usageExpireDateTime = Optional.ofNullable(builder.usageExpireDateTime);
    this.noAuthRequired = builder.noAuthRequired;
    this.userAuthType = Optional.ofNullable(builder.userAuthType);
    this.authTimeout = Optional.ofNullable(builder.authTimeout);
    this.allowWhileOnBody = builder.allowWhileOnBody;
    this.trustedUserPresenceRequired = builder.trustedUserPresenceRequired;
    this.trustedConfirmationRequired = builder.trustedConfirmationRequired;
    this.unlockedDeviceRequired = builder.unlockedDeviceRequired;
    this.allApplications = builder.allApplications;
    this.applicationId = Optional.ofNullable(builder.applicationId);
    this.creationDateTime = Optional.ofNullable(builder.creationDateTime);
    this.origin = Optional.ofNullable(builder.origin);
    this.rollbackResistant = builder.rollbackResistant;
    this.rootOfTrust = Optional.ofNullable(builder.rootOfTrust);
    this.osVersion = Optional.ofNullable(builder.osVersion);
    this.osPatchLevel = Optional.ofNullable(builder.osPatchLevel);
    this.attestationApplicationId = Optional.ofNullable(builder.attestationApplicationId);
    this.attestationApplicationIdBytes = Optional.ofNullable(builder.attestationApplicationIdBytes);
    this.attestationIdBrand = Optional.ofNullable(builder.attestationIdBrand);
    this.attestationIdDevice = Optional.ofNullable(builder.attestationIdDevice);
    this.attestationIdProduct = Optional.ofNullable(builder.attestationIdProduct);
    this.attestationIdSerial = Optional.ofNullable(builder.attestationIdSerial);
    this.attestationIdImei = Optional.ofNullable(builder.attestationIdImei);
    this.attestationIdMeid = Optional.ofNullable(builder.attestationIdMeid);
    this.attestationIdManufacturer = Optional.ofNullable(builder.attestationIdManufacturer);
    this.attestationIdModel = Optional.ofNullable(builder.attestationIdModel);
    this.vendorPatchLevel = Optional.ofNullable(builder.vendorPatchLevel);
    this.bootPatchLevel = Optional.ofNullable(builder.bootPatchLevel);
    this.individualAttestation = builder.individualAttestation;
  }

  static AuthorizationList createAuthorizationList(
      ASN1Encodable[] authorizationList, int attestationVersion) {
    return new AuthorizationList(authorizationList, attestationVersion);
  }

  private static Map<Integer, ASN1Primitive> getAuthorizationMap(
      ASN1Encodable[] authorizationList) {
    Map<Integer, ASN1Primitive> authorizationMap = new HashMap<>();
    for (ASN1Encodable entry : authorizationList) {
      ASN1TaggedObject taggedEntry = (ASN1TaggedObject) entry;
      authorizationMap.put(taggedEntry.getTagNo(), taggedEntry.getObject());
    }
    return authorizationMap;
  }

  private static ASN1Primitive findAuthorizationListEntry(
      Map<Integer, ASN1Primitive> authorizationMap, int tag) {
    return authorizationMap.getOrDefault(tag, null);
  }

  private static Optional<Set<Integer>> findOptionalIntegerSetAuthorizationListEntry(
      Map<Integer, ASN1Primitive> authorizationMap, int tag) {
    ASN1Set asn1Set = (ASN1Set) findAuthorizationListEntry(authorizationMap, tag);
    if (asn1Set == null) {
      return Optional.empty();
    }
    Set<Integer> entrySet = new HashSet<>();
    for (ASN1Encodable value : asn1Set) {
      entrySet.add(ASN1Parsing.getIntegerFromAsn1(value));
    }
    return Optional.of(entrySet);
  }

  private static Optional<Duration> findOptionalDurationSecondsAuthorizationListEntry(
      Map<Integer, ASN1Primitive> authorizationMap, int tag) {
    Optional<Integer> seconds = findOptionalIntegerAuthorizationListEntry(authorizationMap, tag);
    return seconds.map(Duration::ofSeconds);
  }

  private static Optional<Integer> findOptionalIntegerAuthorizationListEntry(
      Map<Integer, ASN1Primitive> authorizationMap, int tag) {
    ASN1Primitive entry = findAuthorizationListEntry(authorizationMap, tag);
    return Optional.ofNullable(entry).map(ASN1Parsing::getIntegerFromAsn1);
  }

  private static Optional<Instant> findOptionalInstantMillisAuthorizationListEntry(
      Map<Integer, ASN1Primitive> authorizationMap, int tag) {
    Optional<Long> millis = findOptionalLongAuthorizationListEntry(authorizationMap, tag);
    return millis.map(Instant::ofEpochMilli);
  }

  private static Optional<Long> findOptionalLongAuthorizationListEntry(
      Map<Integer, ASN1Primitive> authorizationMap, int tag) {
    ASN1Integer longEntry = ((ASN1Integer) findAuthorizationListEntry(authorizationMap, tag));
    return Optional.ofNullable(longEntry).map(value -> value.getValue().longValue());
  }

  private static boolean findBooleanAuthorizationListEntry(
      Map<Integer, ASN1Primitive> authorizationMap, int tag) {
    return null != findAuthorizationListEntry(authorizationMap, tag);
  }

  private static Optional<byte[]> findOptionalByteArrayAuthorizationListEntry(
      Map<Integer, ASN1Primitive> authorizationMap, int tag) {
    ASN1OctetString entry = (ASN1OctetString) findAuthorizationListEntry(authorizationMap, tag);
    return Optional.ofNullable(entry).map(ASN1OctetString::getOctets);
  }

  private static Optional<Set<UserAuthType>> findOptionalUserAuthType(
      Map<Integer, ASN1Primitive> authorizationMap, int tag) {
    Optional<Long> userAuthType = findOptionalLongAuthorizationListEntry(authorizationMap, tag);
    return userAuthType.map(AuthorizationList::userAuthTypeToEnum);
  }

  // Visible for testing.
  static Set<UserAuthType> userAuthTypeToEnum(long userAuthType) {
    if (userAuthType == 0) {
      return Set.of(USER_AUTH_TYPE_NONE);
    }

    Set<UserAuthType> result = new HashSet<>();

    if ((userAuthType & 1L) == 1L) {
      result.add(PASSWORD);
    }
    if ((userAuthType & 2L) == 2L) {
      result.add(FINGERPRINT);
    }
    if (userAuthType == UINT32_MAX) {
      result.add(USER_AUTH_TYPE_ANY);
    }

    if (result.isEmpty()) {
      throw new IllegalArgumentException("Invalid User Auth Type.");
    }

    return result;
  }

  private static Long userAuthTypeToLong(Set<UserAuthType> userAuthType) {
    if (userAuthType.contains(USER_AUTH_TYPE_NONE)) {
      return 0L;
    }

    Long result = 0L;

    for (UserAuthType type : userAuthType) {
      switch (type) {
        case PASSWORD:
          result |= 1L;
          break;
        case FINGERPRINT:
          result |= 2L;
          break;
        case USER_AUTH_TYPE_ANY:
          result |= UINT32_MAX;
          break;
        default:
          break;
      }
    }

    if (result == 0) {
      throw new IllegalArgumentException("Invalid User Auth Type.");
    }

    return result;
  }

  public ASN1Sequence toAsn1Sequence() {
    ASN1EncodableVector vector = new ASN1EncodableVector();
    addOptionalIntegerSet(KM_TAG_PURPOSE, this.purpose, vector);
    addOptionalInteger(KM_TAG_ALGORITHM, this.algorithm, vector);
    addOptionalInteger(KM_TAG_KEY_SIZE, this.keySize, vector);
    addOptionalIntegerSet(KM_TAG_DIGEST, this.digest, vector);
    addOptionalIntegerSet(KM_TAG_PADDING, this.padding, vector);
    addOptionalInteger(KM_TAG_EC_CURVE, this.ecCurve, vector);
    addOptionalLong(KM_TAG_RSA_PUBLIC_EXPONENT, this.rsaPublicExponent, vector);
    addBoolean(KM_TAG_ROLLBACK_RESISTANCE, this.rollbackResistance, vector);
    addOptionalInstant(KM_TAG_ACTIVE_DATE_TIME, this.activeDateTime, vector);
    addOptionalInstant(KM_TAG_ORIGINATION_EXPIRE_DATE_TIME, this.originationExpireDateTime, vector);
    addOptionalInstant(KM_TAG_USAGE_EXPIRE_DATE_TIME, this.usageExpireDateTime, vector);
    addBoolean(KM_TAG_NO_AUTH_REQUIRED, this.noAuthRequired, vector);
    addOptionalUserAuthType(KM_TAG_USER_AUTH_TYPE, this.userAuthType, vector);
    addOptionalDuration(KM_TAG_AUTH_TIMEOUT, this.authTimeout, vector);
    addBoolean(KM_TAG_ALLOW_WHILE_ON_BODY, this.allowWhileOnBody, vector);
    addBoolean(KM_TAG_TRUSTED_USER_PRESENCE_REQUIRED, this.trustedUserPresenceRequired, vector);
    addBoolean(KM_TAG_TRUSTED_CONFIRMATION_REQUIRED, this.trustedConfirmationRequired, vector);
    addBoolean(KM_TAG_UNLOCKED_DEVICE_REQUIRED, this.unlockedDeviceRequired, vector);
    addBoolean(KM_TAG_ALL_APPLICATIONS, this.allApplications, vector);
    addOptionalOctetString(KM_TAG_APPLICATION_ID, this.applicationId, vector);
    addOptionalInstant(KM_TAG_CREATION_DATE_TIME, this.creationDateTime, vector);
    addOptionalInteger(KM_TAG_ORIGIN, this.origin, vector);
    addBoolean(KM_TAG_ROLLBACK_RESISTANT, this.rollbackResistant, vector);
    addOptionalRootOfTrust(KM_TAG_ROOT_OF_TRUST, this.rootOfTrust, vector);
    addOptionalInteger(KM_TAG_OS_VERSION, this.osVersion, vector);
    addOptionalInteger(KM_TAG_OS_PATCH_LEVEL, this.osPatchLevel, vector);
    addOptionalOctetString(
        KM_TAG_ATTESTATION_APPLICATION_ID, this.attestationApplicationIdBytes, vector);
    addOptionalOctetString(KM_TAG_ATTESTATION_ID_BRAND, this.attestationIdBrand, vector);
    addOptionalOctetString(KM_TAG_ATTESTATION_ID_DEVICE, this.attestationIdDevice, vector);
    addOptionalOctetString(KM_TAG_ATTESTATION_ID_PRODUCT, this.attestationIdProduct, vector);
    addOptionalOctetString(KM_TAG_ATTESTATION_ID_SERIAL, this.attestationIdSerial, vector);
    addOptionalOctetString(KM_TAG_ATTESTATION_ID_IMEI, this.attestationIdImei, vector);
    addOptionalOctetString(KM_TAG_ATTESTATION_ID_MEID, this.attestationIdMeid, vector);
    addOptionalOctetString(
        KM_TAG_ATTESTATION_ID_MANUFACTURER, this.attestationIdManufacturer, vector);
    addOptionalOctetString(KM_TAG_ATTESTATION_ID_MODEL, this.attestationIdModel, vector);
    addOptionalInteger(KM_TAG_VENDOR_PATCH_LEVEL, this.vendorPatchLevel, vector);
    addOptionalInteger(KM_TAG_BOOT_PATCH_LEVEL, this.bootPatchLevel, vector);
    addBoolean(KM_TAG_DEVICE_UNIQUE_ATTESTATION, this.individualAttestation, vector);
    return new DERSequence(vector);
  }

  private static void addOptionalIntegerSet(
      int tag, Optional<Set<Integer>> entry, ASN1EncodableVector vector) {
    if (entry.isPresent()) {
      ASN1EncodableVector tmp = new ASN1EncodableVector();
      entry.get().forEach((Integer value) -> tmp.add(new ASN1Integer(value.longValue())));
      vector.add(new DERTaggedObject(tag, new DERSet(tmp)));
    }
  }

  private static void addOptionalInstant(
      int tag, Optional<Instant> entry, ASN1EncodableVector vector) {
    if (entry.isPresent()) {
      vector.add(new DERTaggedObject(tag, new ASN1Integer(entry.get().toEpochMilli())));
    }
  }

  private static void addOptionalDuration(
      int tag, Optional<Duration> entry, ASN1EncodableVector vector) {
    if (entry.isPresent()) {
      vector.add(new DERTaggedObject(tag, new ASN1Integer(entry.get().getSeconds())));
    }
  }

  private static void addBoolean(int tag, boolean entry, ASN1EncodableVector vector) {
    if (entry) {
      vector.add(new DERTaggedObject(tag, DERNull.INSTANCE));
    }
  }

  private static void addOptionalInteger(
      int tag, Optional<Integer> entry, ASN1EncodableVector vector) {
    if (entry.isPresent()) {
      vector.add(new DERTaggedObject(tag, new ASN1Integer(entry.get())));
    }
  }

  private static void addOptionalLong(int tag, Optional<Long> entry, ASN1EncodableVector vector) {
    if (entry.isPresent()) {
      vector.add(new DERTaggedObject(tag, new ASN1Integer(entry.get())));
    }
  }

  private static void addOptionalOctetString(
      int tag, Optional<byte[]> entry, ASN1EncodableVector vector) {
    if (entry.isPresent()) {
      vector.add(new DERTaggedObject(tag, new DEROctetString(entry.get())));
    }
  }

  private static void addOptionalUserAuthType(
      int tag, Optional<Set<UserAuthType>> entry, ASN1EncodableVector vector) {
    if (entry.isPresent()) {
      vector.add(new DERTaggedObject(tag, new ASN1Integer(userAuthTypeToLong(entry.get()))));
    }
  }

  private static void addOptionalRootOfTrust(
      int tag, Optional<RootOfTrust> entry, ASN1EncodableVector vector) {
    if (entry.isPresent()) {
      vector.add(new DERTaggedObject(tag, entry.get().toAsn1Sequence()));
    }
  }

  public static Builder builder() {
    return new Builder();
  }

  /**
   * Builder for an AuthorizationList. Any field not set will be made an Optional.empty or set with
   * the default value.
   */
  public static final class Builder {

    Set<Integer> purpose;
    Integer algorithm;
    Integer keySize;
    Set<Integer> digest;
    Set<Integer> padding;
    Integer ecCurve;
    Long rsaPublicExponent;
    boolean rollbackResistance;
    Instant activeDateTime;
    Instant originationExpireDateTime;
    Instant usageExpireDateTime;
    boolean noAuthRequired;
    Set<UserAuthType> userAuthType;
    Duration authTimeout;
    boolean allowWhileOnBody;
    boolean trustedUserPresenceRequired;
    boolean trustedConfirmationRequired;
    boolean unlockedDeviceRequired;
    boolean allApplications;
    byte[] applicationId;
    Instant creationDateTime;
    Integer origin;
    boolean rollbackResistant;
    RootOfTrust rootOfTrust;
    Integer osVersion;
    Integer osPatchLevel;
    AttestationApplicationId attestationApplicationId;
    byte[] attestationApplicationIdBytes;
    byte[] attestationIdBrand;
    byte[] attestationIdDevice;
    byte[] attestationIdProduct;
    byte[] attestationIdSerial;
    byte[] attestationIdImei;
    byte[] attestationIdMeid;
    byte[] attestationIdManufacturer;
    byte[] attestationIdModel;
    Integer vendorPatchLevel;
    Integer bootPatchLevel;
    boolean individualAttestation;

    public Builder setPurpose(Set<Integer> purpose) {
      this.purpose = purpose;
      return this;
    }

    public Builder setAlgorithm(Integer algorithm) {
      this.algorithm = algorithm;
      return this;
    }

    public Builder setKeySize(Integer keySize) {
      this.keySize = keySize;
      return this;
    }

    public Builder setDigest(Set<Integer> digest) {
      this.digest = digest;
      return this;
    }

    public Builder setPadding(Set<Integer> padding) {
      this.padding = padding;
      return this;
    }

    public Builder setEcCurve(Integer ecCurve) {
      this.ecCurve = ecCurve;
      return this;
    }

    public Builder setRsaPublicExponent(Long rsaPublicExponent) {
      this.rsaPublicExponent = rsaPublicExponent;
      return this;
    }

    public Builder setRollbackResistance(boolean rollbackResistance) {
      this.rollbackResistance = rollbackResistance;
      return this;
    }

    public Builder setActiveDateTime(Instant activeDateTime) {
      this.activeDateTime = activeDateTime;
      return this;
    }

    public Builder setOriginationExpireDateTime(Instant originationExpireDateTime) {
      this.originationExpireDateTime = originationExpireDateTime;
      return this;
    }

    public Builder setUsageExpireDateTime(Instant usageExpireDateTime) {
      this.usageExpireDateTime = usageExpireDateTime;
      return this;
    }

    public Builder setNoAuthRequired(boolean noAuthRequired) {
      this.noAuthRequired = noAuthRequired;
      return this;
    }

    public Builder setUserAuthType(Set<UserAuthType> userAuthType) {
      this.userAuthType = userAuthType;
      return this;
    }

    public Builder setAuthTimeout(Duration authTimeout) {
      this.authTimeout = authTimeout;
      return this;
    }

    public Builder setAllowWhileOnBody(boolean allowWhileOnBody) {
      this.allowWhileOnBody = allowWhileOnBody;
      return this;
    }

    public Builder setTrustedUserPresenceRequired(boolean trustedUserPresenceRequired) {
      this.trustedUserPresenceRequired = trustedUserPresenceRequired;
      return this;
    }

    public Builder setTrustedConfirmationRequired(boolean trustedConfirmationRequired) {
      this.trustedConfirmationRequired = trustedConfirmationRequired;
      return this;
    }

    public Builder setUnlockedDeviceRequired(boolean unlockedDeviceRequired) {
      this.unlockedDeviceRequired = unlockedDeviceRequired;
      return this;
    }

    public Builder setAllApplications(boolean allApplications) {
      this.allApplications = allApplications;
      return this;
    }

    public Builder setApplicationId(byte[] applicationId) {
      this.applicationId = applicationId;
      return this;
    }

    public Builder setCreationDateTime(Instant creationDateTime) {
      this.creationDateTime = creationDateTime;
      return this;
    }

    public Builder setOrigin(Integer origin) {
      this.origin = origin;
      return this;
    }

    public Builder setRollbackResistant(boolean rollbackResistant) {
      this.rollbackResistant = rollbackResistant;
      return this;
    }

    public Builder setRootOfTrust(RootOfTrust rootOfTrust) {
      this.rootOfTrust = rootOfTrust;
      return this;
    }

    public Builder setOsVersion(Integer osVersion) {
      this.osVersion = osVersion;
      return this;
    }

    public Builder setOsPatchLevel(Integer osPatchLevel) {
      this.osPatchLevel = osPatchLevel;
      return this;
    }

    public Builder setAttestationApplicationId(AttestationApplicationId attestationApplicationId) {
      this.attestationApplicationId = attestationApplicationId;
      return this;
    }

    public Builder setAttestationApplicationIdBytes(byte[] attestationApplicationIdBytes) {
      this.attestationApplicationIdBytes = attestationApplicationIdBytes;
      return this;
    }

    public Builder setAttestationIdBrand(byte[] attestationIdBrand) {
      this.attestationIdBrand = attestationIdBrand;
      return this;
    }

    public Builder setAttestationIdProduct(byte[] attestationIdProduct) {
      this.attestationIdProduct = attestationIdProduct;
      return this;
    }

    public Builder setAttestationIdSerial(byte[] attestationIdSerial) {
      this.attestationIdSerial = attestationIdSerial;
      return this;
    }

    public Builder setAttestationIdImei(byte[] attestationIdImei) {
      this.attestationIdImei = attestationIdImei;
      return this;
    }

    public Builder setAttestationIdMeid(byte[] attestationIdMeid) {
      this.attestationIdMeid = attestationIdMeid;
      return this;
    }

    public Builder setAttestationIdManufacturer(byte[] attestationIdManufacturer) {
      this.attestationIdManufacturer = attestationIdManufacturer;
      return this;
    }

    public Builder setAttestationIdModel(byte[] attestationIdModel) {
      this.attestationIdModel = attestationIdModel;
      return this;
    }

    public Builder setVendorPatchLevel(Integer vendorPatchLevel) {
      this.vendorPatchLevel = vendorPatchLevel;
      return this;
    }

    public Builder setBootPatchLevel(Integer bootPatchLevel) {
      this.bootPatchLevel = bootPatchLevel;
      return this;
    }

    public Builder setIndividualAttestation(boolean individualAttestation) {
      this.individualAttestation = individualAttestation;
      return this;
    }

    public AuthorizationList build() {
      return new AuthorizationList(this);
    }
  }
}
