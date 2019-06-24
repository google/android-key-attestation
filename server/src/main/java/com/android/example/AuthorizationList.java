package com.android.example;

import org.bouncycastle.asn1.ASN1Set;

import java.util.Optional;

class AuthorizationList {
  final Optional<ASN1Set> purpose;
  final Optional<Integer> algorithm;
  final Optional<Integer> keySize;
  final Optional<ASN1Set> digest;
  final Optional<ASN1Set> padding;
  final Optional<Integer> ecCurve;
  final Optional<Integer> rsaPublicExponent;
  final Optional<Boolean> rollbackResistance;
  final Optional<Integer> activeDateTime;
  final Optional<Integer> originationExpireDateTime;
  final Optional<Integer> usageExpireDateTime;
  final Optional<Boolean> noAuthRequired;
  final Optional<Integer> userAuthType;
  final Optional<Integer> authTimeout;
  final Optional<Boolean> allowWhileOnBody;
  final Optional<Boolean> trustedUserPresenceRequired;
  final Optional<Boolean> trustedConfirmationRequired;
  final Optional<Boolean> unlockedDeviceRequired;
  final Optional<Boolean> allApplications;
  final Optional<byte[]> applicationId;
  final Optional<Integer> creationDateTime;
  final Optional<Integer> origin;
  final Optional<RootOfTrust> rootOfTrust;
  final Optional<Integer> osVersion;
  final Optional<Integer> osPatchLevel;
  final Optional<byte[]> attestationApplicationId;
  final Optional<byte[]> attestationIdBrand;
  final Optional<byte[]> attestationIdDevice;
  final Optional<byte[]> attestationIdProduct;
  final Optional<byte[]> attestationIdSerial;
  final Optional<byte[]> attestationIdImei;
  final Optional<byte[]> attestationIdMeid;
  final Optional<byte[]> attestationIdManufacturer;
  final Optional<byte[]> attestationIdModel;
  final Optional<Integer> vendorPatchLevel;
  final Optional<Integer> bootPatchLevel;

  AuthorizationList(Optional<ASN1Set> purpose, Optional<Integer> algorithm, Optional<Integer> keySize, Optional<ASN1Set> digest, Optional<ASN1Set> padding, Optional<Integer> ecCurve, Optional<Integer> rsaPublicExponent, Optional<Boolean> rollbackResistance, Optional<Integer> activeDateTime, Optional<Integer> originationExpireDateTime, Optional<Integer> usageExpireDateTime, Optional<Boolean> noAuthRequired, Optional<Integer> userAuthType, Optional<Integer> authTimeout, Optional<Boolean> allowWhileOnBody, Optional<Boolean> trustedUserPresenceRequired, Optional<Boolean> trustedConfirmationRequired, Optional<Boolean> unlockedDeviceRequired, Optional<Boolean> allApplications, Optional<byte[]> applicationId, Optional<Integer> creationDateTime, Optional<Integer> origin, Optional<RootOfTrust> rootOfTrust, Optional<Integer> osVersion, Optional<Integer> osPatchLevel, Optional<byte[]> attestationApplicationId, Optional<byte[]> attestationIdBrand, Optional<byte[]> attestationIdDevice, Optional<byte[]> attestationIdProduct, Optional<byte[]> attestationIdSerial, Optional<byte[]> attestationIdImei, Optional<byte[]> attestationIdMeid, Optional<byte[]> attestationIdManufacturer, Optional<byte[]> attestationIdModel, Optional<Integer> vendorPatchLevel, Optional<Integer> bootPatchLevel) {
    this.purpose = purpose;
    this.algorithm = algorithm;
    this.keySize = keySize;
    this.digest = digest;
    this.padding = padding;
    this.ecCurve = ecCurve;
    this.rsaPublicExponent = rsaPublicExponent;
    this.rollbackResistance = rollbackResistance;
    this.activeDateTime = activeDateTime;
    this.originationExpireDateTime = originationExpireDateTime;
    this.usageExpireDateTime = usageExpireDateTime;
    this.noAuthRequired = noAuthRequired;
    this.userAuthType = userAuthType;
    this.authTimeout = authTimeout;
    this.allowWhileOnBody = allowWhileOnBody;
    this.trustedUserPresenceRequired = trustedUserPresenceRequired;
    this.trustedConfirmationRequired = trustedConfirmationRequired;
    this.unlockedDeviceRequired = unlockedDeviceRequired;
    this.allApplications = allApplications;
    this.applicationId = applicationId;
    this.creationDateTime = creationDateTime;
    this.origin = origin;
    this.rootOfTrust = rootOfTrust;
    this.osVersion = osVersion;
    this.osPatchLevel = osPatchLevel;
    this.attestationApplicationId = attestationApplicationId;
    this.attestationIdBrand = attestationIdBrand;
    this.attestationIdDevice = attestationIdDevice;
    this.attestationIdProduct = attestationIdProduct;
    this.attestationIdSerial = attestationIdSerial;
    this.attestationIdImei = attestationIdImei;
    this.attestationIdMeid = attestationIdMeid;
    this.attestationIdManufacturer = attestationIdManufacturer;
    this.attestationIdModel = attestationIdModel;
    this.vendorPatchLevel = vendorPatchLevel;
    this.bootPatchLevel = bootPatchLevel;
  }

  static class RootOfTrust {
    byte[] verifiedBootKey;
    Boolean deviceLocked;
    VerifiedBootState verifiedBootState;
    byte[] verifiedBootHash;

    enum VerifiedBootState {
      VERIFIED,
      SELFSIGNED,
      UNVERIFIED,
      FAILED
    }
  }
}
