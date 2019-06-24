package com.android.example;

import org.bouncycastle.asn1.ASN1Set;

import java.util.Optional;

class AuthorizationListBuilder {
  private Optional<ASN1Set> purpose = Optional.empty();
  private Optional<Integer> algorithm = Optional.empty();
  private Optional<Integer> keySize = Optional.empty();
  private Optional<ASN1Set> digest = Optional.empty();
  private Optional<ASN1Set> padding = Optional.empty();
  private Optional<Integer> ecCurve = Optional.empty();
  private Optional<Integer> rsaPublicExponent = Optional.empty();
  private Optional<Boolean> rollbackResistance = Optional.empty();
  private Optional<Integer> activeDateTime = Optional.empty();
  private Optional<Integer> originationExpireDateTime = Optional.empty();
  private Optional<Integer> usageExpireDateTime = Optional.empty();
  private Optional<Boolean> noAuthRequired = Optional.empty();
  private Optional<Integer> userAuthType = Optional.empty();
  private Optional<Integer> authTimeout = Optional.empty();
  private Optional<Boolean> allowWhileOnBody = Optional.empty();
  private Optional<Boolean> trustedUserPresenceRequired = Optional.empty();
  private Optional<Boolean> trustedConfirmationRequired = Optional.empty();
  private Optional<Boolean> unlockedDeviceRequired = Optional.empty();
  private Optional<Boolean> allApplications = Optional.empty();
  private Optional<byte[]> applicationId = Optional.empty();
  private Optional<Integer> creationDateTime = Optional.empty();
  private Optional<Integer> origin = Optional.empty();
  private Optional<AuthorizationList.RootOfTrust> rootOfTrust = Optional.empty();
  private Optional<Integer> osVersion = Optional.empty();
  private Optional<Integer> osPatchLevel = Optional.empty();
  private Optional<byte[]> attestationApplicationId = Optional.empty();
  private Optional<byte[]> attestationIdBrand = Optional.empty();
  private Optional<byte[]> attestationIdDevice = Optional.empty();
  private Optional<byte[]> attestationIdProduct = Optional.empty();
  private Optional<byte[]> attestationIdSerial = Optional.empty();
  private Optional<byte[]> attestationIdImei = Optional.empty();
  private Optional<byte[]> attestationIdMeid = Optional.empty();
  private Optional<byte[]> attestationIdManufacturer = Optional.empty();
  private Optional<byte[]> attestationIdModel = Optional.empty();
  private Optional<Integer> vendorPatchLevel = Optional.empty();
  private Optional<Integer> bootPatchLevel = Optional.empty();

  AuthorizationListBuilder setPurpose(ASN1Set purpose) {
    this.purpose = Optional.ofNullable(purpose);
    return this;
  }

  AuthorizationListBuilder setAlgorithm(Integer algorithm) {
    this.algorithm = Optional.ofNullable(algorithm);
    return this;
  }

  AuthorizationListBuilder setKeySize(Integer keySize) {
    this.keySize = Optional.ofNullable(keySize);
    return this;
  }

  AuthorizationListBuilder setDigest(ASN1Set digest) {
    this.digest = Optional.ofNullable(digest);
    return this;
  }

  AuthorizationListBuilder setPadding(ASN1Set padding) {
    this.padding = Optional.ofNullable(padding);
    return this;
  }

  AuthorizationListBuilder setEcCurve(Integer ecCurve) {
    this.ecCurve = Optional.ofNullable(ecCurve);
    return this;
  }

  AuthorizationListBuilder setRsaPublicExponent(Integer rsaPublicExponent) {
    this.rsaPublicExponent = Optional.ofNullable(rsaPublicExponent);
    return this;
  }

  AuthorizationListBuilder setRollbackResistance(Boolean rollbackResistance) {
    this.rollbackResistance = Optional.ofNullable(rollbackResistance);
    return this;
  }

  AuthorizationListBuilder setActiveDateTime(Integer activeDateTime) {
    this.activeDateTime = Optional.ofNullable(activeDateTime);
    return this;
  }

  AuthorizationListBuilder setOriginationExpireDateTime(Integer originationExpireDateTime) {
    this.originationExpireDateTime = Optional.ofNullable(originationExpireDateTime);
    return this;
  }

  AuthorizationListBuilder setUsageExpireDateTime(Integer usageExpireDateTime) {
    this.usageExpireDateTime = Optional.ofNullable(usageExpireDateTime);
    return this;
  }

  AuthorizationListBuilder setNoAuthRequired(Boolean noAuthRequired) {
    this.noAuthRequired = Optional.ofNullable(noAuthRequired);
    return this;
  }

  AuthorizationListBuilder setUserAuthType(Integer userAuthType) {
    this.userAuthType = Optional.ofNullable(userAuthType);
    return this;
  }

  AuthorizationListBuilder setAuthTimeout(Integer authTimeout) {
    this.authTimeout = Optional.ofNullable(authTimeout);
    return this;
  }

  AuthorizationListBuilder setAllowWhileOnBody(Boolean allowWhileOnBody) {
    this.allowWhileOnBody = Optional.ofNullable(allowWhileOnBody);
    return this;
  }

  AuthorizationListBuilder setTrustedUserPresenceRequired(Boolean trustedUserPresenceRequired) {
    this.trustedUserPresenceRequired = Optional.ofNullable(trustedUserPresenceRequired);
    return this;
  }

  AuthorizationListBuilder setTrustedConfirmationRequired(Boolean trustedConfirmationRequired) {
    this.trustedConfirmationRequired = Optional.ofNullable(trustedConfirmationRequired);
    return this;
  }

  AuthorizationListBuilder setUnlockedDeviceRequired(Boolean unlockedDeviceRequired) {
    this.unlockedDeviceRequired = Optional.ofNullable(unlockedDeviceRequired);
    return this;
  }

  AuthorizationListBuilder setAllApplications(Boolean allApplications) {
    this.allApplications = Optional.ofNullable(allApplications);
    return this;
  }

  AuthorizationListBuilder setApplicationId(byte[] applicationId) {
    this.applicationId = Optional.ofNullable(applicationId);
    return this;
  }

  AuthorizationListBuilder setCreationDateTime(Integer creationDateTime) {
    this.creationDateTime = Optional.ofNullable(creationDateTime);
    return this;
  }

  AuthorizationListBuilder setOrigin(Integer origin) {
    this.origin = Optional.ofNullable(origin);
    return this;
  }

  AuthorizationListBuilder setRootOfTrust(AuthorizationList.RootOfTrust rootOfTrust) {
    this.rootOfTrust = Optional.ofNullable(rootOfTrust);
    return this;
  }

  AuthorizationListBuilder setOsVersion(Integer osVersion) {
    this.osVersion = Optional.ofNullable(osVersion);
    return this;
  }

  AuthorizationListBuilder setOsPatchLevel(Integer osPatchLevel) {
    this.osPatchLevel = Optional.ofNullable(osPatchLevel);
    return this;
  }

  AuthorizationListBuilder setAttestationApplicationId(byte[] attestationApplicationId) {
    this.attestationApplicationId = Optional.ofNullable(attestationApplicationId);
    return this;
  }

  AuthorizationListBuilder setAttestationIdBrand(byte[] attestationIdBrand) {
    this.attestationIdBrand = Optional.ofNullable(attestationIdBrand);
    return this;
  }

  AuthorizationListBuilder setAttestationIdDevice(byte[] attestationIdDevice) {
    this.attestationIdDevice = Optional.ofNullable(attestationIdDevice);
    return this;
  }

  AuthorizationListBuilder setAttestationIdProduct(byte[] attestationIdProduct) {
    this.attestationIdProduct = Optional.ofNullable(attestationIdProduct);
    return this;
  }

  AuthorizationListBuilder setAttestationIdSerial(byte[] attestationIdSerial) {
    this.attestationIdSerial = Optional.ofNullable(attestationIdSerial);
    return this;
  }

  AuthorizationListBuilder setAttestationIdImei(byte[] attestationIdImei) {
    this.attestationIdImei = Optional.ofNullable(attestationIdImei);
    return this;
  }

  AuthorizationListBuilder setAttestationIdMeid(byte[] attestationIdMeid) {
    this.attestationIdMeid = Optional.ofNullable(attestationIdMeid);
    return this;
  }

  AuthorizationListBuilder setAttestationIdManufacturer(byte[] attestationIdManufacturer) {
    this.attestationIdManufacturer = Optional.ofNullable(attestationIdManufacturer);
    return this;
  }

  AuthorizationListBuilder setAttestationIdModel(byte[] attestationIdModel) {
    this.attestationIdModel = Optional.ofNullable(attestationIdModel);
    return this;
  }

  AuthorizationListBuilder setVendorPatchLevel(Integer vendorPatchLevel) {
    this.vendorPatchLevel = Optional.ofNullable(vendorPatchLevel);
    return this;
  }

  AuthorizationListBuilder setBootPatchLevel(Integer bootPatchLevel) {
    this.bootPatchLevel = Optional.ofNullable(bootPatchLevel);
    return this;
  }

  AuthorizationList build() {
    return new AuthorizationList(purpose, algorithm, keySize, digest, padding, ecCurve, rsaPublicExponent, rollbackResistance, activeDateTime, originationExpireDateTime, usageExpireDateTime, noAuthRequired, userAuthType, authTimeout, allowWhileOnBody, trustedUserPresenceRequired, trustedConfirmationRequired, unlockedDeviceRequired, allApplications, applicationId, creationDateTime, origin, rootOfTrust, osVersion, osPatchLevel, attestationApplicationId, attestationIdBrand, attestationIdDevice, attestationIdProduct, attestationIdSerial, attestationIdImei, attestationIdMeid, attestationIdManufacturer, attestationIdModel, vendorPatchLevel, bootPatchLevel);
  }
}