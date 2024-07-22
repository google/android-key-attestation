/* Copyright 2016, The Android Open Source Project, Inc.
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

package com.android.example;

import static com.google.android.attestation.Constants.GOOGLE_ROOT_CA_PUB_KEY;
import static com.google.android.attestation.ParsedAttestationRecord.createParsedAttestationRecord;
import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.collect.ImmutableList.toImmutableList;

import com.google.android.attestation.AttestationApplicationId;
import com.google.android.attestation.AttestationApplicationId.AttestationPackageInfo;
import com.google.android.attestation.AuthorizationList;
import com.google.android.attestation.CertificateRevocationStatus;
import com.google.android.attestation.ParsedAttestationRecord;
import com.google.android.attestation.RootOfTrust;
import com.google.common.collect.ImmutableList;
import com.google.protobuf.ByteString;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Stream;

/**
 * This is an illustration of how you can use the Bouncy Castle ASN.1 parser to extract information
 * from an Android attestation data structure. On a secure server that you trust, create similar
 * logic to verify that a key pair has been generated in an Android device. The app on the device
 * must retrieve the key's certificate chain using KeyStore.getCertificateChain(), then send the
 * contents to the trusted server.
 *
 * <p>In this example, the certificate chain includes hard-coded excerpts of each certificate.
 *
 * <p>This example demonstrates the following tasks:
 *
 * <p>1. Loading the certificates from PEM-encoded strings.
 *
 * <p>2. Verifying the certificate chain, up to the root. Note that this example does NOT require
 * the root certificate to appear within Google's list of root certificates. However, if you're
 * verifying the properties of hardware-backed keys on a device that ships with hardware-level key
 * attestation, Android 7.0 (API level 24) or higher, and Google Play services, your production code
 * should enforce this requirement.
 *
 * <p>3. Checking if any certificate in the chain has been revoked or suspended.
 *
 * <p>4. Extracting the attestation extension data from the attestation certificate.
 *
 * <p>5. Verifying (and printing) several important data elements from the attestation extension.
 *
 */
@SuppressWarnings("OptionalUsedAsFieldOrParameterType")
public class KeyAttestationExample {

  private KeyAttestationExample() {}

  public static void main(String[] args)
      throws CertificateException, IOException, NoSuchProviderException, NoSuchAlgorithmException,
          InvalidKeyException, SignatureException {
    checkArgument(
        args.length == 1, "expected path to a directory containing certificates as an argument");

    ImmutableList<X509Certificate> certs = loadCertificates(args[0]);

    verifyCertificateChain(certs);

    ParsedAttestationRecord parsedAttestationRecord = createParsedAttestationRecord(certs);

    System.out.println("Attestation version: " + parsedAttestationRecord.attestationVersion());
    System.out.println(
        "Attestation Security Level: " + parsedAttestationRecord.attestationSecurityLevel().name());
    System.out.println("Keymaster Version: " + parsedAttestationRecord.keymasterVersion());
    System.out.println(
        "Keymaster Security Level: " + parsedAttestationRecord.keymasterSecurityLevel().name());

    System.out.println(
        "Attestation Challenge: " + parsedAttestationRecord.attestationChallenge().toStringUtf8());
    System.out.println(
        "Unique ID: " + Arrays.toString(parsedAttestationRecord.uniqueId().toByteArray()));

    System.out.println("Software Enforced Authorization List:");
    AuthorizationList softwareEnforced = parsedAttestationRecord.softwareEnforced();
    printAuthorizationList(softwareEnforced, "\t");

    System.out.println("TEE Enforced Authorization List:");
    AuthorizationList teeEnforced = parsedAttestationRecord.teeEnforced();
    printAuthorizationList(teeEnforced, "\t");
  }

  private static void printAuthorizationList(AuthorizationList authorizationList, String indent) {
    // Detailed explanation of the keys and their values can be found here:
    // https://source.android.com/security/keystore/tags
    print(authorizationList.purpose(), indent + "Purpose(s)");
    print(authorizationList.algorithm(), indent + "Algorithm");
    print(authorizationList.keySize(), indent + "Key Size");
    print(authorizationList.digest(), indent + "Digest");
    print(authorizationList.padding(), indent + "Padding");
    print(authorizationList.ecCurve(), indent + "EC Curve");
    print(authorizationList.rsaPublicExponent(), indent + "RSA Public Exponent");
    System.out.println(indent + "Rollback Resistance: " + authorizationList.rollbackResistance());
    print(authorizationList.activeDateTime(), indent + "Active DateTime");
    print(authorizationList.originationExpireDateTime(), indent + "Origination Expire DateTime");
    print(authorizationList.usageExpireDateTime(), indent + "Usage Expire DateTime");
    System.out.println(indent + "No Auth Required: " + authorizationList.noAuthRequired());
    print(authorizationList.userAuthType(), indent + "User Auth Type");
    print(authorizationList.authTimeout(), indent + "Auth Timeout");
    System.out.println(indent + "Allow While On Body: " + authorizationList.allowWhileOnBody());
    System.out.println(
        indent
            + "Trusted User Presence Required: "
            + authorizationList.trustedUserPresenceRequired());
    System.out.println(
        indent
            + "Trusted Confirmation Required: "
            + authorizationList.trustedConfirmationRequired());
    System.out.println(
        indent + "Unlocked Device Required: " + authorizationList.unlockedDeviceRequired());
    print(authorizationList.creationDateTime(), indent + "Creation DateTime");
    print(authorizationList.origin(), indent + "Origin");
    authorizationList
        .rootOfTrust()
        .ifPresent(
            rootOfTrust -> {
              System.out.println(indent + "Root Of Trust:");
              print(rootOfTrust, indent + "\t");
            });
    print(authorizationList.osVersion(), indent + "OS Version");
    print(authorizationList.osPatchLevel(), indent + "OS Patch Level");
    authorizationList
        .attestationApplicationId()
        .ifPresent(
            attestationApplicationId -> {
              System.out.println(indent + "Attestation Application ID:");
              print(attestationApplicationId, indent + "\t");
            });
    print(authorizationList.attestationIdBrand(), indent + "Attestation ID Brand");
    print(authorizationList.attestationIdDevice(), indent + "Attestation ID Device");
    print(authorizationList.attestationIdProduct(), indent + "Attestation ID Product");
    print(authorizationList.attestationIdSerial(), indent + "Attestation ID Serial");
    print(authorizationList.attestationIdImei(), indent + "Attestation ID IMEI");
    print(authorizationList.attestationIdSecondImei(), indent + "Attestation ID SECOND IMEI");
    print(authorizationList.attestationIdMeid(), indent + "Attestation ID MEID");
    print(authorizationList.attestationIdManufacturer(), indent + "Attestation ID Manufacturer");
    print(authorizationList.attestationIdModel(), indent + "Attestation ID Model");
    print(authorizationList.vendorPatchLevel(), indent + "Vendor Patch Level");
    print(authorizationList.bootPatchLevel(), indent + "Boot Patch Level");
  }

  private static void print(RootOfTrust rootOfTrust, String indent) {
    System.out.println(
        indent
            + "Verified Boot Key: "
            + Base64.getEncoder().encodeToString(rootOfTrust.verifiedBootKey().toByteArray()));
    System.out.println(indent + "Device Locked: " + rootOfTrust.deviceLocked());
    System.out.println(indent + "Verified Boot State: " + rootOfTrust.verifiedBootState().name());
    rootOfTrust.verifiedBootHash().ifPresent(
        verifiedBootHash ->
            System.out.println(
                indent
                    + "Verified Boot Hash: "
                + Base64.getEncoder().encodeToString(verifiedBootHash.toByteArray())));
  }

  private static void print(AttestationApplicationId attestationApplicationId, String indent) {
      System.out.println(indent + "Package Infos (<package name>, <version>): ");
    for (AttestationPackageInfo info : attestationApplicationId.packageInfos()) {
      System.out.println(indent + "\t" + info.packageName() + ", " + info.version());
      }
      System.out.println(indent + "Signature Digests:");
      for (ByteString digest : attestationApplicationId.signatureDigests()) {
      System.out.println(indent + "\t" + Base64.getEncoder().encodeToString(digest.toByteArray()));
    }
  }

  private static <T> void print(Optional<T> optional, String caption) {
    if (optional.isPresent()) {
      if (optional.get() instanceof byte[]) {
        System.out.println(
            caption + ": " + Base64.getEncoder().encodeToString((byte[]) optional.get()));
      } else {
        System.out.println(caption + ": " + optional.get());
      }
    }
  }

  private static <T> void print(Set<T> set, String caption) {
    if (!set.isEmpty()) {
      System.out.println(caption + ": " + set);
    }
  }

  private static void verifyCertificateChain(List<X509Certificate> certs)
      throws CertificateException, NoSuchAlgorithmException, InvalidKeyException,
      NoSuchProviderException, SignatureException, IOException {
    X509Certificate parent = certs.get(certs.size() - 1);
    for (int i = certs.size() - 1; i >= 0; i--) {
      X509Certificate cert = certs.get(i);
      // Verify that the certificate has not expired.
      cert.checkValidity();
      cert.verify(parent.getPublicKey());
      parent = cert;
      try {
        CertificateRevocationStatus certStatus = CertificateRevocationStatus
            .fetchStatus(cert.getSerialNumber());
        if (certStatus != null) {
          throw new CertificateException(
              "Certificate revocation status is " + certStatus.status.name());
        }
      } catch (IOException e) {
        throw new IOException("Unable to fetch certificate status. Check connectivity.", e);
      }
    }

    // If the attestation is trustworthy and the device ships with hardware-
    // backed key attestation, Android 7.0 (API level 24) or higher, and
    // Google Play services, the root certificate should be signed with the
    // Google attestation root key.
    byte[] googleRootCaPubKey = Base64.getDecoder().decode(GOOGLE_ROOT_CA_PUB_KEY);
    if (Arrays.equals(
        googleRootCaPubKey,
        certs.get(certs.size() - 1).getPublicKey().getEncoded())) {
      System.out.println(
          "The root certificate is correct, so this attestation is trustworthy, as long as none of"
              + " the certificates in the chain have been revoked.");
    } else {
      System.out.println(
          "The root certificate is NOT correct. The attestation was probably generated by"
              + " software, not in secure hardware. This means that there is no guarantee that the"
              + " claims within the attestation are correct. If you're using a production-level"
              + " system, you should disregard any claims made within this attestation certificate"
              + " as there is no authority backing them up.");
    }
  }

  private static ImmutableList<X509Certificate> loadCertificates(String certFilesDir)
      throws CertificateException, IOException {
    ImmutableList<Path> records;
    try (Stream<Path> stream = Files.walk(Paths.get(certFilesDir))) {
      records = stream.filter(Files::isRegularFile).sorted().collect(toImmutableList());
    }
    ImmutableList.Builder<X509Certificate> certs = new ImmutableList.Builder<>();
    CertificateFactory factory = CertificateFactory.getInstance("X.509");
    for (int i = 0; i < records.size(); ++i) {
      byte[] encodedCert = Files.readAllBytes(records.get(i));
      ByteArrayInputStream inputStream = new ByteArrayInputStream(encodedCert);
      certs.add((X509Certificate) factory.generateCertificate(inputStream));
    }
    return certs.build();
  }
}
