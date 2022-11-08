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

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import java.io.ByteArrayInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.math.BigInteger;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.file.Files;
import java.util.HashMap;


/**
 * Utils for fetching and decoding attestation certificate status.
 */
public class CertificateRevocationStatus {

  private static final String STATUS_URL = "https://android.googleapis.com/attestation/status";
  public final Status status;
  public final Reason reason;
  public final String comment;
  public final String expires;

  public static HashMap<String, CertificateRevocationStatus> fetchAllEntries() throws IOException {
    URL url = new URL(STATUS_URL);
    InputStreamReader statusListReader = new InputStreamReader(url.openStream());
    return getEntryToStatusMap(statusListReader);
  }

  public static HashMap<String, CertificateRevocationStatus> loadAllEntriesFromFile(String filePath)
          throws IOException {
    FileReader reader = new FileReader(filePath);
    return getEntryToStatusMap(reader);
  }

  private static HashMap<String, CertificateRevocationStatus> getEntryToStatusMap(
          Reader statusListReader) {
    JsonObject entries =
            new JsonParser().parse(statusListReader).getAsJsonObject().getAsJsonObject("entries");

    HashMap<String, CertificateRevocationStatus> serialNumberToStatus = new HashMap<>();
    for (String serialNumber : entries.keySet()) {
      serialNumberToStatus.put(
              serialNumber,
              new Gson().fromJson(entries.get(serialNumber), CertificateRevocationStatus.class));
    }

    return serialNumberToStatus;
  }

  public static CertificateRevocationStatus loadStatusFromFile(BigInteger serialNumber,
      String filePath)
      throws IOException {
    return loadStatusFromFile(serialNumber.toString(16), filePath);
  }

  public static CertificateRevocationStatus loadStatusFromFile(String serialNumber, String filePath)
      throws IOException {
    FileReader reader = new FileReader(filePath);
    return decodeStatus(serialNumber, reader);
  }


  public static CertificateRevocationStatus fetchStatus(BigInteger serialNumber)
      throws IOException {
    return fetchStatus(serialNumber.toString(16));
  }

  public static CertificateRevocationStatus fetchStatus(String serialNumber) throws IOException {
    URL url;
    try {
      url = new URL(STATUS_URL);
    } catch (MalformedURLException e) {
      throw new IllegalStateException(e);
    }

    InputStreamReader statusListReader = new InputStreamReader(url.openStream());

    return decodeStatus(serialNumber, statusListReader);

  }

  private static CertificateRevocationStatus decodeStatus(String serialNumber,
      Reader statusListReader) {
    if (serialNumber == null) {
      throw new IllegalArgumentException("serialNumber cannot be null");
    }
    serialNumber = serialNumber.toLowerCase();

    JsonObject entries = new JsonParser().parse(statusListReader)
        .getAsJsonObject()
        .getAsJsonObject("entries");

    if (!entries.has(serialNumber)) {
      return null;
    }

    return new Gson().fromJson(entries.get(serialNumber), CertificateRevocationStatus.class);
  }

  public enum Status {
    REVOKED, SUSPENDED
  }

  public enum Reason {
    UNSPECIFIED, KEY_COMPROMISE, CA_COMPROMISE, SUPERSEDED, SOFTWARE_FLAW
  }

  public CertificateRevocationStatus() {
    status = Status.REVOKED;
    reason = Reason.UNSPECIFIED;
    comment = null;
    expires = null;
  }
}
