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

import static java.nio.charset.StandardCharsets.UTF_8;

import com.google.common.base.Ascii;
import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.math.BigInteger;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import okhttp3.Cache;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

/**
 * Utils for fetching and decoding attestation certificate status.
 */
public class CertificateRevocationStatus {

  private static final String STATUS_URL = "https://android.googleapis.com/attestation/status";
  private static final String CACHE_PATH = "httpcache";
  private static final Cache CACHE = new Cache(new File(CACHE_PATH), 10 * 1024 * 1024);
  private static final OkHttpClient CLIENT = new OkHttpClient.Builder()
          .cache(CACHE)
          .build();

  public final Status status;
  public final Reason reason;
  public final String comment;
  public final String expires;

  public static HashMap<String, CertificateRevocationStatus> fetchAllEntries() throws IOException {
    URL url = new URL(STATUS_URL);
    return getEntryToStatusMap(new InputStreamReader(url.openStream(), UTF_8));
  }

  public static HashMap<String, CertificateRevocationStatus> loadAllEntriesFromFile(String filePath)
      throws IOException {
    return getEntryToStatusMap(Files.newBufferedReader(Path.of(filePath)));
  }

  private static HashMap<String, CertificateRevocationStatus> getEntryToStatusMap(
      Reader statusListReader) {
    JsonObject entries =
            JsonParser.parseReader(statusListReader).getAsJsonObject().getAsJsonObject("entries");

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
    return decodeStatus(serialNumber, Files.newBufferedReader(Path.of(filePath)));
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

    Request request = new Request.Builder()
            .url(url)
            .build();

    try (Response response = CLIENT.newCall(request).execute()) {
      return decodeStatus(serialNumber, response.body().charStream());
    }
  }

  private static CertificateRevocationStatus decodeStatus(String serialNumber,
      Reader statusListReader) {
    if (serialNumber == null) {
      throw new IllegalArgumentException("serialNumber cannot be null");
    }
    serialNumber = Ascii.toLowerCase(serialNumber);

    JsonObject entries = JsonParser.parseReader(statusListReader)
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
