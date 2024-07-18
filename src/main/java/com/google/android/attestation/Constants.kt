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

/** Key Attestation constants  */
object Constants {
    const val KEY_DESCRIPTION_OID: String = "1.3.6.1.4.1.11129.2.1.17"
    const val ATTESTATION_VERSION_INDEX: Int = 0
    const val ATTESTATION_SECURITY_LEVEL_INDEX: Int = 1
    const val KEYMASTER_VERSION_INDEX: Int = 2
    const val KEYMASTER_SECURITY_LEVEL_INDEX: Int = 3
    const val ATTESTATION_CHALLENGE_INDEX: Int = 4
    const val UNIQUE_ID_INDEX: Int = 5
    const val SW_ENFORCED_INDEX: Int = 6
    const val TEE_ENFORCED_INDEX: Int = 7

    // Authorization list tags. The list is in this AOSP file:
    // hardware/libhardware/include/hardware/keymaster_defs.h
    const val KM_TAG_PURPOSE: Int = 1
    const val KM_TAG_ALGORITHM: Int = 2
    const val KM_TAG_KEY_SIZE: Int = 3
    const val KM_TAG_DIGEST: Int = 5
    const val KM_TAG_PADDING: Int = 6
    const val KM_TAG_EC_CURVE: Int = 10
    const val KM_TAG_RSA_PUBLIC_EXPONENT: Int = 200
    const val KM_TAG_RSA_OAEP_MGF_DIGEST: Int = 203
    const val KM_TAG_ROLLBACK_RESISTANCE: Int = 303
    const val KM_TAG_ACTIVE_DATE_TIME: Int = 400
    const val KM_TAG_ORIGINATION_EXPIRE_DATE_TIME: Int = 401
    const val KM_TAG_USAGE_EXPIRE_DATE_TIME: Int = 402
    const val KM_TAG_NO_AUTH_REQUIRED: Int = 503
    const val KM_TAG_USER_AUTH_TYPE: Int = 504
    const val KM_TAG_AUTH_TIMEOUT: Int = 505
    const val KM_TAG_ALLOW_WHILE_ON_BODY: Int = 506
    const val KM_TAG_TRUSTED_USER_PRESENCE_REQUIRED: Int = 507
    const val KM_TAG_TRUSTED_CONFIRMATION_REQUIRED: Int = 508
    const val KM_TAG_UNLOCKED_DEVICE_REQUIRED: Int = 509
    const val KM_TAG_CREATION_DATE_TIME: Int = 701
    const val KM_TAG_ORIGIN: Int = 702
    const val KM_TAG_ROOT_OF_TRUST: Int = 704
    const val KM_TAG_OS_VERSION: Int = 705
    const val KM_TAG_OS_PATCH_LEVEL: Int = 706
    const val KM_TAG_ATTESTATION_APPLICATION_ID: Int = 709
    const val KM_TAG_ATTESTATION_ID_BRAND: Int = 710
    const val KM_TAG_ATTESTATION_ID_DEVICE: Int = 711
    const val KM_TAG_ATTESTATION_ID_PRODUCT: Int = 712
    const val KM_TAG_ATTESTATION_ID_SERIAL: Int = 713
    const val KM_TAG_ATTESTATION_ID_IMEI: Int = 714
    const val KM_TAG_ATTESTATION_ID_MEID: Int = 715
    const val KM_TAG_ATTESTATION_ID_MANUFACTURER: Int = 716
    const val KM_TAG_ATTESTATION_ID_MODEL: Int = 717
    const val KM_TAG_VENDOR_PATCH_LEVEL: Int = 718
    const val KM_TAG_BOOT_PATCH_LEVEL: Int = 719
    const val KM_TAG_DEVICE_UNIQUE_ATTESTATION: Int = 720
    const val KM_TAG_ATTESTATION_ID_SECOND_IMEI: Int = 723
    const val ROOT_OF_TRUST_VERIFIED_BOOT_KEY_INDEX: Int = 0
    const val ROOT_OF_TRUST_DEVICE_LOCKED_INDEX: Int = 1
    const val ROOT_OF_TRUST_VERIFIED_BOOT_STATE_INDEX: Int = 2
    const val ROOT_OF_TRUST_VERIFIED_BOOT_HASH_INDEX: Int = 3
    const val ATTESTATION_APPLICATION_ID_PACKAGE_INFOS_INDEX: Int = 0
    const val ATTESTATION_APPLICATION_ID_SIGNATURE_DIGESTS_INDEX: Int = 1
    const val ATTESTATION_PACKAGE_INFO_PACKAGE_NAME_INDEX: Int = 0
    const val ATTESTATION_PACKAGE_INFO_VERSION_INDEX: Int = 1

    // Some security values. The complete list is in this AOSP file:
    // hardware/libhardware/include/hardware/keymaster_defs.h
    const val KM_SECURITY_LEVEL_SOFTWARE: Int = 0
    const val KM_SECURITY_LEVEL_TRUSTED_ENVIRONMENT: Int = 1
    const val KM_SECURITY_LEVEL_STRONG_BOX: Int = 2
    const val KM_VERIFIED_BOOT_STATE_VERIFIED: Int = 0
    const val KM_VERIFIED_BOOT_STATE_SELF_SIGNED: Int = 1
    const val KM_VERIFIED_BOOT_STATE_UNVERIFIED: Int = 2
    const val KM_VERIFIED_BOOT_STATE_FAILED: Int = 3
}
