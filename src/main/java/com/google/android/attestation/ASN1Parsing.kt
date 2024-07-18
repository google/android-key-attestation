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

import org.bouncycastle.asn1.ASN1Boolean
import org.bouncycastle.asn1.ASN1Encodable
import org.bouncycastle.asn1.ASN1Enumerated
import org.bouncycastle.asn1.ASN1Integer

/** Utils to get java representation of ASN1 types.  */
internal object ASN1Parsing {
    @JvmStatic
    fun getBooleanFromAsn1(asn1Value: ASN1Encodable): Boolean {
        if (asn1Value is ASN1Boolean) {
            return asn1Value.isTrue
        } else {
            throw IllegalArgumentException(
                "Boolean value expected; found " + asn1Value.javaClass.name + " instead."
            )
        }
    }

    @JvmStatic
    fun getIntegerFromAsn1(asn1Value: ASN1Encodable): Int {
        return if (asn1Value is ASN1Integer) {
            asn1Value.value.intValueExact()
        } else if (asn1Value is ASN1Enumerated) {
            asn1Value.value.intValueExact()
        } else {
            throw IllegalArgumentException(
                "Integer value expected; found " + asn1Value.javaClass.name + " instead."
            )
        }
    }
}
