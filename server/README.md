Android Key Attestation Sample
==============================

This sample illustrates how to use the [Bouncy Castle ASN.1][1] parser to extract information
from an Android attestation data structure to verify that a key pair has been
generated in an Android device. This sample demonstrates how to verify a certificate on a server.

[1]: https://www.bouncycastle.org/

Introduction
------------

This example demonstrates the following tasks:

1. Loading the certificates from [PEM/DER][2]-encoded strings.
1. Verifying the [X.509][3] certificate chain, up to the root. This includes checking that the root certificate is one of Google's root certificates listed in https://developer.android.com/training/articles/security-key-attestation.
1. Extracting the attestation extension data from the attestation
   certificate.
1. Verifying (and printing) data elements from the attestation extension.

For more information about the process of extracting attestation certificate
extension data, as well as the extension data schema, see the
[Key Attestation][4] Android developer training article.

Note that this sample demonstrates the verification of a certificate on a server and not
on the Android framework. Although you can test the certificate and extensions directly
on a device, it is safer to run these checks on a separate server you can trust.

[2]: https://developer.android.com/reference/java/security/KeyStore.html#getCertificateChain(java.lang.String)
[3]: https://developer.android.com/reference/javax/security/cert/X509Certificate.html
[4]: https://developer.android.com/training/articles/security-key-attestation.html

Pre-requisites
--------------

- Up-to-date Java JDK
- [Bouncy Castle Cryptography Java APIs][5] (included as dependency in gradle build configuration).

[5]: https://www.bouncycastle.org/java.html

Getting Started
---------------

This sample uses the Gradle build system. To build this project, use the
`gradlew build` command or use "Import Project" in IntelliJ or Android Studio.
 
Run the main method in `KeyAttestationExample` directly or use the
`gradlew run --args="<cert-directory>"` task to execute this sample. The `cert-directory` must
contain the certificate chain, one certificate per file in either DER or PEM encoding and the files
are read in alphabetical order. For example the provided
`/examples/pem/algorithm_EC_SecurityLevel_StrongBox/` can be used.

Support
-------

- Stack Overflow: http://stackoverflow.com/questions/tagged/android

If you've found an error in this sample, please file an issue:
https://github.com/googlesamples/android-key-attestation

Patches are encouraged, and may be submitted by forking this project and
submitting a pull request through GitHub. Please see CONTRIBUTING.md for more details.

License
-------

Copyright 2016, The Android Open Source Project, Inc.

Licensed to the Apache Software Foundation (ASF) under one or more contributor
license agreements. See the NOTICE file distributed with this work for
additional information regarding copyright ownership. The ASF licenses this
file to you under the Apache License, Version 2.0 (the "License"); you may not
use this file except in compliance with the License. You may obtain a copy of
the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
License for the specific language governing permissions and limitations under
the License.
