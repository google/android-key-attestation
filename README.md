Android Key Attestation Library
===================================

This library uses the [Bouncy Castle ASN.1][1] parser to extract information
from an Android attestation data structure to verify that a key pair has been
generated in a hardware-protected environment of an Android device. It is
maintained in tandem with Android's key attestation capabilities and is meant
for production use.

This repository contains a [server](server/src/main/java/com/android/example/)
sample code that shows how to validate an Android attestation certificate chain
outside the Android framework. This is the recommended best practice, since if
the Android device is rooted or otherwise compromised, on-device validation of
the attestation may be inaccurate.

The entry point into the
[library itself](server/src/main/java/com/google/android/attestation/)
is `com.google.android.attestation.ParsedAttestationRecord.createParsedAttestationRecord`.

For more details, see the documentation and the guide at
https://developer.android.com/training/articles/security-key-attestation.html .

[1]: https://www.bouncycastle.org/


Getting Started
---------------

See the [server](server/) sample for details.

Support
-------

- Stack Overflow: http://stackoverflow.com/questions/tagged/android

If you've found an error in this sample, please file an issue:
https://github.com/google/android-key-attestation

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
