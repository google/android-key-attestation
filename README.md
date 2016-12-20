Android Key Attestation Sample
===================================

This sample illustrates how to use the [Bouncy Castle ASN.1][1] parser to extract information
from an Android attestation data structure to verify that a key pair has been
generated in an Android device. 

This repository contains a [server](server/) sample that shows how to attest an Android certificate
outside the Android framework. This is the recommended best practise, as it is safer to check the
certificate's authenticity on a separate server that you trust.

For more details, see the documentation and the guide at 
https://developer.android.com/training/articles/security-key-attestation.html .

[1]: https://www.bouncycastle.org/


Getting Started
---------------

See the [server](server/) sample for details.

Support
-------

- Google+ Community: https://plus.google.com/communities/105153134372062985968
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