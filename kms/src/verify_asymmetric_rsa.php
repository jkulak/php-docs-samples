<?php
/*
 * Copyright 2020 Google LLC.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

declare(strict_types=1);

// [START kms_verify_asymmetric_signature_rsa]

function verify_asymmetric_rsa_sample(
  $projectId = 'my-project',
  $locationId = 'us-east1',
  $keyRingId = 'my-key-ring',
  $keyId = 'my-key',
  $versionId = '123',
  $message = '...',
  $signature = '...'
) {
    // PHP has limited support for asymmetric encryption operations.
    // Specifically, openssl_public_encrypt() does not allow customizing
    // algorithms or padding. Thus, it is not currently possible to use PHP
    // core for asymmetric operations on RSA keys.
    //
    // Third party libraries like phpseclib may provide the required
    // functionality. Google does not endorse this external library.
}
// [END kms_verify_asymmetric_signature_rsa]

if (isset($argv)) {
    require_once __DIR__ . '/../vendor/autoload.php';
    list($_, $projectId, $locationId, $keyRingId, $keyId, $versionId, $message, $signature) = $argv;
    verify_asymmetric_rsa_sample($projectId, $locationId, $keyRingId, $keyId, $versionId, $message, $signature);
}
