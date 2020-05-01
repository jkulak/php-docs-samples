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

// [START kms_iam_remove_member]
use Google\Cloud\Kms\V1\KeyManagementServiceClient;

function iam_remove_member_sample(
  $projectId = 'my-project',
  $locationId = 'us-east1',
  $keyRingId = 'my-key-ring',
  $keyId = 'my-key',
  $member = 'user:foo@example.com'
) {
    // Create the Cloud KMS client.
    $client = new KeyManagementServiceClient();

    // Build the resource name.
    $resourceName = $client->cryptoKeyName($projectId, $locationId, $keyRingId, $keyId);

    // The resource name could also be a key ring.
    // $resourceName = $client->keyRingName($projectId, $locationId, $keyRingId);

    // Get the current IAM policy.
    $policy = $client->getIamPolicy($resourceName);

    // Remove the member from the policy.
    foreach ($policy->getBindings() as $binding) {
        if ($binding->getRole() === 'roles/cloudkms.cryptoKeyEncrypterDecrypter') {
            $members = $binding->getMembers();
            foreach ($members as $i => $m) {
                if ($member === $m) {
                    unset($members[$i]);
                    $binding->setMembers($members);
                    break;
                }
            }
        }
    }

    // Save the updated IAM policy.
    $updatedPolicy = $client->setIamPolicy($resourceName, $policy);
    printf('Removed %s' . PHP_EOL, $member);
    return $updatedPolicy;
}
// [END kms_iam_remove_member]

if (isset($argv)) {
    require_once __DIR__ . '/../vendor/autoload.php';
    list($_, $projectId, $locationId, $keyRingId, $keyId, $versionId, $member) = $argv;
    iam_remove_member_sample($projectId, $locationId, $keyRingId, $keyId, $versionId, $member);
}
