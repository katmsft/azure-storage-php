<?php

/**
 * LICENSE: The MIT License (the "License")
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * https://github.com/azure/azure-storage-php/LICENSE
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * PHP version 5
 *
 * @category  Microsoft
 * @package   MicrosoftAzure\Storage\Common\Internal\Authentication
 * @author    Azure Storage PHP SDK <dmsh@microsoft.com>
 * @copyright Microsoft Corporation
 * @license   https://github.com/azure/azure-storage-php/LICENSE
 * @link      https://github.com/azure/azure-storage-php
 */

namespace MicrosoftAzure\Storage\Common;

use MicrosoftAzure\Storage\Common\Internal\Resources;
use MicrosoftAzure\Storage\Common\Internal\Utilities;
use MicrosoftAzure\Storage\Common\Internal\Validate;
use MicrosoftAzure\Storage\Common\Models\AccessPolicy;

/**
 * Provides methods to generate Azure Storage Shared Access Signature
 *
 * @category  Microsoft
 * @package   MicrosoftAzure\Storage\Common\Internal\Authentication
 * @author    Azure Storage PHP SDK <dmsh@microsoft.com>
 * @copyright 2017 Microsoft Corporation
 * @license   https://github.com/azure/azure-storage-php/LICENSE
 * @link      https://github.com/azure/azure-storage-php
 */
class SharedAccessSignatureHelper
{
    protected $accountName;
    protected $accountKey;

    /**
     * Constructor.
     *
     * @param string $accountName the name of the storage account.
     * @param string $accountKey the shared key of the storage account
     *
     * @return
     * MicrosoftAzure\Storage\Common\SharedAccessSignatureHelper
     */
    public function __construct($accountName, $accountKey)
    {
        Validate::isString($accountName, 'accountName');
        Validate::notNullOrEmpty($accountName, 'accountName');

        Validate::isString($accountKey, 'accountKey');
        Validate::notNullOrEmpty($accountKey, 'accountKey');

        $this->accountName = urldecode($accountName);
        $this->accountKey = $accountKey;
    }

    /**
     * Helper function to generate a Blob or File service shared access signature.
     *
     * This only supports version 2015-04-05 and later.
     *
     * @param  string $signedVersion      Contains the service version of the
     *                                    shared access signature
     * @param  string $signedService      The service type of the SAS, can only
     *                                    be 'b' or 'f'.
     * @param  string $signedResource     Resource name to generate the
     *                                    canonicalized resource.
     *                                    It can be 'b', 'c', 'f' or 's'.
     * @param  string $resourceName       The name of the resource, including
     *                                    the path of the resource. It should be
     *                                    - {container}/{blob}: for blobs,
     *                                    - {container}: for containers,
     *                                    - {share}/{file}: for files,
     *                                    - {share}: for file shares, e.g.:
     *                                    /mymusic/music.mp3 or
     *                                    music.mp3
     * @param  string $signedPermissions  Signed permissions.
     * @param  string $signedExpiry       Signed expiry date.
     * @param  string $signedStart        Signed start date.
     * @param  string $signedIP           Signed IP address.
     * @param  string $signedProtocol     Signed protocol.
     * @param  string $signedIdentifier   Signed identifier.
     * @param  string $cacheControl       Cache-Control header (rscc).
     * @param  string $contentDisposition Content-Disposition header (rscd).
     * @param  string $contentEncoding    Content-Encoding header (rsce).
     * @param  string $contentLanguage    Content-Language header (rscl).
     * @param  string $contentType        Content-Type header (rsct).
     *
     * @see Constructing an service SAS at
     * https://docs.microsoft.com/en-us/rest/api/storageservices/constructing-a-service-sas
     * @return string
     */
    private function generateBlobOrFileServiceSharedAccessSignatureToken(
        $signedVersion,
        $signedService,
        $signedResource,
        $resourceName,
        $signedPermissions,
        $signedExpiry,
        $signedStart = "",
        $signedIP = "",
        $signedProtocol = "",
        $signedIdentifier = "",
        $cacheControl = "",
        $contentDisposition = "",
        $contentEncoding = "",
        $contentLanguage = "",
        $contentType = ""
    ) {
        // check that version is valid
        Validate::isString($signedVersion, 'signedVersion');
        Validate::notNullOrEmpty($signedVersion, 'signedVersion');
        Validate::isDateString($signedVersion, 'signedVersion');
        // check that the resource name is valid.
        Validate::isString($resourceName, 'resourceName');
        Validate::notNullOrEmpty($resourceName, 'resourceName');
        // validate and sanitize signed permissions
        $signedPermissions = $this->validateAndSanitizeSignedPermissions(
            $signedPermissions,
            $signedResource
        );
        // check that expiracy is valid
        Validate::isString($signedExpiry, 'signedExpiry');
        Validate::notNullOrEmpty($signedExpiry, 'signedExpiry');
        Validate::isDateString($signedExpiry, 'signedExpiry');
        // check that signed start is valid
        Validate::isString($signedStart, 'signedStart');
        if (strlen($signedStart) > 0) {
            Validate::isDateString($signedStart, 'signedStart');
        }
        // check that signed IP is valid
        Validate::isString($signedIP, 'signedIP');
        // validate and sanitize signed protocol
        $signedProtocol = $this->validateAndSanitizeSignedProtocol($signedProtocol);
        // check that signed identifier is valid
        Validate::isString($signedIdentifier, 'signedIdentifier');
        Validate::isTrue(
            (strlen($signedIdentifier) <= 64),
            sprintf(Resources::INVALID_STRING_LENGTH, 'signedIdentifier', 'maximum 64')
        );
        Validate::isString($cacheControl, 'cacheControl');
        Validate::isString($contentDisposition, 'contentDisposition');
        Validate::isString($contentEncoding, 'contentEncoding');
        Validate::isString($contentLanguage, 'contentLanguage');
        Validate::isString($contentType, 'contentType');

        // construct an array with the parameters to generate the shared access signature at the account level
        $parameters = array();
        $parameters[] = urldecode($signedPermissions);
        $parameters[] = urldecode($signedStart);
        $parameters[] = urldecode($signedExpiry);
        $parameters[] = urldecode(static::generateCanonicalResource(
            $this->accountName,
            $signedService,
            $resourceName
        ));
        $parameters[] = urldecode($signedIdentifier);
        $parameters[] = urldecode($signedIP);
        $parameters[] = urldecode($signedProtocol);
        $parameters[] = urldecode($signedVersion);
        $parameters[] = urldecode($cacheControl);
        $parameters[] = urldecode($contentDisposition);
        $parameters[] = urldecode($contentEncoding);
        $parameters[] = urldecode($contentLanguage);
        $parameters[] = urldecode($contentType);

        // implode the parameters into a string
        $stringToSign = utf8_encode(implode("\n", $parameters));
        // decode the account key from base64
        $decodedAccountKey = base64_decode($this->accountKey);
        // create the signature with hmac sha256
        $signature = hash_hmac("sha256", $stringToSign, $decodedAccountKey, true);
        // encode the signature as base64
        $sig = urlencode(base64_encode($signature));
        //adding all the components for account SAS together.
        $sas  = 'sv='    . $signedVersion;
        $sas .= '&sr='   . $signedResource;
        $sas .= $cacheControl === ''? '' : '&rscc=' . $cacheControl;
        $sas .= $contentDisposition === ''? '' : '&rscd=' . $contentDisposition;
        $sas .= $contentEncoding === ''? '' : '&rsce=' . $contentEncoding;
        $sas .= $contentLanguage === ''? '' : '&rscl=' . $contentLanguage;
        $sas .= $contentType === ''? '' : '&rsct=' . $contentType;
        $sas .= $signedStart === ''? '' : '&st=' . $signedStart;
        $sas .= '&se='   . $signedExpiry;
        $sas .= '&sp='   . $signedPermissions;
        $sas .= $signedIP === ''? '' : '&sip=' . $signedIP;
        $sas .= $signedProtocol === ''? '' : '&spr=' . $signedProtocol;
        $sas .= $signedIdentifier === ''? '' : '&si=' . $signedIdentifier;
        $sas .= '&sig='  . $sig;

        // return the signature
        return $sas;
    }

    /**
     * Generates Blob service shared access signature.
     *
     * This only supports version 2015-04-05 and later.
     *
     * @param  string $signedVersion      Contains the service version of the
     *                                    shared access signature
     * @param  string $signedResource     Resource name to generate the
     *                                    canonicalized resource.
     *                                    It can be Resources::RESOURCE_TYPE_BLOB
     *                                    or Resources::RESOURCE_TYPE_CONTAINER.
     * @param  string $resourceName       The name of the resource, including
     *                                    the path of the resource. It should be
     *                                    - {container}/{blob}: for blobs,
     *                                    - {container}: for containers, e.g.:
     *                                    /mymusic/music.mp3 or
     *                                    music.mp3
     * @param  string $signedPermissions  Signed permissions.
     * @param  string $signedExpiry       Signed expiry date.
     * @param  string $signedStart        Signed start date.
     * @param  string $signedIP           Signed IP address.
     * @param  string $signedProtocol     Signed protocol.
     * @param  string $signedIdentifier   Signed identifier.
     * @param  string $cacheControl       Cache-Control header (rscc).
     * @param  string $contentDisposition Content-Disposition header (rscd).
     * @param  string $contentEncoding    Content-Encoding header (rsce).
     * @param  string $contentLanguage    Content-Language header (rscl).
     * @param  string $contentType        Content-Type header (rsct).
     *
     * @see Constructing an service SAS at
     * https://docs.microsoft.com/en-us/rest/api/storageservices/constructing-a-service-sas
     * @return string
     */
    public function generateBlobServiceSharedAccessSignatureToken(
        $signedVersion,
        $signedResource,
        $resourceName,
        $signedPermissions,
        $signedExpiry,
        $signedStart = "",
        $signedIP = "",
        $signedProtocol = "",
        $signedIdentifier = "",
        $cacheControl = "",
        $contentDisposition = "",
        $contentEncoding = "",
        $contentLanguage = "",
        $contentType = ""
    ) {
        // check that the resource name is valid.
        Validate::isString($signedResource, 'signedResource');
        Validate::notNullOrEmpty($signedResource, 'signedResource');
        Validate::isTrue(
            $signedResource == Resources::RESOURCE_TYPE_BLOB ||
            $signedResource == Resources::RESOURCE_TYPE_CONTAINER,
            \sprintf(
                Resources::INVALID_VALUE_MSG,
                '$signedResource',
                'Can only be \'b\' or \'c\'.'
            )
        );

        return $this->generateBlobOrFileServiceSharedAccessSignatureToken(
            $signedVersion,
            Resources::RESOURCE_TYPE_BLOB,
            $signedResource,
            $resourceName,
            $signedPermissions,
            $signedExpiry,
            $signedStart,
            $signedIP,
            $signedProtocol,
            $signedIdentifier,
            $cacheControl,
            $contentDisposition,
            $contentEncoding,
            $contentLanguage,
            $contentType
        );
    }

    /**
     * Generates File service shared access signature.
     *
     * This only supports version 2015-04-05 and later.
     *
     * @param  string $signedVersion      Contains the service version of the
     *                                    shared access signature
     * @param  string $signedResource     Resource name to generate the
     *                                    canonicalized resource.
     *                                    It can be Resources::RESOURCE_TYPE_FILE
     *                                    or Resources::RESOURCE_TYPE_SHARE.
     * @param  string $resourceName       The name of the resource, including
     *                                    the path of the resource. It should be
     *                                    - {share}/{file}: for files,
     *                                    - {share}: for shares, e.g.:
     *                                    /mymusic/music.mp3 or
     *                                    music.mp3
     * @param  string $signedPermissions  Signed permissions.
     * @param  string $signedExpiry       Signed expiry date.
     * @param  string $signedStart        Signed start date.
     * @param  string $signedIP           Signed IP address.
     * @param  string $signedProtocol     Signed protocol.
     * @param  string $signedIdentifier   Signed identifier.
     * @param  string $cacheControl       Cache-Control header (rscc).
     * @param  string $contentDisposition Content-Disposition header (rscd).
     * @param  string $contentEncoding    Content-Encoding header (rsce).
     * @param  string $contentLanguage    Content-Language header (rscl).
     * @param  string $contentType        Content-Type header (rsct).
     *
     * @see Constructing an service SAS at
     * https://docs.microsoft.com/en-us/rest/api/storageservices/constructing-a-service-sas
     * @return string
     */
    public function generateFileServiceSharedAccessSignatureToken(
        $signedVersion,
        $signedResource,
        $resourceName,
        $signedPermissions,
        $signedExpiry,
        $signedStart = "",
        $signedIP = "",
        $signedProtocol = "",
        $signedIdentifier = "",
        $cacheControl = "",
        $contentDisposition = "",
        $contentEncoding = "",
        $contentLanguage = "",
        $contentType = ""
    ) {
        // check that the resource name is valid.
        Validate::isString($signedResource, 'signedResource');
        Validate::notNullOrEmpty($signedResource, 'signedResource');
        Validate::isTrue(
            $signedResource == Resources::RESOURCE_TYPE_FILE ||
            $signedResource == Resources::RESOURCE_TYPE_SHARE,
            \sprintf(
                Resources::INVALID_VALUE_MSG,
                '$signedResource',
                'Can only be \'f\' or \'s\'.'
            )
        );

        return $this->generateBlobOrFileServiceSharedAccessSignatureToken(
            $signedVersion,
            Resources::RESOURCE_TYPE_FILE,
            $signedResource,
            $resourceName,
            $signedPermissions,
            $signedExpiry,
            $signedStart,
            $signedIP,
            $signedProtocol,
            $signedIdentifier,
            $cacheControl,
            $contentDisposition,
            $contentEncoding,
            $contentLanguage,
            $contentType
        );
    }

    /**
     * Generates Table service shared access signature.
     *
     * This only supports version 2015-04-05 and later.
     *
     * @param  string $signedVersion        Contains the service version of the
     *                                      shared access signature
     * @param  string $tableName            The name of the table.
     * @param  string $signedPermissions    Signed permissions.
     * @param  string $signedExpiry         Signed expiry date.
     * @param  string $signedStart          Signed start date.
     * @param  string $signedIP             Signed IP address.
     * @param  string $signedProtocol       Signed protocol.
     * @param  string $signedIdentifier     Signed identifier.
     * @param  string $startingPartitionKey Minimum partition key.
     * @param  string $startingRowKey       Minimum row key.
     * @param  string $endingPartitionKey   Maximum partition key.
     * @param  string $endingRowKey         Maximum row key.
     *
     * @see Constructing an service SAS at
     * https://docs.microsoft.com/en-us/rest/api/storageservices/constructing-a-service-sas
     * @return string
     */
    public function generateTableServiceSharedAccessSignatureToken(
        $signedVersion,
        $tableName,
        $signedPermissions,
        $signedExpiry,
        $signedStart = "",
        $signedIP = "",
        $signedProtocol = "",
        $signedIdentifier = "",
        $startingPartitionKey = "",
        $startingRowKey = "",
        $endingPartitionKey = "",
        $endingRowKey = ""
    ) {
        // check that version is valid
        Validate::isString($signedVersion, 'signedVersion');
        Validate::notNullOrEmpty($signedVersion, 'signedVersion');
        Validate::isDateString($signedVersion, 'signedVersion');
        // check that tableName is valid
        Validate::isString($tableName, 'tableName');
        Validate::notNullOrEmpty($tableName, 'tableName');

        // validate and sanitize signed permissions
        $signedPermissions = $this->validateAndSanitizeSignedPermissions(
            $signedPermissions,
            Resources::RESOURCE_TYPE_TABLE
        );
        // check that expiracy is valid
        Validate::isString($signedExpiry, 'signedExpiry');
        Validate::notNullOrEmpty($signedExpiry, 'signedExpiry');
        Validate::isDateString($signedExpiry, 'signedExpiry');
        // check that signed start is valid
        Validate::isString($signedStart, 'signedStart');
        if (strlen($signedStart) > 0) {
            Validate::isDateString($signedStart, 'signedStart');
        }
        // check that signed IP is valid
        Validate::isString($signedIP, 'signedIP');
        // validate and sanitize signed protocol
        $signedProtocol = $this->validateAndSanitizeSignedProtocol($signedProtocol);
        // check that signed identifier is valid
        Validate::isString($signedIdentifier, 'signedIdentifier');
        Validate::isTrue(
            (strlen($signedIdentifier) <= 64),
            sprintf(Resources::INVALID_STRING_LENGTH, 'signedIdentifier', 'maximum 64')
        );
        Validate::isString($startingPartitionKey, 'startingPartitionKey');
        Validate::isString($startingRowKey, 'startingRowKey');
        Validate::isString($endingPartitionKey, 'endingPartitionKey');
        Validate::isString($endingRowKey, 'endingRowKey');
        // construct an array with the parameters to generate the shared access signature at the account level
        $parameters = array();
        $parameters[] = urldecode($signedPermissions);
        $parameters[] = urldecode($signedStart);
        $parameters[] = urldecode($signedExpiry);
        $parameters[] = urldecode(static::generateCanonicalResource(
            $this->accountName,
            Resources::RESOURCE_TYPE_TABLE,
            $tableName
        ));
        $parameters[] = urldecode($signedIdentifier);
        $parameters[] = urldecode($signedIP);
        $parameters[] = urldecode($signedProtocol);
        $parameters[] = urldecode($signedVersion);
        $parameters[] = urldecode($startingPartitionKey);
        $parameters[] = urldecode($startingRowKey);
        $parameters[] = urldecode($endingPartitionKey);
        $parameters[] = urldecode($endingRowKey);
        // implode the parameters into a string
        $stringToSign = utf8_encode(implode("\n", $parameters));
        // decode the account key from base64
        $decodedAccountKey = base64_decode($this->accountKey);
        // create the signature with hmac sha256
        $signature = hash_hmac("sha256", $stringToSign, $decodedAccountKey, true);
        // encode the signature as base64
        $sig = urlencode(base64_encode($signature));

        //adding all the components for account SAS together.
        $sas  = 'sv='    . $signedVersion;
        $sas .= '&tn='   . $tableName;
        $sas .= $signedStart === ''? '' : '&st=' . $signedStart;
        $sas .= '&se='   . $signedExpiry;
        $sas .= '&sp='   . $signedPermissions;
        $sas .= $startingPartitionKey === ''? '' : '&spk=' . $startingPartitionKey;
        $sas .= $startingRowKey === ''? '' : '&srk=' . $startingRowKey;
        $sas .= $endingPartitionKey === ''? '' : '&epk=' . $endingPartitionKey;
        $sas .= $endingRowKey === ''? '' : '&erk=' . $endingRowKey;
        $sas .= $signedIP === ''? '' : '&sip=' . $signedIP;
        $sas .= $signedProtocol === ''? '' : '&spr=' . $signedProtocol;
        $sas .= $signedIdentifier === ''? '' : '&si=' . $signedIdentifier;
        $sas .= '&sig='  . $sig;

        // return the signature
        return $sas;
    }

    /**
     * Generates a queue service shared access signature.
     *
     * This only supports version 2015-04-05 and later.
     *
     * @param  string $signedVersion      Contains the service version of the
     *                                    shared access signature
     * @param  string $queueName          The name of the queue.
     * @param  string $signedPermissions  Signed permissions.
     * @param  string $signedExpiry       Signed expiry date.
     * @param  string $signedStart        Signed start date.
     * @param  string $signedIdentifier   Signed identifier.
     * @param  string $signedIP           Signed IP address.
     * @param  string $signedProtocol     Signed protocol.
     *
     * @see Constructing an service SAS at
     * https://docs.microsoft.com/en-us/rest/api/storageservices/constructing-a-service-sas
     * @return string
     */
    public function generateQueueServiceSharedAccessSignatureToken(
        $signedVersion,
        $queueName,
        $signedPermissions,
        $signedExpiry,
        $signedStart = "",
        $signedIP = "",
        $signedProtocol = "",
        $signedIdentifier = ""
    ) {
        // check that version is valid
        Validate::isString($signedVersion, 'signedVersion');
        Validate::notNullOrEmpty($signedVersion, 'signedVersion');
        Validate::isDateString($signedVersion, 'signedVersion');
        // check that queue name is valid
        Validate::isString($queueName, 'queueName');
        Validate::notNullOrEmpty($queueName, 'queueName');
        // validate and sanitize signed permissions
        $signedPermissions = $this->validateAndSanitizeSignedPermissions(
            $signedPermissions,
            Resources::RESOURCE_TYPE_QUEUE
        );

        // check that expiracy is valid
        Validate::isString($signedExpiry, 'signedExpiry');
        Validate::notNullOrEmpty($signedExpiry, 'signedExpiry');
        Validate::isDateString($signedExpiry, 'signedExpiry');
        // check that signed start is valid
        Validate::isString($signedStart, 'signedStart');
        if (strlen($signedStart) > 0) {
            Validate::isDateString($signedStart, 'signedStart');
        }
        // check that signed IP is valid
        Validate::isString($signedIP, 'signedIP');
        // validate and sanitize signed protocol
        $signedProtocol = $this->validateAndSanitizeSignedProtocol($signedProtocol);
        // check that signed identifier is valid
        Validate::isString($signedIdentifier, 'signedIdentifier');
        Validate::isTrue(
            (strlen($signedIdentifier) <= 64),
            sprintf(Resources::INVALID_STRING_LENGTH, 'signedIdentifier', 'maximum 64')
        );
        // construct an array with the parameters to generate the shared access signature at the account level
        $parameters = array();
        $parameters[] = urldecode($signedPermissions);
        $parameters[] = urldecode($signedStart);
        $parameters[] = urldecode($signedExpiry);
        $parameters[] = urldecode(static::generateCanonicalResource(
            $this->accountName,
            Resources::RESOURCE_TYPE_QUEUE,
            $queueName
        ));
        $parameters[] = urldecode($signedIdentifier);
        $parameters[] = urldecode($signedIP);
        $parameters[] = urldecode($signedProtocol);
        $parameters[] = urldecode($signedVersion);

        // implode the parameters into a string
        $stringToSign = utf8_encode(implode("\n", $parameters));
        // decode the account key from base64
        $decodedAccountKey = base64_decode($this->accountKey);
        // create the signature with hmac sha256
        $signature = hash_hmac("sha256", $stringToSign, $decodedAccountKey, true);
        // encode the signature as base64
        $sig = urlencode(base64_encode($signature));

        //adding all the components for account SAS together.
        $sas  = 'sv='    . $signedVersion;
        $sas .= $signedStart === ''? '' : '&st=' . $signedStart;
        $sas .= '&se='   . $signedExpiry;
        $sas .= '&sp='   . $signedPermissions;
        $sas .= $signedIP === ''? '' : '&sip=' . $signedIP;
        $sas .= $signedProtocol === ''? '' : '&spr=' . $signedProtocol;
        $sas .= $signedIdentifier === ''? '' : '&si=' . $signedIdentifier;
        $sas .= '&sig='  . $sig;

        // return the signature
        return $sas;
    }

    /**
     * Generates a shared access signature at the account level.
     *
     * @param string $signedVersion         Specifies the signed version to use.
     * @param string $signedPermissions     Specifies the signed permissions for
     *                                      the account SAS.
     * @param string $signedService         Specifies the signed services
     *                                      accessible with the account SAS.
     * @param string $signedResourceType    Specifies the signed resource types
     *                                      that are accessible with the account
     *                                      SAS.
     * @param string $signedExpiry          The time at which the shared access
     *                                      signature becomes invalid, in an ISO
     *                                      8601 format.
     * @param string $signedStart           The time at which the SAS becomes
     *                                      valid, in an ISO 8601 format.
     * @param string $signedIP              Specifies an IP address or a range
     *                                      of IP addresses from which to accept
     *                                      requests.
     * @param string $signedProtocol        Specifies the protocol permitted for
     *                                      a request made with the account SAS.
     *
     * @see Constructing an account SAS at
     *      https://docs.microsoft.com/en-us/rest/api/storageservices/fileservices/constructing-an-account-sas
     *
     * @return string
     */
    public function generateAccountSharedAccessSignatureToken(
        $signedVersion,
        $signedPermissions,
        $signedService,
        $signedResourceType,
        $signedExpiry,
        $signedStart = "",
        $signedIP = "",
        $signedProtocol = ""
    ) {
        // check that version is valid
        Validate::isString($signedVersion, 'signedVersion');
        Validate::notNullOrEmpty($signedVersion, 'signedVersion');
        Validate::isDateString($signedVersion, 'signedVersion');

        // validate and sanitize signed service
        $signedService = $this->validateAndSanitizeSignedService($signedService);

        // validate and sanitize signed resource type
        $signedResourceType = $this->validateAndSanitizeSignedResourceType($signedResourceType);
        
        // validate and sanitize signed permissions
        $signedPermissions = $this->validateAndSanitizeSignedPermissions($signedPermissions);

        // check that expiracy is valid
        Validate::isString($signedExpiry, 'signedExpiry');
        Validate::notNullOrEmpty($signedExpiry, 'signedExpiry');
        Validate::isDateString($signedExpiry, 'signedExpiry');

        // check that signed start is valid
        Validate::isString($signedStart, 'signedStart');
        if (strlen($signedStart) > 0) {
            Validate::isDateString($signedStart, 'signedStart');
        }

        // check that signed IP is valid
        Validate::isString($signedIP, 'signedIP');

        // validate and sanitize signed protocol
        $signedProtocol = $this->validateAndSanitizeSignedProtocol($signedProtocol);

        // construct an array with the parameters to generate the shared access signature at the account level
        $parameters = array();
        $parameters[] = $this->accountName;
        $parameters[] = urldecode($signedPermissions);
        $parameters[] = urldecode($signedService);
        $parameters[] = urldecode($signedResourceType);
        $parameters[] = urldecode($signedStart);
        $parameters[] = urldecode($signedExpiry);
        $parameters[] = urldecode($signedIP);
        $parameters[] = urldecode($signedProtocol);
        $parameters[] = urldecode($signedVersion);

        // implode the parameters into a string
        $stringToSign = utf8_encode(implode("\n", $parameters) . "\n");

        // decode the account key from base64
        $decodedAccountKey = base64_decode($this->accountKey);
        
        // create the signature with hmac sha256
        $signature = hash_hmac("sha256", $stringToSign, $decodedAccountKey, true);

        // encode the signature as base64 and url encode.
        $sig = urlencode(base64_encode($signature));

        //adding all the components for account SAS together.
        $sas  = 'sv=' . $signedVersion;
        $sas .= '&ss=' . $signedService;
        $sas .= '&srt=' . $signedResourceType;
        $sas .= '&sp=' . $signedPermissions;
        $sas .= '&se=' . $signedExpiry;
        $sas .= $signedStart === ''? '' : '&st=' . $signedStart;
        $sas .= $signedIP === ''? '' : '&sip=' . $signedIP;
        $sas .= '&spr=' . $signedProtocol;
        $sas .= '&sig=' . $sig;

        // return the signature
        return $sas;
    }

    /**
     * Validates and sanitizes the signed service parameter
     *
     * @param string $signedService Specifies the signed services accessible
     *                              with the account SAS.
     *
     * @return string
     */
    private function validateAndSanitizeSignedService($signedService)
    {
        // validate signed service is not null or empty
        Validate::isString($signedService, 'signedService');
        Validate::notNullOrEmpty($signedService, 'signedService');

        // The signed service should only be a combination of the letters b(lob) q(ueue) t(able) or f(ile)
        $validServices = ['b', 'q', 't', 'f'];

        return $this->validateAndSanitizeStringWithArray(
            strtolower($signedService),
            $validServices
        );
    }

    /**
     * Validates and sanitizes the signed resource type parameter
     *
     * @param string $signedResourceType    Specifies the signed resource types
     *                                      that are accessible with the account
     *                                      SAS.
     *
     * @return string
     */
    private function validateAndSanitizeSignedResourceType($signedResourceType)
    {
        // validate signed resource type is not null or empty
        Validate::isString($signedResourceType, 'signedResourceType');
        Validate::notNullOrEmpty($signedResourceType, 'signedResourceType');

        // The signed resource type should only be a combination of the letters s(ervice) c(container) or o(bject)
        $validResourceTypes = ['s', 'c', 'o'];

        return $this->validateAndSanitizeStringWithArray(
            strtolower($signedResourceType),
            $validResourceTypes
        );
    }

    /**
     * Validates and sanitizes the signed permissions parameter
     *
     * @param string $signedPermissions Specifies the signed permissions for the
     *                                  account SAS.
     * @param string $signedResource    Specifies the signed resource for the
     *
     * @return string
     */
    private function validateAndSanitizeSignedPermissions(
        $signedPermissions,
        $signedResource = ''
    ) {
        // validate signed permissions are not null or empty
        Validate::isString($signedPermissions, 'signedPermissions');
        Validate::notNullOrEmpty($signedPermissions, 'signedPermissions');

        if ($signedResource == '') {
            $validPermissions = ['r', 'w', 'd', 'l', 'a', 'c', 'u', 'p'];
        } else {
            $validPermissions =
                AccessPolicy::getResourceValidPermissions()[$signedResource];
        }

        return $this->validateAndSanitizeStringWithArray(
            strtolower($signedPermissions),
            $validPermissions
        );
    }

    /**
     * Validates and sanitizes the signed protocol parameter
     *
     * @param string $signedProtocol Specifies the signed protocol for the
     *                               account SAS.

     * @return string
     */
    private function validateAndSanitizeSignedProtocol($signedProtocol)
    {
        Validate::isString($signedProtocol, 'signedProtocol');
        // sanitize string
        $sanitizedSignedProtocol = strtolower($signedProtocol);
        if (strlen($sanitizedSignedProtocol) > 0) {
            if (strcmp($sanitizedSignedProtocol, "https") != 0 && strcmp($sanitizedSignedProtocol, "https,http") != 0) {
                throw new \InvalidArgumentException(Resources::SIGNED_PROTOCOL_INVALID_VALIDATION_MSG);
            }
        }

        return $sanitizedSignedProtocol;
    }

    /**
     * Checks if a string contains an other string
     *
     * @param string $input        The input to test.
     * @param string $toFind       The string to find in the input.

     * @return bool
     */
    private function strcontains($input, $toFind)
    {
        return strpos($input, $toFind) !== false;
    }

    /**
     * Removes duplicate characters from a string
     *
     * @param string $input        The input string.

     * @return string
     */
    private function validateAndSanitizeStringWithArray($input, array $array)
    {
        $result = '';
        foreach ($array as $value) {
            if (strpos($input, $value) !== false) {
                //append the valid permission to result.
                $result .= $value;
                //remove all the character that represents the permission.
                $input = str_replace(
                    $value,
                    '',
                    $input
                );
            }
        }

        Validate::isTrue(
            strlen($input) == '',
            sprintf(
                Resources::STRING_NOT_WITH_GIVEN_COMBINATION,
                implode(', ', $array)
            )
        );
        return $result;
    }


    /**
     * Generate the canonical resource using the given account name, service
     * type and resource.
     *
     * @param  string $accountName The account name of the service.
     * @param  string $service     The service name of the service.
     * @param  string $resource    The name of the resource.
     *
     * @return string
     */
    private static function generateCanonicalResource(
        $accountName,
        $service,
        $resource
    ) {
        static $serviceMap = array(
            Resources::RESOURCE_TYPE_BLOB  => 'blob',
            Resources::RESOURCE_TYPE_FILE  => 'file',
            Resources::RESOURCE_TYPE_QUEUE => 'queue',
            Resources::RESOURCE_TYPE_TABLE => 'table',
        );
        $serviceName = $serviceMap[$service];
        if (Utilities::startsWith($resource, '/')) {
            $resource = substr(1, strlen($resource) - 1);
        }
        return sprintf('/%s/%s/%s', $serviceName, $accountName, $resource);
    }
}
