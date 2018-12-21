#!/usr/bin/env python
# -*- coding: utf-8 -*-

###############################################################################
#  Copyright Kitware Inc.
#
#  Licensed under the Apache License, Version 2.0 ( the "License" );
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
###############################################################################

import diskcache
import errno
import getpass
import glob
import json
import logging
import mimetypes
import os
import re
import requests
import shutil
import six
import tempfile

from contextlib import contextmanager
from requests_toolbelt import MultipartEncoder

__version__ = '2.4.0'
__license__ = 'Apache 2.0'

DEFAULT_PAGE_LIMIT = 50  # Number of results to fetch per request
REQ_BUFFER_SIZE = 65536  # Chunk size when iterating a download body

_safeNameRegex = re.compile(r'^[/\\]+')

_logger = logging.getLogger('girder_client.lib')


def _safeMakedirs(path):
    """
    Wraps os.makedirs in such a way that it will not raise exceptions if the
    directory already exists.

    :param path: The directory to create.
    """
    try:
        os.makedirs(path)
    except OSError as exception:
        if exception.errno != errno.EEXIST:
            raise


class AuthenticationError(RuntimeError):
    pass


class IncorrectUploadLengthError(RuntimeError):
    def __init__(self, message, upload=None):
        super(IncorrectUploadLengthError, self).__init__(message)
        self.upload = upload


class HttpError(requests.HTTPError):
    """
    Raised if the server returns an error status code from a request.
    @deprecated This will be removed in a future release of Girder. Raisers of this
    exception should instead raise requests.HTTPError manually or through another mechanism
    such as requests.Response.raise_for_status.
    """
    def __init__(self, status, text, url, method, response=None):
        super(HttpError, self).__init__('HTTP error %s: %s %s' % (status, method, url),
                                        response=response)
        self.status = status
        self.responseText = text
        self.url = url
        self.method = method

    def __str__(self):
        return super(HttpError, self).__str__() + '\nResponse text: ' + self.responseText


class IncompleteResponseError(requests.RequestException):
    def __init__(self, message, expected, received, response=None):
        super(IncompleteResponseError, self).__init__('%s (%d of %d bytes received)' % (
            message, received, expected
        ), response=response)


class _NoopProgressReporter(object):
    reportProgress = False

    def __init__(self, label='', length=0):
        self.label = label
        self.length = length

    def update(self, chunkSize):
        pass

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, tb):
        pass


# Used for fast non-multipart upload
class _ProgressBytesIO(six.BytesIO):
    def __init__(self, *args, **kwargs):
        self.reporter = kwargs.pop('reporter')
        six.BytesIO.__init__(self, *args, **kwargs)

    def read(self, _size=-1):
        _chunk = six.BytesIO.read(self, _size)
        self.reporter.update(len(_chunk))
        return _chunk


# Used for deprecated multipart upload
class _ProgressMultiPartEncoder(MultipartEncoder):
    def __init__(self, *args, **kwargs):
        self.reporter = kwargs.pop('reporter')
        MultipartEncoder.__init__(self, *args, **kwargs)

    def read(self, _size=-1):
        _chunk = MultipartEncoder.read(self, _size)
        self.reporter.update(len(_chunk))
        return _chunk


class GirderClient(object):
    """
    A class for interacting with the Girder RESTful API.
    """

    # The current maximum chunk size for uploading file chunks
    MAX_CHUNK_SIZE = 1024 * 1024 * 64

    DEFAULT_API_ROOT = 'api/v1'
    DEFAULT_HOST = 'localhost'
    DEFAULT_LOCALHOST_PORT = 8080
    DEFAULT_HTTP_PORT = 80
    DEFAULT_HTTPS_PORT = 443

    @staticmethod
    def getDefaultPort(hostname, scheme):
        """Get default port based on the hostname.
        Returns `GirderClient.DEFAULT_HTTPS_PORT` if scheme is `https`, otherwise
        returns `GirderClient.DEFAULT_LOCALHOST_PORT` if `hostname` is `localhost`,
        and finally returns `GirderClient.DEFAULT_HTTP_PORT`.
        """
        if scheme == 'https':
            return GirderClient.DEFAULT_HTTPS_PORT
        if hostname == 'localhost':
            return GirderClient.DEFAULT_LOCALHOST_PORT
        return GirderClient.DEFAULT_HTTP_PORT

    @staticmethod
    def getDefaultScheme(hostname):
        """Get default scheme based on the hostname.
        Returns `http` if `hostname` is `localhost` otherwise returns `https`.
        """
        if hostname == 'localhost':
            return 'http'
        else:
            return 'https'

    def __init__(self, host=None, port=None, apiRoot=None, scheme=None, apiUrl=None,
                 cacheSettings=None, progressReporterCls=None):
        """
        Construct a new GirderClient object, given a host name and port number,
        as well as a username and password which will be used in all requests
        (HTTP Basic Auth). You can pass the URL in parts with the `host`,
        `port`, `scheme`, and `apiRoot` kwargs, or simply pass it in all as
        one URL with the `apiUrl` kwarg instead. If you pass `apiUrl`, the
        individual part kwargs will be ignored.

        :param apiUrl: The full path to the REST API of a Girder instance, e.g.
            `http://my.girder.com/api/v1`.
        :param host: A string containing the host name where Girder is running,
            the default value is 'localhost'
        :param port: The port number on which to connect to Girder,
            the default value is 80 for http: and 443 for https:
        :param apiRoot: The path on the server corresponding to the root of the
            Girder REST API. If None is passed, assumes '/api/v1'.
        :param scheme: A string containing the scheme for the Girder host,
            the default value is 'http'; if you pass 'https' you likely want
            to pass 443 for the port
        :param cacheSettings: Settings to use with the diskcache library, or
            None to disable caching.
        :param progressReporterCls: the progress reporter class to instantiate. This class
            is expected to be a context manager with a constructor accepting `label` and
            `length` keyword arguments, an `update` method accepting a `chunkSize` argument and
            a class attribute `reportProgress` set to True (It can conveniently be
            initialized using `sys.stdout.isatty()`).
            This defaults to :class:`_NoopProgressReporter`.
        """
        self.host = None
        self.scheme = None
        self.port = None
        if apiUrl is None:
            if not apiRoot:
                apiRoot = self.DEFAULT_API_ROOT
            # If needed, prepend '/'
            if not apiRoot.startswith('/'):
                apiRoot = '/' + apiRoot

            self.host = host or self.DEFAULT_HOST
            self.scheme = scheme or GirderClient.getDefaultScheme(self.host)
            self.port = port or GirderClient.getDefaultPort(self.host, self.scheme)

            self.urlBase = '%s://%s:%s%s' % (
                self.scheme, self.host, str(self.port), apiRoot)
        else:
            self.urlBase = apiUrl

        if self.urlBase[-1] != '/':
            self.urlBase += '/'

        self.token = ''
        self._folderUploadCallbacks = []
        self._fileUploadCallbacks = []
        self._serverApiDescription = {}

        if cacheSettings is None:
            self.cache = None
        else:
            self.cache = diskcache.Cache(**cacheSettings)

        if progressReporterCls is None:
            progressReporterCls = _NoopProgressReporter

        self.progressReporterCls = progressReporterCls
        self._session = None

    @contextmanager
    def session(self, session=None):
        """
        Use a :class:`requests.Session` object for all outgoing requests from
        :class:`GirderClient`. If `session` isn't passed into the context manager
        then one will be created and yielded. Session objects are useful for enabling
        persistent HTTP connections as well as partially applying arguments to many
        requests, such as headers.

        Note: `session` is closed when the context manager exits, regardless of who
        created it.

        .. code-block:: python

            with gc.session() as session:
                session.headers.update({'User-Agent': 'myapp 1.0'})

                for fileId in fileIds:
                    gc.downloadFile(fileId, fh)

        In the above example, each request will be executed with the User-Agent header
        while reusing the same TCP connection.

        :param session: An existing :class:`requests.Session` object, or None.
        """
        self._session = session if session else requests.Session()

        yield self._session

        self._session.close()
        self._session = None

    def authenticate(self, username=None, password=None, interactive=False, apiKey=None):
        """
        Authenticate to Girder, storing the token that comes back to be used in
        future requests. This method can be used in two modes, either username
        and password authentication, or using an API key. Username example:

        .. code-block:: python

            gc.authenticate(username='myname', password='mypass')

        Note that you may also pass ``interactive=True`` and omit either the
        username or password argument to be prompted for them in the shell. The
        second mode is using an API key:

        .. code-block::python

            gc.authenticate(apiKey='J77R3rsLYYqFXXwQ4YquQtek1N26VEJ7IAVz9IpU')

        API keys can be created and managed on your user account page in the
        Girder web client, and can be used to provide limited access to the Girder web API.

        :param username: A string containing the username to use in basic authentication.
        :param password: A string containing the password to use in basic authentication.
        :param interactive: If you want the user to type their username or
            password in the shell rather than passing it in as an argument,
            set this to True. If you pass a username in interactive mode, the
            user will only be prompted for a password. This option only works
            in username/password mode, not API key mode.
        :param apiKey: Pass this to use an API key instead of username/password authentication.
        :type apiKey: str
        """
        if apiKey:
            resp = self.post('api_key/token', parameters={
                'key': apiKey
            })
            self.setToken(resp['authToken']['token'])
        else:
            if interactive:
                if username is None:
                    username = six.moves.input('Login or email: ')
                password = getpass.getpass('Password for %s: ' % username)

            if username is None or password is None:
                raise Exception('A user name and password are required')

            try:
                resp = self.sendRestRequest('get', 'user/authentication', auth=(username, password),
                                            headers={'Girder-Token': None})
            except HttpError as e:
                if e.status in (401, 403):
                    raise AuthenticationError()
                raise

            self.setToken(resp['authToken']['token'])

    def setToken(self, token):
        """
        Set a token on the GirderClient instance. This is useful in the case
        where the client has already been given a valid token, such as a remote job.

        :param token: A string containing the existing Girder token
        """
        self.token = token

    def getServerVersion(self, useCached=True):
        """
        Fetch server API version. By default, caches the version
        such that future calls to this function do not make another request to
        the server.

        :param useCached: Whether to return the previously fetched value. Set
            to False to force a re-fetch of the version from the server.
        :type useCached: bool
        :return: The API version as a list (e.g. ``['1', '0', '0']``)
        """
        description = self.getServerAPIDescription(useCached)
        version = description.get('info', {}).get('version')
        return version.split('.') if version else None

    def getServerAPIDescription(self, useCached=True):
        """
        Fetch server RESTful API description.

        :param useCached: Whether to return the previously fetched value. Set
            to False to force a re-fetch of the description from the server.
        :type useCached: bool
        :return: The API descriptions as a dict.

        For example: ::

            {
                "basePath": "/api/v1",
                "definitions": {},
                "host": "girder.example.com",
                "info": {
                    "title": "Girder REST API",
                    "version": "X.Y.Z"
                },
                "paths": {
                    "/api_key": {
                        "get": {
                            "description": "Only site administrators [...]",
                            "operationId": "api_key_listKeys",
                            "parameters": [
                                {
                                    "description": "ID of the user whose keys to list.",
                                    "in": "query",
                                    "name": "userId",
                                    "required": false,
                                    "type": "string"
                                },
                                ...
                            ]
                        }.
                        ...
                    }
                ...
                }
            }

        """
        if not self._serverApiDescription or not useCached:
            self._serverApiDescription = self.get('describe')

        return self._serverApiDescription

    def _requestFunc(self, method):
        if self._session is not None:
            return getattr(self._session, method.lower())
        else:
            return getattr(requests, method.lower())

    def sendRestRequest(self, method, path, parameters=None, data=None, files=None, json=None,
                        headers=None, jsonResp=True, **kwargs):
        """
        This method looks up the appropriate method, constructs a request URL
        from the base URL, path, and parameters, and then sends the request. If
        the method is unknown or if the path is not found, an exception is
        raised, otherwise a JSON object is returned with the Girder response.

        This is a convenience method to use when making basic requests that do
        not involve multipart file data that might need to be specially encoded
        or handled differently.

        :param method: The HTTP method to use in the request (GET, POST, etc.)
        :type method: str
        :param path: A string containing the path elements for this request.
            Note that the path string should not begin or end with the path  separator, '/'.
        :type path: str
        :param parameters: A dictionary mapping strings to strings, to be used
            as the key/value pairs in the request parameters.
        :type parameters: dict
        :param data: A dictionary, bytes or file-like object to send in the body.
        :param files: A dictionary of 'name' => file-like-objects for multipart encoding upload.
        :type files: dict
        :param json: A JSON object to send in the request body.
        :type json: dict
        :param headers: If present, a dictionary of headers to encode in the request.
        :type headers: dict
        :param jsonResp: Whether the response should be parsed as JSON. If False, the raw
            response object is returned. To get the raw binary content of the response,
            use the ``content`` attribute of the return value, e.g.

            .. code-block:: python

                resp = client.get('my/endpoint', jsonResp=False)
                print(resp.content)  # Raw binary content
                print(resp.headers)  # Dict of headers

        :type jsonResp: bool
        """
        if not parameters:
            parameters = {}

        # Look up the HTTP method we need
        f = self._requestFunc(method)

        # Construct the url
        url = self.urlBase + path

        # Make the request, passing parameters and authentication info
        _headers = {'Girder-Token': self.token}
        if isinstance(headers, dict):
            _headers.update(headers)

        result = f(
            url, params=parameters, data=data, files=files, json=json, headers=_headers,
            **kwargs)

        # If success, return the json object. Otherwise throw an exception.
        if result.status_code in (200, 201):
            if jsonResp:
                return result.json()
            else:
                return result
        else:
            raise HttpError(
                status=result.status_code, url=result.url, method=method, text=result.text,
                response=result)

    def get(self, path, parameters=None, jsonResp=True):
        """
        Convenience method to call :py:func:`sendRestRequest` with the 'GET' HTTP method.
        """
        return self.sendRestRequest('GET', path, parameters, jsonResp=jsonResp)

    def post(self, path, parameters=None, files=None, data=None, json=None, headers=None,
             jsonResp=True):
        """
        Convenience method to call :py:func:`sendRestRequest` with the 'POST' HTTP method.
        """
        return self.sendRestRequest('POST', path, parameters, files=files,
                                    data=data, json=json, headers=headers, jsonResp=jsonResp)

    def put(self, path, parameters=None, data=None, json=None, jsonResp=True):
        """
        Convenience method to call :py:func:`sendRestRequest` with the 'PUT'
        HTTP method.
        """
        return self.sendRestRequest('PUT', path, parameters, data=data,
                                    json=json, jsonResp=jsonResp)

    def delete(self, path, parameters=None, jsonResp=True):
        """
        Convenience method to call :py:func:`sendRestRequest` with the 'DELETE' HTTP method.
        """
        return self.sendRestRequest('DELETE', path, parameters, jsonResp=jsonResp)

    def patch(self, path, parameters=None, data=None, json=None, jsonResp=True):
        """
        Convenience method to call :py:func:`sendRestRequest` with the 'PATCH' HTTP method.
        """
        return self.sendRestRequest('PATCH', path, parameters, data=data,
                                    json=json, jsonResp=jsonResp)

    def createResource(self, path, params):
        """
        Creates and returns a resource.
        """
        return self.post(path, params)

    def getResource(self, path, id=None, property=None):
        """
        Returns a resource based on ``id`` or None if no resource is found; if
        ``property`` is passed, returns that property value from the found resource.
        """
        route = path
        if id is not None:
            route += '/%s' % id
        if property is not None:
            route += '/%s' % property

        return self.get(route)

    def resourceLookup(self, path, test=False):
        """
        Look up and retrieve resource in the data hierarchy by path.

        :param path: The path of the resource. The path must be an absolute
            Unix path starting with either "/user/[user name]" or
            "/collection/[collection name]".
        :param test: Whether or not to return None, if the path does not
            exist, rather than throwing an exception.
        """
        return self.get('resource/lookup', parameters={'path': path, 'test': test})

    def listResource(self, path, params=None, limit=None, offset=None):
        """
        This is a generator that will yield records using the given path and
        params until exhausted. Paging of the records is done internally, but
        can be overriden by manually passing a ``limit`` value to select only
        a single page. Passing an ``offset`` will work in both single-page and
        exhaustive modes.
        """
        params = dict(params or {})
        params['offset'] = offset or 0
        params['limit'] = limit or DEFAULT_PAGE_LIMIT

        while True:
            records = self.get(path, params)
            for record in records:
                yield record

            n = len(records)
            if limit or n < params['limit']:
                # Either a single slice was requested, or this is the last page
                break

            params['offset'] += n

    def setResourceTimestamp(self, id, type, created=None, updated=None):
        """
        Set the created or updated timestamps for a resource.
        """
        url = 'resource/%s/timestamp' % id
        params = {
            'type': type,
        }
        if created:
            params['created'] = str(created)
        if updated:
            params['updated'] = str(updated)
        return self.put(url, parameters=params)

    def getFile(self, fileId):
        """
        Retrieves a file by its ID.

        :param fileId: A string containing the ID of the file to retrieve from Girder.
        """
        return self.getResource('file', fileId)

    def listFile(self, folderId, name=None, limit=None, offset=None):
        """
        This is a generator that will yield files under the given folderId.

        :param folderId: the folder's ID
        :param limit: the result set size limit.
        :param offset: the result offset.
        """
        return self.listResource('file', params={
            'folderId': folderId,
            'name': name
        }, limit=limit, offset=offset)

    def listUser(self, limit=None, offset=None):
        """
        This is a generator that will yield all users in the system.

        :param limit: If requesting a specific slice, the length of the slice.
        :param offset: Starting offset into the list.
        """
        return self.listResource('user', limit=limit, offset=offset)

    def getUser(self, userId):
        """
        Retrieves a user by its ID.

        :param userId: A string containing the ID of the user to
            retrieve from Girder.
        """
        return self.getResource('user', userId)

    def createUser(self, login, email, firstName, lastName, password, admin=None):
        """
        Creates and returns a user.
        """
        params = {
            'login': login,
            'email': email,
            'firstName': firstName,
            'lastName': lastName,
            'password': password
        }
        if admin is not None:
            params['admin'] = admin
        return self.createResource('user', params)

    def listCollection(self, limit=None, offset=None):
        """
        This is a generator that will yield all collections in the system.

        :param limit: If requesting a specific slice, the length of the slice.
        :param offset: Starting offset into the list.
        """
        return self.listResource('collection', limit=limit, offset=offset)

    def getCollection(self, collectionId):
        """
        Retrieves a collection by its ID.

        :param collectionId: A string containing the ID of the collection to
            retrieve from Girder.
        """
        return self.getResource('collection', collectionId)

    def createCollection(self, name, description='', public=False):
        """
        Creates and returns a collection.
        """
        params = {
            'name': name,
            'description': description,
            'public': public
        }
        return self.createResource('collection', params)

    def createFolder(self, parentId, name, description='', parentType='folder',
                     public=None, reuseExisting=False, metadata=None):
        """
        Creates and returns a folder.

        :param parentId: The id of the parent resource to create the folder in.
        :param name: The name of the folder.
        :param description: A description of the folder.
        :param parentType: One of ('folder', 'user', 'collection')
        :param public: Whether the folder should be marked a public.
        :param reuseExisting: Whether to return an existing folder if one with
            the same name exists.
        :param metadata: JSON metadata to set on the folder.
        """

        if metadata is not None and not isinstance(metadata, six.string_types):
            metadata = json.dumps(metadata)

        params = {
            'parentId': parentId,
            'parentType': parentType,
            'name': name,
            'description': description,
            'reuseExisting': reuseExisting,
            'metadata': metadata
        }
        if public is not None:
            params['public'] = public
        return self.createResource('folder', params)

    def getFolder(self, folderId):
        """
        Retrieves a folder by its ID.

        :param folderId: A string containing the ID of the folder to retrieve from Girder.
        """
        return self.getResource('folder', folderId)

    def listFolder(self, parentId, parentFolderType='folder', name=None,
                   limit=None, offset=None):
        """
        This is a generator that will yield a list of folders based on the filter parameters.

        :param parentId: The parent's ID.
        :param parentFolderType: One of ('folder', 'user', 'collection').
        :param name: query for exact name match within the parent.
        :param limit: If requesting a specific slice, the length of the slice.
        :param offset: Starting offset into the list.
        """
        params = {
            'parentId': parentId,
            'parentType': parentFolderType
        }

        if name:
            params['name'] = name

        return self.listResource('folder', params, limit=limit, offset=offset)

    def getFolderAccess(self, folderId):
        """
        Retrieves a folder's access by its ID.

        :param folderId: A string containing the ID of the folder to retrieve
            access for from Girder.
        """
        return self.getResource('folder', folderId, 'access')

    def setFolderAccess(self, folderId, access, public):
        """
        Sets the passed in access control document along with the public value
        to the target folder.

        :param folderId: Id of the target folder.
        :param access: JSON document specifying access control.
        :param public: Boolean specificying the public value.
        """

        if access is not None and not isinstance(access, six.string_types):
            access = json.dumps(access)

        path = 'folder/' + folderId + '/access'
        params = {
            'access': access,
            'public': public
        }
        return self.put(path, params)

    def uploadFileFromStream(self, folderId, stream, filename, size, reference=None, mimeType=None,
                             progressCallback=None):
        """
        Uploads a file-like object to a folder. If the file has 0 bytes, no uploading
        will be performed.

        :param folderId: ID of parent folder for file.
        :param stream: Readable stream object.
        :param filename: Filename used for Girder only.
        :param size: The length of the file. This must be exactly equal to the
            total number of bytes that will be read from ``stream``, otherwise
            the upload will fail.
        :param reference: optional reference to send along with the upload.
        :param mimeType: MIME type for the file.
        :param progressCallback: If passed, will be called after each chunk
            with progress information. It passes a single positional argument
            to the callable which is a dict of information about progress.
        """
        if mimeType is None:
            mimeType, _ = mimetypes.guess_type(filename)

        params = {
            'folderId': folderId,
            'name': filename,
            'size': size,
            'mimeType': mimeType
        }

        if reference:
            params['reference'] = reference

        obj = self.post('file', params)

        if '_id' not in obj:
            raise Exception(
                'After creating an upload token for a new file, expected '
                'an object with an id. Got instead: ' + json.dumps(obj))

        return self._uploadContents(obj, stream, size, progressCallback=progressCallback)

    def uploadFileFromPath(self, folderId, filepath, reference=None, mimeType=None, filename=None,
                           progressCallback=None):
        """
        Uploads a local file on the filesystem to a folder. If the file has 0 bytes,
        no uploading will be performed.

        :param folderId: ID of parent folder for file.
        :param filepath: path to file on disk.
        :param reference: optional reference to send along with the upload.
        :type reference: str
        :param mimeType: MIME type for the file. Will be guessed if not passed.
        :type mimeType: str or None
        :param filename: path with filename used in Girder. Defaults to basename of filepath.
        :param progressCallback: If passed, will be called after each chunk
            with progress information. It passes a single positional argument
            to the callable which is a dict of information about progress.
        :type progressCallback: callable
        :returns: the file that was created.
        """
        if filename is None:
            filename = filepath
        filename = os.path.basename(filename)
        filepath = os.path.abspath(filepath)
        filesize = os.path.getsize(filepath)

        if mimeType is None:
            # Attempt to guess MIME type if not passed explicitly
            mimeType, _ = mimetypes.guess_type(filepath)

        with open(filepath, 'rb') as f:
            file = self.uploadFileFromStream(
                folderId, f, filename, filesize, reference, mimeType, progressCallback)

        for callback in self._fileUploadCallbacks:
            callback(file, filepath)

        return file

    def _uploadContents(self, uploadObj, stream, size, progressCallback=None):
        """
        Uploads contents of a file.

        :param uploadObj: The upload object contain the upload id.
        :type uploadObj: dict
        :param stream: Readable stream object.
        :type stream: file-like
        :param size: The length of the file. This must be exactly equal to the
            total number of bytes that will be read from ``stream``, otherwise
            the upload will fail.
        :type size: str
        :param progressCallback: If passed, will be called after each chunk
            with progress information. It passes a single positional argument
            to the callable which is a dict of information about progress.
        :type progressCallback: callable
        """
        offset = 0
        uploadId = uploadObj['_id']

        with self.progressReporterCls(label=uploadObj.get('name', ''), length=size) as reporter:
            while True:
                chunk = stream.read(min(self.MAX_CHUNK_SIZE, (size - offset)))

                if not chunk:
                    break

                if isinstance(chunk, six.text_type):
                    chunk = chunk.encode('utf8')

                uploadObj = self.post(
                    'file/chunk?offset=%d&uploadId=%s' % (offset, uploadId),
                    data=_ProgressBytesIO(chunk, reporter=reporter))

                if '_id' not in uploadObj:
                    raise Exception(
                        'After uploading a file chunk, did not receive object with _id. '
                        'Got instead: ' + json.dumps(uploadObj))

                offset += len(chunk)

                if callable(progressCallback):
                    progressCallback({
                        'current': offset,
                        'total': size
                    })

        if offset != size:
            self.delete('file/upload/' + uploadId)
            raise IncorrectUploadLengthError(
                'Expected upload to be %d bytes, but received %d.' % (size, offset),
                upload=uploadObj)

        return uploadObj

    def replaceFileContents(self, fileId, stream, size, reference=None):
        """
        Replaces the contents of an existing file.

        :param fileId: ID of file to update
        :param stream: Readable stream object.
        :type stream: file-like
        :param size: The length of the file. This must be exactly equal to the
            total number of bytes that will be read from ``stream``, otherwise
            the upload will fail.
        :type size: str
        :param reference: optional reference to send along with the upload.
        :type reference: str
        """
        path = 'file/%s/contents' % fileId
        params = {
            'size': size
        }
        if reference:
            params['reference'] = reference

        obj = self.put(path, params)
        if '_id' not in obj:
            raise Exception(
                'After creating an upload token for replacing file '
                'contents, expected an object with an id. Got instead: ' +
                json.dumps(obj))

        return self._uploadContents(obj, stream, size)

    def addMetadataToFile(self, fileId, metadata):
        """
        Add metadata fields to a file.

        :param fileId: ID of the file to set metadata on.
        :param metadata: dictionary of metadata to set on file.
        """
        # TODO(zach) implement

    def addMetadataToFolder(self, folderId, metadata):
        """
        Takes a folder ID and a dictionary containing the metadata

        :param folderId: ID of the folder to set metadata on.
        :param metadata: dictionary of metadata to set on folder.
        """
        path = 'folder/' + folderId + '/metadata'
        obj = self.put(path, json=metadata)
        return obj

    def _transformFilename(self, name):
        """
        Sanitize a resource name from Girder into a name that is safe to use
        as a filesystem path.

        :param name: The name to transform.
        :type name: str
        """
        if name in {'.', '..'}:
            name = '_' + name
        name = name.replace(os.path.sep, '_')
        if os.path.altsep:
            name = name.replace(os.path.altsep, '_')
        return _safeNameRegex.sub('_', name)

    def _copyFile(self, fp, path):
        """
        Copy the `fp` file-like object to `path` which may be a filename string
        or another file-like object to write to.
        """
        if isinstance(path, six.string_types):
            _safeMakedirs(os.path.dirname(path))
            with open(path, 'wb') as dst:
                shutil.copyfileobj(fp, dst)
        else:
            # assume `path` is a file-like object
            shutil.copyfileobj(fp, path)

    def _streamingFileDownload(self, fileId):
        """
        Download a file streaming the contents

        :param fileId: The ID of the Girder file to download.

        :returns: The request
        """

        path = 'file/%s/download' % fileId
        return self.sendRestRequest('get', path, stream=True, jsonResp=False)

    def downloadFile(self, fileId, path, created=None):
        """
        Download a file to the given local path or file-like object.

        :param fileId: The ID of the Girder file to download.
        :param path: The path to write the file to, or a file-like object.
        """
        fileObj = self.getFile(fileId)
        created = created or fileObj['created']
        cacheKey = '\n'.join([self.urlBase, fileId, created])

        # see if file is in local cache
        if self.cache is not None:
            fp = self.cache.get(cacheKey, read=True)
            if fp:
                with fp:
                    self._copyFile(fp, path)
                return

        # download to a tempfile
        progressFileName = fileId
        if isinstance(path, six.string_types):
            progressFileName = os.path.basename(path)

        req = self._streamingFileDownload(fileId)
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            with self.progressReporterCls(
                    label=progressFileName,
                    length=int(req.headers.get('content-length', 0))) as reporter:
                for chunk in req.iter_content(chunk_size=REQ_BUFFER_SIZE):
                    reporter.update(len(chunk))
                    tmp.write(chunk)

        size = os.stat(tmp.name).st_size
        if size != fileObj['size']:
            os.remove(tmp.name)
            raise IncompleteResponseError('File %s download' % fileId, fileObj['size'], size)

        # save file in cache
        if self.cache is not None:
            with open(tmp.name, 'rb') as fp:
                self.cache.set(cacheKey, fp, read=True)

        if isinstance(path, six.string_types):
            # we can just rename the tempfile
            _safeMakedirs(os.path.dirname(path))
            shutil.move(tmp.name, path)
        else:
            # write to file-like object
            with open(tmp.name, 'rb') as fp:
                shutil.copyfileobj(fp, path)
            # delete the temp file
            os.remove(tmp.name)

    def downloadFileAsIterator(self, fileId, chunkSize=REQ_BUFFER_SIZE):
        """
        Download a file streaming the contents as an iterator.

        :param fileId: The ID of the Girder file to download.
        :param chunkSize: The chunk size to download the contents in.

        :returns: The request content iterator.
        """
        return self._streamingFileDownload(fileId).iter_content(chunk_size=chunkSize)

    def downloadFolderRecursive(self, folderId, dest):
        """
        Download a folder recursively from Girder into a local directory.

        :param folderId: Id of the Girder folder or resource path to download.
        :type folderId: ObjectId or Unix-style path to the resource in Girder.
        :param dest: The local download destination.
        :type dest: str
        """
        offset = 0
        folderId = self._checkResourcePath(folderId)
        _safeMakedirs(dest)

        while True:
            folders = self.get('folder', parameters={
                'limit': DEFAULT_PAGE_LIMIT,
                'offset': offset,
                'parentType': 'folder',
                'parentId': folderId
            })

            for folder in folders:
                local = os.path.join(dest, self._transformFilename(folder['name']))
                self.downloadFolderRecursive(folder['_id'], local)

            offset += len(folders)
            if len(folders) < DEFAULT_PAGE_LIMIT:
                break

        offset = 0

        while True:
            files = self.get('file', parameters={
                'folderId': folderId,
                'limit': DEFAULT_PAGE_LIMIT,
                'offset': offset
            })

            for file in files:
                self.downloadFile(
                    file['_id'], os.path.join(dest, self._transformFilename(file['name'])))

            offset += len(files)
            if len(files) < DEFAULT_PAGE_LIMIT:
                break

    def downloadResource(self, resourceId, dest, resourceType='folder'):
        """
        Download a collection, user, or folder recursively from Girder into a local directory.

        :param resourceId: ID or path of the resource to download.
        :type resourceId: ObjectId or Unix-style path to the resource in Girder.
        :param dest: The local download destination. Can be an absolute path or relative to
            the current working directory.
        :type dest: str
        :param resourceType: The type of resource being downloaded: 'collection', 'user',
            or 'folder'.
        :type resourceType: str
        """
        if resourceType == 'folder':
            self.downloadFolderRecursive(resourceId, dest)
        elif resourceType in {'collection', 'user'}:
            offset = 0
            resourceId = self._checkResourcePath(resourceId)
            while True:
                folders = self.get('folder', parameters={
                    'limit': DEFAULT_PAGE_LIMIT,
                    'offset': offset,
                    'parentType': resourceType,
                    'parentId': resourceId
                })

                for folder in folders:
                    local = os.path.join(dest, self._transformFilename(folder['name']))
                    _safeMakedirs(local)

                    self.downloadFolderRecursive(folder['_id'], local)

                offset += len(folders)
                if len(folders) < DEFAULT_PAGE_LIMIT:
                    break
        else:
            raise Exception('Invalid resource type: %s' % resourceType)

    def addFolderUploadCallback(self, callback):
        """Saves a passed in callback function that will be called after each
        folder has completed.  Multiple callback functions can be added, they
        will be called in the order they were added by calling this function.
        Callback functions will be called after a folder in Girder is created
        and all subfolders and files for that folder have completed uploading.
        Callback functions should take two positional args:
        - the folder in Girder
        - the full path to the local folder

        :param callback: callback function to be called.
        """
        self._folderUploadCallbacks.append(callback)

    def addFileUploadCallback(self, callback):
        """Saves a passed in callback function that will be called after each
        file has completed.  Multiple callback functions can be added, they
        will be called in the order they were added by calling this function.
        Callback functions will be called after a file in Girder is finished uploading.
        Callback functions should take two positional args:
        - the file in Girder
        - the full path to the corresponding local file

        :param callback: callback function to be called.
        """
        self._fileUploadCallbacks.append(callback)

    def _uploadFolderRecursive(self, localFolder, parentId, parentType, blacklist=None,
                               dryRun=False, reference=None):
        """
        Function to recursively upload a folder and all of its descendants.

        :param localFolder: full path to local folder to be uploaded
        :param parentId: id of parent in Girder, where new folder will be added
        :param parentType: one of (collection, folder, user)
        :param reference: Option reference to send along with the upload.
        """
        blacklist = blacklist or []

        filename = os.path.basename(localFolder)
        if filename in blacklist:
            if dryRun:
                print('Ignoring file %s as it is blacklisted' % filename)
            return

        print('Creating Folder from %s' % localFolder)
        if dryRun:
            # create a dry run placeholder
            folder = {'_id': 'dryrun'}
        else:
            folder = self.createFolder(
                parentId, os.path.basename(localFolder), parentType=parentType, reuseExisting=True)

        for entry in os.listdir(localFolder):
            if entry in blacklist:
                if dryRun:
                    print('Ignoring file %s as it is blacklisted' % entry)
                continue
            fullEntry = os.path.join(localFolder, entry)
            if os.path.islink(fullEntry):
                # os.walk skips symlinks by default
                print('Skipping file %s as it is a symlink' % entry)
                continue
            elif os.path.isdir(fullEntry):
                # At this point we should have an actual folder, so can
                # pass that as the parent_type
                self._uploadFolderRecursive(
                    fullEntry, folder['_id'], 'folder', dryRun=dryRun, reference=reference)
            else:
                print('Uploading file from %s' % fullEntry)
                if not dryRun:
                    self.uploadFileFromPath(
                        folder['_id'], fullEntry, reference=reference, filename=entry)

        if not dryRun:
            for callback in self._folderUploadCallbacks:
                callback(folder, localFolder)

    def upload(self, filePattern, parentId, parentType='folder', blacklist=None, dryRun=False,
               reference=None):
        """
        Upload a pattern of files.

        This will recursively walk down every tree in the file pattern to
        create a hierarchy on the server under the parentId.

        :param filePattern: a glob pattern for files that will be uploaded,
            recursively copying any file folder structures.  If this is a list
            or tuple each element in it will be used in turn.
        :type filePattern: str
        :param parentId: Id of the parent in Girder or resource path.
        :type parentId: ObjectId or Unix-style path to the resource in Girder.
        :param parentType: one of (collection,folder,user), default of folder.
        :type parentType: str
        :param dryRun: Set this to True to print out what actions would be taken, but
            do not actually communicate with the server.
        :type dryRun: bool
        :param reference: Option reference to send along with the upload.
        :type reference: str
        """
        filePatternList = filePattern if isinstance(filePattern, (list, tuple)) else [filePattern]
        blacklist = blacklist or []
        empty = True
        parentId = self._checkResourcePath(parentId)
        for pattern in filePatternList:
            for currentFile in glob.iglob(pattern):
                empty = False
                currentFile = os.path.normpath(currentFile)
                filename = os.path.basename(currentFile)
                if filename in blacklist:
                    if dryRun:
                        print('Ignoring file %s as it is blacklisted' % filename)
                    continue
                if os.path.isfile(currentFile):
                    if parentType != 'folder':
                        raise Exception(
                            'Attempting to upload a file under a %s. Files can only be added to '
                            'folders.' % parentType)
                    else:
                        print('Uploading file from %s' % currentFile)
                        if not dryRun:
                            self.uploadFileFromPath(
                                parentId, currentFile, filename=os.path.basename(currentFile),
                                reference=reference)
                else:
                    self._uploadFolderRecursive(
                        currentFile, parentId, parentType, blacklist=blacklist, dryRun=dryRun,
                        reference=reference)
        if empty:
            print('No matching files: ' + repr(filePattern))

    def _checkResourcePath(self, objId):
        if isinstance(objId, six.string_types) and objId.startswith('/'):
            obj = self.resourceLookup(objId, test=True)
            if obj is not None:
                return obj['_id']
        return objId
