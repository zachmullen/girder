#!/usr/bin/env python
# -*- coding: utf-8 -*-

###############################################################################
#  Copyright 2014 Kitware Inc.
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

import datetime
import io
import json
import os
import six
from six.moves import range, urllib
import zipfile

from .. import base

from girder.models.notification import Notification, ProgressState
from girder.models.collection import Collection
from girder.models.file import File
from girder.models.folder import Folder
from girder.models.user import User
import girder.utility.ziputil


def setUpModule():
    base.startServer()


def tearDownModule():
    base.stopServer()


class ResourceTestCase(base.TestCase):
    def setUp(self):
        base.TestCase.setUp(self)
        admin = {
            'email': 'good@email.com',
            'login': 'goodlogin',
            'firstName': 'First',
            'lastName': 'Last',
            'password': 'goodpassword'
        }
        self.admin = User().createUser(**admin)
        user = {
            'email': 'user@email.com',
            'login': 'userlogin',
            'firstName': 'Normal',
            'lastName': 'User',
            'password': 'goodpassword'
        }
        self.user = User().createUser(**user)

    def _createFiles(self, user=None):
        """
        Create a set of folders, files, metadata, and collections for testing.

        :param user: the user who should own these items.
        """
        if user is None:
            user = self.admin
        self.expectedZip = {}
        # Create a collection
        coll = {
            'name': 'Test Collection',
            'description': 'The description',
            'public': True,
            'creator': user
        }
        self.collection = Collection().createCollection(**coll)
        self.collectionPrivateFolder = Folder().createFolder(
            parent=self.collection, parentType='collection', name='Private',
            creator=user, public=False)

        # Get the admin user's folders
        resp = self.request(
            path='/folder', user=user, params={
                'parentType': 'user',
                'parentId': user['_id'],
                'sort': 'name',
                'sortdir': 1
            })
        self.adminPrivateFolder = Folder().load(resp.json[0]['_id'], user=user)
        self.adminPublicFolder = Folder().load(resp.json[1]['_id'], user=user)
        # Create a folder within the admin public folder
        resp = self.request(
            path='/folder', method='POST', user=user, params={
                'name': 'Folder 1', 'parentId': self.adminPublicFolder['_id']
            })
        self.adminSubFolder = Folder().load(resp.json['_id'], force=True)

        # Upload a series of files
        self.files = []
        file, path, contents = self._uploadFile('File 1', self.adminPublicFolder)
        self.files.append(file)
        self.expectedZip[path] = contents
        file, path, contents = self._uploadFile('File 2', self.adminPublicFolder)
        self.files.append(file)
        self.expectedZip[path] = contents
        file, path, contents = self._uploadFile('File 3', self.adminPublicFolder)
        self.files.append(file)
        self.expectedZip[path] = contents
        file, path, contents = self._uploadFile('File 4', self.adminSubFolder)
        self.files.append(file)
        self.expectedZip[path] = contents
        file, path, contents = self._uploadFile('File 5', self.collectionPrivateFolder)
        self.files.append(file)
        self.expectedZip[path] = contents
        # place some metadata on two of the items and one of the folders
        meta = {'key': 'value'}
        Folder().setMetadata(self.adminSubFolder, meta)
        parents = Folder().parentsToRoot(self.adminSubFolder, user=self.admin)
        path = os.path.join(*([part['object'].get(
            'name', part['object'].get('login', '')) for part in parents] +
            [self.adminSubFolder['name'], 'girder-folder-metadata.json']))
        self.expectedZip[path] = meta

        meta = {'x': 'y'}
        Folder().setMetadata(self.collectionPrivateFolder, meta)
        parents = Folder().parentsToRoot(self.collectionPrivateFolder, user=self.admin)
        path = os.path.join(*([part['object'].get(
            'name', part['object'].get('login', '')) for part in parents] +
            [self.collectionPrivateFolder['name'], 'girder-folder-metadata.json']))
        self.expectedZip[path] = meta

        meta = {'key2': 'value2', 'date': datetime.datetime.utcnow()}
        # mongo rounds to millisecond, so adjust our expectations
        meta['date'] -= datetime.timedelta(microseconds=meta['date'].microsecond % 1000)
        Folder().setMetadata(self.adminPublicFolder, meta)
        parents = Folder().parentsToRoot(self.adminPublicFolder, user=user)
        path = os.path.join(*([part['object'].get(
            'name', part['object'].get('login', '')) for part in parents] +
            [self.adminPublicFolder['name'], 'girder-folder-metadata.json']))
        self.expectedZip[path] = meta

    def _uploadFile(self, name, folder):
        """
        Upload a random file to a folder.

        :param name: name of the file.
        :param folder: folder to upload the file to.
        :returns: file: the created file object
                  path: the path to the file within the parent hierarchy.
                  contents: the contents that were generated for the file.
        """
        contents = os.urandom(1024)
        resp = self.request(
            path='/file', method='POST', user=self.admin, params={
                'folderId': folder['_id'],
                'name': name,
                'size': len(contents),
                'mimeType': 'application/octet-stream'
            })
        self.assertStatusOk(resp)
        upload = resp.json
        fields = [('offset', 0), ('uploadId', upload['_id'])]
        files = [('chunk', name, contents)]
        resp = self.multipartRequest(
            path='/file/chunk', user=self.admin, fields=fields, files=files)
        self.assertStatusOk(resp)
        file = resp.json
        parents = Folder().parentsToRoot(folder, user=self.admin)
        path = os.path.join(*([part['object'].get(
            'name', part['object'].get('login', '')) for part in parents] +
            [folder['name'], name]))
        return (file, path, contents)

    def testDownloadResources(self):
        self._createFiles()
        resourceList = {
            'collection': [str(self.collection['_id'])],
            'user': [str(self.admin['_id'])]
            }
        # We should fail with bad json, an empty list, an invalid item in the
        # list, or a list that is an odd format.
        resp = self.request(
            path='/resource/download', user=self.admin, params={
                'resources': 'this_is_not_json',
            }, isJson=False)
        self.assertStatus(resp, 400)
        resp = self.request(
            path='/resource/download', user=self.admin, params={
                'resources': json.dumps('this_is_not_a_dict_of_resources')
            }, isJson=False)
        self.assertStatus(resp, 400)
        resp = self.request(
            path='/resource/download', user=self.admin, params={
                'resources': json.dumps({'not_a_resource': ['not_an_id']})
            }, isJson=False)
        self.assertStatus(resp, 400)
        resp = self.request(
            path='/resource/download', user=self.admin, params={
                'resources': json.dumps({'folder': []})
            }, isJson=False)
        self.assertStatus(resp, 400)
        resp = self.request(
            path='/resource/download', user=self.admin, params={
                'resources': json.dumps({'collection': [str(self.admin['_id'])]})
            }, isJson=False)
        self.assertStatus(resp, 400)
        # Download the resources
        resp = self.request(
            path='/resource/download', user=self.admin, params={
                'resources': json.dumps(resourceList),
                'includeMetadata': True
            }, isJson=False)
        self.assertStatusOk(resp)
        self.assertEqual(resp.headers['Content-Type'], 'application/zip')
        zip = zipfile.ZipFile(io.BytesIO(self.getBody(resp, text=False)), 'r')
        self.assertTrue(zip.testzip() is None)
        self.assertHasKeys(self.expectedZip, zip.namelist())
        self.assertHasKeys(zip.namelist(), self.expectedZip)

        for name in zip.namelist():
            expected = self.expectedZip[name]
            if isinstance(expected, dict):
                self.assertEqual(json.loads(zip.read(name).decode('utf8')),
                                 json.loads(json.dumps(expected, default=str)))
            else:
                if not isinstance(expected, six.binary_type):
                    expected = expected.encode('utf8')
                self.assertEqual(expected, zip.read(name))
        # Download the same resources again, this time triggering the large zip
        # file creation (artificially forced).  We could do this naturally by
        # downloading >65536 files, but that would make the test take several
        # minutes.
        girder.utility.ziputil.Z_FILECOUNT_LIMIT = 5
        resourceList = {
            'file': [str(f['_id']) for f in self.files]
        }
        resp = self.request(
            path='/resource/download', method='POST', user=self.admin, params={
                'resources': json.dumps(resourceList),
                'includeMetadata': True
            }, isJson=False,
            additionalHeaders=[('X-HTTP-Method-Override', 'GET')])
        self.assertStatusOk(resp)
        self.assertEqual(resp.headers['Content-Type'], 'application/zip')
        zip = zipfile.ZipFile(io.BytesIO(self.getBody(resp, text=False)), 'r')
        self.assertTrue(zip.testzip() is None)

        # Test deleting resources
        resourceList = {
            'collection': [str(self.collection['_id'])],
            'folder': [str(self.adminSubFolder['_id'])],
            }
        resp = self.request(
            path='/resource', method='DELETE', user=self.admin, params={
                'resources': json.dumps(resourceList),
                'progress': True
            }, isJson=False)
        self.assertStatusOk(resp)
        # Make sure progress record exists and that it is set to expire soon
        notifs = list(Notification().get(self.admin))
        self.assertEqual(len(notifs), 1)
        self.assertEqual(notifs[0]['type'], 'progress')
        self.assertEqual(notifs[0]['data']['state'], ProgressState.SUCCESS)
        self.assertEqual(notifs[0]['data']['title'], 'Deleting resources')
        self.assertEqual(notifs[0]['data']['message'], 'Done')
        self.assertEqual(notifs[0]['data']['total'], 5)
        self.assertEqual(notifs[0]['data']['current'], 5)
        self.assertTrue(notifs[0]['expires'] < datetime.datetime.utcnow() +
                        datetime.timedelta(minutes=1))
        # Test deletes using a body on the request
        resourceList = {
            'file': [str(self.files[1]['_id']), str(self.files[2]['_id'])]
            }
        resp = self.request(
            path='/resource', method='DELETE', user=self.admin,
            body=urllib.parse.urlencode({
                'resources': json.dumps(resourceList)
            }),
            type='application/x-www-form-urlencoded', isJson=False)
        self.assertStatusOk(resp)
        # Test deletes using POST and override method
        resourceList = {
            'file': [str(self.files[0]['_id'])]
            }
        resp = self.request(
            path='/resource', method='POST', user=self.admin, params={
                'resources': json.dumps(resourceList)
            }, isJson=False,
            additionalHeaders=[('X-HTTP-Method-Override', 'DELETE')])
        self.assertStatusOk(resp)
        # All files should now be deleted
        self.assertEqual(File().find().count(), 0)

        # Add a file under the admin private folder
        _, path, contents = self._uploadFile('private_file', self.adminPrivateFolder)
        self.assertEqual(path, 'goodlogin/Private/private_file')

        # Download as admin, should get private file
        resp = self.request(
            path='/resource/download', user=self.admin, params={
                'resources': json.dumps({'user': [str(self.admin['_id'])]})
            }, isJson=False)
        self.assertStatusOk(resp)
        self.assertEqual(resp.headers['Content-Type'], 'application/zip')
        zip = zipfile.ZipFile(io.BytesIO(self.getBody(resp, text=False)), 'r')
        self.assertTrue(zip.testzip() is None)
        self.assertEqual(zip.namelist(), [path])
        self.assertEqual(zip.read(path), contents)

        # Download as normal user, should get empty zip
        resp = self.request(
            path='/resource/download', user=self.user, params={
                'resources': json.dumps({'user': [str(self.admin['_id'])]})
            }, isJson=False)
        self.assertStatusOk(resp)
        self.assertEqual(resp.headers['Content-Type'], 'application/zip')
        zip = zipfile.ZipFile(io.BytesIO(self.getBody(resp, text=False)), 'r')
        self.assertTrue(zip.testzip() is None)
        self.assertEqual(zip.namelist(), [])

    def testDeleteResources(self):
        self._createFiles(user=self.user)

        # Make sure we cannot delete a non-AC resource
        resp = self.request('/resource', method='DELETE', user=self.admin, params={
            'resources': json.dumps({'assetstore': [str(self.assetstore['_id'])]})
        })
        self.assertStatus(resp, 400)
        self.assertEqual(resp.json['message'], 'Invalid resource types requested: assetstore')

        # Test delete of a file
        resp = self.request(
            path='/resource', method='DELETE', user=self.admin, params={
                'resources': json.dumps({'file': [str(self.files[0]['_id'])]}),
                'progress': True
            }, isJson=False)
        self.assertStatusOk(resp)
        # Test delete of a user who owns a folder
        resp = self.request(
            path='/resource', method='DELETE', user=self.admin, params={
                'resources': json.dumps({'user': [str(self.user['_id'])]}),
                'progress': True
            }, isJson=False)
        self.assertStatusOk(resp)
        resp = self.request(path='/user', user=self.admin)
        self.assertStatusOk(resp)
        self.assertEqual(len(resp.json), 1)
        # Deleting a non-existent object should give an error
        resp = self.request(
            path='/resource', method='DELETE', user=self.admin, params={
                'resources': json.dumps({'file': [str(self.admin['_id'])]})
            }, isJson=False)
        self.assertStatus(resp, 400)

    def testGetResourceById(self):
        self._createFiles()
        resp = self.request(path='/resource/%s' % self.admin['_id'],
                            user=self.admin,
                            params={'type': 'user'})
        self.assertStatusOk(resp)
        self.assertEqual(str(resp.json['_id']), str(self.admin['_id']))
        self.assertEqual(resp.json['email'], 'good@email.com')
        # Get a file via this method
        resp = self.request(path='/resource/%s' % self.files[0]['_id'],
                            user=self.admin,
                            params={'type': 'file'})
        self.assertStatusOk(resp)
        self.assertEqual(str(resp.json['_id']), str(self.files[0]['_id']))

    def testGetResourceByPath(self):
        self._createFiles()

        # test users
        resp = self.request(path='/resource/lookup',
                            user=self.admin,
                            params={'path': '/user/goodlogin'})

        self.assertStatusOk(resp)
        self.assertEqual(str(resp.json['_id']), str(self.admin['_id']))

        resp = self.request(path='/resource/lookup',
                            user=self.user,
                            params={'path': '/user/userlogin'})
        self.assertStatusOk(resp)
        self.assertEqual(str(resp.json['_id']), str(self.user['_id']))

        # test collections
        resp = self.request(path='/resource/lookup',
                            user=self.user,
                            params={'path': '/collection/Test Collection'})
        self.assertStatusOk(resp)
        self.assertEqual(str(resp.json['_id']), str(self.collection['_id']))

        resp = self.request(path='/resource/lookup',
                            user=self.admin,
                            params={'path':
                                    '/collection/Test Collection/' +
                                    self.collectionPrivateFolder['name']})
        self.assertStatusOk(resp)
        self.assertEqual(str(resp.json['_id']),
                         str(self.collectionPrivateFolder['_id']))

        # test folders
        resp = self.request(path='/resource/lookup',
                            user=self.user,
                            params={'path': '/user/goodlogin/Public'})
        self.assertStatusOk(resp)
        self.assertEqual(
            str(resp.json['_id']), str(self.adminPublicFolder['_id']))

        resp = self.request(path='/resource/lookup',
                            user=self.user,
                            params={'path': '/user/goodlogin/Private'})
        self.assertStatus(resp, 400)

        # test subfolders
        resp = self.request(path='/resource/lookup',
                            user=self.admin,
                            params={'path': '/user/goodlogin/Public/Folder 1'})
        self.assertStatusOk(resp)
        self.assertEqual(
            str(resp.json['_id']), str(self.adminSubFolder['_id']))

        # test items
        privateFolder = self.collectionPrivateFolder['name']
        paths = ('/user/goodlogin/Public/File 1',
                 '/user/goodlogin/Public/File 2',
                 '/user/goodlogin/Public/File 3',
                 '/user/goodlogin/Public/Folder 1/File 4',
                 '/collection/Test Collection/%s/File 5' % privateFolder)

        users = (self.user,
                 self.user,
                 self.user,
                 self.admin,
                 self.admin)

        for path, item, user in zip(paths, self.files, users):
            resp = self.request(path='/resource/lookup',
                                user=user,
                                params={'path': path})

            self.assertStatusOk(resp)
            self.assertEqual(
                str(resp.json['_id']), str(item['_id']))

        # test bogus path
        # test is not set
        resp = self.request(path='/resource/lookup',
                            user=self.user,
                            params={'path': '/bogus/path'})
        self.assertStatus(resp, 400)
        # test is set to false, response code should be 400
        resp = self.request(path='/resource/lookup',
                            user=self.user,
                            params={'path': '/collection/bogus/path',
                                    'test': False})
        self.assertStatus(resp, 400)

        # test is set to true, response code should be 200 and response body
        # should be null (None)
        resp = self.request(path='/resource/lookup',
                            user=self.user,
                            params={'path': '/collection/bogus/path',
                                    'test': True})
        self.assertStatusOk(resp)
        self.assertEqual(resp.json, None)

    def testGetResourcePath(self):
        self._createFiles()

        # Get a user's path
        resp = self.request(path='/resource/%s/path' % self.user['_id'],
                            user=self.user,
                            params={'type': 'user'})
        self.assertStatusOk(resp)
        self.assertEqual(resp.json, '/user/userlogin')

        # Get a collection's path
        resp = self.request(path='/resource/%s/path' % self.collection['_id'],
                            user=self.user,
                            params={'type': 'collection'})
        self.assertStatusOk(resp)
        self.assertEqual(resp.json, '/collection/Test Collection')

        # Get a folder's path
        resp = self.request(path='/resource/%s/path' % self.adminSubFolder['_id'],
                            user=self.user,
                            params={'type': 'folder'})
        self.assertStatusOk(resp)
        self.assertEqual(resp.json, '/user/goodlogin/Public/Folder 1')

        # Get a file's path
        resp = self.request(path='/resource/%s/path' % self.files[0]['_id'],
                            user=self.user,
                            params={'type': 'file'})
        self.assertStatusOk(resp)
        self.assertEqual(resp.json, '/user/goodlogin/Public/File 1')

        # Test access denied response
        resp = self.request(path='/resource/%s/path' % self.adminPrivateFolder['_id'],
                            user=self.user,
                            params={'type': 'folder'})
        self.assertStatus(resp, 403)

        # Test invalid id response
        resp = self.request(path='/resource/%s/path' % self.user['_id'],
                            user=self.user,
                            params={'type': 'folder'})
        self.assertStatus(resp, 400)

        # Test invalid type response
        resp = self.request(path='/resource/%s/path' % self.user['_id'],
                            user=self.user,
                            params={'type': 'invalid type'})
        self.assertStatus(resp, 400)

    def testMove(self):
        self._createFiles()

        # Make sure passing invalid resource type is caught gracefully
        resp = self.request(
            path='/resource/move', method='PUT', user=self.admin, params={
                'resources': json.dumps({'invalid_type': [str(self.files[0]['_id'])]}),
                'parentType': 'folder',
                'parentId': str(self.adminPrivateFolder['_id'])
            })
        self.assertStatus(resp, 400)
        self.assertEqual(resp.json['message'], 'Invalid resource types requested: invalid_type')

        # Move file 1 from the public to the private folder
        resp = self.request(
            path='/resource/move', method='PUT', user=self.admin, params={
                'resources': json.dumps({'file': [str(self.files[0]['_id'])]}),
                'parentType': 'folder',
                'parentId': str(self.adminPrivateFolder['_id']),
                'progress': True
            })
        self.assertStatusOk(resp)
        resp = self.request(path='/file/%s' % self.files[0]['_id'], user=self.admin)
        self.assertStatusOk(resp)
        self.assertEqual(resp.json['folderId'], str(self.adminPrivateFolder['_id']))
        # We shouldn't be able to move the file into the user
        resp = self.request(
            path='/resource/move', method='PUT', user=self.admin,
            params={
                'resources': json.dumps({'file': [str(self.files[0]['_id'])]}),
                'parentType': 'user',
                'parentId': str(self.admin['_id'])
            })
        self.assertStatus(resp, 400)
        # Asking to move into a file is also an error
        resp = self.request(
            path='/resource/move', method='PUT', user=self.admin,
            params={
                'resources': json.dumps({'file': [str(self.files[0]['_id'])]}),
                'parentType': 'file',
                'parentId': str(self.files[1]['_id'])
            })
        self.assertStatus(resp, 400)
        # Move file 1 and subFolder from the public to the private folder (item1
        # is already there).
        resp = self.request(
            path='/resource/move', method='PUT', user=self.admin,
            params={
                'resources': json.dumps({
                    'folder': [str(self.adminSubFolder['_id'])],
                    'file': [str(self.files[0]['_id'])]}),
                'parentType': 'folder',
                'parentId': str(self.adminPrivateFolder['_id']),
                'progress': True
            })
        self.assertStatusOk(resp)
        resp = self.request(path='/file/%s' % self.files[0]['_id'], user=self.admin)
        self.assertStatusOk(resp)
        self.assertEqual(resp.json['folderId'], str(self.adminPrivateFolder['_id']))
        resp = self.request(
            path='/folder/%s' % self.adminSubFolder['_id'], user=self.admin)
        self.assertStatusOk(resp)
        self.assertEqual(resp.json['parentId'], str(self.adminPrivateFolder['_id']))
        # You can't move a folder into itself
        resp = self.request(
            path='/resource/move', method='PUT', user=self.admin,
            params={
                'resources': json.dumps({
                    'folder': [str(self.adminSubFolder['_id'])]}),
                'parentType': 'folder',
                'parentId': str(self.adminSubFolder['_id']),
                'progress': True
            })
        self.assertStatus(resp, 400)
        # You can move a folder into a user
        resp = self.request(
            path='/resource/move', method='PUT', user=self.admin,
            params={
                'resources': json.dumps({
                    'folder': [str(self.adminSubFolder['_id'])]}),
                'parentType': 'user',
                'parentId': str(self.admin['_id'])
            })
        self.assertStatusOk(resp)
        resp = self.request(
            path='/folder/%s' % self.adminSubFolder['_id'], method='GET',
            user=self.admin)
        self.assertStatusOk(resp)
        self.assertEqual(resp.json['parentCollection'], 'user')
        self.assertEqual(resp.json['parentId'], str(self.admin['_id']))
        # The non-admin user can't move other people's stuff
        resp = self.request(
            path='/resource/move', method='PUT', user=self.user,
            params={
                'resources': json.dumps({'file': [str(self.files[2]['_id'])]}),
                'parentType': 'folder',
                'parentId': str(self.adminPublicFolder['_id'])
            })
        self.assertStatus(resp, 403)

        # Moving a non-existent object should give an error
        resp = self.request(
            path='/resource/move', method='PUT', user=self.admin, params={
                'resources': json.dumps({'file': [str(self.admin['_id'])]}),
                'parentType': 'folder',
                'parentId': str(self.adminPublicFolder['_id'])
            }, isJson=False)
        self.assertStatus(resp, 400)

    def testCopy(self):
        self._createFiles()
        # The non-admin user should be able to copy public documents
        resp = self.request(
            path='/resource/copy', method='POST', user=self.user,
            params={
                'resources': json.dumps({
                    'folder': [str(self.adminSubFolder['_id'])]}),
                'parentType': 'user',
                'parentId': str(self.user['_id']),
                'progress': True
            })
        self.assertStatusOk(resp)

        resp = self.request(
            path='/folder', user=self.user,
            params={
                'parentType': 'user',
                'parentId': str(self.user['_id']),
                'text': 'Folder 1'})
        self.assertStatusOk(resp)
        self.assertEqual(len(resp.json), 1)
        copiedFolder = resp.json[0]
        self.assertNotEqual(str(copiedFolder['_id']), str(self.adminSubFolder['_id']))
        # We should have reported 2 things copied in the progress (1 folder and 1 file)
        resp = self.request(
            path='/notification/stream', user=self.user,
            isJson=False, params={'timeout': 1})
        messages = self.getSseMessages(resp)
        self.assertTrue(len(messages) >= 1)
        self.assertEqual(messages[-1]['data']['current'], 2)
        # The non-admin user should not be able to copy private documents
        resp = self.request(
            path='/resource/copy', method='POST', user=self.user,
            params={
                'resources': json.dumps({
                    'folder': [str(self.adminPrivateFolder['_id'])]}),
                'parentType': 'user',
                'parentId': str(self.user['_id'])
            })
        self.assertStatus(resp, 403)
        # Copy a group of files from different spots.  Do this as admin
        resp = self.request(
            path='/resource/copy', method='POST', user=self.admin,
            params={
                'resources': json.dumps({
                    'file': [str(file['_id']) for file in self.files]}),
                'parentType': 'folder',
                'parentId': str(copiedFolder['_id']),
                'progress': True
            })
        self.assertStatusOk(resp)
        # We already had one file in that folder, so now we should have one
        # more than in the self.files list.  The user should be able to see
        # these files.
        resp = self.request(path='/file', user=self.user,
                            params={'folderId': str(copiedFolder['_id'])})
        self.assertStatusOk(resp)
        self.assertEqual(len(resp.json), len(self.files)+1)
        # Copying a non-existant object should give an error
        resp = self.request(
            path='/resource/copy', method='POST', user=self.admin, params={
                'resources': json.dumps({'file': [str(self.admin['_id'])]}),
                'parentType': 'folder',
                'parentId': str(self.adminPublicFolder['_id'])
            }, isJson=False)
        self.assertStatus(resp, 400)

    def testZipUtil(self):
        # Exercise the large zip file code

        def genEmptyFile(fileLength, chunkSize=65536):
            chunk = '\0' * chunkSize

            def genEmptyData():
                for val in range(0, fileLength, chunkSize):
                    if fileLength - val < chunkSize:
                        yield chunk[:fileLength - val]
                    else:
                        yield chunk

            return genEmptyData

        zip = girder.utility.ziputil.ZipGenerator()
        # Most of the time in generating a zip file is spent in CRC
        # calculation.  We turn it off so that we can perform tests in a timely
        # fashion.
        zip.useCRC = False
        for data in zip.addFile(
                genEmptyFile(6 * 1024 * 1024 * 1024), 'bigfile'):
            pass
        # Add a second small file at the end to test some of the other Zip64
        # code
        for data in zip.addFile(genEmptyFile(100), 'smallfile'):
            pass
        # Test that we don't crash on Unicode file names
        for data in zip.addFile(
                genEmptyFile(100), u'\u0421\u0443\u043f\u0435\u0440-\u0440'
                '\u0443\u0441\u0441\u043a\u0438, \u0627\u0633\u0645 \u0627'
                '\u0644\u0645\u0644\u0641 \u0628\u0627\u0644\u0644\u063a'
                '\u0629 \u0627\u0644\u0639\u0631\u0628\u064a\u0629'):
            pass
        # Test filename with a null
        for data in zip.addFile(genEmptyFile(100), 'with\x00null'):
            pass
        footer = zip.footer()
        self.assertEqual(footer[-6:], b'\xFF\xFF\xFF\xFF\x00\x00')

    def testResourceTimestamps(self):
        self._createFiles()

        created = datetime.datetime(2000, 1, 1)
        updated = datetime.datetime(2001, 1, 1)

        # non-admin cannot use this endpoint
        resp = self.request(
            path='/resource/%s/timestamp' % self.collection['_id'],
            method='PUT',
            user=self.user,
            params={
                'type': 'collection',
                'created': str(created),
                'updated': str(updated),
            })
        self.assertStatus(resp, 403)

        c = Collection().load(self.collection['_id'], force=True)
        self.assertNotEqual(c['created'], created)
        self.assertNotEqual(c['updated'], updated)

        # admin can change created timestamp
        resp = self.request(
            path='/resource/%s/timestamp' % self.collection['_id'],
            method='PUT',
            user=self.admin,
            params={
                'type': 'collection',
                'created': str(created),
                'updated': str(updated),
            })
        self.assertStatusOk(resp)

        c = Collection().load(self.collection['_id'], force=True)
        self.assertEqual(c['created'], created)
        self.assertEqual(c['updated'], updated)
