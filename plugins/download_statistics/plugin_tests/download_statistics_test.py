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

import os
import json

from tests import base
from girder.constants import ROOT_DIR
from girder.models.collection import Collection
from girder.models.folder import Folder
from girder.models.upload import Upload
from girder.models.user import User


def setUpModule():
    base.enabledPlugins.append('download_statistics')
    base.startServer()


def tearDownModule():
    base.stopServer()


class DownloadStatisticsTestCase(base.TestCase):
    def setUp(self):
        base.TestCase.setUp(self)

        admin = {'email': 'admin@email.com',
                 'login': 'adminLogin',
                 'firstName': 'adminFirst',
                 'lastName': 'adminLast',
                 'password': 'adminPassword',
                 'admin': True}
        self.admin = User().createUser(**admin)
        self.filesDir = os.path.join(
            ROOT_DIR, 'plugins', 'download_statistics', 'plugin_tests', 'files')

    def _downloadFolder(self, folderId):
        resp = self.request('/folder/%s/download' % folderId, isJson=False)
        self.assertStatusOk(resp)

        # Iterate through generator to trigger download events
        list(resp.body)

    def _downloadFile(self, fileId):
        resp = self.request('/file/%s/download' % fileId, isJson=False)
        self.assertStatusOk(resp)

        # Iterate through generator to trigger download events
        list(resp.body)

    def _checkDownloadsCount(self, fileId, started, requested, completed):
        # Downloads file info and asserts download statistics are accurate
        resp = self.request('/file/%s' % fileId, isJson=True)
        self.assertStatusOk(resp)
        data = resp.json
        print(data['downloadStatistics'])

        # The generator is never iterated as to not trigger additional events
        self.assertEqual(data['downloadStatistics']['started'], started)
        self.assertEqual(data['downloadStatistics']['requested'], requested)
        self.assertEqual(data['downloadStatistics']['completed'], completed)

    def _downloadFileInTwoChunks(self, fileId):
        # Adds 1 to downloads started, 2 to requested, and 1 to completed
        # txt1.txt and txt2.txt each have a filesize of 5
        path = '/file/%s/download' % fileId
        params = {
            'offset': 0,
            'endByte': 3
        }
        list(self.request(path, method='GET', isJson=False, params=params).body)

        params['offset'] = 3
        params['endByte'] = 6
        list(self.request(path, method='GET', isJson=False, params=params).body)

    def _downloadPartialFile(self, fileId):
        # Adds 1 to downloads started and 4 to downloads requested
        # txt1.txt and txt2.txt each have a filesize of 5
        path = '/file/%s/download' % fileId
        for i in range(1, 5):
            params = {
                'offset': i-1,
                'endByte': i
            }
            list(self.request(path, method='GET', isJson=False, params=params).body)

    def testDownload(self):
        collection = Collection().createCollection('collection1', public=True)
        folder = Folder().createFolder(collection, 'folder1', parentType='collection', public=True)
        file1Path = os.path.join(self.filesDir, 'txt1.txt')
        file2Path = os.path.join(self.filesDir, 'txt2.txt')

        with open(file1Path, 'rb') as fp:
            file1 = Upload().uploadFromFile(
                fp, os.path.getsize(file1Path), 'txt1.txt', parent=folder, user=self.admin)

        with open(file2Path, 'rb') as fp:
            file2 = Upload().uploadFromFile(
                fp, os.path.getsize(file2Path), 'txt2.txt', mimeType='image/jpeg',
                parent=folder, user=self.admin)

        # Download files individually 1 time
        self._downloadFile(file1['_id'])
        self._downloadFile(file2['_id'])

        # Download each file 1 time by downloading parent folder
        self._downloadFolder(folder['_id'])

        # Download each file over 2 requests
        self._downloadFileInTwoChunks(file1['_id'])
        self._downloadFileInTwoChunks(file2['_id'])

        # Download each file partially, adding 1 to start and 4 to requested
        self._downloadPartialFile(file1['_id'])
        self._downloadPartialFile(file2['_id'])

        # Download entire collection
        # Each file is downloaded 1 additional time
        path = '/collection/%s/download' % collection['_id']
        list(self.request(path, user=self.admin, isJson=False).body)

        # Download collection filtered by mime type
        # file2 is downloaded one additional time
        path = '/collection/%s/download' % collection['_id']
        list(self.request(path, user=self.admin, isJson=False, method='GET', params={
            'id': collection['_id'],
            'mimeFilter': json.dumps(['image/jpeg'])
        }).body)

        self._checkDownloadsCount(file1['_id'], 5, 9, 4)
        self._checkDownloadsCount(file2['_id'], 6, 10, 5)
