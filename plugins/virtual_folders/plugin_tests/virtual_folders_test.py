import json
import six

from tests import base
from girder.constants import AccessType, SortDir
from girder.exceptions import ValidationException
from girder.models.file import File
from girder.models.folder import Folder
from girder.models.user import User


def setUpModule():
    base.enabledPlugins.append('virtual_folders')
    base.startServer()


def tearDownModule():
    base.stopServer()


class VirtualFoldersTestCase(base.TestCase):
    def setUp(self):
        base.TestCase.setUp(self)

        self.admin = User().createUser(
            email='admin@admin.com', login='admin', lastName='admin', firstName='admin',
            password='passwd', admin=True)
        self.user = User().createUser(
            email='user@user.com', login='user', lastName='u', firstName='u', password='passwd')

        self.f1 = Folder().createFolder(self.admin, 'f1', creator=self.admin, parentType='user')
        self.f2 = Folder().createFolder(self.admin, 'f2', creator=self.admin, parentType='user')
        self.virtual = Folder().createFolder(self.user, 'v', creator=self.user, parentType='user')
        self.virtual['isVirtual'] = True

    def testVirtualQuery(self):
        for i in range(10):
            file = File().createFile(
                creator=self.admin, name=str(i), folder=(self.f1, self.f2)[i % 2], size=0,
                assetstore=self.assetstore)
            file['someVal'] = i
            File().save(file)

        self.virtual['virtualFilesQuery'] = json.dumps({
            'someVal': {
                '$gt': 5
            }
        })
        self.virtual = Folder().save(self.virtual)

        def listFiles():
            resp = self.request('/file', user=self.user, params={
                'folderId': self.virtual['_id']
            })
            self.assertStatusOk(resp)
            return resp.json

        self.assertEqual(listFiles(), [])

        # Grant permission on the first folder
        Folder().setUserAccess(self.f1, self.user, AccessType.READ, save=True)
        self.assertEqual([i['name'] for i in listFiles()], ['6', '8'])

        # Grant permission on the second folder
        Folder().setUserAccess(self.f2, self.user, AccessType.READ, save=True)
        self.assertEqual([i['name'] for i in listFiles()], ['6', '7', '8', '9'])

        # Add a custom sort
        self.virtual['virtualFilesSort'] = json.dumps([('someVal', SortDir.DESCENDING)])
        self.virtual = Folder().save(self.virtual)
        self.assertEqual([i['name'] for i in listFiles()], ['9', '8', '7', '6'])

        # Using childFiles on a vfolder should not yield any results
        self.assertEqual(list(Folder().childFiles(self.virtual)), [])

    def testVirtualFolderValidation(self):
        # Can't make folder virtual if it has children
        subfolder = Folder().createFolder(self.f1, 'sub', creator=self.admin)
        self.f1['isVirtual'] = True

        with six.assertRaisesRegex(
                self, ValidationException, 'Virtual folders may not contain child folders.'):
            Folder().save(self.f1)

        Folder().remove(subfolder)
        file = File().createFile(
            name='i', creator=self.admin, folder=self.f1, size=0, assetstore=self.assetstore)

        with six.assertRaisesRegex(
                self, ValidationException, 'Virtual folders may not contain child files.'):
            Folder().save(self.f1)

        File().remove(file)
        Folder().save(self.f1)

        # Can't make subfolders or files under a virtual folder
        with six.assertRaisesRegex(
                self, ValidationException, 'You may not place files under a virtual folder.'):
            File().createFile(
                name='i', creator=self.admin, folder=self.f1, size=0, assetstore=self.assetstore)

        with six.assertRaisesRegex(
                self, ValidationException, 'You may not place folders under a virtual folder.'):
            Folder().createFolder(self.f1, 'f', creator=self.admin)

        # Can't move a file under a virtual folder
        file = File().createFile(
            name='i', creator=self.admin, folder=self.f2, size=0, assetstore=self.assetstore)
        with six.assertRaisesRegex(
                self, ValidationException, 'You may not place files under a virtual folder.'):
            File().move(file, self.f1)

        # Ensure JSON for query
        self.f1['virtualFilesQuery'] = 'not JSON'
        with six.assertRaisesRegex(
                self, ValidationException, 'The virtual files query must be valid JSON.'):
            Folder().save(self.f1)

        del self.f1['virtualFilesQuery']
        self.f1['virtualFilesSort'] = 'not JSON'
        with six.assertRaisesRegex(
                self, ValidationException, 'The virtual files sort must be valid JSON.'):
            Folder().save(self.f1)

    def testRestEndpoint(self):
        def updateFolder(user):
            return self.request('/folder/%s' % self.f1['_id'], method='PUT', params={
                'isVirtual': True,
                'virtualFilesQuery': json.dumps({'foo': 'bar'}),
                'virtualFilesSort': json.dumps([('meta.someVal', SortDir.DESCENDING)])
            }, user=user)

        Folder().setUserAccess(self.f1, self.user, level=AccessType.ADMIN, save=True)

        resp = updateFolder(self.user)
        self.assertStatus(resp, 403)
        self.assertEqual(resp.json['message'], 'Must be admin to setup virtual folders.')
        f1 = Folder().load(self.f1['_id'], force=True)
        self.assertNotIn('isVirtual', f1)
        self.assertNotIn('virtualFilesQuery', f1)
        self.assertNotIn('virtualFilesSort', f1)

        resp = updateFolder(self.admin)
        self.assertStatusOk(resp)
        self.assertTrue(Folder().load(self.f1['_id'], force=True)['isVirtual'])
