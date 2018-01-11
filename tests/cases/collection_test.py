class CollectionTestCase(base.TestCase):
    def testCollectionAccess(self):
        # Asking to change to an invalid access list should fail
        resp = self.request(path='/collection/%s/access' %
                            self.collection['_id'], method='PUT', params={
                                'access': 'not an access list',
                                'public': False
                            }, user=self.admin)
        self.assertStatus(resp, 400)

        # Create some folders underneath the collection
        folder1 = Folder().createFolder(
            parentType='collection', parent=self.collection, creator=self.admin,
            public=False, name='top level')
        folder2 = Folder().createFolder(
            parentType='folder', parent=folder1, creator=self.admin,
            public=False, name='subfolder')
        Folder().createFolder(
            parentType='collection', parent=self.collection, creator=self.admin,
            public=False, name='another top level folder')

        # Admin should see two top level folders
        resp = self.request(path='/collection/%s/details' % self.collection['_id'], user=self.admin)
        self.assertStatusOk(resp)
        self.assertEqual(resp.json['nFolders'], 2)
        self.assertNotIn('nItems', resp.json)

        # Normal user should see 0 folders
        resp = self.request(path='/collection/%s/details' % self.collection['_id'], user=self.user)
        self.assertStatusOk(resp)
        self.assertEqual(resp.json['nFolders'], 0)

        # Add read access on one of the folders
        Folder().setUserAccess(folder1, self.user, AccessType.READ, save=True)

        # Normal user should see one folder now
        resp = self.request(path='/collection/%s/details' % self.collection['_id'], user=self.user)
        self.assertStatusOk(resp)
        self.assertEqual(resp.json['nFolders'], 1)

        # Change the access to allow just the user
        obj = {'users': [{'id': str(self.user['_id']),
                          'level': AccessType.WRITE}]}
        resp = self.request(path='/collection/%s/access' %
                            self.collection['_id'], method='PUT', params={
                                'access': json.dumps(obj),
                                'public': True
                            }, user=self.admin)
        self.assertStatusOk(resp)

        # Request the collection access
        resp = self.request(path='/collection/%s/access' % self.collection['_id'], user=self.admin)
        self.assertStatusOk(resp)
        access = resp.json
        self.assertEqual(access['users'][0]['id'], str(self.user['_id']))
        self.assertEqual(access['users'][0]['level'], AccessType.WRITE)
        coll = Collection().load(self.collection['_id'], force=True)
        folder1 = Folder().load(folder1['_id'], force=True)
        folder2 = Folder().load(folder2['_id'], force=True)
        self.assertEqual(coll['public'], True)
        self.assertEqual(folder1['public'], False)

        # Update the collection recursively to public
        resp = self.request(
            path='/collection/%s/access' % coll['_id'], method='PUT', params={
                'access': json.dumps(obj),
                'public': True,
                'recurse': True,
                'progress': True
            }, user=self.admin)
        self.assertStatusOk(resp)
        coll = Collection().load(coll['_id'], force=True)
        folder1 = Folder().load(folder1['_id'], force=True)
        folder2 = Folder().load(folder2['_id'], force=True)
        self.assertEqual(coll['public'], True)
        self.assertEqual(folder1['public'], True)
        self.assertEqual(folder2['public'], True)
        self.assertEqual(folder1['access'], coll['access'])
        self.assertEqual(folder1['access'], folder2['access'])
        self.assertEqual(folder2['access'], {
            'users': [{
                'id': self.user['_id'],
                'level': AccessType.WRITE,
                'flags': []
            }],
            'groups': []
        })

        # Recursively drop the user's access level to READ
        obj['users'][0]['level'] = AccessType.READ
        resp = self.request(
            path='/collection/%s/access' % coll['_id'], method='PUT', params={
                'access': json.dumps(obj),
                'public': True,
                'recurse': True,
                'progress': True
            }, user=self.admin)
        self.assertStatusOk(resp)
        coll = Collection().load(coll['_id'], force=True)
        folder1 = Folder().load(folder1['_id'], force=True)
        folder2 = Folder().load(folder2['_id'], force=True)
        self.assertEqual(coll['public'], True)
        self.assertEqual(folder1['public'], True)
        self.assertEqual(folder2['public'], True)
        self.assertEqual(folder1['access'], coll['access'])
        self.assertEqual(folder1['access'], folder2['access'])
        self.assertEqual(folder2['access'], {
            'users': [{
                'id': self.user['_id'],
                'level': AccessType.READ,
                'flags': []
            }],
            'groups': []
        })

        # Recursively remove the user's access altogether, also make sure that
        # passing no "public" param just retains the current flag state
        obj['users'] = ()
        resp = self.request(
            path='/collection/%s/access' % coll['_id'], method='PUT', params={
                'access': json.dumps(obj),
                'recurse': True
            }, user=self.admin)
        self.assertStatusOk(resp)
        coll = Collection().load(coll['_id'], force=True)
        folder1 = Folder().load(folder1['_id'], force=True)
        folder2 = Folder().load(folder2['_id'], force=True)
        self.assertEqual(coll['public'], True)
        self.assertEqual(folder1['public'], True)
        self.assertEqual(folder2['public'], True)
        self.assertEqual(folder1['access'], coll['access'])
        self.assertEqual(folder1['access'], folder2['access'])
        self.assertEqual(folder2['access'], {
            'users': [],
            'groups': []
        })

        # Add group access to the collection
        group = Group().createGroup('test', self.admin)
        obj = {
            'groups': [{
                'id': str(group['_id']),
                'level': AccessType.WRITE
            }]
        }

        resp = self.request(
            path='/collection/%s/access' % coll['_id'], method='PUT', params={
                'access': json.dumps(obj),
                'recurse': False
            }, user=self.admin)
        self.assertStatusOk(resp)

        # Create a new top-level folder, it should inherit the collection ACL.
        resp = self.request(path='/folder', method='POST', params={
            'name': 'top level 2',
            'parentId': coll['_id'],
            'parentType': 'collection'
        }, user=self.admin)
        self.assertStatusOk(resp)
        folder = Folder().load(resp.json['_id'], force=True)
        coll = Collection().load(coll['_id'], force=True)
        self.assertEqual(coll['access']['users'], [])
        self.assertEqual(folder['access']['users'], [{
            'id': self.admin['_id'],
            'level': AccessType.ADMIN,
            'flags': []
        }])
        self.assertEqual(folder['access']['groups'], [{
            'id': group['_id'],
            'level': AccessType.WRITE,
            'flags': []
        }])
        self.assertEqual(folder['access']['groups'], coll['access']['groups'])
