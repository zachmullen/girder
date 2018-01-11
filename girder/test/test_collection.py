import json
import pytest

from pytest_girder.assertions import assertStatus, assertStatusOk, assertRequiredParams

from bson.objectid import ObjectId
from girder.constants import AccessType, SettingKey
from girder.models.collection import Collection
from girder.models.folder import Folder
from girder.models.group import Group
from girder.models.setting import Setting
from girder.models.user import User


@pytest.fixture
def publicAdminCollection(admin):
    collection = Collection().createCollection(name='Test Collection',
                                               description='The description',
                                               public=True,
                                               creator=admin)

    yield collection

    Collection().remove(collection)


def testCollectionsHaveNoCreatorByDefault(db):
    collection = Collection().createCollection('No Creator')
    assert collection['creatorId'] is None


def testCollectionCreation(server, admin, user):
    assertRequiredParams(server, path='/collection', method='POST', required=['name'], user=admin)

    # Try to create a collection anonymously; should fail
    resp = server.request(path='/collection', method='POST', params={
        'name': 'new collection'
    })
    assertStatus(resp, 401)

    # Try to create a collection as non-admin user; should fail
    resp = server.request(path='/collection', method='POST', params={
        'name': 'new collection'
    }, user=user)
    assertStatus(resp, 403)


def testCollectionVisibility(server, admin, publicAdminCollection):
    # Create the collection as the admin user, make it private
    resp = server.request(path='/collection', method='POST', params={
        'name': '  New collection  ',
        'description': '  my description ',
        'public': 'false'
    }, user=admin)
    assertStatusOk(resp)

    # Now attempt to list the collections as anonymous user
    resp = server.request(path='/collection')
    assertStatusOk(resp)
    assert len(resp.json) == 1
    assert resp.json[0]['name'] == publicAdminCollection['name']

    # Admin user should see both collections
    resp = server.request(path='/collection', user=admin)
    assertStatusOk(resp)
    assert len(resp.json) == 2
    assert resp.json[0]['name'] == 'New collection'
    assert resp.json[0]['description'] == 'my description'
    assert resp.json[1]['name'] == publicAdminCollection['name']


def testCollectionTextSearch(server, admin, publicAdminCollection):
    # Test text search, 'Test' is in the name of publicAdminCollection
    resp = server.request(path='/collection', user=admin, params={
        'text': 'Test'
    })
    assertStatusOk(resp)
    assert len(resp.json) == 1
    assert resp.json[0]['_id'] == str(publicAdminCollection['_id'])
    assert resp.json[0]['name'] == 'Test Collection'


def testCollectionGetUpdate(server, admin, publicAdminCollection):
    # Test collection get
    resp = server.request(path='/collection/%s' % str(publicAdminCollection['_id']), user=admin)
    assertStatusOk(resp)
    assert resp.json['_accessLevel'] == AccessType.ADMIN

    # Test collection update
    resp = server.request(path='/collection/%s' % str(publicAdminCollection['_id']),
                          method='PUT', user=admin,
                          params={'id': str(publicAdminCollection['_id']),
                                  'name': 'New collection name'})
    assertStatusOk(resp)
    assert resp.json['name'] == 'New collection name'


def testDeleteCollection(server, admin, user, publicAdminCollection):
    # Requesting with no path should fail
    resp = server.request(path='/collection', method='DELETE', user=admin)
    assertStatus(resp, 400)

    # User without permission should not be able to delete collection
    resp = server.request(path='/collection/%s' % publicAdminCollection['_id'],
                          method='DELETE', user=user)
    assertStatus(resp, 403)

    # Admin user should be able to delete the collection
    resp = server.request(path='/collection/%s' % publicAdminCollection['_id'],
                          method='DELETE', user=admin)
    assertStatusOk(resp)

    coll = Collection().load(publicAdminCollection['_id'], force=True)
    assert coll is None


def testCollectionCreationPolicy(server, user):
    # With default settings, non-admin users cannot create collections
    resp = server.request(path='/collection', method='POST', params={
        'name': 'user collection'
    }, user=user)
    assertStatus(resp, 403)

    # Allow any user to create collections
    Setting().set(SettingKey.COLLECTION_CREATE_POLICY, {
        'open': True
    })

    resp = server.request(path='/collection', method='POST', params={
        'name': 'open collection'
    }, user=user)
    assertStatusOk(resp)
    assert '_id' in resp.json

    # Anonymous users still shouldn't be able to
    resp = server.request(path='/collection', method='POST', params={
        'name': 'open collection'
    }, user=None)
    assertStatus(resp, 401)


def testCollectionCreationPolicyOnGroups(server, admin, user):
    # Add a group that has collection create permission
    group = Group().createGroup(name='coll. creators', creator=admin)

    Setting().set(SettingKey.COLLECTION_CREATE_POLICY, {
        'open': False,
        'groups': [str(group['_id'])]
    })

    # Group membership should allow creation now
    Group().addUser(group=group, user=user)
    resp = server.request(path='/collection', method='POST', params={
        'name': 'group collection'
    }, user=user)
    assertStatusOk(resp)
    assert '_id' in resp.json

    # Test individual user access
    Group().removeUser(group=group, user=user)
    resp = server.request(path='/collection', method='POST', params={
        'name': 'group collection'
    }, user=user)
    assertStatus(resp, 403)

    Setting().set(SettingKey.COLLECTION_CREATE_POLICY, {
        'open': False,
        'users': [str(user['_id'])]
    })

    resp = server.request(path='/collection', method='POST', params={
        'name': 'user collection'
    }, user=user)
    assertStatusOk(resp)
    assert '_id' in resp.json


def testMissingAclRefsAreDiscarded(db, publicAdminCollection):
    # Make fake user and group documents and put them into the
    # collection ACL.
    coll = Collection().setAccessList(
        publicAdminCollection, {
            'users': [{'id': ObjectId(), 'level': AccessType.READ}],
            'groups': [{'id': ObjectId(), 'level': AccessType.READ}]
        }, save=True)
    assert len(coll['access']['users']) == 1
    assert len(coll['access']['groups']) == 1

    # Bad refs should have been removed
    acl = Collection().getFullAccessList(coll)
    assert acl == {'users': [], 'groups': []}

    # Changes should have been saved to the database
    coll = Collection().load(coll['_id'], force=True)
    assert acl == coll['access']
