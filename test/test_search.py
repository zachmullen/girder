#!/usr/bin/env python
# -*- coding: utf-8 -*-

###############################################################################
#  Copyright 2013 Kitware Inc.
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
import json
import pytest

from girder.api.v1 import resource
from girder.constants import AccessType
from girder.models.model_base import AccessControlledModel
from girder.models.assetstore import Assetstore
from girder.models.collection import Collection
from girder.models.item import Item
from girder.models.user import User
from girder.utility.acl_mixin import AccessControlMixin
from girder.utility import search

from pytest_girder.assertions import assertStatusOk, assertStatus, assertRequiredParams


@pytest.mark.dbFixture('test_search.yml')
def testResourceSearch(server, fsAssetstore):
    """
    Test resource/search endpoint
    """
    # get expected models from the database
    admin = User().findOne({'login': 'adminlogin'})
    user = User().findOne({'login': 'goodlogin'})
    coll1 = Collection().findOne({'name': 'Test Collection'})
    coll2 = Collection().findOne({'name': 'Magic collection'})
    item1 = Item().findOne({'name': 'Public object'})

    # set user read permissions on the private collection
    Collection().setUserAccess(coll2, user, level=AccessType.READ, save=True)

    # Grab the default user folders
    resp = server.request(
        path='/folder', method='GET', user=user, params={
            'parentType': 'user',
            'parentId': user['_id'],
            'sort': 'name',
            'sortdir': 1
        })
    privateFolder = resp.json[0]

    # First test all of the required parameters.
    assertRequiredParams(server, path='/resource/search', required=['q', 'types'])

    # Now test parameter validation
    resp = server.request(path='/resource/search', params={
        'q': 'query',
        'types': ',,invalid;json!'
    })
    assertStatus(resp, 400)
    assert 'Parameter types must be valid JSON.' == resp.json['message']

    # Test searching with no results
    resp = server.request(path='/resource/search', params={
        'q': 'gibberish',
        'types': '["folder", "user", "collection", "group"]'
    })
    assertStatusOk(resp)
    assert resp.json == {
        'folder': [],
        'user': [],
        'collection': [],
        'group': []
    }

    # Ensure searching respects permissions
    resp = server.request(path='/resource/search', params={
        'q': 'private',
        'types': '["folder", "user", "collection"]'
    })
    assertStatusOk(resp)
    assert resp.json == {
        'folder': [],
        'user': [],
        'collection': []
    }

    resp = server.request(path='/resource/search', params={
        'q': 'pr',
        'mode': 'prefix',
        'types': '["folder", "user", "collection"]'
    })
    assertStatusOk(resp)
    assert resp.json == {
        'folder': [],
        'user': [],
        'collection': []
    }

    resp = server.request(path='/resource/search', params={
        'q': 'private',
        'types': '["folder", "user", "collection"]'
    }, user=user)
    assertStatusOk(resp)
    assert len(resp.json['folder']) == 1

    assert {'_id': str(privateFolder['_id']),
            'name': 'Private'}.viewitems() <= resp.json['folder'][0].viewitems()

    assert len(resp.json['collection']) == 1
    assert {'_id': str(coll2['_id']),
            'name': coll2['name']}.viewitems() <= resp.json['collection'][0].viewitems()
    assert 0 == len(resp.json['user'])

    resp = server.request(path='/resource/search', params={
        'q': 'pr',
        'mode': 'prefix',
        'types': '["folder", "user", "collection", "item"]'
    }, user=user)
    assertStatusOk(resp)
    assert 1 == len(resp.json['folder'])
    assert {'_id': str(privateFolder['_id']),
            'name': 'Private'}.viewitems() <= resp.json['folder'][0].viewitems()
    assert len(resp.json['collection']) == 0
    assert len(resp.json['item']) == 0
    assert len(resp.json['user']) == 0

    # Ensure that weights are respected, e.g. description should be
    # weighted less than name.
    resp = server.request(path='/resource/search', params={
        'q': 'magic',
        'types': '["collection"]'
    }, user=admin)
    assertStatusOk(resp)
    assert 2 == len(resp.json['collection'])
    assert {'_id': str(coll2['_id']),
            'name': coll2['name']}.viewitems() <= resp.json['collection'][0].viewitems()
    assert {'_id': str(coll1['_id']),
            'name': coll1['name']}.viewitems() <= resp.json['collection'][1].viewitems()
    assert resp.json['collection'][0]['_textScore'] > \
        resp.json['collection'][1]['_textScore']

    # Exercise user search by login
    resp = server.request(path='/resource/search', params={
        'q': 'goodlogin',
        'types': '["user"]'
    }, user=admin)
    assertStatusOk(resp)
    assert 1 == len(resp.json['user'])
    assert {'_id': str(user['_id']),
            'firstName': user['firstName'],
            'lastName': user['lastName'],
            'login': user['login']}.viewitems() <= resp.json['user'][0].viewitems()

    # check item search with proper permissions
    resp = server.request(path='/resource/search', params={
        'q': 'object',
        'types': '["item"]'
    }, user=user)
    assertStatusOk(resp)
    assert 1 == len(resp.json['item'])
    assert {'_id': str(item1['_id']),
            'name': item1['name']}.viewitems() <= resp.json['item'][0].viewitems()

    # Check search for model that is not access controlled
    assert not isinstance(Assetstore(), AccessControlledModel)
    assert not isinstance(Assetstore(), AccessControlMixin)
    resource.allowedSearchTypes.add('assetstore')
    resp = server.request(path='/resource/search', params={
        'q': fsAssetstore['name'],
        'mode': 'prefix',
        'types': '["assetstore"]'
    }, user=user)
    assertStatusOk(resp)
    assert 1 == len(resp.json['assetstore'])


@pytest.mark.dbFixture('test_search.yml')
def testSearchModeRegistry(server):
    def testSearchHandler(query, types, user, level, limit, offset):
        return {
            'query': query,
            'types': types
        }

    search.addSearchMode('testSearch', testSearchHandler)

    # Use the new search mode.
    resp = server.request(path='/resource/search', params={
        'q': 'Test',
        'mode': 'testSearch',
        'types': json.dumps(["collection"])
    })
    assertStatusOk(resp)
    assert resp.json == {
        'query': 'Test',
        'types': ["collection"]
    }

    search.removeSearchMode('testSearch')

    # Use the deleted search mode.
    resp = server.request(path='/resource/search', params={
        'q': 'Test',
        'mode': 'testSearch',
        'types': json.dumps(["collection"])
    })
    assertStatus(resp, 400)
