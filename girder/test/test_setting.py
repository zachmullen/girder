#!/usr/bin/env python
# -*- coding: utf-8 -*-

#############################################################################
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
#############################################################################

from girder.exceptions import ValidationException
from girder.models.setting import Setting
from girder.utility import setting_utilities

import pytest


def testUniqueIndex(db):
    settingModel = Setting()
    coll = settingModel.collection
    indices = coll.index_information()
    # Make sure we have just one index on key and that it specifies that it
    # is unique
    assert any(indices[index]['key'][0][0] == 'key' and
               indices[index].get('unique') for index in indices)
    assert not any(indices[index]['key'][0][0] == 'key' and
                   not indices[index].get('unique') for index in indices)
    # Delete that index, create a non-unique index, and make some duplicate
    # settings so that we can test that this will be corrected.
    coll.drop_index(next(index for index in indices
                         if indices[index]['key'][0][0] == 'key'))
    coll.create_index('key')
    for val in range(3, 8):
        coll.insert_one({'key': 'duplicate', 'value': val})
    # Check that we've broken things
    indices = coll.index_information()
    assert settingModel.get('duplicate') >= 3
    assert settingModel.find({'key': 'duplicate'}).count() == 5
    assert not any(indices[index]['key'][0][0] == 'key' and
                   indices[index].get('unique') for index in indices)
    assert any(indices[index]['key'][0][0] == 'key' and
               not indices[index].get('unique') for index in indices)
    # Reconnecting the model should fix the issues we just created
    settingModel.reconnect()
    indices = coll.index_information()
    assert any(indices[index]['key'][0][0] == 'key' and
               indices[index].get('unique') for index in indices)
    assert not any(indices[index]['key'][0][0] == 'key' and
                   not indices[index].get('unique') for index in indices)
    assert settingModel.get('duplicate') == 3
    assert settingModel.find({'key': 'duplicate'}).count() == 1


def testValidators(db):
    @setting_utilities.validator('test.key1')
    def key1v1(doc):
        raise ValidationException('key1v1')

    with pytest.raises(ValidationException, match='^key1v1$'):
        Setting().set('test.key1', '')

    @setting_utilities.validator('test.key1')
    def key1v2(doc):
        raise ValidationException('key1v2')

    with pytest.raises(ValidationException, match='^key1v2$'):
        Setting().set('test.key1', '')

    @setting_utilities.validator('test.key2')
    def key2v1(doc):
        raise ValidationException('key2v1')

    with pytest.raises(ValidationException, match='^key2v1$'):
        Setting().set('test.key2', '')


def testValidatorReplacement(db):
    @setting_utilities.validator('test.key2')
    def key2v1(doc):
        raise ValidationException('key2v1')

    @setting_utilities.validator('test.key2', replace=True)
    def key2v2(doc):
        doc['value'] = 'modified'

    setting = Setting().set('test.key2', 'original')
    assert setting['value'] == 'modified'


def testDefaultSettingFunction(db):
    assert Setting().get('test.key') is None

    @setting_utilities.default('test.key')
    def default():
        return 'default value'

    assert Setting().get('test.key') == 'default value'
