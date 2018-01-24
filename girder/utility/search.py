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
from flask import current_app
from functools import partial

from girder.models.model_base import ModelImporter
from girder.exceptions import GirderException


class SearchRegistry(object):
    def __init__(self, app=None):
        self.app = app
        self.r = {}

        if app is not None:
            self.init_app(app)

    def init_app(self, app):
        self.app = app
        # copy values
        self.app.extensions['search_registry'] = self

    @staticmethod
    def getSearchModeHandler(mode):
        return current_app.extensions['search_registry'].r.get(mode)

    def addSearchMode(self, mode, handler):
        # guard  app context
        if self.r.get(mode) is not None:
            raise GirderException('A search mode %r already exists.' % mode)
        self.r[mode] = handler

    def removeSearchMode(self, mode):
        return self.r.pop(mode, None) is not None

    @staticmethod
    def _commonSearchModeHandler(mode, query, types, user, level, limit, offset):
        """
        The common handler for `text` and `prefix` search modes.
        """
        # Avoid circular import
        from girder.api.v1.resource import allowedSearchTypes

        method = '%sSearch' % mode
        results = {}

        for modelName in types:
            if modelName not in allowedSearchTypes:
                continue

            if '.' in modelName:
                name, plugin = modelName.rsplit('.', 1)
                model = ModelImporter.model(name, plugin)
            else:
                model = ModelImporter.model(modelName)

            if model is not None:
                results[modelName] = [
                    model.filter(d, user) for d in getattr(model, method)(
                        query=query, user=user, limit=limit, offset=offset, level=level)
                ]
        return results

search_registry = SearchRegistry()

# Add dynamically the default search mode
search_registry.addSearchMode('text',
                              partial(SearchRegistry._commonSearchModeHandler, mode='text'))
search_registry.addSearchMode('prefix',
                              partial(SearchRegistry._commonSearchModeHandler, mode='prefix'))
