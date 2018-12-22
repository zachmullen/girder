import json
from bson import json_util
from girder import events
from girder.api import access, rest
from girder.api.v1.folder import Folder as FolderResource
from girder.constants import AccessType
from girder.exceptions import ValidationException
from girder.models.file import File
from girder.models.folder import Folder
from girder.plugin import GirderPlugin


def _validateFolder(event):
    doc = event.info

    if 'isVirtual' in doc and not isinstance(doc['isVirtual'], bool):
        raise ValidationException('The isVirtual field must be boolean.', field='isVirtual')

    if doc.get('isVirtual'):
        # Make sure it doesn't have children
        if list(Folder().childFiles(doc, limit=1)):
            raise ValidationException(
                'Virtual folders may not contain child files.', field='isVirtual')
        if list(Folder().find({
            'parentId': doc['_id'],
            'parentCollection': 'folder'
        }, limit=1)):
            raise ValidationException(
                'Virtual folders may not contain child folders.', field='isVirtual')
    if doc['parentCollection'] == 'folder':
        parent = Folder().load(event.info['parentId'], force=True, exc=True)
        if parent.get('isVirtual'):
            raise ValidationException(
                'You may not place folders under a virtual folder.', field='folderId')

    if 'virtualFilesQuery' in doc:
        try:
            json.loads(doc['virtualFilesQuery'])
        except (TypeError, ValueError):
            raise ValidationException(
                'The virtual files query must be valid JSON.', field='virtualFilesQuery')

    if 'virtualFilesSort' in doc:
        try:
            json.loads(doc['virtualFilesSort'])
        except (TypeError, ValueError):
            raise ValidationException(
                'The virtual files sort must be valid JSON.', field='virtualFilesSort')


def _validateFile(event):
    parent = Folder().load(event.info['folderId'], force=True, exc=True)
    if parent.get('isVirtual'):
        raise ValidationException(
            'You may not place files under a virtual folder.', field='folderId')


@rest.boundHandler
def _folderUpdate(self, event):
    params = event.info['params']
    if {'isVirtual', 'virtualFilesQuery', 'virtualFilesSort'} & set(params):
        folder = Folder().load(event.info['returnVal']['_id'], force=True)
        update = False

        if params.get('isVirtual') is not None:
            update = True
            folder['isVirtual'] = params['isVirtual']
        if params.get('virtualFilesQuery') is not None:
            update = True
            folder['virtualFilesQuery'] = params['virtualFilesQuery']
        if params.get('virtualFilesSort') is not None:
            update = True
            folder['virtualFilesSort'] = params['virtualFilesSort']

        if update:
            self.requireAdmin(self.getCurrentUser(), 'Must be admin to setup virtual folders.')
            folder = Folder().filter(Folder().save(folder), rest.getCurrentUser())
            event.preventDefault().addResponse(folder)


@access.public
@rest.boundHandler
def _virtualChildFiles(self, event):
    params = event.info['params']

    if 'folderId' not in params:
        return  # This is not a child listing request

    user = self.getCurrentUser()
    folder = Folder().load(params['folderId'], user=user, level=AccessType.READ)

    if not folder.get('isVirtual') or 'virtualFilesQuery' not in folder:
        return  # Parent is not a virtual folder, proceed as normal

    limit, offset, sort = self.getPagingParameters(params, defaultSortField='name')
    q = json_util.loads(folder['virtualFilesQuery'])

    if 'virtualFilesSort' in folder:
        sort = json.loads(folder['virtualFilesSort'])

    file = File()
    # These files may reside in folders that the user cannot read, so we must filter
    # TODO findWithPermissions
    files = file.filterResultsByPermission(
        file.find(q, sort=sort), user, level=AccessType.READ, limit=limit, offset=offset)
    event.preventDefault().addResponse([file.filter(f, user) for f in files])


class VirtualFoldersPlugin(GirderPlugin):
    DISPLAY_NAME = 'Virtual folders'

    def load(self, info):
        name = 'virtual_folders'
        events.bind('model.folder.validate', name, _validateFolder)
        events.bind('model.file.validate', name, _validateFile)
        events.bind('rest.get.file.before', name, _virtualChildFiles)
        events.bind('rest.post.folder.after', name, _folderUpdate)
        events.bind('rest.put.folder/:id.after', name, _folderUpdate)

        Folder().exposeFields(level=AccessType.READ, fields={'isVirtual'})
        Folder().exposeFields(level=AccessType.SITE_ADMIN, fields={
            'virtualFilesQuery', 'virtualFilesSort'})

        for endpoint in (FolderResource.updateFolder, FolderResource.createFolder):
            (endpoint.description
                .param('isVirtual', 'Whether this is a virtual folder.', required=False,
                       dataType='boolean')
                .param('virtualFilesQuery', 'Query to use to do virtual file lookup, as JSON.',
                       required=False)
                .param('virtualFilesSort', 'Sort to use during virtual file lookup, as JSON.',
                       required=False))
