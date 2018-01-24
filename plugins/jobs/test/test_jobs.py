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

import json
import time

from girder import events
from girder.constants import AccessType
from girder.exceptions import ValidationException
from girder_plugin_jobs.models.job import Job
from girder_plugin_jobs.constants import REST_CREATE_JOB_TOKEN_SCOPE, JobStatus
from girder.models.user import User
from girder.models.token import Token
import pytest

from pytest_girder.assertions import assertStatus, assertStatusOk
from pytest_girder.utils import getSseMessages

pytestmark = pytest.mark.testPlugin('jobs')


@pytest.fixture
def users(admin):
    # tests rely on users[0] being an admin user, they should be written to take admin, user1, user2
    users = [admin] + [User().createUser('usr' + str(n), 'passwd', 'tst', 'usr', 'u%d@u.com' % n)
                       for n in range(2)]

    yield users

    for u in users:
        User().remove(u)


def testJobs(server, users):
    testJobs._job = None

    def schedule(event):
        testJobs._job = event.info
        if testJobs._job['handler'] == 'my_handler':
            testJobs._job['status'] = JobStatus.RUNNING
            testJobs._job = Job().save(testJobs._job)
            assert testJobs._job['args'] == ('hello', 'world')
            assert testJobs._job['kwargs'] == {'a': 'b'}

    events.bind('jobs.schedule', 'test', schedule)

    # Create a job
    job = Job().createJob(
        title='Job Title', type='my_type', args=('hello', 'world'),
        kwargs={'a': 'b'}, user=users[1], handler='my_handler',
        public=False)

    assert testJobs._job is None
    assert job['status'] == JobStatus.INACTIVE

    # Schedule the job, make sure our handler was invoked
    Job().scheduleJob(job)
    assert testJobs._job['_id'] == job['_id']
    assert testJobs._job['status'] == JobStatus.RUNNING

    # Since the job is not public, user 2 should not have access
    path = '/job/%s' % job['_id']
    resp = server.request(path, user=users[2])
    assertStatus(resp, 403)
    resp = server.request(path, user=users[2], method='PUT')
    assertStatus(resp, 403)
    resp = server.request(path, user=users[2], method='DELETE')
    assertStatus(resp, 403)

    # Make sure user who created the job can see it
    resp = server.request(path, user=users[1])
    assertStatusOk(resp)

    # We should be able to update the job as the user who created it
    resp = server.request(path, method='PUT', user=users[1], params={
        'log': 'My log message\n'
    })
    assertStatusOk(resp)

    # We should be able to create a job token and use that to update it too
    token = Job().createJobToken(job)
    resp = server.request(path, method='PUT', params={
        'log': 'append message',
        'token': token['_id']
    })
    assertStatusOk(resp)
    # We shouldn't get the log back in this case
    assert 'log' not in resp.json

    # Do a fetch on the job itself to get the log
    resp = server.request(path, user=users[1])
    assertStatusOk(resp)
    assert resp.json['log'] == ['My log message\n', 'append message']

    # Test overwriting the log and updating status
    resp = server.request(path, method='PUT', params={
        'log': 'overwritten log',
        'overwrite': 'true',
        'status': JobStatus.SUCCESS,
        'token': token['_id']
    })
    assertStatusOk(resp)
    assert 'log' not in resp.json
    assert resp.json['status'] == JobStatus.SUCCESS

    job = Job().load(job['_id'], force=True, includeLog=True)
    assert job['log'] == ['overwritten log']

    # We should be able to delete the job as the user who created it
    resp = server.request(path, user=users[1], method='DELETE')
    assertStatusOk(resp)
    job = Job().load(job['_id'], force=True)
    assert job is None


def testLegacyLogBehavior(db, users):
    # Force save a job with a string log to simulate a legacy job record
    job = Job().createJob(
        title='legacy', type='legacy', user=users[1], save=False)
    job['log'] = 'legacy log'
    job = Job().save(job, validate=False)

    assert job['log'] == 'legacy log'

    # Load the record, we should now get the log as a list
    job = Job().load(job['_id'], force=True, includeLog=True)
    assert job['log'] == ['legacy log']


def testListJobs(server, users):
    job = Job().createJob(title='A job', type='t', user=users[1], public=False)
    anonJob = Job().createJob(title='Anon job', type='t')
    # Ensure timestamp for public job is strictly higher (ms resolution)
    time.sleep(0.1)
    publicJob = Job().createJob(
        title='Anon job', type='t', public=True)

    # User 1 should be able to see their own jobs
    resp = server.request('/job', user=users[1], params={
        'userId': users[1]['_id']
    })
    assertStatusOk(resp)
    assert len(resp.json) == 1
    assert resp.json[0]['_id'] == str(job['_id'])

    # User 2 should not see user 1's jobs in the list
    resp = server.request('/job', user=users[2], params={
        'userId': users[1]['_id']
    })
    assert resp.json == []

    # Omitting a userId should assume current user
    resp = server.request('/job', user=users[1])
    assertStatusOk(resp)
    assert len(resp.json) == 1
    assert resp.json[0]['_id'] == str(job['_id'])

    # Explicitly passing "None" should show anonymous jobs
    resp = server.request('/job', user=users[0], params={
        'userId': 'none'
    })
    assertStatusOk(resp)
    assert len(resp.json) == 2
    assert resp.json[0]['_id'] == str(publicJob['_id'])
    assert resp.json[1]['_id'] == str(anonJob['_id'])

    # Non-admins should only see public anon jobs
    resp = server.request('/job', params={'userId': 'none'})
    assertStatusOk(resp)
    assert len(resp.json) == 1
    assert resp.json[0]['_id'] == str(publicJob['_id'])


def testListAllJobs(server, users):
    Job().createJob(title='user 0 job', type='t', user=users[0], public=False)
    Job().createJob(title='user 1 job', type='t', user=users[1], public=False)
    Job().createJob(title='user 1 job', type='t', user=users[1], public=True)
    Job().createJob(title='user 2 job', type='t', user=users[2])
    Job().createJob(title='anonymous job', type='t')
    Job().createJob(title='anonymous public job', type='t2', public=True)

    # User 0, as a site admin, should be able to see all jobs
    resp = server.request('/job/all', user=users[0])
    assertStatusOk(resp)
    assert len(resp.json) == 6

    # Test deprecated listAll method
    jobs = list(Job().listAll(limit=0, offset=0, sort=None, currentUser=users[0]))
    assert len(jobs) == 6

    # get with filter
    resp = server.request('/job/all', user=users[0], params={
        'types': json.dumps(['t']),
        'statuses': json.dumps([0])
    })
    assertStatusOk(resp)
    assert len(resp.json) == 5

    # get with unmet filter conditions
    resp = server.request('/job/all', user=users[0], params={
        'types': json.dumps(['nonexisttype'])
    })
    assertStatusOk(resp)
    assert len(resp.json) == 0

    # User 1, as non site admin, should encounter http 403 (Forbidden)
    resp = server.request('/job/all', user=users[1])
    assertStatus(resp, 403)

    # Not authenticated user should encounter http 401 (unauthorized)
    resp = server.request('/job/all')
    assertStatus(resp, 401)


def testFiltering(server, users):
    job = Job().createJob(title='A job', type='t', user=users[1], public=True)

    job['_some_other_field'] = 'foo'
    job = Job().save(job)

    resp = server.request('/job/%s' % job['_id'])
    assertStatusOk(resp)
    assert 'created' in resp.json
    assert '_some_other_field' not in resp.json
    assert 'kwargs' not in resp.json
    assert 'args' not in resp.json

    resp = server.request('/job/%s' % job['_id'], user=users[0])
    assert 'kwargs' in resp.json
    assert 'args' in resp.json

    Job().exposeFields(level=AccessType.READ, fields={'_some_other_field'})
    Job().hideFields(level=AccessType.READ, fields={'created'})

    resp = server.request('/job/%s' % job['_id'])
    assertStatusOk(resp)
    assert resp.json['_some_other_field'] == 'foo'
    assert 'created' not in resp.json


def testJobProgressAndNotifications(server, users):
    job = Job().createJob(title='a job', type='t', user=users[1], public=True)

    path = '/job/%s' % job['_id']
    resp = server.request(path)
    assert resp.json['progress'] is None
    assert resp.json['timestamps'] == []

    resp = server.request(path, method='PUT', user=users[1], params={
        'progressTotal': 100,
        'progressCurrent': 3,
        'progressMessage': 'Started',
        'notify': 'false',
        'status': JobStatus.QUEUED
    })
    assertStatusOk(resp)
    assert resp.json['progress'] == {
        'total': 100,
        'current': 3,
        'message': 'Started',
        'notificationId': None
    }

    # The status update should make it so we now have a timestamp
    assert len(resp.json['timestamps']) == 1
    assert resp.json['timestamps'][0]['status'] == JobStatus.QUEUED
    assert 'time' in resp.json['timestamps'][0]

    # If the status does not change on update, no timestamp should be added
    resp = server.request(path, method='PUT', user=users[1], params={
        'status': JobStatus.QUEUED
    })
    assertStatusOk(resp)
    assert len(resp.json['timestamps']) == 1
    assert resp.json['timestamps'][0]['status'] == JobStatus.QUEUED

    # We passed notify=false, so we should only have the job creation notification
    resp = server.request(path='/notification/stream', method='GET',
                          user=users[1], isJson=False,
                          params={'timeout': 0})
    messages = getSseMessages(resp)
    assert len(messages) == 1

    # Update progress with notify=true (the default)
    resp = server.request(path, method='PUT', user=users[1], params={
        'progressCurrent': 50,
        'progressMessage': 'Something bad happened',
        'status': JobStatus.ERROR
    })
    assertStatusOk(resp)
    assert resp.json['progress']['notificationId'] is not None

    # We should now see three notifications (job created + job status + progress)
    resp = server.request(path='/notification/stream', method='GET',
                          user=users[1], isJson=False,
                          params={'timeout': 0})
    messages = getSseMessages(resp)
    job = Job().load(job['_id'], force=True)
    assert len(messages) == 3
    creationNotify = messages[0]
    progressNotify = messages[1]
    statusNotify = messages[2]

    assert creationNotify['type'] == 'job_created'
    assert creationNotify['data']['_id'] == str(job['_id'])
    assert statusNotify['type'] == 'job_status'
    assert statusNotify['data']['_id'] == str(job['_id'])
    assert int(statusNotify['data']['status']) == JobStatus.ERROR
    assert 'kwargs' not in statusNotify['data']
    assert 'log' not in statusNotify['data']

    assert progressNotify['type'] == 'progress'
    assert progressNotify['data']['title'] == job['title']
    assert progressNotify['data']['current'] == float(50)
    assert progressNotify['data']['state'] == 'error'
    assert progressNotify['_id'] == str(job['progress']['notificationId'])



def testDotsInKwargs(server, users):
    kwargs = {
        '$key.with.dots': 'value',
        'foo': [{
            'moar.dots': True
        }]
    }
    job = Job().createJob(title='dots', type='x', user=users[0], kwargs=kwargs)

    # Make sure we can update a job and notification creation works
    Job().updateJob(job, status=JobStatus.QUEUED, notify=True)

    assert job['kwargs'] == kwargs

    resp = server.request('/job/%s' % job['_id'], user=users[0])
    assertStatusOk(resp)
    assert resp.json['kwargs'] == kwargs

    job = Job().load(job['_id'], force=True)
    assert job['kwargs'] == kwargs
    job = Job().filter(job, users[0])
    assert job['kwargs'] == kwargs
    job = Job().filter(job, users[1])
    assert not ('kwargs' in job)


@pytest.mark.skip('Unimplemented')
def testLocalJob(server, users):
    job = Job().createLocalJob(
        title='local', type='local', user=users[0], kwargs={
            'hello': 'world'
        }, module='plugin_tests.local_job_impl')

    Job().scheduleJob(job)

    job = Job().load(job['_id'], force=True, includeLog=True)
    assert job['log'] == ['job ran!']

    job = Job().createLocalJob(
        title='local', type='local', user=users[0], kwargs={
            'hello': 'world'
        }, module='plugin_tests.local_job_impl', function='fail')

    Job().scheduleJob(job)

    job = Job().load(job['_id'], force=True, includeLog=True)
    assert job['log'] == ['job failed']


def testValidateCustomStatus(server, users):
    job = Job().createJob(title='test', type='x', user=users[0])

    def validateStatus(event):
        if event.info == 1234:
            event.preventDefault().addResponse(True)

    def validTransitions(event):
        if event.info['status'] == 1234:
            event.preventDefault().addResponse([JobStatus.INACTIVE])

    with pytest.raises(ValidationException):
        Job().updateJob(job, status=1234)  # Should fail

    with events.bound('jobs.status.validate', 'test', validateStatus), \
            events.bound('jobs.status.validTransitions', 'test', validTransitions):
        Job().updateJob(job, status=1234)  # Should work

        with pytest.raises(ValidationException):
            Job().updateJob(job, status=4321)  # Should fail


def testValidateCustomStrStatus(server, users):
    job = Job().createJob(title='test', type='x', user=users[0])

    def validateStatus(event):
        states = ['a', 'b', 'c']

        if event.info in states:
            event.preventDefault().addResponse(True)

    def validTransitions(event):
        if event.info['status'] == 'a':
            event.preventDefault().addResponse([JobStatus.INACTIVE])

    with pytest.raises(ValidationException):
        Job().updateJob(job, status='a')

    with events.bound('jobs.status.validate', 'test', validateStatus), \
            events.bound('jobs.status.validTransitions', 'test', validTransitions):
        Job().updateJob(job, status='a')
        assert job['status'] == 'a'

    with pytest.raises(ValidationException), \
            events.bound('jobs.status.validate', 'test', validateStatus):
        Job().updateJob(job, status='foo')


def testUpdateOtherFields(server, users):
    job = Job().createJob(title='test', type='x', user=users[0])
    job = Job().updateJob(job, otherFields={'other': 'fields'})
    assert job['other'] == 'fields'


def testCancelJob(server, users):
    job = Job().createJob(title='test', type='x', user=users[0])
    # add to the log
    job = Job().updateJob(job, log='entry 1\n')
    # Reload without the log
    job = Job().load(id=job['_id'], force=True)
    assert len(job.get('log', [])) == 0
    # Cancel
    job = Job().cancelJob(job)
    assert job['status'] == JobStatus.CANCELED
    # Reloading should still have the log and be canceled
    job = Job().load(id=job['_id'], force=True, includeLog=True)
    assert job['status'] == JobStatus.CANCELED
    assert len(job.get('log', [])) == 1


def testCancelJobEndpoint(server, users):
    job = Job().createJob(title='test', type='x', user=users[0])

    # Ensure requires write perms
    jobCancelUrl = '/job/%s/cancel' % job['_id']
    resp = server.request(jobCancelUrl, user=users[1], method='PUT')
    assertStatus(resp, 403)

    # Try again with the right user
    jobCancelUrl = '/job/%s/cancel' % job['_id']
    resp = server.request(jobCancelUrl, user=users[0], method='PUT')
    assertStatusOk(resp)
    assert resp.json['status'] == JobStatus.CANCELED



def testJobsTypesAndStatuses(server, users):
    Job().createJob(title='user 0 job', type='t1', user=users[0], public=False)
    Job().createJob(title='user 1 job', type='t2', user=users[1], public=False)
    Job().createJob(title='user 1 job', type='t3', user=users[1], public=True)
    Job().createJob(title='user 2 job', type='t4', user=users[2])
    Job().createJob(title='anonymous job', type='t5')
    Job().createJob(title='anonymous public job', type='t6', public=True)

    # User 1, as non site admin, should encounter http 403 (Forbidden)
    resp = server.request('/job/typeandstatus/all', user=users[1])
    assertStatus(resp, 403)

    # Admin user gets all types and statuses
    resp = server.request('/job/typeandstatus/all', user=users[0])
    assertStatusOk(resp)
    assert len(resp.json['types']) == 6
    assert len(resp.json['statuses']) == 1

    # standard user gets types and statuses of its own jobs
    resp = server.request('/job/typeandstatus', user=users[1])
    assertStatusOk(resp)
    assert len(resp.json['types']) == 2
    assert len(resp.json['statuses']) == 1


def testDefaultParentId(server, users):
    job = Job().createJob(title='Job', type='Job', user=users[0])
    # If not specified parentId should be None
    assert job['parentId'] is None


def testIsParentIdCorrect(server, users):
    parentJob = Job().createJob(
        title='Parent Job', type='Parent Job', user=users[0])

    childJob = Job().createJob(
        title='Child Job', type='Child Job', user=users[0], parentJob=parentJob)
    # During initialization parent job should be set correctly
    assert childJob['parentId'] == parentJob['_id']


def testSetParentCorrectly(server, users):
    parentJob = Job().createJob(
        title='Parent Job', type='Parent Job', user=users[0])
    childJob = Job().createJob(title='Child Job', type='Child Job', user=users[0])

    Job().setParentJob(childJob, parentJob)

    # After setParentJob method is called parent job should be set correctly
    assert childJob['parentId'] == parentJob['_id']


def testParentCannotBeEqualToChild(server, users):
    childJob = Job().createJob(title='Child Job', type='Child Job', user=users[0])

    # Cannot set a job as it's own parent
    with pytest.raises(ValidationException):
        Job().setParentJob(childJob, childJob)


def testParentIdCannotBeOverridden(server, users):
    parentJob = Job().createJob(
        title='Parent Job', type='Parent Job', user=users[0])

    anotherParentJob = Job().createJob(
        title='Another Parent Job', type='Parent Job', user=users[0])

    childJob = Job().createJob(
        title='Child Job', type='Child Job', user=users[0], parentJob=parentJob)

    with pytest.raises(ValidationException):
        # If parent job is set, cannot be overridden
        Job().setParentJob(childJob, anotherParentJob)


def testListChildJobs(server, users):
    parentJob = Job().createJob(
        title='Parent Job', type='Parent Job', user=users[0])

    childJob = Job().createJob(
        title='Child Job', type='Child Job', user=users[0], parentJob=parentJob)

    Job().createJob(
        title='Another Child Job', type='Child Job', user=users[0], parentJob=parentJob)

    # Should return a list with 2 jobs
    assert len(list(Job().listChildJobs(parentJob))) == 2
    # Should return an empty list
    assert len(list(Job().listChildJobs(childJob))) == 0


def testListChildJobsRest(server, users):
    parentJob = Job().createJob(
        title='Parent Job', type='Parent Job', user=users[0])

    childJob = Job().createJob(
        title='Child Job', type='Child Job', user=users[0], parentJob=parentJob)

    Job().createJob(
        title='Another Child Job', type='Child Job', user=users[0], parentJob=parentJob)

    resp = server.request('/job', user=users[0],
                          params={'parentId': str(parentJob['_id'])})
    resp2 = server.request('/job', user=users[0],
                           params={'parentId': str(childJob['_id'])})

    assertStatusOk(resp)
    assertStatusOk(resp2)

    # Should return a list with 2 jobs
    assert len(resp.json) == 2
    # Should return an empty list
    assert len(resp2.json) == 0



def testCreateJobRest(server, users):
    resp = server.request('/job', method='POST',
                          user=users[0],
                          params={'title': 'job', 'type': 'job'})
    # If user does not have the necessary token status is 403
    assertStatus(resp, 403)

    token = Token().createToken(scope=REST_CREATE_JOB_TOKEN_SCOPE)

    resp2 = server.request(
        '/job', method='POST', token=token, params={'title': 'job', 'type': 'job'})
    # If user has the necessary token status is 200
    assertStatusOk(resp2)


def testJobStateTransitions(server, users):
    job = Job().createJob(
        title='user 0 job', type='t1', user=users[0], public=False)

    # We can't move straight to SUCCESS
    with pytest.raises(ValidationException):
        job = Job().updateJob(job, status=JobStatus.SUCCESS)

    Job().updateJob(job, status=JobStatus.QUEUED)
    Job().updateJob(job, status=JobStatus.RUNNING)
    Job().updateJob(job, status=JobStatus.ERROR)

    # We shouldn't be able to move backwards
    with pytest.raises(ValidationException):
        Job().updateJob(job, status=JobStatus.QUEUED)
    with pytest.raises(ValidationException):
        Job().updateJob(job, status=JobStatus.RUNNING)
    with pytest.raises(ValidationException):
        Job().updateJob(job, status=JobStatus.INACTIVE)
