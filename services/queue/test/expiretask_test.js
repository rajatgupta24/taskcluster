import debugFactory from 'debug';
const debug = debugFactory('test:expireTasks');
import slugid from 'slugid';
import taskcluster from '@taskcluster/client';
import assume from 'assume';
import helper from './helper.js';
import testing from '@taskcluster/lib-testing';

helper.secrets.mockSuite(testing.suiteName(), ['aws'], function(mock, skipping) {
  helper.withDb(mock, skipping);
  helper.withAmazonIPRanges(mock, skipping);
  helper.withPulse(mock, skipping);
  helper.withS3(mock, skipping);
  helper.withServer(mock, skipping);
  helper.resetTables(mock, skipping);

  // Use the same task definition for everything
  const makeTask = (expiration) => {
    const task = {
      taskQueueId: 'no-provisioner-extended-extended/test-worker-extended-extended',
      created: taskcluster.fromNowJSON(),
      deadline: taskcluster.fromNowJSON('1 day'),
      // Notice that in config/test.js we've configured
      // expire-tasks to expire 4 days before expires
      expires: taskcluster.fromNowJSON(expiration),
      retries: 1,
      payload: {},
      metadata: {
        name: 'Unit testing task',
        description: 'Task created during unit tests',
        owner: 'jonsafj@mozilla.com',
        source: 'https://github.com/taskcluster/taskcluster-queue',
      },
    };
    return { taskId: slugid.v4(), task };
  };

  test('expire completed task', async () => {
    const { taskId, task } = makeTask('2 day');

    debug('### Creating task');
    const r1 = await helper.queue.createTask(taskId, task);
    assume(r1.status.state).equals('pending');
    assume(r1.status.runs.length).equals(1);

    debug('### Claim task');
    await helper.queue.claimTask(taskId, 0, {
      workerGroup: 'my-worker-group-extended-extended',
      workerId: 'my-worker-extended-extended',
    });

    debug('### Report task completed');
    const r3 = await helper.queue.reportCompleted(taskId, 0);

    debug('### Validate task status');
    const r4 = helper.checkDates(await helper.queue.status(taskId));
    assume(r4.status).deep.equals(r3.status);

    debug('### Expire tasks');
    await helper.runExpiration('expire-tasks');

    debug('### Check that task is gone');
    await helper.queue.status(taskId).then(() => {
      throw new Error('Expected the task to be missing');
    }, (err) => {
      debug('Expected error: %s, tasks have been expired as expected!', err);
      assume(err.statusCode).equals(404);
    });
  });

  test('expire won\'t drop table', async () => {
    const { taskId, task } = makeTask('12 day');

    debug('### Creating task');
    const r1 = await helper.queue.createTask(taskId, task);
    assume(r1.status.state).equals('pending');
    assume(r1.status.runs.length).equals(1);

    debug('### Claim task');
    await helper.queue.claimTask(taskId, 0, {
      workerGroup: 'my-worker-group-extended-extended',
      workerId: 'my-worker-extended-extended',
    });

    debug('### Report task completed');
    const r3 = await helper.queue.reportCompleted(taskId, 0);

    debug('### Validate task status');
    const r4 = await helper.queue.status(taskId);
    assume(r4.status).deep.equals(r3.status);

    debug('### Expire tasks');
    await helper.runExpiration('expire-tasks');

    debug('### Check that task isn\'t gone');
    const r5 = await helper.queue.status(taskId);
    assume(r5.status).deep.equals(r4.status);
  });
});
