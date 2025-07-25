const assert = require('assert');
const { suiteName } = require('@taskcluster/lib-testing');
const helper = require('../helper');

const DockerWorker = require('../dockerworker');
const TestWorker = require('../testworker');

helper.secrets.mockSuite(suiteName(), ['docker', 'ci-creds'], function(mock, skipping) {
  if (mock) {
    return; // no fake equivalent for integration tests
  }

  let worker;

  setup(async () => {
    worker = new TestWorker(DockerWorker);
    await worker.launch();
  });

  teardown(async () => {
    await worker.terminate();
  });

  test('caught failure - invalid command', async () => {
    let result = await worker.postToQueue({
      payload: {
        image: 'taskcluster/test-ubuntu',
        command: [
          '/usr/bin/no-such-command',
        ],
        maxRunTime: 30,
      },
    });

    assert.equal(result.run.state, 'failed', 'task should be failed');
    assert.equal(result.run.reasonResolved, 'failed', 'task should be failed');
    assert.ok(
      result.log.includes('Failure to properly start execution environment'),
      'Error message was not written to the task log.',
    );
  });
});
