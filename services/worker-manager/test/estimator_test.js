import assert from 'assert';
import helper from './helper.js';
import testing from '@taskcluster/lib-testing';

helper.secrets.mockSuite(testing.suiteName(), [], function(mock, skipping) {
  helper.withFakeQueue(mock, skipping);
  helper.withFakeNotify(mock, skipping);

  let estimator, monitor;

  setup(async function() {
    estimator = await helper.load('estimator');
    monitor = await helper.load('monitor');
  });

  test('empty estimation', async function() {
    const workerInfo = {
      existingCapacity: 0,
      requestedCapacity: 0,
      stoppingCapacity: 0,
    };
    const estimate = await estimator.simple({
      workerPoolId: 'foo/bar',
      maxCapacity: 0,
      minCapacity: 0,
      scalingRatio: 1,
      workerInfo,
    });

    assert.strictEqual(estimate, 0);
    assert.strictEqual(monitor.manager.messages.length, 1);
    assert(monitor.manager.messages.some(({ Type, Severity }) => Type === 'simple-estimate' && Severity === 5));
  });

  test('single estimation', async function() {
    const workerInfo = {
      existingCapacity: 0,
      requestedCapacity: 0,
      stoppingCapacity: 0,
    };
    const estimate = await estimator.simple({
      workerPoolId: 'foo/bar',
      maxCapacity: 1,
      minCapacity: 1,
      workerInfo,
    });

    assert.strictEqual(estimate, 1);
    assert.strictEqual(monitor.manager.messages.length, 1);
    assert(monitor.manager.messages.some(({ Type, Severity }) => Type === 'simple-estimate' && Severity === 5));
  });

  test('satisfied estimation', async function() {
    const workerInfo = {
      existingCapacity: 0,
      requestedCapacity: 1,
      stoppingCapacity: 0,
    };
    const estimate = await estimator.simple({
      workerPoolId: 'foo/bar',
      maxCapacity: 1,
      minCapacity: 1,
      workerInfo,
    });

    assert.strictEqual(estimate, 0);
    assert.strictEqual(monitor.manager.messages.length, 1);
    assert(monitor.manager.messages.some(({ Type, Severity }) => Type === 'simple-estimate' && Severity === 5));
  });

  test('scaling ratio 1:1 scale-up', async function() {
    const workerInfo = {
      existingCapacity: 0,
      requestedCapacity: 0,
      stoppingCapacity: 0,
    };
    helper.queue.setPending('foo/bar', 100);
    const estimate = await estimator.simple({
      workerPoolId: 'foo/bar',
      maxCapacity: 100,
      minCapacity: 0,
      scalingRatio: 1,
      workerInfo,
    });

    assert.strictEqual(estimate, 100);
    assert.strictEqual(monitor.manager.messages.length, 1);
    assert(monitor.manager.messages.some(({ Type, Severity }) => Type === 'simple-estimate' && Severity === 5));
  });

  test('scaling ratio 1:1 scale-up with lesser max capacity', async function() {
    const workerInfo = {
      existingCapacity: 0,
      requestedCapacity: 0,
      stoppingCapacity: 0,
    };
    helper.queue.setPending('foo/bar', 100);
    const estimate = await estimator.simple({
      workerPoolId: 'foo/bar',
      maxCapacity: 50,
      minCapacity: 0,
      scalingRatio: 1,
      workerInfo,
    });

    assert.strictEqual(estimate, 50);
    assert.strictEqual(monitor.manager.messages.length, 1);
    assert(monitor.manager.messages.some(({ Type, Severity }) => Type === 'simple-estimate' && Severity === 5));
  });

  test('scaling ratio 1:2 scale-up', async function() {
    const workerInfo = {
      existingCapacity: 0,
      requestedCapacity: 0,
      stoppingCapacity: 0,
    };
    helper.queue.setPending('foo/bar', 100);
    const estimate = await estimator.simple({
      workerPoolId: 'foo/bar',
      maxCapacity: 100,
      minCapacity: 0,
      scalingRatio: 0.5,
      workerInfo,
    });

    assert.strictEqual(estimate, 50);
    assert.strictEqual(monitor.manager.messages.length, 1);
    assert(monitor.manager.messages.some(({ Type, Severity }) => Type === 'simple-estimate' && Severity === 5));
  });

  test('scaling ratio 1:2 scale-up with existing capacity', async function() {
    const workerInfo = {
      existingCapacity: 25,
      requestedCapacity: 0,
      stoppingCapacity: 0,
    };
    helper.queue.setPending('foo/bar', 100);
    helper.queue.setClaimed('foo/bar', 25);
    const estimate = await estimator.simple({
      workerPoolId: 'foo/bar',
      maxCapacity: 100,
      minCapacity: 0,
      scalingRatio: 0.5,
      workerInfo,
    });
    // 50 more to spawn for 75 total
    assert.strictEqual(estimate, 50);
    assert.strictEqual(monitor.manager.messages.length, 1);
    assert(monitor.manager.messages.some(({ Type, Severity }) => Type === 'simple-estimate' && Severity === 5));
  });

  test('over-satisfied estimation', async function() {
    const workerInfo = {
      existingCapacity: 50,
      requestedCapacity: 0,
      stoppingCapacity: 0,
    };
    const estimate = await estimator.simple({
      workerPoolId: 'foo/bar',
      maxCapacity: 1,
      minCapacity: 1,
      workerInfo,
    });

    // for #3372
    if (monitor.manager.messages.length !== 2) {
      console.log(monitor.manager.messages);
    }

    assert.strictEqual(estimate, 0);
    assert.strictEqual(monitor.manager.messages.length, 2);
    assert(monitor.manager.messages.some(({ Type, Severity }) => Type === 'simple-estimate' && Severity === 3));
    assert(monitor.manager.messages.some(({ Type, Fields }) => Type === 'monitor.error' && Fields.existingCapacity === 50));
    monitor.manager.reset();
  });

  test('over-satisfied estimation (false positive is not raised)', async function() {
    const workerInfo = {
      existingCapacity: 5,
      requestedCapacity: 0,
      stoppingCapacity: 0,
    };
    const estimate = await estimator.simple({
      workerPoolId: 'foo/bar',
      maxCapacity: 1,
      minCapacity: 1,
      workerInfo,
    });

    assert.strictEqual(estimate, 0);
    assert.strictEqual(monitor.manager.messages.length, 1);
    assert(monitor.manager.messages.some(({ Type, Severity }) => Type === 'simple-estimate' && Severity === 5));
    monitor.manager.reset();
  });

  test('empty estimation', async function () {
    const workerInfo = {
      existingCapacity: 0,
      requestedCapacity: 0,
      stoppingCapacity: 0,
    };
    const estimate = await estimator.simple({
      workerPoolId: 'foo/bar',
      maxCapacity: 0,
      minCapacity: 0,
      scalingRatio: 1,
      workerInfo,
    });

    assert.strictEqual(estimate, 0);
    assert.strictEqual(monitor.manager.messages.length, 1);
    assert(monitor.manager.messages.some(({ Type, Severity }) => Type === 'simple-estimate' && Severity === 5));
  });

  test('stopping capacity non zero', async function () {
    const workerInfo = {
      existingCapacity: 10,
      requestedCapacity: 10,
      stoppingCapacity: 10,
    };
    const estimate = await estimator.simple({
      workerPoolId: 'foo/bar',
      maxCapacity: 50,
      minCapacity: 0,
      scalingRatio: 1,
      workerInfo,
    });

    assert.strictEqual(estimate, 20);
    assert.strictEqual(monitor.manager.messages.length, 1);
    assert(monitor.manager.messages.some(({ Type, Severity }) => Type === 'simple-estimate' && Severity === 5));
  });
  test('stopping capacity exceeds max capacity', async function () {
    const workerInfo = {
      existingCapacity: 10,
      requestedCapacity: 10,
      stoppingCapacity: 100,
    };
    const estimate = await estimator.simple({
      workerPoolId: 'foo/bar',
      maxCapacity: 50,
      minCapacity: 0,
      scalingRatio: 1,
      workerInfo,
    });

    assert.strictEqual(estimate, 0);
    assert.strictEqual(monitor.manager.messages.length, 1);
    assert(monitor.manager.messages.some(({ Type, Severity }) => Type === 'simple-estimate' && Severity === 5));
  });
  test('stopping + requested capacity exceeds pending', async function () {
    const workerInfo = {
      existingCapacity: 0,
      requestedCapacity: 10,
      stoppingCapacity: 10,
    };
    helper.queue.setPending('foo/bar', 20);
    helper.queue.setClaimed('foo/bar', 0);
    const estimate = await estimator.simple({
      workerPoolId: 'foo/bar',
      maxCapacity: 50,
      minCapacity: 0,
      scalingRatio: 1,
      workerInfo,
    });

    assert.strictEqual(estimate, 10);
    assert.strictEqual(monitor.manager.messages.length, 1);
    assert(monitor.manager.messages.some(({ Type, Severity }) => Type === 'simple-estimate' && Severity === 5));
  });
  test('idle capacity', async function () {
    const workerInfo = {
      existingCapacity: 10,
    };

    const tests = [
      { pending: 5, claimed: 0, expected: 0 },
      { pending: 10, claimed: 0, expected: 0 },
      { pending: 11, claimed: 0, expected: 1 }, // pending - existing = 1

      { pending: 5, claimed: 5, expected: 0 }, // pending - claimed = 0
      { pending: 5, claimed: 10, expected: 5 },

      // estimator is currently working with partially stale data
      // as it gets to the actual calculation and calls queue.taskQueueCounts
      // workerInfo values obtained some time ago might be different
      // in this test we would have more claimed than existing
      { pending: 0, claimed: workerInfo.existingCapacity + 1, expected: 0 },
    ];

    for (const { pending, claimed, expected } of tests) {
      helper.queue.setPending('foo/bar', pending);
      helper.queue.setClaimed('foo/bar', claimed);
      const result = await estimator.simple({
        workerPoolId: 'foo/bar',
        maxCapacity: 50,
        minCapacity: 0,
        scalingRatio: 1,
        workerInfo,
      });
      assert.strictEqual(expected, result);
    }
  });
});
