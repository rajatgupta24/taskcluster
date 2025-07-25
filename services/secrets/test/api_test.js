import helper from './helper.js';
import assert from 'assert';
import slugid from 'slugid';
import taskcluster from '@taskcluster/client';
import testing from '@taskcluster/lib-testing';

helper.secrets.mockSuite(testing.suiteName(), [], function(mock, skipping) {
  helper.withDb(mock, skipping);
  helper.withServer(mock, skipping);

  const SECRET_NAME = `captain:${slugid.v4()}`;
  const testValueFoo = {
    secret: { data: 'bar' },
    expires: taskcluster.fromNowJSON('1 day'),
  };
  const testValueBar = {
    secret: { data: 'foo' },
    expires: taskcluster.fromNowJSON('1 day'),
  };
  const testValueExpired = {
    secret: { data: 'bar' },
    expires: taskcluster.fromNowJSON('- 2 hours'),
  };

  /**
   * clientName - name of the client to use
   * apiCall - API method name
   * name - secret name
   * args - additional API call arguments
   * res - expected result
   * statusCode - expected non-200 result
   * errMessage - if statusCode is set, error messages should begin with this
   */
  const makeApiCall = async ({ clientName, apiCall, name, args, res, statusCode, errMessage }) => {
    let client = await helper.client(clientName);
    let gotRes = undefined;
    try {
      if (args) {
        gotRes = await client[apiCall](name, args);
      } else {
        gotRes = await client[apiCall](name);
      }
    } catch (e) {
      if (e.statusCode) {
        assert(statusCode, `got unexpected error: ${e}`);
        assert.deepEqual(statusCode, e.statusCode);
        if (errMessage) {
          assert(e.body.message.startsWith(errMessage));
        }
        // if there's a payload, the secret should be obscured
        if (e.body.requestInfo && e.body.requestInfo.payload.secret) {
          assert.equal(e.body.requestInfo.payload.secret, '(OMITTED)');
        }
        return;
      } else {
        throw e; // if there's no statusCode this isn't an API error
      }
    }
    assert(!statusCode, 'did not get expected error');
    res && Object.keys(res).forEach(key => {
      assert.deepEqual(gotRes[key], res[key]);
    });
  };

  test('set allowed key (twice)', async function() {
    await makeApiCall({
      clientName: 'captain-write',
      apiCall: 'set',
      name: SECRET_NAME,
      args: testValueFoo,
      res: {},
    });

    // a second call overwrites the value of the secret, without error
    await makeApiCall({
      clientName: 'captain-write',
      apiCall: 'set',
      name: SECRET_NAME,
      args: testValueBar,
      res: {},
    });
  });

  test('set disallowed key', async function() {
    await makeApiCall({
      clientName: 'captain-write',
      apiCall: 'set',
      name: 'some-other-name',
      args: testValueFoo,
      statusCode: 403, // It's not authorized!
    });
  });

  test('get with only "set" scope fails to read', async function() {
    const client = await helper.client('captain-write');
    await client.set(SECRET_NAME, testValueFoo);
    await makeApiCall({
      clientName: 'captain-write',
      apiCall: 'get',
      name: SECRET_NAME,
      statusCode: 403, // it's not authorized!
    });
  });

  test('get with read-only scopes reads the secret', async function() {
    const client = await helper.client('captain-write');
    await client.set(SECRET_NAME, testValueFoo);
    await makeApiCall({
      clientName: 'captain-read',
      apiCall: 'get',
      name: SECRET_NAME,
      res: testValueFoo,
    });
  });

  test('get with read-only scopes reads an updated secret after set', async function() {
    const client = await helper.client('captain-write');
    await client.set(SECRET_NAME, testValueFoo);
    await client.set(SECRET_NAME, testValueBar);
    await makeApiCall({
      clientName: 'captain-read',
      apiCall: 'get',
      name: SECRET_NAME,
      res: testValueBar,
    });
  });

  test('remove with read-only scopes fails', async function() {
    const client = await helper.client('captain-write');
    await client.set(SECRET_NAME, testValueBar);
    await makeApiCall({
      clientName: 'captain-read',
      apiCall: 'remove',
      name: SECRET_NAME,
      statusCode: 403, // It's not authorized!
    });
  });

  test('remove with write-only scopes succeeds', async function() {
    const client = await helper.client('captain-write');
    await client.set(SECRET_NAME, testValueBar);
    await makeApiCall({
      clientName: 'captain-write',
      apiCall: 'remove',
      name: SECRET_NAME,
      res: {},
    });
    const [result] = await helper.db.fns.get_secret(SECRET_NAME);
    assert.equal(result, undefined);
  });

  test('getting a missing secret is a 404', async function() {
    await makeApiCall({
      clientName: 'captain-read',
      apiCall: 'get',
      name: SECRET_NAME,
      statusCode: 404,
      errMessage: 'Secret not found',
    });
  });

  test('deleting a missing secret "succeeds"', function() {
    return makeApiCall({
      clientName: 'captain-write',
      apiCall: 'remove',
      name: SECRET_NAME,
      res: {},
    });
  });

  test('reading an expired secret is a 410', async function() {
    const client = await helper.client('captain-write');
    await client.set(SECRET_NAME, testValueExpired);
    await makeApiCall({
      clientName: 'captain-read',
      apiCall: 'get',
      name: SECRET_NAME,
      statusCode: 404,
      errMessage: 'Secret not found',
    });
  });

  test('Expire secrets', async () => {
    let client = await helper.client('captain-read-write');
    let expireKey = 'captain:' + slugid.v4();
    let saveKey = 'captain:' + slugid.v4();

    helper.load.save();

    try {
      await client.set(expireKey, {
        secret: {
          message: 'get rid of this secret',
          list: ['goodbye', 'world'],
        },
        expires: taskcluster.fromNowJSON('-2 hours'),
      });
      await client.set(saveKey, {
        secret: {
          message: 'keep this secret!!',
          list: ['hello', 'world'],
        },
        expires: taskcluster.fromNowJSON('2 hours'),
      });

      await helper.load('expire');

      let { secret } = await client.get(saveKey);
      assert.deepEqual(secret, {
        message: 'keep this secret!!',
        list: ['hello', 'world'],
      });

      // check audit trail
      const results = await helper.db.fns.get_combined_audit_history(null, expireKey, 'secret', 2, 0);
      assert.deepEqual(results.map(({ action_type }) => action_type).sort(), ['created', 'expired']);

      try {
        await client.get(expireKey);
      } catch (err) {
        if (err.statusCode === 404) {
          return;
        }
        throw err;
      }
      assert(false, 'Expected an error');
    } finally {
      helper.load.restore();
    }
  });

  test('List secrets', async () => {
    const client = await helper.client('captain-read-write');

    // delete any secrets we can see
    let list = await client.list();
    for (let secret of list.secrets) {
      await client.remove(secret);
    }

    // assert the list is empty
    list = await client.list();
    assert.deepEqual(list, { secrets: [] });

    // create some
    await client.set('captain:hidden/1', {
      secret: { sekrit: 1 },
      expires: taskcluster.fromNowJSON('2 hours'),
    });
    await client.set('captain:limited/1', {
      secret: { 'less-sekrit': 1 },
      expires: taskcluster.fromNowJSON('2 hours'),
    });

    list = await client.list();
    list.secrets.sort();
    assert.deepEqual(list, { secrets: ['captain:hidden/1', 'captain:limited/1'] });
  });

  test('Listing secrets requires scopes', async () => {
    const client = await helper.client('none');

    await assert.rejects(
      () => client.list(),
      err => err.code === 'InsufficientScopes');
  });
});
