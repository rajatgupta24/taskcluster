import hawk from 'hawk';
import assert from 'assert';
import scopes from 'taskcluster-lib-scopes';
import crypto from 'crypto';
import { cleanRouteAndParams } from '../utils.js';
import ScopeExpressionTemplate from '../expressions.js';
import { ErrorReply } from '../error-reply.js';

/** @typedef {import('../../@types/index.d.ts').SignatureValidatorResult} SignatureValidatorResult */
/** @typedef {import('../../@types/index.d.ts').APIRequest} APIRequest */
/** @typedef {import('../../@types/index.d.ts').SignatureValidator} SignatureValidator */
/**
 * @template {Record<string, any>} TContext
 * @typedef {import('../../@types/index.d.ts').APIEntryOptions<TContext>} APIEntryOptions
 */
/**
 * @template {Record<string, any>} TContext
 * @typedef {import('../../@types/index.d.ts').APIRequestHandler<TContext>} APIRequestHandler
 */

/**
 * Authenticate client using remote API end-point and validate that it satisfies
 * a specified scope expression.
 *
 * options:
 * {
 *    signatureValidator:   async (data) => {message}, {scheme, scopes}, or
 *                                          {scheme, scopes, hash}
 *    entry: // the declared entity
 * },
 *
 * where `data` is the form: {method, url, host, port, authorization}.
 *
 * entry:
 * {
 *   scopes:  {AnyOf: [
 *     'service:method:action:<resource>'
 *     {AllOf: ['admin', 'superuser']},
 *   ]},
 *   name:        '...', // API end-point name for internal errors
 * }
 *
 * Check that the client is authenticated and has scope patterns that satisfies
 * either `'service:method:action:<resource>'` or both `'admin'` and
 * `'superuser'`. If the client has pattern "service:*" this will match any
 * scope that starts with "service:" as is the case in the example above.
 *
 * The request grows the following properties:
 *
 *  * `req.authorize(params, options)`
 *  * `await req.scopes()`
 *  * `await req.clientId()`
 *
 * The `req.authorize(params, options)` method will substitute params
 * into the scope expression in `options.scopes`. This can happen in one of three
 * ways:
 *
 * First is that any strings with `<foo>` in them will have `<foo>` replaced
 * by whatever parameter you pass in to authorize that has the key `foo`. It
 * must be a string to be substituted in this manner.
 *
 * Second is a case where an object of the form
 * `{for: 'foo', in: 'bar', each: 'baz:<foo>'}`. In this case, the param
 * `bar` must be an array and each element of `bar` will be substituted
 * into the string in `each` in the same way as described above for regular
 * strings. The results will then be concatenated into the array that this
 * object is a part of. An example:
 *
 * options.scopes = {AnyOf: ['abc', {for: 'foo', in: 'bar', each: '<foo>:baz'}]}
 *
 * params = {bar: ['def', 'qed']}
 *
 * results in:
 *
 * {AnyOf: [
 *   'abc',
 *   'def:baz',
 *   'qed:baz',
 * ]}
 *
 * Third is an object of the form `{if: 'foo', then: ...}`.
 * In this case if the parameter `foo` is a boolean and true, then the
 * object will be substituted with the scope expression specified
 * in `then`. No truthiness conversions will be done for you.
 *
 * Params specified in `<...>` or the `in` part of the objects are allowed to
 * use dotted syntax to descend into params. Example:
 *
 * options.scopes = {AllOf: ['whatever:<foo.bar>]}
 *
 * params = {foo: {bar: 'abc'}}
 *
 * results in:
 *
 * {AllOf: ['whatever:abc']}
 *
 * The `req.authorize(params, options)` method returns `true` if the
 * client satisfies the scope expression in `options.scopes` after the
 * parameters denoted by `<...>` and `{for: ..., each: ..., in: ...}` are
 * substituted in. If the client does not satisfy the scope expression, it
 * throws an Error.
 *
 * The `req.scopes()` method returns a Promise for the set of scopes the caller
 * has. Please, note that `req.scopes()` returns `[]` if there was an
 * authentication error.
 *
 * The `req.clientId` function returns (via Promise) the requesting clientId,
 * or the reason no clientId is known (`auth-failed:status`).  This value can
 * be used for logging and auditing, but should **never** be used for access
 * control.
 *
 * If authentication was successful, `req.expires()` returns (via Promise) the
 * expiration time of the credentials used to make this request.  If the
 * response includes some additional security token, its duration should be
 * limited to this expiration time.
 *
 * Reports 401 if authentication fails.
 *
 * @template {Record<string, any>} TContext
 * @param {{ entry: APIEntryOptions<TContext>, signatureValidator: SignatureValidator }} options
 * @returns {APIRequestHandler<TContext>}
 */
export const remoteAuthentication = ({ signatureValidator, entry }) => {
  assert(signatureValidator instanceof Function,
    'Expected signatureValidator to be a function!');

  // Returns promise for object on the form:
  //   {status, message, scopes, scheme, hash}
  // scopes, scheme, hash are only present if status isn't auth-failed
  /** @param {APIRequest} req */
  const authenticate = async (req) => {
    // Check that we're not using two authentication schemes, we could
    // technically allow two. There are cases where we redirect and it would be
    // smart to let bewit overwrite header authentication.
    // But neither Azure or AWS tolerates two authentication schemes,
    // so this is probably a fair policy for now. We can always allow more.
    if (req.headers && req.headers.authorization &&
        req.query && req.query.bewit) {
      return {
        status: 'auth-failed',
        message: 'Cannot use two authentication schemes at once ' +
                  'this request has both bewit in querystring and ' +
                  '\'authorization\' header',
      };
    }

    // Parse host header
    const host = hawk.utils.parseHost(req);
    // Find port, overwrite if forwarded by reverse proxy
    let port = host.port;
    if (req.headers['x-forwarded-port'] !== undefined) {
      if (Array.isArray(req.headers['x-forwarded-port'])) {
        port = parseInt(req.headers['x-forwarded-port'][0], 10);
      } else {
        port = parseInt(req.headers['x-forwarded-port'], 10);
      }
    } else if (req.headers['x-forwarded-proto'] !== undefined) {
      port = req.headers['x-forwarded-proto'] === 'https' ? 443 : port;
    }

    // Send input to signatureValidator (auth server or local validator)
    let result = await Promise.resolve(signatureValidator({
      method: req.method.toLowerCase(),
      resource: req.originalUrl,
      host: host.name,
      port: parseInt(port, 10),
      authorization: req.headers.authorization,
      sourceIp: req.ip,
    }, { traceId: req.traceId, requestId: req.requestId }));

    // Validate request hash if one is provided
    if (result.status === 'auth-success'
      && typeof result.hash === 'string' && result.scheme === 'hawk') {
      const hash = hawk.crypto.calculatePayloadHash(
        Buffer.from(req.text ?? '', 'utf-8'),
        'sha256',
        req.headers['content-type'],
      );
      if (!crypto.timingSafeEqual(
        new Uint8Array(Buffer.from(result.hash)),
        new Uint8Array(Buffer.from(hash)))
      ) {
        // create a fake auth-failed result with the failed hash
        result = {
          status: 'auth-failed',
          message:
            'Invalid payload hash: {{hash}}\n' +
            'Computed payload hash: {{computedHash}}\n' +
            'This happens when your request carries a signed hash of the ' +
            'payload and the hash doesn\'t match the hash we\'ve computed ' +
            'on the server-side.',
          computedHash: hash,
        };
      }
    }

    return result;
  };

  // Compile the scopeTemplate
  /** @type {ScopeExpressionTemplate} */
  let scopeTemplate;
  let useUrlParams = false;
  if (entry.scopes) {
    scopeTemplate = new ScopeExpressionTemplate(entry.scopes);
    // Write route parameters into {[param]: ''}
    // if these are valid parameters, then we can parameterize using req.params
    let [, params, optionalParams] = cleanRouteAndParams(entry.route);
    // We can only decide to useUrlParams if all params are required params.
    // Otherwise if they are not provided the scope checking will fail.
    // This means all endpoints with optional params that get included in the
    // scope expression must call req.authorize.
    params = params.filter(param => !optionalParams.includes(param));
    params = Object.assign({}, ...params.map(p => ({ [p]: '' })));
    useUrlParams = scopeTemplate.validate(params);
  }

  return async (req, res, next) => {
    /** @type {SignatureValidatorResult | Promise<SignatureValidatorResult>} */
    let result;
    try {
      /** Create method that returns list of scopes the caller has */
      req.scopes = async () => {
        // This lint can be disabled because authenticate() will always return the same value
        result = await (result || authenticate(req)); // eslint-disable-line require-atomic-updates
        if (result.status === 'auth-failed') {
          return [];
        }
        return result.scopes || [];
      };

      req.clientId = async () => {
        // This lint can be disabled because authenticate() will always return the same value
        result = await (result || authenticate(req)); // eslint-disable-line require-atomic-updates
        if (result.status === 'auth-success') {
          return result.clientId || 'unknown-clientId';
        }
        return 'auth-failed:' + result.status;
      };

      req.expires = async () => {
        // This lint can be disabled because authenticate() will always return the same value
        result = await (result || authenticate(req)); // eslint-disable-line require-atomic-updates
        if (result.status === 'auth-success') {
          return new Date(result.expires);
        }
        return undefined;
      };

      req.satisfies = () => {
        throw new Error('req.satisfies is deprecated! use req.authorize instead');
      };

      /**
       * Create method to check if request satisfies the scope expression. Given
       * extra parameters.
       * Return true, if successful and if unsuccessful it throws an Error with
       * code = 'AuthenticationFailed'.
       */
      req.authorize = async (params) => {
        // Render the scope expression template
        const scopeExpression = scopeTemplate.render(params);

        // if there's no scope expression then this is a public request (as
        // occurs with getArtifact for a public artifact, for example)
        if (!scopeExpression) {
          req.public = true;
          return;
        }

        // This lint can be disabled because authenticate() will always return the same value
        result = await (result || authenticate(req)); // eslint-disable-line require-atomic-updates

        // If authentication failed
        if (result.status === 'auth-failed') {
          res.set('www-authenticate', 'hawk');
          throw new ErrorReply({
            code: 'AuthenticationFailed',
            message: result.message,
            details: result,
          });
        }

        // Test that we have scope intersection, and hence, is authorized
        const satisfyingScopes = scopes.scopesSatisfying(result.scopes, scopeExpression);
        req.authenticated = true;

        if (!satisfyingScopes) {
          const clientId = await req.clientId();

          const gotCreds = result.status === 'auth-success';
          const message = (gotCreds ? [
            'Client ID ' + clientId + ' does not have sufficient scopes and is missing the following scopes:',
            '',
            '```',
            '{{unsatisfied}}',
            '```',
            '',
            'This request requires the client to satisfy the following scope expression:',
            '',
            '```',
            '{{required}}',
            '```',
          ] : [
            'This request requires Taskcluster credentials that satisfy the following scope expression:',
            '',
            '```',
            '{{required}}',
            '```',
          ]).join('\n');
          throw new ErrorReply({
            code: 'InsufficientScopes',
            message,
            details: {
              required: scopeExpression,
              unsatisfied: gotCreds ? scopes.removeGivenScopes(result.scopes, scopeExpression) : undefined,
            },
          });
        }
        req.satisfyingScopes = satisfyingScopes;
      };

      req.authenticated = false;
      req.public = false;

      // If authentication is deferred or satisfied, then we proceed,
      // substituting the request parameters by default
      if (!entry.scopes) {
        req.public = true; // No need to check auth if there are no scopes
      } else if (useUrlParams) {
        // If url parameters is enough to parameterize we do it automatically
        await req.authorize(req.params);
      }
      next();
    } catch (err) {
      return next(err);
    }
  };
};
