import _ from 'lodash';
import stringify from 'fast-json-stable-stringify';
import crypto from 'crypto';
import taskcluster from '@taskcluster/client';
import yaml from 'js-yaml';
import assert from 'assert';
import { consume } from '@taskcluster/lib-pulse';
import { deprecatedStatusHandler } from './deprecatedStatus.js';
import { taskGroupCreationHandler } from './taskGroupCreation.js';
import { statusHandler } from './status.js';
import { jobHandler } from './job.js';
import { rerunHandler } from './rerun.js';
import { POLICIES } from './policies.js';
import { GITHUB_BUILD_STATES } from '../constants.js';

/**
 * Create handlers
 */
class Handlers {
  constructor(options) {
    const {
      rootUrl,
      credentials,
      monitor,
      reference,
      jobQueueName,
      deprecatedResultStatusQueueName,
      deprecatedInitialStatusQueueName,
      resultStatusQueueName,
      rerunQueueName,
      intree,
      context,
      pulseClient,
      queueClient,
    } = options;

    assert(monitor, 'monitor is required for statistics');
    assert(reference, 'reference must be provided');
    assert(rootUrl, 'rootUrl must be provided');
    assert(intree, 'intree configuration builder must be provided');
    this.rootUrl = rootUrl;
    this.credentials = credentials;
    this.monitor = monitor;
    this.reference = reference;
    this.intree = intree;
    this.connection = null;
    this.deprecatedResultStatusQueueName = deprecatedResultStatusQueueName;
    this.resultStatusQueueName = resultStatusQueueName;
    this.jobQueueName = jobQueueName;
    this.rerunQueueName = rerunQueueName;
    this.deprecatedInitialStatusQueueName = deprecatedInitialStatusQueueName;
    this.context = context;
    this.pulseClient = pulseClient;

    this.handlerComplete = null;
    this.handlerRejected = null;

    this.commentHashCache = [];

    this.jobPq = null;
    this.resultStatusPq = null;
    this.deprecatedResultStatusPq = null;
    this.deprecatedInitialStatusPq = null;
    this.rerunPq = null;

    this.queueClient = queueClient;

    this.handlersCount = {};

    this.exchangeNames = {};
  }

  /**
   * Set up the handlers.
   */
  async setup(options = {}) {
    assert(!this.jobPq, 'Cannot setup twice!');
    assert(!this.resultStatusPq, 'Cannot setup twice!');
    assert(!this.deprecatedResultStatusPq, 'Cannot setup twice!');
    assert(!this.deprecatedInitialStatusPq, 'Cannot setup twice!');
    assert(!this.rerunPq, 'Cannot setup twice!');

    // Listen for new jobs created via the api webhook endpoint
    const GithubEvents = taskcluster.createClient(this.reference);
    const githubEvents = new GithubEvents({ rootUrl: this.rootUrl });

    const jobBindings = [
      githubEvents.pullRequest(),
      githubEvents.push(),
      githubEvents.release(),
    ];

    const rerunBindings = [
      githubEvents.rerun(),
    ];

    const schedulerId = this.context.cfg.taskcluster.schedulerId;
    const queueEvents = new taskcluster.QueueEvents({ rootUrl: this.rootUrl });

    this.exchangeNames = {
      taskDefined: queueEvents.taskDefined().exchange,
      taskFailed: queueEvents.taskFailed().exchange,
      taskException: queueEvents.taskException().exchange,
      taskCompleted: queueEvents.taskCompleted().exchange,
      taskPending: queueEvents.taskPending().exchange,
      taskRunning: queueEvents.taskRunning().exchange,
      taskGroupResolved: queueEvents.taskGroupResolved().exchange,
    };

    // Listen for state changes of tasks and update check runs on github
    const taskStatusBindings = [
      queueEvents.taskDefined(`route.${this.context.cfg.app.checkTaskRoute}`),
      queueEvents.taskFailed(`route.${this.context.cfg.app.checkTaskRoute}`),
      queueEvents.taskException(`route.${this.context.cfg.app.checkTaskRoute}`),
      queueEvents.taskCompleted(`route.${this.context.cfg.app.checkTaskRoute}`),
      queueEvents.taskRunning(`route.${this.context.cfg.app.checkTaskRoute}`),
    ];

    // Listen for state changes to the taskcluster tasks and taskgroups
    // We only need to listen for failure and exception events on
    // tasks. We wait for the entire group to be resolved before checking
    // for success.
    const deprecatedResultStatusBindings = [
      queueEvents.taskPending(`route.${this.context.cfg.app.statusTaskRoute}`),
      queueEvents.taskRunning(`route.${this.context.cfg.app.statusTaskRoute}`),
      queueEvents.taskFailed(`route.${this.context.cfg.app.statusTaskRoute}`),
      queueEvents.taskException(`route.${this.context.cfg.app.statusTaskRoute}`),
      queueEvents.taskGroupResolved({ schedulerId }),
    ];

    // Listen for taskGroupCreationRequested event to create initial status on github
    const deprecatedInitialStatusBindings = [
      githubEvents.taskGroupCreationRequested(`route.${this.context.cfg.app.statusTaskRoute}`),
    ];

    // This handler is called by PulseConsumer in sync manner
    // If this would have wait for handler to finish,
    // it will block new messages from being processed on time
    // Consumer by default uses "prefetch: 5", which means only 5 messages would be delivered to client at a time,
    // before client ACK them.
    // To avoid queue grow over time we consume all messages and let nodejs runtime handle concurrent routines.
    const callHandler = (name, handler) => {
      const timedHandler = this.monitor.timedHandler(`${name}listener`, handler.bind(this));

      return (message) => {
        this._handlerStarted(name);
        timedHandler.call(this, message).catch(async err => {
          await this.monitor.reportError(err);
          return err;
        }).then((err = null) => {
          this._handlerFinished(name, !!err);
          if (this.handlerComplete && !err) {
            this.handlerComplete();
          } else if (this.handlerRejected && err) {
            this.handlerRejected(err);
          }
        });
      };
    };

    this.jobPq = await consume(
      {
        client: this.pulseClient,
        bindings: jobBindings,
        queueName: this.jobQueueName,
      },
      callHandler('job', jobHandler),
    );

    this.deprecatedResultStatusPq = await consume(
      {
        client: this.pulseClient,
        bindings: deprecatedResultStatusBindings,
        queueName: this.deprecatedResultStatusQueueName,
      },
      callHandler('status', deprecatedStatusHandler),
    );

    this.deprecatedInitialStatusPq = await consume(
      {
        client: this.pulseClient,
        bindings: deprecatedInitialStatusBindings,
        queueName: this.deprecatedInitialStatusQueueName,
      },
      callHandler('task', taskGroupCreationHandler),
    );

    this.resultStatusPq = await consume(
      {
        client: this.pulseClient,
        bindings: taskStatusBindings,
        queueName: this.resultStatusQueueName,
      },
      callHandler('status', statusHandler),
    );

    this.rerunPq = await consume(
      {
        client: this.pulseClient,
        bindings: rerunBindings,
        queueName: this.rerunQueueName,
      },
      callHandler('rerun', rerunHandler),
    );

    this.reportHandlersCount = setInterval(() => this._reportHandlersCount(), 60 * 1000);
  }

  async terminate() {
    if (this.jobPq) {
      await this.jobPq.stop();
    }
    if (this.resultStatusPq) {
      await this.resultStatusPq.stop();
    }
    if (this.deprecatedResultStatusPq) {
      await this.deprecatedResultStatusPq.stop();
    }
    if (this.deprecatedInitialStatusPq) {
      await this.deprecatedInitialStatusPq.stop();
    }
    if (this.rerunPq) {
      await this.rerunPq.stop();
    }
    if (this.reportHandlersCount) {
      clearInterval(this.reportHandlersCount);
    }
  }

  // Create a collection of tasks, centralized here to enable testing without creating tasks.
  async createTasks({ scopes, tasks }) {
    const limitedQueueClient = this.queueClient.use({
      authorizedScopes: scopes,
    });
    for (const t of tasks) {
      try {
        await limitedQueueClient.createTask(t.taskId, t.task);
      } catch (err) {
        // translate InsufficientScopes errors nicely for our users, since they are common and
        // since we can provide additional context not available from the queue.
        if (err.code === 'InsufficientScopes') {
          err.message = [
            'Taskcluster-GitHub attempted to create a task for this event with the following scopes:',
            '',
            '```',
            stringify(scopes, null, 2),
            '```',
            '',
            'The expansion of these scopes is not sufficient to create the task, leading to the following:',
            '',
            err.message,
          ].join('\n');
        }
        throw err;
      }
    }
  }

  /**
   * Cancel any running builds that are not the current build for a given pull request.
   * This will not cancel builds for the same SHA because they can belong to different branches.
   * If this is a pull request event, we only want to cancel builds of the same type:
   *  [pull_request.opened, pull_request.synchronize] are treated as the same type
   *  pull_request.[labeled, edited, closed, review_requested, assigned] are different events
   */
  async cancelPreviousTaskGroups({ instGithub, debug, newBuild }) {
    const { organization, repository, sha, pull_number: pullNumber,
      task_group_id: newTaskGroupId, event_type: eventType } = newBuild;
    debug(`canceling previous task groups for ${organization}/${repository} eventType=${eventType} newTaskGroupId=${newTaskGroupId} sha=${sha} PR=${pullNumber} if they exist`);

    // avoid performing cancellation for non-push and non-pull-request events
    if (!eventType || !['pull_request'].includes(eventType.split('.')[0])) {
      debug(`event type ${eventType} is not supported. skipping cancelPreviousTaskGroups`);
      return;
    }

    if (!pullNumber) {
      debug(`pullNumber is not defined. Skipping cancelPreviousTaskGroups`);
      return;
    }

    const scopes = [
      `assume:repo:github.com/${organization}/${repository}:*`,
      'queue:seal-task-group:taskcluster-github/*',
      'queue:cancel-task-group:taskcluster-github/*',
    ];

    try {
      let includedEventTypes = [eventType];
      if (['pull_request.opened', 'pull_request.synchronize'].includes(eventType)) {
        includedEventTypes = ['pull_request.opened', 'pull_request.synchronize'];
      }

      const builds = await this.context.db.fns.get_pending_github_builds(
        null,
        null,
        organization,
        repository,
        null, // no cancelling by sha here
        pullNumber,
      );
      const taskGroupIds = builds?.filter(
        build => build.task_group_id !== newTaskGroupId && includedEventTypes.includes(build.event_type),
      ).map(build => build.task_group_id);

      if (taskGroupIds.length > 0) {
        // we want to make sure that github client respects repository scopes when sealing and cancelling tasks
        const limitedQueueClient = this.queueClient.use({ authorizedScopes: scopes });

        debug(`Found running task groups: ${taskGroupIds.join(', ')}. Sealing and cancelling`);
        try {
          await Promise.all(taskGroupIds.map(taskGroupId => limitedQueueClient.sealTaskGroup(taskGroupId)));
          await Promise.all(taskGroupIds.map(taskGroupId => limitedQueueClient.cancelTaskGroup(taskGroupId)));
        } catch (queueErr) {
          if (queueErr.code !== 'ResourceNotFound' || queueErr.statusCode !== 404) {
            throw queueErr;
          }
          // we can ignore task groups that were not yet created on queue side, and simply mark as cancelled in the db
          this.monitor.reportError(`Task group not found in queue: ${queueErr.message} while canceling`);
        }

        await Promise.all(taskGroupIds.map(taskGroupId => this.context.db.fns.set_github_build_state(
          taskGroupId, GITHUB_BUILD_STATES.CANCELLED,
        )));
      }
    } catch (err) {
      debug(`Error while canceling previous task groups: ${err.message}\nscopes used: ${scopes.join(', ')}`);
      err.message = [
        'Taskcluster-GitHub attempted to cancel previously created task groups with following scopes:',
        '',
        '```',
        scopes.join(', '),
        '```',
        '',
        err.message,
      ].join('\n');

      await this.monitor.reportError(err);
      await this.createExceptionComment({
        debug,
        instGithub,
        organization,
        repository,
        sha,
        pullNumber,
        error: err,
      });
    }
  }

  commentKey(idents) {
    return crypto
      .createHash('md5')
      .update(stringify(idents))
      .digest('hex');
  }

  isDuplicateComment(...idents) {
    return _.indexOf(this.commentHashCache, this.commentKey(idents)) !== -1;
  }

  markCommentSent(...idents) {
    this.commentHashCache.unshift(this.commentKey(idents));
    this.commentHashCache = _.take(this.commentHashCache, 1000);
  }

  // Send an exception to Github in the form of a comment.
  async createExceptionComment({ debug, instGithub, organization, repository, sha, error, pullNumber }) {
    if (this.isDuplicateComment(organization, repository, sha, error, pullNumber)) {
      debug(`exception comment on ${organization}/${repository}#${pullNumber} found to be duplicate. skipping`);
      return;
    }
    let errorBody = error.body && error.body.error || error.message;
    // Let's prettify any objects
    if (typeof errorBody === 'object') {
      errorBody = stringify(errorBody, null, 4);
    }

    // Warn the user know that there was a problem handling their request
    // by posting a comment; this error is then considered handled and not
    // reported to the taskcluster team or retried
    await this.createComment({ debug, instGithub, organization, repository, sha, pullNumber,
      body: {
        summary: 'Uh oh! Looks like an error!',
        details: errorBody,
      },
    });
  }

  async createComment({ debug, instGithub, organization, repository, sha, pullNumber, body }) {
    if (this.isDuplicateComment(organization, repository, sha, body, pullNumber)) {
      debug(`comment on ${organization}/${repository}#${pullNumber} found to be duplicate. skipping`);
      return;
    }

    let commentBody = body;
    if (commentBody.summary && commentBody.details) {
      commentBody = [
        '<details>\n',
        `<summary>${commentBody.summary}</summary>`,
        '',
        commentBody.details, // already in Markdown..
        '',
        '</details>',
      ].join('\n');
    }

    if (pullNumber) {
      debug(`creating comment on ${organization}/${repository}#${pullNumber}`);
      await instGithub.issues.createComment({
        owner: organization,
        repo: repository,
        issue_number: pullNumber,
        body: commentBody,
      });
      this.markCommentSent(organization, repository, sha, body, pullNumber);
      return;
    }
    debug(`creating comment on ${organization}/${repository}@${sha}`);
    await instGithub.repos.createCommitComment({
      owner: organization,
      repo: repository,
      commit_sha: sha,
      body: commentBody,
    });
    this.markCommentSent(organization, repository, sha, body, pullNumber);
  }

  async addCommentReaction({ instGithub, organization, repository, commentId, reaction }) {
    assert(['+1', '-1', 'laugh', 'confused', 'heart', 'hooray', 'rocket', 'eyes'].includes(reaction),
      `Invalid reaction: ${reaction}`);
    try {
      await instGithub.reactions.createForIssueComment({
        owner: organization,
        repo: repository,
        comment_id: commentId,
        content: reaction,
      });
    } catch (err) {
      if (err.status === 404) {
        return;
      }
      throw err;
    }
  }

  /**
   * Function that examines the yml and decides which policy we're using. Defining policy in the yml is not required
   * by the schema, so if it's not defined, the function returns default policy.
   *
   * @param taskclusterYml - parsed YML (JSON object, see docs on `.taskcluster.yml`)
   * @returns policy, a string (either "collaborator" or "public" - available values at the moment)
   */
  getRepoPolicy(taskclusterYml) {
    const DEFAULT_POLICY = POLICIES.COLLABORATORS;

    if (taskclusterYml.version === 0) {
      // consult its `allowPullRequests` field
      return taskclusterYml.allowPullRequests || DEFAULT_POLICY;
    } else if (taskclusterYml.version === 1) {
      if (taskclusterYml.policy) {
        return taskclusterYml.policy.pullRequests || DEFAULT_POLICY;
      }
    }

    return DEFAULT_POLICY;
  }

  /**
   * Checks if the repository allows comments to trigger builds on Pull Requests.
   * Only v1 of `.taskcluster.yml` supports this feature.
   * `policy.allowComments` needs to be set to `"collaborators"` to enable this feature.
   * (Currently the only option allowed)
   *
   * @param {object} taskclusterYml
   * @returns string | null
   */
  getRepoAllowCommentsPolicy(taskclusterYml) {
    if (taskclusterYml.version === 1) {
      return taskclusterYml?.policy?.allowComments || null;
    }

    return null;
  }

  /**
   * Try to get `.taskcluster.yml` from a certain ref.
   *
   * @param instGithub - authenticated installation object
   * @param owner - org or a user, a string
   * @param repo - repository, a string
   * @param ref - SHA or branch/tag name, a string
   *
   * @returns either parsed YML if there's a YML and it was parsed successfully,
   * or null if there's no YML,
   * or throws an error in other cases
   */
  async getYml({ instGithub, owner, repo, ref }) {
    let response;
    try {
      response = await instGithub.repos.getContent({ owner, repo, path: '.taskcluster.yml', ref });
    } catch (e) {
      if (e.status === 404) {
        return null;
      }

      if (e.message.endsWith('</body>\n</html>\n') && e.message.length > 10000) {
        // We kept getting full html 500/400 pages from github in the logs.
        // I consider this to be a hard-to-fix bug in octokat, so let's make
        // the logs usable for now and try to fix this later. It's a relatively
        // rare occurence.
        e.message = e.message.slice(0, 100).concat('...');
        e.stack = e.stack.split('</body>\n</html>\n')[1] || e.stack;
      }

      e.owner = owner;
      e.repo = repo;
      e.ref = ref;
      throw e;
    }

    return yaml.load(Buffer.from(response.data.content, 'base64').toString());
  }

  _handlerStarted(name) {
    if (typeof this.handlersCount[name] === 'undefined') {
      this.handlersCount[name] = {
        total: 1,
        finished: 0,
        error: 0,
      };
    } else {
      this.handlersCount[name].total += 1;
    }
  }

  _handlerFinished(name, hasError = false) {
    this.handlersCount[name].finished += 1;
    if (hasError) {
      this.handlersCount[name].error += 1;
    }
  }

  _reportHandlersCount() {
    if (!this.monitor) {
      return;
    }

    for (const [handlerName, stats] of Object.entries(this.handlersCount)) {
      this.monitor.log.githubActiveHandlers({
        handlerName,
        totalCount: stats.total,
        runningCount: stats.total - stats.finished,
        errorCount: stats.error,
      });
    }
  }
}

export default Handlers;
