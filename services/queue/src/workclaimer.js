import assert from 'assert';
import _ from 'lodash';
import events from 'events';
import taskCreds from './task-creds.js';
import { Task } from './data.js';
import HintPoller from './hintpoller.js';

/** WorkClaimer manages to claim work from internal queues. */
class WorkClaimer extends events.EventEmitter {
  /**
   * Create a new WorkClaimer.
   *
   * options:
   * {
   *   publisher:     // Pulse publisher from exchanges.js
   *   db:            // Database object
   *   queueService:  // queueService from queueservice.js
   *   monitor:       // monitor object from @taskcluster/lib-monitor
   *   claimTimeout:  // Time for a claim to timeout in seconds
   *   credentials:   // Taskcluster credentials for creating temp creds.
   * }
   */
  constructor(options) {
    assert(options);
    assert(options.publisher);
    assert(options.db);
    assert(options.queueService);
    assert(options.monitor);
    assert(typeof options.claimTimeout === 'number');
    assert(options.credentials);
    super();
    this._monitor = options.monitor;
    this._publisher = options.publisher;
    this.db = options.db;
    this._queueService = options.queueService;
    this._claimTimeout = options.claimTimeout;
    this._credentials = options.credentials;
    this._hintPollers = {}; // provisionerId/workerType -> HintPoller
  }

  getHintPoller(taskQueueId) {
    if (!this._hintPollers[taskQueueId]) {
      this._hintPollers[taskQueueId] = new HintPoller(taskQueueId, {
        monitor: this._monitor,
        pollPendingQueue: async (count) => this._queueService.pollPendingQueue(taskQueueId)(count),
        onError: err => this.emit('error', err),
        onDestroy: () => delete this._hintPollers[taskQueueId],
      });
    }
    return this._hintPollers[taskQueueId];
  }

  async claim(taskQueueId, workerGroup, workerId, count, aborted) {
    let claims = [];
    let done = false;
    let hintPoller;

    aborted.then(() => done = true);
    // As soon as we have claims we return so work can get started.
    // We don't try to claim up to the count, that could take time and we risk
    // dropping the claims in case of server crash.
    while (claims.length === 0 && !done) {
      hintPoller = this.getHintPoller(taskQueueId);

      // Poll for hints (messages saying a task may be pending)
      let hints = await hintPoller.requestClaim(count, aborted);
      // Try to claim all the hints
      claims = await Promise.all(hints.map(async (hint) => {
        try {
          // Try to claim task from hint
          let result = await this._monitor.timer('claimTask', this.claimTask(
            hint.taskId, hint.runId, workerGroup, workerId, null, hint.hintId,
          ));
          // Remove hint, if successfully used (don't block)
          hint.remove().catch(err => {
            this._monitor.reportError(err, 'warning', {
              comment: 'hint.remove() -- error ignored',
            });
          });
          // Return result
          return result;
        } catch (err) {
          // Report error, don't block
          this._monitor.reportError(err, {
            comment: 'claimTask from hint failed',
          });
          // Release hint (so it becomes visible again)
          hint.release().catch(err => {
            this._monitor.reportError(err, 'warning', {
              comment: 'hint.release() -- error ignored',
            });
          });
        }
        return 'error-claiming';
      }));

      // Remove entries from claims resolved as string (which indicates error)
      claims = claims.filter(claim => typeof claim !== 'string');
    }
    return claims;
  }

  /**
   * Claim a taskId/runId, returns 'conflict' if already claimed, and
   * 'task-not-found' or 'task-not-found' if not found.
   * If claim works out this returns a claim structure.
   */
  async claimTask(taskId, runId, workerGroup, workerId, task = null, hintId = null) {
    // Load task, if not given
    if (!task) {
      task = await Task.get(this.db, taskId);
      if (!task) {
        return 'task-not-found';
      }
    }

    // Set takenUntil to now + claimTimeout, rounding up to the nearest second
    // since we compare these times for equality after sending them to queue
    // and toJSON()
    let takenUntil = new Date();
    takenUntil.setSeconds(Math.ceil(takenUntil.getSeconds() + this._claimTimeout));

    // put the claim-expiration message into the queue first.  If the
    // subsequent claim_task fails, the claim-expiration message will be
    // ignored when it appears.
    await this._queueService.putClaimMessage(taskId, runId, takenUntil, task.taskQueueId, workerGroup, workerId);
    task.updateStatusWith(
      await this.db.fns.claim_task(taskId, runId, workerGroup, workerId, hintId, takenUntil));

    // Find run that we (may) have modified
    let run = task.runs[runId];
    if (!run) {
      return 'run-not-found';
    }

    // If the run wasn't claimed by this workerGroup/workerId, then we return
    // 'conflict' as it must have claimed by someone else
    if (task.runs.length - 1 !== runId ||
        run.state !== 'running' ||
        run.workerGroup !== workerGroup ||
        run.workerId !== workerId ||
        run.hintId !== hintId) {
      return 'conflict';
    }

    // Construct status object
    let status = task.status();

    // Publish task running message, it's important that we publish even if this
    // is a retry request and we didn't make any changes in task.modify
    await this._publisher.taskRunning({
      status: status,
      runId: runId,
      workerGroup: workerGroup,
      workerId: workerId,
      takenUntil: run.takenUntil,
      task: { tags: task.tags || {} },
    }, task.routes);
    this._monitor.log.taskRunning({ taskId, runId });

    let credentials = taskCreds(
      taskId,
      runId,
      workerGroup,
      workerId,
      takenUntil,
      task.scopes,
      this._credentials,
    );

    // Return claim structure
    return {
      status: status,
      runId: runId,
      workerGroup: workerGroup,
      workerId: workerId,
      takenUntil: run.takenUntil,
      task: await task.definition(),
      credentials: credentials,
    };
  }
}

// Export WorkClaimer
export default WorkClaimer;
