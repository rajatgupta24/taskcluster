require('../../prelude');
const aws = require('aws-sdk');
const { Client, pulseCredentials } = require('taskcluster-lib-pulse');
const { App } = require('taskcluster-lib-app');
const loader = require('taskcluster-lib-loader');
const config = require('taskcluster-lib-config');
const SchemaSet = require('taskcluster-lib-validate');
const libReferences = require('taskcluster-lib-references');
const taskcluster = require('taskcluster-client');
const _ = require('lodash');
const { MonitorManager } = require('taskcluster-lib-monitor');
const builder = require('./api');
const Notifier = require('./notifier');
const RateLimit = require('./ratelimit');
const Denier = require('./denier');
const Handler = require('./handler');
const exchanges = require('./exchanges');
const matrix = require('matrix-js-sdk');
const MatrixBot = require('./matrix');
const slack = require('@slack/web-api');
const SlackBot = require('./slack');
const tcdb = require('taskcluster-db');

require('./monitor');

// Create component loader
const load = loader({
  cfg: {
    requires: ['profile'],
    setup: ({ profile }) => config({
      profile,
      serviceName: 'notify',
    }),
  },

  monitor: {
    requires: ['process', 'profile', 'cfg'],
    setup: ({ process, profile, cfg }) => MonitorManager.setup({
      serviceName: 'notify',
      processName: process,
      verify: profile !== 'production',
      ...cfg.monitoring,
    }),
  },

  schemaset: {
    requires: ['cfg'],
    setup: ({ cfg }) => new SchemaSet({
      serviceName: 'notify',
    }),
  },

  reference: {
    requires: ['cfg'],
    setup: ({ cfg }) => exchanges.reference({
      rootUrl: cfg.taskcluster.rootUrl,
      credentials: cfg.pulse,
    }),
  },

  db: {
    requires: ['process', 'cfg', 'monitor'],
    setup: ({ process, cfg, monitor }) => tcdb.setup({
      serviceName: 'notify',
      readDbUrl: cfg.postgres.readDbUrl,
      writeDbUrl: cfg.postgres.writeDbUrl,
      statementTimeout: process === 'server' ? 30000 : 0,
      monitor: monitor.childMonitor('db'),
    }),
  },

  generateReferences: {
    requires: ['cfg', 'schemaset'],
    setup: ({ cfg, schemaset }) => libReferences.fromService({
      schemaset,
      references: [builder.reference(), exchanges.reference(), MonitorManager.reference('notify')],
    }).generateReferences(),
  },

  pulseClient: {
    requires: ['cfg', 'monitor'],
    setup: ({ cfg, monitor }) => {
      return new Client({
        namespace: 'taskcluster-notify',
        monitor: monitor.childMonitor('pulse-client'),
        credentials: pulseCredentials(cfg.pulse),
      });
    },
  },

  publisher: {
    requires: ['cfg', 'pulseClient', 'schemaset'],
    setup: async ({ cfg, pulseClient, schemaset }) => await exchanges.publisher({
      rootUrl: cfg.taskcluster.rootUrl,
      client: pulseClient,
      schemaset,
    }),
  },

  queue: {
    requires: ['cfg'],
    setup: ({ cfg }) => new taskcluster.Queue({
      rootUrl: cfg.taskcluster.rootUrl,
      credentials: cfg.taskcluster.credentials,
    }),
  },

  queueEvents: {
    requires: ['cfg'],
    setup: ({ cfg }) => new taskcluster.QueueEvents({
      rootUrl: cfg.taskcluster.rootUrl,
    }),
  },

  rateLimit: {
    requires: ['cfg'],
    setup: ({ cfg }) => new RateLimit({
      count: cfg.app.maxMessageCount,
      time: cfg.app.maxMessageTime,
    }),
  },

  ses: {
    requires: ['cfg'],
    setup: ({ cfg }) => new aws.SES(cfg.aws),
  },

  denier: {
    requires: ['cfg', 'db'],
    setup: ({ cfg, db }) =>
      new Denier({ emailBlacklist: cfg.app.emailBlacklist, db: db }),
  },

  matrixClient: {
    requires: ['cfg'],
    setup: ({ cfg }) => matrix.createClient({
      ...cfg.matrix,
      localTimeoutMs: 60 * 1000, // We will timeout http requests after 60 seconds. By default this has no timeout.
    }),
  },

  matrix: {
    requires: ['cfg', 'matrixClient', 'monitor'],
    setup: async ({ cfg, matrixClient, monitor }) => {
      let client = new MatrixBot({
        ...cfg.matrix,
        matrixClient,
        monitor: monitor.childMonitor('matrix'),
      });
      if (cfg.matrix.baseUrl) {
        await client.start();
      }
      return client;
    },
  },

  slackClient: {
    requires: ['cfg'],
    setup: ({ cfg }) => cfg.slack.accessToken ?
      new slack.WebClient(cfg.slack.accessToken, {
        slackApiUrl: cfg.slack.apiUrl,
      }) : null,
  },

  slack: {
    requires: ['slackClient', 'monitor'],
    setup({ slackClient, monitor }) {
      if (!slackClient) {
        return null;
      }

      let bot = new SlackBot({
        slackClient,
        monitor: monitor.childMonitor('slack'),
      });
      return bot;
    },
  },

  notifier: {
    requires: ['cfg', 'publisher', 'rateLimit', 'ses', 'denier', 'monitor', 'matrix', 'slack'],
    setup: ({ cfg, publisher, rateLimit, ses, denier, monitor, matrix, slack }) => new Notifier({
      denier,
      publisher,
      rateLimit,
      ses,
      matrix,
      slack,
      sourceEmail: cfg.app.sourceEmail,
      monitor: monitor.childMonitor('notifier'),
    }),
  },

  handler: {
    requires: ['profile', 'cfg', 'monitor', 'notifier', 'pulseClient', 'queue', 'queueEvents'],
    setup: async ({ cfg, monitor, notifier, pulseClient, queue, queueEvents }) => {
      let handler = new Handler({
        rootUrl: cfg.taskcluster.rootUrl,
        notifier,
        monitor: monitor.childMonitor('handler'),
        routePrefix: cfg.app.routePrefix,
        ignoreTaskReasonResolved: cfg.app.ignoreTaskReasonResolved,
        queue,
        queueEvents,
        pulseClient,
      });
      await handler.listen();
      return handler;
    },
  },

  api: {
    requires: ['cfg', 'monitor', 'schemaset', 'notifier', 'denier', 'db'],
    setup: ({ cfg, monitor, schemaset, notifier, denier, db }) => builder.build({
      rootUrl: cfg.taskcluster.rootUrl,
      context: { notifier, denier, db },
      monitor: monitor.childMonitor('api'),
      schemaset,
    }),
  },

  server: {
    requires: ['cfg', 'api'],
    setup: ({ cfg, api }) => App({
      ...cfg.server,
      apis: [api],
    }),
  },

}, {
  profile: process.env.NODE_ENV,
  process: process.argv[2],
});

// If this file is executed launch component from first argument
if (!module.parent) {
  load.crashOnError(process.argv[2]);
}

module.exports = load;
