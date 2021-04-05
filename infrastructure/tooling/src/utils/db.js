const path = require('path');
const assert = require('assert');
const { readRepoFile, writeRepoFile, modifyRepoFile } = require('./repo');

/**
 * Get an array giving the DB version for each Taskcluster version
 */
exports.getDbReleases = async () => {
  const releases = [];

  for (let line of (await readRepoFile(path.join('db', 'releases.txt'))).split('\n')) {
    line = line.trim();
    if (line.length === 0 || line[0] === '#') {
      continue;
    }
    const [tcVersion, dbVersion] = line.split(':').map(s => s.trim());
    releases.push([tcVersion, parseInt(dbVersion, 10)]);
  }

  return releases;
};

/**
 * Given the releases.txt file contents and a db version, get the TC version
 * in which that DB version was introduced, or undefined if it's pending release
 */
const tcversion = (releases, dbversion) => {
  for (let [tc, db] of releases) {
    if (db >= dbversion) {
      return tc;
    }
  }
};

/**
 * Update db/versions/README.md.  This occurs in both `yarn generate` and `yarn release`,
 * so it is included as a utility function here.
 */
exports.updateVersionsReadme = async (schema, releases) => {
  // get the *first* TC version containing this DB version

  const table = [];
  table.push('| DB Version | TC Version | Description |');
  table.push('| --- | --- | --- |');

  for (let version of schema.versions) {
    const zpad = version.version.toString().padStart(4, '0');
    table.push(`| [${zpad}](./${zpad}.yml) | ${tcversion(releases, version.version) || '(pending release)' } | ${version.description || ''} |`);
  }

  const versionsReadme = path.join('db', 'versions', 'README.md');
  await modifyRepoFile(versionsReadme,
    content => content.replace(
      /(<!-- AUTOGENERATED DO NOT EDIT -->)(?:.|\n)*(<!-- AUTOGENERATED DO NOT EDIT - END -->)/m,
      `$1\n${table.join('\n')}\n$2`));

  return versionsReadme;
};

/**
 * Calculate how long a deprecated DB function must be supported, given the
 * version in which the deprecation occurred, returning a message about
 * compatibility or false if the function is no longer supported.  See
 * taskcluster/taskcluster#3328 for background on this scheme.
 *
 * The intent is that once a change lands, the compatibility guarantee should
 * not change, regardless of whether the next release is major or minor.
 */
const deprecatedFunctionSupport = (currentMajor, tcversion) => {
  if (tcversion) {
    /* calculate when a change that landed in tcversion can be broken
     * v50.1.2 -> 52 -- v50.1.1 used the deprecated function
     * v51.0.0 -> 52 -- no v51.x.y used the deprecated function
     * v51.0.1 -> 53 -- v51.0.0 used the deprecated function */
    let until;
    const [_, major, minorPatch] = tcversion.match(/v(\d+)\.(\d+\.\d+)/);
    if (minorPatch === '0.0') {
      until = parseInt(major, 10) + 1;
    } else {
      until = parseInt(major, 10) + 2;
    }

    // reflect that into a message
    if (until > currentMajor) {
      return `compatibility guaranteed until v${until}.0.0`;
    } else {
      return false;
    }
  } else {
    // an unreleased change will live at last two major versions from the
    // last release, regardless of whether the next release is major or minor.
    return `compatibility guaranteed until v${currentMajor + 2}.0.0`;
  }
};

// a poor excuse for a test suite, that illustrates the intent
assert.equal(deprecatedFunctionSupport(50, undefined), 'compatibility guaranteed until v52.0.0');
assert.equal(deprecatedFunctionSupport(50, 'v50.1.2'), 'compatibility guaranteed until v52.0.0');
assert.equal(deprecatedFunctionSupport(51, 'v51.0.0'), 'compatibility guaranteed until v52.0.0');
assert.equal(deprecatedFunctionSupport(51, 'v51.0.1'), 'compatibility guaranteed until v53.0.0');
assert.equal(deprecatedFunctionSupport(52, 'v51.0.1'), 'compatibility guaranteed until v53.0.0');
assert.equal(deprecatedFunctionSupport(53, 'v51.0.1'), false);
assert.equal(deprecatedFunctionSupport(54, 'v51.0.1'), false);

/**
 * Update db/fns.md.  This also occurs in both `yarn generate` and `yarn release`
 */
exports.updateDbFns = async (schema, releases, currentTcVersion) => {
  const methods = schema.allMethods();
  methods.sort((a, b) => a.name.localeCompare(b.name));
  const serviceNames = [...new Set([...methods].map(({ serviceName }) => serviceName).sort())];
  const services = new Map();

  serviceNames.forEach(sn => {
    const serviceMethods = [...methods].reduce((acc, method) => {
      if (method.serviceName !== sn) {
        return acc;
      }

      return acc.concat(method);
    }, []);

    services.set(sn, serviceMethods.sort((a, b) => a.name.localeCompare(b.name)));
  });

  let output = [];
  output.push('# Stored Functions');
  output.push('<!-- AUTOGENERATED CONTENT; DO NOT EDIT -->\n');

  for (let [serviceName, methods] of services.entries()) {
    output.push(` * [${serviceName} functions](#${serviceName})`);
    for (let { name } of methods.filter(method => !method.deprecated)) {
      output.push(`   * [\`${name}\`](#${name})`);
    }
  }

  output.push('');

  for (let [serviceName, methods] of services.entries()) {
    output.push(`## ${serviceName}\n`);

    for (let { name } of methods.filter(method => !method.deprecated)) {
      output.push(`* [\`${name}\`](#${name})`);
    }

    output.push('');

    for (let method of methods.filter(method => !method.deprecated)) {
      output.push(`### ${method.name}\n`);
      output.push(`* *Mode*: ${method.mode}`);
      output.push(`* *Arguments*:`);

      const args = method.args.replace(/\n/g, ' ').trim();
      if (args.length > 0) {
        for (let arg of args.split(', ')) {
          output.push(`  * \`${arg}\``);
        }
      }

      const returns = method.returns.replace(/\n/g, ' ').trim();
      const tableReturns = /table *\((.*)\)/.exec(returns);
      if (tableReturns) {
        output.push(`* *Returns*: \`table\``);
        for (let r of tableReturns[1].split(', ')) {
          output.push(`  * \`${r}\``);
        }
      } else {
        output.push(`* *Returns*: \`${returns}\``);
      }

      output.push(`* *Last defined on version*: ${method.version}`);

      output.push('');
      output.push(method.description);
      output.push('');
    }

    const depMethods = methods.filter(method => method.deprecated);
    const depOutput = [];
    let [_, currentMajor] = currentTcVersion.match(/^(\d+)\./);
    currentMajor = parseInt(currentMajor, 10);

    for (let method of depMethods) {
      let version;

      // we need to figure out the DB version where this method was first deprecated..
      for (version of schema.versions) {
        if (version.methods[method.name] && version.methods[method.name].deprecated) {
          break;
        }
      }

      // and from that, what TC version that was..
      const tcv = tcversion(releases, version.version);

      // and then calculate the support range
      const compat = deprecatedFunctionSupport(currentMajor, tcv);

      if (compat) {
        depOutput.push(`* \`${method.name}(${method.args.replace(/\n/g, ' ')})\`${compat ? ` (${compat})` : ''}`);
      }
    }

    if (depOutput.length) {
      output.push('### deprecated methods\n');
      output = output.concat(depOutput);
      output.push('');
    }
  }

  const dbFnsFile = path.join('db', 'fns.md');
  await writeRepoFile(dbFnsFile, output.join('\n'));

  return dbFnsFile;
};
