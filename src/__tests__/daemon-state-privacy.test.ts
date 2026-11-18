// What the daemon does with its OWN state directory when the ground under it is not its own (#4649): a
// state diagnostic is refused, the shutdown is not, and nothing is written through a name another local
// user picked.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { afterEach, test, vi } from 'vitest';
import {
  tryAcquireDaemonRegistration,
  type DaemonRegistrationOwner,
} from '@agent-device/daemon-contracts/daemon-registration-owner';
import {
  resolveDaemonPaths,
  type DaemonPaths,
} from '@agent-device/daemon-contracts/daemon-resolution';
import { readDaemonShutdownReport } from '@agent-device/daemon-contracts/daemon-shutdown-report';
import { FOREIGN_UID, mkdtempForTestSync, serveHostOwnership } from '@agent-device/test-kit';

const fields = {
  socketPort: 4210,
  token: 'token',
  version: '0.0.0-test',
  codeOrigin: 'checkout' as const,
  codeSignature: 'signature',
};
const report = {
  providerReleases: { released: [], pending: [] },
  claims: { released: [], orphaned: [], superseded: [], unattributable: [] },
};

afterEach(() => vi.restoreAllMocks());

async function acquire(): Promise<Acquired> {
  const paths = resolveDaemonPaths(mkdtempForTestSync('agent-device-state-privacy-'));
  const attempt = await tryAcquireDaemonRegistration(paths);
  assert.equal(attempt.status, 'acquired');
  if (attempt.status !== 'acquired') throw new Error('registration refused');
  return { paths, owner: attempt.owner };
}

type Acquired = Readonly<{ paths: DaemonPaths; owner: DaemonRegistrationOwner }>;

test.skipIf(process.platform === 'win32')(
  'a shutdown report replaces a symbolic link at its name, never writes through it',
  async () => {
    const { paths, owner } = await acquire();
    // Another local user who can write the state directory picks the report's name. A write that resolved
    // that name would put the daemon's shutdown record in THEIRS.
    const outside = path.join(paths.baseDir, 'theirs.json');
    fs.writeFileSync(outside, 'theirs\n', { mode: 0o600 });
    fs.symlinkSync(outside, path.join(paths.baseDir, 'daemon-shutdown.json'));
    owner.publish(fields);

    assert.deepEqual(await owner.finish(report), { state: 'removed' });

    assert.equal(fs.readFileSync(outside, 'utf8'), 'theirs\n');
    assert.equal(fs.lstatSync(path.join(paths.baseDir, 'daemon-shutdown.json')).isFile(), true);
    assert.deepEqual(readDaemonShutdownReport(paths.baseDir), report);
  },
);

test.skipIf(process.platform === 'win32')(
  'a state directory another local user owns costs the shutdown report, never the shutdown',
  async () => {
    const { paths, owner } = await acquire();
    owner.publish(fields);
    // The daemon writes this record without being asked. Ground somebody else controls gets the refusal,
    // and the shutdown still retires the registration: a diagnostic is never worth a stuck daemon.
    serveHostOwnership({ [paths.baseDir]: FOREIGN_UID });

    assert.deepEqual(await owner.finish(report), { state: 'removed' });

    assert.equal(fs.existsSync(path.join(paths.baseDir, 'daemon-shutdown.json')), false);
    assert.match(fs.readFileSync(paths.logPath, 'utf8'), /daemon_shutdown_record_failed/);
  },
);
