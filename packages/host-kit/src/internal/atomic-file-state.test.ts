// The daemon's OWN state directory: what it creates, what it repairs, and what it refuses to write into
// (#4649). A caller-named destination is judged by `atomic-file-ancestry.test.ts`; this suite is the other
// rule, the one that decides whether a directory the daemon picked for itself is private at all.
import { afterEach, expect, test, vi } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import {
  FOREIGN_UID,
  ancestryRoot as root,
  directoryWith,
  modeOf,
  serveOwnership,
  withSharedUmask,
} from './atomic-file-host.fixtures.ts';
import { ensurePrivateDirectoryChain, judgePrivateDirectoryChain } from './atomic-file.ts';

const skipOnWindows = process.platform === 'win32' ? test.skip : test;

afterEach(() => {
  vi.restoreAllMocks();
});

/** A state directory this test owns and trusts, at the mode the rule creates at. */
function stateDir(name = 'state'): string {
  return directoryWith(path.join(root(), name), 0o700);
}

skipOnWindows('creates a missing state chain at 0700 under the shared checkout umask', () => {
  // The umask a group-writable home directory carries. A mode-less `mkdir` here answers 0775, and the very
  // next startup would refuse that directory as writable by another local user — so a daemon on a shared
  // checkout would break its own state directory on every restart.
  const parent = directoryWith(path.join(root(), 'parent'), 0o700);
  const state = path.join(parent, 'state');

  withSharedUmask(() => {
    expect(ensurePrivateDirectoryChain(state, ['sessions']).exposure).toBeUndefined();
  });

  expect(modeOf(state)).toBe(0o700);
  expect(modeOf(path.join(state, 'sessions'))).toBe(0o700);
});

skipOnWindows('repairs a state level this user owns that stands loose', () => {
  // A state directory a host or an older build left group- or world-writable is narrowed rather than
  // refused: the daemon owns this ground, and refusing to start over its own leftover helps nobody.
  const state = directoryWith(path.join(root(), 'state'), 0o755);

  expect(ensurePrivateDirectoryChain(state).exposure).toBeUndefined();

  expect(modeOf(state)).toBe(0o700);
});

skipOnWindows('repairs every level below the state directory it owns', () => {
  const state = stateDir();
  const loose = directoryWith(path.join(state, 'sessions'), 0o775);

  expect(ensurePrivateDirectoryChain(state, ['sessions']).exposure).toBeUndefined();

  expect(modeOf(loose)).toBe(0o700);
});

skipOnWindows('never repairs a level another local user owns', () => {
  // `chmod` on somebody else's directory is not this rule's to do, so the level keeps its mode AND its
  // refusal: the daemon will not write where it cannot say who else could have written.
  const state = stateDir();
  const theirs = directoryWith(path.join(state, 'sessions'), 0o755);
  serveOwnership({ [theirs]: FOREIGN_UID });

  const chain = ensurePrivateDirectoryChain(state, ['sessions']);

  expect(chain.exposure).toBe('foreign_owned');
  expect(modeOf(theirs)).toBe(0o755);
});

skipOnWindows(
  'refuses a state directory another local user can add a name to, and does not touch it',
  () => {
    // The destination rule lets a STICKY shared directory pass, because passing THROUGH one is safe there.
    // Here the daemon creates names of its own choosing in it, so another local user can plant the marker's
    // name or the shutdown report's name first, and a sticky bit does not stop that: it only stops them
    // replacing an entry they do not own. A directory root owns is also never `chmod`ed by a non-root process.
    const state = directoryWith(path.join(root(), 'state'), 0o700);
    fs.chmodSync(state, 0o1777);
    serveOwnership({ [state]: 0 });

    const chain = ensurePrivateDirectoryChain(state);

    expect(chain.exposure).toBe('shared_writable');
    // The sticky bit is what the destination rule would accept; `modeOf` answers the permission bits, and
    // the flag bit is what the rule never treats as a pass.
    expect(modeOf(state)).toBe(0o777);
    expect(fs.statSync(state).mode & 0o1000).toBe(0o1000);
  },
);

skipOnWindows('refuses a level the group can add a name to', () => {
  // A group-writable state directory is the shared checkout's own failure mode: umask 002 is what a
  // group-writable home directory carries, and the group is other local users. Judged, not established:
  // `ensure` would repair this user's own 0770 to 0700 first, which is what its own case asserts.
  const state = directoryWith(path.join(root(), 'state'), 0o770);

  expect(judgePrivateDirectoryChain(state).exposure).toBe('shared_writable');
});

skipOnWindows('refuses a symbolic link planted at the base of a missing state directory', () => {
  // The daemon picks this path and creates it without being asked. If the name where it would land is a
  // link somebody else put there, a recursive `mkdir` builds the state directory where THAT link points —
  // so the whole tree the daemon then trusts sits in ground it never judged.
  const directory = root();
  const elsewhere = directoryWith(path.join(directory, 'elsewhere'), 0o700);
  const link = path.join(directory, 'state');
  fs.symlinkSync(elsewhere, link, 'dir');

  const chain = ensurePrivateDirectoryChain(link, ['sessions']);

  expect(chain.exposure).toBe('planted_link');
  expect(fs.readdirSync(elsewhere)).toEqual([]);
});

skipOnWindows('refuses a symbolic link planted at sessions/ and creates nothing beside it', () => {
  const state = stateDir();
  const elsewhere = directoryWith(path.join(root(), 'elsewhere'), 0o700);
  const link = path.join(state, 'sessions');
  fs.symlinkSync(elsewhere, link, 'dir');

  const chain = ensurePrivateDirectoryChain(state, ['sessions']);

  expect(chain.exposure).toBe('planted_link');
  expect(fs.readdirSync(elsewhere)).toEqual([]);
});

skipOnWindows('refuses a symbolic link planted at remote-scripts/', () => {
  // The daemon-picked recording directory: the destination no caller ever named, and the one the client
  // then downloads bytes from.
  const state = stateDir();
  const scripts = directoryWith(path.join(state, 'sessions'), 0o700);
  const elsewhere = directoryWith(path.join(root(), 'elsewhere'), 0o700);
  fs.symlinkSync(elsewhere, path.join(scripts, 'remote-scripts'), 'dir');

  const chain = ensurePrivateDirectoryChain(state, ['sessions', 'remote-scripts']);

  expect(chain.exposure).toBe('planted_link');
  expect(fs.readdirSync(elsewhere)).toEqual([]);
});

skipOnWindows('refuses a state path that steps back out of the tree through a link', () => {
  // The spelled chain says `state/sessions`; the kernel, following the link, puts `<sessions>/../escape`
  // OUTSIDE the state directory. A rule that judged the spelled chain and wrote the resolved one would
  // hand that outside directory a daemon-created 0700 tree, so the step back is what is refused.
  const state = stateDir();
  const elsewhere = directoryWith(path.join(root(), 'elsewhere'), 0o700);
  fs.symlinkSync(elsewhere, path.join(state, 'sessions'), 'dir');

  const chain = judgePrivateDirectoryChain(`${state}/sessions`, ['..', 'escape']);

  expect(chain.exposure).toBe('outside_state_dir');
  expect(fs.existsSync(path.join(elsewhere, 'escape'))).toBe(false);
});

skipOnWindows('answers the physical directory it judged, not the caller spelling', () => {
  // A doubled separator and a `.` are the kernel's own no-ops, so folding them is exactly what the kernel
  // does. The answer is what a writer spells its entry from, so it has to be the judged ground.
  const state = stateDir();
  const sessions = directoryWith(path.join(state, 'sessions'), 0o700);

  const chain = judgePrivateDirectoryChain(`${state}/sessions/.`);

  expect(chain.exposure).toBeUndefined();
  expect(chain.directory).toBe(sessions);
});

skipOnWindows('judging creates nothing, and reports a missing level', () => {
  const state = stateDir();

  const chain = judgePrivateDirectoryChain(state, ['sessions']);

  expect(chain.exposure).toBe('unreachable');
  expect(fs.existsSync(path.join(state, 'sessions'))).toBe(false);
});

skipOnWindows('refuses a state directory that is a regular file', () => {
  const directory = root();
  const file = path.join(directory, 'state');
  fs.writeFileSync(file, 'not a directory\n');

  expect(ensurePrivateDirectoryChain(file).exposure).toBe('not_a_directory');
});

skipOnWindows('a repair that cannot carry the mode is a skip, not a refusal', () => {
  // A read-only mount or an ACL-only filesystem cannot answer `chmod`. The daemon still has its own
  // directory and the mode it can still read is the mode the judgment reports, so the startup goes ahead
  // and the skip is what gets written down.
  const state = directoryWith(path.join(root(), 'state'), 0o755);
  const chmod = vi.spyOn(fs, 'chmodSync').mockImplementation(() => {
    throw Object.assign(new Error('EROFS'), { code: 'EROFS' });
  });
  try {
    expect(ensurePrivateDirectoryChain(state).exposure).toBeUndefined();
  } finally {
    chmod.mockRestore();
  }
  expect(modeOf(state)).toBe(0o755);
});

skipOnWindows.for(['EPERM', 'EROFS', 'EACCES', 'ENOENT'])(
  'a repair that fails with %s is a skip and never decides the outcome',
  (code) => {
    // Repair never decides whether a daemon starts or a state file is judged usable: a read-only mount, an
    // ACL-only filesystem or a directory that went between the look and the `chmod` all leave the chain to
    // be read as it stands. A repair that could throw would cost a working daemon its startup.
    const state = directoryWith(path.join(root(), `state-${code}`), 0o755);
    vi.spyOn(fs, 'chmodSync').mockImplementation(() => {
      throw Object.assign(new Error(code), { code });
    });
    expect(() => ensurePrivateDirectoryChain(state)).not.toThrow();
    expect(ensurePrivateDirectoryChain(state).exposure).toBeUndefined();
    expect(modeOf(state)).toBe(0o755);
  },
);

skipOnWindows('leaves the directories ABOVE the state directory alone', () => {
  // The daemon did not choose `$HOME` or `~/.agent-device` and cannot tighten a home directory it was
  // never given. What it owns starts at the state directory.
  const parent = directoryWith(path.join(root(), 'parent'), 0o755);
  const state = path.join(parent, 'state');

  expect(ensurePrivateDirectoryChain(state).exposure).toBeUndefined();

  expect(modeOf(parent)).toBe(0o755);
  expect(modeOf(state)).toBe(0o700);
});

test('refuses a state path that is not absolute', () => {
  expect(ensurePrivateDirectoryChain('relative/state').exposure).toBe('outside_state_dir');
  expect(judgePrivateDirectoryChain(process.cwd(), ['..']).exposure).toBe('outside_state_dir');
});

test('a state directory made under a umask that takes an owner bit is still writable by this call', () => {
  // `mkdir` ANDs its mode with the umask, so 0277 would leave the new directory 0500: this call could not
  // create the name below it, and the next one could not read it. The mode is said again after the create.
  const parent = directoryWith(path.join(root(), 'parent'), 0o700);
  const state = path.join(parent, 'state');

  const previous = process.umask(0o077);
  try {
    expect(ensurePrivateDirectoryChain(state, ['sessions']).exposure).toBeUndefined();
  } finally {
    process.umask(previous);
  }

  fs.writeFileSync(path.join(state, 'sessions', 'marker.jsonl'), '{}\n', { mode: 0o600 });
  expect(modeOf(path.join(state, 'sessions'))).toBe(0o700);
});
