import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { AppError } from '@agent-device/kernel/errors';
import { emitDiagnostic } from './diagnostics.ts';

/**
 * What this process may rely on when it judges ground: who it is, as the kernel answers. The rule reads no
 * account database, so the answer does not depend on which name services run (ADR 0016). Every judgment below
 * decides over the fields of one `lstat`, so each is testable on its values.
 */
export type ScriptDestinationTrust = Readonly<{ uid: number }>;

function scriptTrust(): ScriptDestinationTrust {
  return { uid: process.getuid?.() ?? -1 };
}

/**
 * The fields of a directory, or of a link, that the ancestry rule reads. The group id is deliberately absent,
 * for the account-file reason ADR 0016 states.
 */
export type DirectoryAuthority = Readonly<{ uid: number; mode: number }>;

export type LinkAuthority = Readonly<{ uid: number }>;

/** The ways a step can be unsafe; `untrustedGroundWording` words each one for the caller. */
export type ScriptAncestryExposure =
  | 'foreign_owned'
  | 'world_writable'
  | 'shared_group_writable'
  | 'shared_parent'
  | 'planted_link'
  | 'link_loop_exceeded'
  | 'not_a_directory'
  | 'entry_appeared'
  | 'relative_destination'
  | 'unresolvable_parent'
  | 'unreachable_parent'
  | 'parent_replaced';

/**
 * Whether this user can rely on a destination being inside `directory`, and why not if they cannot. The
 * ownership-first order, the group-writable refusal, and the one sticky-bit exception are ADR 0016's; the
 * exception holds only for PASSING THROUGH, so {@link othersCreateEntriesIn} is asked separately before a name
 * is created.
 */
export function untrustedAncestryExposure(
  directory: DirectoryAuthority,
  trust: ScriptDestinationTrust,
): ScriptAncestryExposure | undefined {
  if (directory.uid !== 0 && directory.uid !== trust.uid) return 'foreign_owned';
  if (directory.mode & 0o1000) return undefined;
  if (directory.mode & 0o002) return 'world_writable';
  if (directory.mode & 0o020) return 'shared_group_writable';
  return undefined;
}

/**
 * Whether other local users can add an entry here, which is how the destination's own name becomes theirs. A
 * directory somebody else owns counts whatever its mode says: the sticky bit shields other people's entries
 * (ADR 0016).
 */
export function othersCreateEntriesIn(
  directory: DirectoryAuthority,
  trust: ScriptDestinationTrust,
): boolean {
  if (directory.uid !== 0 && directory.uid !== trust.uid) return true;
  if (directory.mode & 0o002) return true;
  return Boolean(directory.mode & 0o020);
}

/**
 * Whether a link on the path is one another local user could have put there, or could replace, and whose
 * target is therefore theirs to choose (ADR 0016).
 */
export function untrustedLinkExposure(
  link: LinkAuthority,
  home: DirectoryAuthority,
  trust: ScriptDestinationTrust,
): ScriptAncestryExposure | undefined {
  if (!othersCreateEntriesIn(home, trust)) return undefined;
  if (home.mode & 0o1000 && (link.uid === 0 || link.uid === trust.uid)) return undefined;
  return 'planted_link';
}

export type AtomicPublishMode = 'replace' | 'link-exclusive';

/**
 * Publishes a complete file from a same-directory temporary sibling. Contents are text or bytes: an
 * encoding is passed only for text, so a PNG or a video chunk reaches the disk as the caller built it.
 *
 * The temporary file is always removed. Cleanup is best effort and never replaces the write or publish
 * error; a cleanup failure is retained as secondary evidence when a request diagnostics scope exists.
 */
export function publishFileSync(options: {
  destination: string;
  contents: string | Uint8Array;
  mode?: number;
  preserveExistingMode?: boolean;
  publish?: AtomicPublishMode;
  /** The asked-for mode is MADE exact on the sibling instead of paid for with the umask. */
  exactMode?: boolean;
}): void {
  withAtomicPublishTempPathSync(options.destination, (temporaryPath) => {
    const existing = options.preserveExistingMode
      ? fs.statSync(options.destination, { throwIfNoEntry: false })
      : undefined;
    const preservedMode = existing?.isFile() ? existing.mode & 0o777 : undefined;
    const mode = preservedMode ?? options.mode;
    const writeOptions = {
      encoding: typeof options.contents === 'string' ? ('utf8' as const) : undefined,
      ...(mode === undefined ? {} : { mode }),
    };
    fs.writeFileSync(temporaryPath, options.contents, writeOptions);
    // A file CREATE ANDs its mode with the umask, so a mode that has to be EXACT is SAID on the temporary
    // sibling before the entry exists and no reader sees a wider file. Preserving an existing mode is always
    // exact. An asked-for mode is NOT, which is what a generic caller has always relied on: with `mode` 0600
    // under umask 0200 it gets 0400, and only {@link publishScriptFileSync} asks for the exact number.
    const exactMode = preservedMode ?? (options.exactMode ? mode : undefined);
    if (exactMode !== undefined) fs.chmodSync(temporaryPath, exactMode);
    if (options.publish === 'link-exclusive') {
      fs.linkSync(temporaryPath, options.destination);
    } else {
      fs.renameSync(temporaryPath, options.destination);
    }
  });
}

/**
 * Publishes a session script, and nothing else: {@link publishFileSync} at {@link SCRIPT_FILE_MODE}, with the
 * destination-ancestry rule asked through {@link prepareScriptDestination}. A recording is a transcript of what
 * someone did here, so it is private, and the mode is asked EXACT: the umask of a shared checkout would
 * otherwise narrow it away from what the rule publishes everywhere else.
 */
export function publishScriptFileSync(options: {
  destination: string;
  contents: string;
  publish?: AtomicPublishMode;
}): void {
  // The entry is spelled FROM the directory the rule judged, never from the caller's spelling: a `..` or a
  // link sends the entry elsewhere, and a temporary sibling beside that spelling is one another local user
  // can reach (ADR 0016). Spelling it here puts the sibling where the entry lands, on its own.
  const judged = prepareScriptDestination(options.destination).directory;
  publishFileSync({
    destination: path.join(judged, path.basename(options.destination)),
    contents: options.contents,
    mode: SCRIPT_FILE_MODE,
    publish: options.publish,
    exactMode: true,
  });
}

/**
 * The canonical temp path for a destination: a sibling of the name, inside the directory the publish will
 * create the entry in — the walk's answer for a script destination, `path.dirname` for every other one.
 */
function createAtomicPublishTempPath(directory: string, destination: string): string {
  return path.join(
    directory,
    `.${path.basename(destination)}.${process.pid}-${crypto.randomUUID()}.tmp`,
  );
}

function removeTempBestEffort(destination: string, temporaryPath: string | undefined): void {
  if (temporaryPath === undefined) return;
  try {
    fs.rmSync(temporaryPath, { force: true });
  } catch (error) {
    emitDiagnostic({
      level: 'warn',
      phase: 'atomic_file_cleanup_failed',
      data: {
        destination,
        temporaryPath,
        error: error instanceof Error ? error.message : String(error),
      },
    });
  }
}

/** A recording holds literals a `fill` did not parameterize (ADR 0017), so it is written private. */
const SCRIPT_FILE_MODE = 0o600;

/**
 * A directory a publish creates is itself judged on the way to a later version, so it is created at the mode
 * the rule accepts under every umask — the shared-checkout umask 002 would otherwise leave it 0775 and refuse.
 */
const SCRIPT_DIR_MODE = 0o700;

/**
 * Readies a script destination and reports the PHYSICAL directory to create the entry in, in ADR 0016's order:
 * walk, refuse before anything is created, create what is missing, walk the completed chain again, answer.
 */
export function prepareScriptDestination(destination: string): ScriptDestination {
  return scriptDestination(destination, true);
}

/**
 * ADR 0016's judgment of one destination. `create` says whether the caller needs the missing tail created:
 * a walk that stops short is an answer for that caller and a refusal for the other.
 */
function scriptDestination(destination: string, create: boolean): ScriptDestination {
  const spelled = spelledParent(destination);
  if (process.platform === 'win32') {
    // Access is an ACL here, so no walk runs, and `lstat` answers no usable directory identity.
    if (create) fs.mkdirSync(spelled, { recursive: true, mode: SCRIPT_DIR_MODE });
    return { directory: spelled, identity: 'windows' };
  }
  const trust = scriptTrust();
  // The walk answers the COMPLETED chain, so this is the one place the CREATION question is asked: below the
  // walk the missing directories are this call's own to create, and asking it before creation would refuse
  // `mkdir -p <sticky shared>/recordings`, where those levels are 0700 of this call's own (ADR 0016).
  const arrived = walkSpelledParent(spelled, destination, trust, create);
  if (othersCreateEntriesIn(arrived.authority, trust)) {
    throw scriptAncestryFailure(destination, arrived.deepest, 'shared_parent');
  }
  return { directory: arrived.deepest, identity: arrived.identity };
}

/**
 * Where a script entry is created: the PHYSICAL directory the rule judged, and that directory's identity as
 * the walk's own `lstat` answered it — what {@link confirmScriptDestination} compares before a rename.
 */
export type ScriptDestination = Readonly<{
  directory: string;
  identity: string | undefined;
}>;

export type DurableFilePublishMode = 'replace' | 'link-exclusive';

/** Publishes complete UTF-8 contents with a durable file and directory fence. */
export function publishDurableFileSync(options: {
  destination: string;
  contents: string;
  mode?: number;
  publish?: DurableFilePublishMode;
}): void {
  const directory = path.dirname(options.destination);
  withAtomicPublishTempPathSync(options.destination, (temporaryPath) => {
    let descriptor: number | undefined;
    let failed = false;
    let primaryError: unknown;
    try {
      assertSafeDestination(options.destination);
      descriptor = fs.openSync(temporaryPath, 'wx', options.mode ?? 0o600);
      fs.writeFileSync(descriptor, options.contents, 'utf8');
      fs.fsyncSync(descriptor);
      fs.closeSync(descriptor);
      descriptor = undefined;
      assertSafeDestination(options.destination);
      if (options.publish === 'link-exclusive') {
        fs.linkSync(temporaryPath, options.destination);
      } else {
        fs.renameSync(temporaryPath, options.destination);
      }
      syncDirectoryBestEffort(directory);
    } catch (error) {
      failed = true;
      primaryError = error;
    }
    if (descriptor !== undefined) {
      try {
        fs.closeSync(descriptor);
      } catch (error) {
        if (!failed) {
          failed = true;
          primaryError = error;
        }
      }
    }
    if (failed) throw primaryError;
  });
}

/**
 * Gives a publisher a canonical temp path and cleanup ownership while it performs its own write protocol.
 * The sibling goes in `directory`, which the caller must name when it knows the physical directory the entry
 * is created in; a spelling that sends `..` or a link elsewhere is not where a temporary file may land.
 */
export function withAtomicPublishTempPathSync<T>(
  destination: string,
  publish: (temporaryPath: string) => T,
): T {
  const temporaryPath = createAtomicPublishTempPath(path.dirname(destination), destination);
  try {
    return publish(temporaryPath);
  } finally {
    removeTempBestEffort(destination, temporaryPath);
  }
}

/** Syncs a containing directory where the filesystem supports directory fsync. */
function syncDirectoryBestEffort(directory: string): void {
  let descriptor: number | undefined;
  try {
    descriptor = fs.openSync(directory, 'r');
    fs.fsyncSync(descriptor);
  } catch {
  } finally {
    if (descriptor !== undefined) {
      try {
        fs.closeSync(descriptor);
      } catch {}
    }
  }
}

/** Identifies a temp path produced for a particular destination. */
export function isAtomicPublishTemporaryPath(value: unknown, destination: string): boolean {
  if (typeof value !== 'string') return false;
  if (path.dirname(value) !== path.dirname(destination)) return false;
  const name = path.basename(value);
  return name.startsWith(`.${path.basename(destination)}.`) && name.endsWith('.tmp');
}

/**
 * Confirms a destination host-kit ANSWERED earlier, and reports the directory to create the entry in. The one
 * check a caller that stages bytes owes, for the reason ADR 0016 states.
 */
export function confirmScriptDestination(destination: string, prepared: ScriptDestination): string {
  const current = scriptDestination(destination, false);
  if (current.identity !== prepared.identity) {
    throw scriptAncestryFailure(destination, current.directory, 'parent_replaced');
  }
  return current.directory;
}

/**
 * The parent of `destination` exactly as the caller spells it, refusing a RELATIVE destination on every
 * platform, Windows included, where no walk runs to catch it (ADR 0016).
 */
function spelledParent(destination: string): string {
  const parent = path.dirname(destination);
  if (!path.isAbsolute(parent)) {
    throw scriptAncestryFailure(destination, parent, 'relative_destination');
  }
  return parent;
}

/** Where the walk stands: a judged directory, the identity its own `lstat` answered, names left to resolve. */
type WalkState = Readonly<{
  deepest: string;
  authority: DirectoryAuthority;
  identity: string;
  /** Path components left to resolve, nearest first. */
  queue: readonly string[];
  /** Link targets expanded so far. */
  hops: number;
}>;

/**
 * The ground a walk answered: the PHYSICAL directory the entry is created in, with the authority and identity
 * it was judged under, so the caller never asks the host about ground the walk already read.
 */
type WalkGround = Readonly<{
  deepest: string;
  authority: DirectoryAuthority;
  /** That directory's identity, as this walk's `lstat` of it answered. */
  identity: string;
}>;

/** The tail a walk stopped below: the nearest judged directory and the spelled names absent beneath it. */
type ShortTail = Readonly<{
  /** The nearest directory the walk did judge; the destination's name is absent below it. */
  deepest: string;
  /** The spelled names below `deepest`, the first of them absent. */
  missing: readonly string[];
  /** Whether a `..` is queued behind that name, so creating cannot resolve the chain. */
  unresolvable: boolean;
}>;

/**
 * Walks the spelled parent exactly as the kernel resolves a path — the resolution ADR 0016 describes: no
 * `realpath`, `..` applied to the directory physically stood in, a link's raw components queued ahead of the
 * rest, hops capped at {@link MAX_SCRIPT_PATH_LINK_HOPS}. It throws at the first step another local user could
 * steer; `destination` appears only in the refusal that names it.
 *
 * A caller that creates gets the ANSWER FOR THE COMPLETED CHAIN: the walk stops at the first absent name, makes
 * that tail inside the directory it judged, and judges the chain again from the root, because creating is the
 * one moment ground below this call's feet changes. Anything still short then is a refusal.
 */
function walkSpelledParent(
  parent: string,
  destination: string,
  trust: ScriptDestinationTrust,
  create: boolean,
): WalkGround {
  const refuse = (ancestor: string, exposure: ScriptAncestryExposure): never => {
    throw scriptAncestryFailure(destination, ancestor, exposure);
  };
  let state = standOn('/', pathComponents(parent), trust, 0, refuse);
  let created = false;
  // Every step consumes a component, and every link hop counts against a fixed limit, so this ends.
  for (;;) {
    const [component, ...rest] = state.queue;
    // The only ending that ARRIVES: an empty queue, every name the parent spelled resolved and judged.
    if (component === undefined) {
      return { deepest: state.deepest, authority: state.authority, identity: state.identity };
    }
    // `..` is the parent of the directory PHYSICALLY stood in, not of the spelling: where `work` is a link,
    // `.../work/../x` steps back from the link's target and lands beside it.
    if (component === '..') {
      state = standOn(path.dirname(state.deepest), rest, trust, state.hops, refuse);
      continue;
    }
    const step = stepIntoEntry(state, component, rest, trust, refuse);
    if (step.ended === 'short') {
      const { deepest, missing, unresolvable } = step;
      // Nothing stands below here. A caller that creates makes that tail and is judged again; a step back out
      // of a directory that is not there is something no amount of creating resolves.
      if (!create || created || unresolvable) {
        throw scriptAncestryFailure(
          destination,
          deepest,
          unresolvable ? 'unresolvable_parent' : 'unreachable_parent',
        );
      }
      createMissingLevels(destination, deepest, missing, trust);
      created = true;
      state = standOn('/', pathComponents(parent), trust, 0, refuse);
      continue;
    }
    state = step.state;
  }
}

/** Where one named entry leaves the walk: standing on a judged directory, or short of the chain. */
type EntryStep =
  | Readonly<{ ended: 'stand'; state: WalkState }>
  | (ShortTail & Readonly<{ ended: 'short' }>);

/**
 * Resolves one named entry inside the directory the walk stands in, judged by this call's own `lstat` of the
 * NAME (ADR 0016).
 */
function stepIntoEntry(
  state: WalkState,
  component: string,
  rest: readonly string[],
  trust: ScriptDestinationTrust,
  refuse: (ancestor: string, exposure: ScriptAncestryExposure) => never,
): EntryStep {
  const entry = path.join(state.deepest, component);
  const stats = lstatEntry(entry);
  if (stats === undefined) {
    return {
      ended: 'short',
      deepest: state.deepest,
      missing: [component, ...rest],
      unresolvable: rest.includes('..'),
    };
  }
  if (stats.isSymbolicLink()) return hopThroughLink(state, entry, stats, rest, trust, refuse);
  if (!stats.isDirectory()) refuse(entry, 'not_a_directory');
  const authority = directoryAuthority(stats);
  const exposure = untrustedAncestryExposure(authority, trust);
  if (exposure) refuse(entry, exposure);
  return {
    ended: 'stand',
    state: {
      deepest: entry,
      authority,
      identity: identityOf(stats),
      queue: rest,
      hops: state.hops,
    },
  };
}

/** One hop: the link is judged where it stands, and its target's components enter the queue. */
function hopThroughLink(
  state: WalkState,
  link: string,
  stats: fs.BigIntStats,
  rest: readonly string[],
  trust: ScriptDestinationTrust,
  refuse: (ancestor: string, exposure: ScriptAncestryExposure) => never,
): EntryStep {
  const exposure = untrustedLinkExposure({ uid: Number(stats.uid) }, state.authority, trust);
  if (exposure) refuse(link, exposure);
  if (state.hops >= MAX_SCRIPT_PATH_LINK_HOPS) refuse(link, 'link_loop_exceeded');
  const target = fs.readlinkSync(link);
  // A relative target continues from the directory that HOLDS the link, and its components are queued RAW
  // rather than joined: ADR 0016.
  const home = path.isAbsolute(target) ? '/' : path.dirname(link);
  return {
    ended: 'stand',
    state: standOn(home, [...pathComponents(target), ...rest], trust, state.hops + 1, refuse),
  };
}

/**
 * Stands the walk on `directory`, judged from this call's own `lstat` of it, or refuses it. A name come back
 * around through a `..` or an alias is judged again, and reaches the judgment it had on the first visit
 * (ADR 0016).
 */
function standOn(
  directory: string,
  queue: readonly string[],
  trust: ScriptDestinationTrust,
  hops: number,
  refuse: (ancestor: string, exposure: ScriptAncestryExposure) => never,
): WalkState {
  const stats = lstatEntry(directory);
  if (stats === undefined || !stats.isDirectory()) refuse(directory, 'not_a_directory');
  const authority = directoryAuthority(stats);
  const exposure = untrustedAncestryExposure(authority, trust);
  if (exposure) refuse(directory, exposure);
  return { deepest: directory, authority, identity: identityOf(stats), queue, hops };
}

/** Owner and mode of the ENTRY one `lstat` answer describes. */
function directoryAuthority(stats: fs.BigIntStats): DirectoryAuthority {
  return { uid: Number(stats.uid), mode: Number(stats.mode) };
}

/**
 * The device and inode an `lstat` answer names. BIGINT stats: a numeric `ino` cannot hold every inode a
 * filesystem hands out, so two distinct large inodes would collapse onto one identity.
 */
function identityOf(stats: fs.BigIntStats): string {
  return `${stats.dev}:${stats.ino}`;
}

/** The only lookup this rule makes: `lstat` with bigint ids, absence as `undefined`. */
function lstatEntry(pathname: string): fs.BigIntStats | undefined {
  return fs.lstatSync(pathname, { bigint: true, throwIfNoEntry: false });
}

/** The names of `directory`, every `.` resolved away the way the kernel does. */
function pathComponents(directory: string): string[] {
  return directory.split('/').filter((component) => component.length > 0 && component !== '.');
}

/**
 * How many link targets one walk expands before it refuses, kept BELOW the smallest limit the supported
 * kernels apply (macOS 32, Linux 40) so this rule reaches its own limit first and answers with its own reason.
 */
export const MAX_SCRIPT_PATH_LINK_HOPS = 30;

/** `lstat` where absence is `undefined` and any other failure is the caller's to answer for. */
function lstatIfPresent(pathname: string): fs.Stats | undefined {
  try {
    return fs.lstatSync(pathname);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return undefined;
    throw error;
  }
}

/** Why each exposure makes that ground unsafe, in the caller's terms. */
const untrustedGroundWording: Record<ScriptAncestryExposure, string> = {
  foreign_owned: 'another local user owns that part of the path.',
  world_writable: 'any local user can write that part of the path.',
  shared_group_writable:
    'the group can write that part of the path, and agent-device cannot tell who else belongs to that group.',
  shared_parent: 'another local user could create the script file there first.',
  planted_link: 'another local user could have put that symbolic link there, or could replace it.',
  link_loop_exceeded:
    'that part of the path follows more symbolic links than the system allows, so where the script would land is not established.',
  not_a_directory: 'a directory was expected there, and something else stands in the way.',
  entry_appeared:
    'a directory the script path needs was missing when the path was checked and appeared before this save could create it.',
  relative_destination:
    'the script path has to be absolute, so the directories it names are the ones that get checked.',
  unresolvable_parent:
    'the script path names a directory that does not exist and steps back out of it with `..`, so where the script would land is not established.',
  unreachable_parent:
    'the directory the script path names does not exist, so the script has nowhere to be written.',
  parent_replaced:
    'that directory was replaced while the script was staged, so the script may not be created in what stands there now.',
};

/**
 * The typed reasons a destination-ancestry refusal answers with, named here rather than spelled again by
 * whoever reads them.
 */
const SCRIPT_ANCESTRY_REASONS = ['script_ancestor_untrusted', 'script_ancestry_replaced'] as const;

/** A reason this rule answers with, or `undefined` for an error that came from somewhere else. */
export function scriptAncestryReason(error: unknown): string | undefined {
  if (!(error instanceof AppError)) return undefined;
  const reason = error.details?.reason;
  return typeof reason === 'string' &&
    (SCRIPT_ANCESTRY_REASONS as readonly string[]).includes(reason)
    ? reason
    : undefined;
}

function scriptAncestryFailure(
  destination: string,
  ancestor: string,
  exposure: ScriptAncestryExposure,
): AppError {
  return new AppError(
    'COMMAND_FAILED',
    `Refusing to save the script under ${ancestor}: ${untrustedGroundWording[exposure]}`,
    {
      reason:
        exposure === 'parent_replaced' ? SCRIPT_ANCESTRY_REASONS[1] : SCRIPT_ANCESTRY_REASONS[0],
      exposure,
      path: destination,
      ancestor,
      hint: ancestryHint(exposure, ancestor),
    },
  );
}

/** What to do about it. A group-writable directory is the one refusal the caller can fix in place. */
function ancestryHint(exposure: ScriptAncestryExposure, ancestor: string): string {
  if (exposure === 'parent_replaced') {
    return 'Re-record with open --save-script, or save under a directory nobody else can write.';
  }
  if (exposure === 'shared_group_writable') {
    return `Close the directory to its group with \`chmod g-w ${ancestor}\`, or save the script under a directory only you can write.`;
  }
  return 'Save the script under a directory you own that only you can write, and keep the path out of directories other users own.';
}

/**
 * Creates the tail the walk found missing, ONE LEVEL AT A TIME, inside the directory the walk judged, for the
 * one-name-at-a-time reason ADR 0016 states. A name that arrived since the walk looked is judged here, not
 * refused and not trusted, because two processes saving into the same new directory meet at that entry.
 */
function createMissingLevels(
  destination: string,
  established: string,
  missing: readonly string[],
  trust: ScriptDestinationTrust,
): void {
  let parent = established;
  for (const name of missing) {
    parent = createMissingLevel(destination, parent, name, trust);
  }
}

/**
 * Creates one missing level inside `parent`, or adopts the entry that appeared in its place, and reports the
 * directory the next name is created in.
 */
function createMissingLevel(
  destination: string,
  parent: string,
  name: string,
  trust: ScriptDestinationTrust,
): string {
  const level = path.join(parent, name);
  let created = true;
  try {
    fs.mkdirSync(level, { mode: SCRIPT_DIR_MODE });
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error;
    created = false;
  }
  // The `lstat` of the NAME, after the creation attempt, is the judgment either way: what this call made
  // and what arrived beside it are read the same way and judged by the same rule.
  const seen = lstatEntry(level);
  if (seen === undefined || !seen.isDirectory()) {
    throw scriptAncestryFailure(destination, level, created ? 'not_a_directory' : 'entry_appeared');
  }
  const authority = directoryAuthority(seen);
  const exposure = untrustedAncestryExposure(authority, trust);
  if (exposure) throw scriptAncestryFailure(destination, level, exposure);
  if (created) {
    // `mkdir` ANDs its mode with the umask, and a umask can take an OWNER bit away: umask 200 would leave
    // this level 0500, where this call could not create the name below it. One `chmod` makes the level the
    // mode this rule creates, whatever the host's umask is.
    fs.chmodSync(level, SCRIPT_DIR_MODE);
    return level;
  }
  // Somebody else's directory: the one place this rule asks whether OTHER users could add a name here.
  if (othersCreateEntriesIn(authority, trust)) {
    throw scriptAncestryFailure(destination, level, 'shared_parent');
  }
  return level;
}

/* ---------------------------------------------------------------------------
 * The daemon's own state directory (#4649).
 *
 * A destination a caller names is the caller's own, and `prepareScriptDestination` judges it. A state
 * directory is the opposite case: the daemon picked it and writes into it without being asked, so the
 * daemon OWNS it, and everything below it is judged by the one rule below. State creation, repair, and
 * the answer a state-diagnostic writer gets before it writes all come from here, so the three cannot
 * disagree.
 *
 * Two points stricter than the destination rule, because nothing here is chosen by a caller. No level is
 * entered through a link, so no spelling below one can leave the tree, and the rule never has to reason
 * about a link another local user could swap. And the levels ABOVE the state directory are neither
 * judged nor repaired: the daemon does not choose them, and a home directory is nobody's to tighten.
 * ------------------------------------------------------------------------- */

/** What a caller may do with one state chain, and the ground it was judged on. */
export type PrivateDirectoryChain = Readonly<{
  /** The PHYSICAL directory to create the entry in, never the caller's spelling. */
  directory: string;
  /** Why the chain is not private, or `undefined` when it is. */
  exposure: PrivateDirectoryExposure | undefined;
}>;

/** The ways a state chain fails the rule; {@link privateDirectoryWordingOf} words each one. */
export type PrivateDirectoryExposure =
  | 'not_a_directory'
  | 'planted_link'
  | 'foreign_owned'
  | 'shared_writable'
  | 'unreachable'
  | 'outside_state_dir';

/**
 * Establishes a private chain under `stateDir`, creating what is missing, and answers typed.
 *
 * Repair never decides whether a process starts: a level another user owns is left alone and reported,
 * and a filesystem that will not carry a mode is a skip with a diagnostic. A refusal before creation
 * leaves nothing behind.
 */
export function ensurePrivateDirectoryChain(
  stateDir: string,
  names: readonly string[] = [],
): PrivateDirectoryChain {
  const spelled = spelledStateChain(stateDir, names);
  if (spelled === undefined) return { directory: stateDir, exposure: 'outside_state_dir' };
  if (process.platform === 'win32') {
    // Access is an ACL here, so no walk runs and `lstat` answers no usable directory identity. One
    // recursive `mkdir` is what this host has always done: it forces nothing on a level that stands.
    return createStateDirectory(spelled.target);
  }
  const trust = scriptTrust();
  // Creating is the one moment ground below this call's feet changes, so a chain it completed is judged
  // again from the state directory, the way the walk re-judges after `createMissingLevels`.
  const arrived = walkStateChain(spelled, trust, true);
  return arrived.exposure === undefined ? walkStateChain(spelled, trust, false) : arrived;
}

/**
 * Judges a chain that must already stand, creating and repairing nothing. This is what a writer of a
 * state diagnostic asks before it opens a file: an `exposure` says the chain is not this process's own to
 * write into, and the writer skips its file rather than write through ground another local user controls.
 */
export function judgePrivateDirectoryChain(
  stateDir: string,
  names: readonly string[] = [],
): PrivateDirectoryChain {
  const spelled = spelledStateChain(stateDir, names);
  if (spelled === undefined) return { directory: stateDir, exposure: 'outside_state_dir' };
  if (process.platform === 'win32') return { directory: spelled.target, exposure: undefined };
  return walkStateChain(spelled, scriptTrust(), false);
}

/**
 * Where the chain stands and what it is spelled from: `root` is the state directory and `target` its
 * deepest level, both absolute and free of `.` and `..`.
 */
type SpelledStateChain = Readonly<{ root: string; target: string }>;

/**
 * The chain's spelling, refused when there is none.
 *
 * A `..` has no answer here. Folding one away is what sends a state path OUTSIDE the state directory
 * through a link, and the writer would then be told about a directory it never named. `spelledStateChain`
 * is where that is decided once, before any lookups.
 */
function spelledStateChain(
  stateDir: string,
  names: readonly string[],
): SpelledStateChain | undefined {
  if (!path.isAbsolute(stateDir)) return undefined;
  if (stateDir.split(/[\\/]/).includes('..')) return undefined;
  const oneName = (name: string): boolean =>
    name.length > 0 && name !== '.' && name !== '..' && !name.includes('/') && !name.includes('\\');
  if (!names.every(oneName)) return undefined;
  const root = path.resolve(stateDir);
  return { root, target: path.join(root, ...names) };
}

/**
 * Walks the chain from the state directory down, judging every level by this call's own `lstat` of the
 * NAME. With `create`, a missing level is made at 0700 inside the level the walk just judged, one name at
 * a time; a name that arrived since the look is judged by the same rule, because two processes starting
 * on one state directory meet at that entry. Without it, an absent level is `unreachable` and nothing is
 * created.
 */
function walkStateChain(
  spelled: SpelledStateChain,
  trust: ScriptDestinationTrust,
  create: boolean,
): PrivateDirectoryChain {
  let stood = standOnStateDir(spelled.root, trust, create);
  if (stood.exposure !== undefined) return { directory: spelled.root, exposure: stood.exposure };
  for (const name of stateNamesBelow(spelled)) {
    const level = path.join(stood.directory, name);
    const seen = lstatEntry(level);
    if (seen === undefined) {
      if (!create) return { directory: level, exposure: 'unreachable' };
      const made = createStateLevel(level);
      if (made.exposure !== undefined) return made;
      const judged = judgeStateLevel(level, lstatEntry(level), trust);
      if (judged.exposure !== undefined) return judged;
      stood = judged;
      continue;
    }
    const judged = judgeStateLevel(level, seen, trust, create);
    if (judged.exposure !== undefined) return judged;
    stood = judged;
  }
  return stood;
}

/**
 * Stands on the state directory itself, creating it when `create` allows.
 *
 * A missing state directory is made with one RECURSIVE `mkdir`, which is also what fills in any missing
 * ANCESTOR: the default state dir sits below `$HOME/.agent-device/dev` and nothing else creates those.
 * Those ancestors are above the chain this rule owns, so they are neither judged nor repaired.
 */
function standOnStateDir(
  root: string,
  trust: ScriptDestinationTrust,
  create: boolean,
): PrivateDirectoryChain {
  const seen = lstatEntry(root);
  if (seen !== undefined) return judgeStateLevel(root, seen, trust, create);
  if (!create) return { directory: root, exposure: 'unreachable' };
  const made = createStateDirectory(root);
  return made.exposure === undefined ? judgeStateLevel(root, lstatEntry(root), trust) : made;
}

/** Creates the state directory and its missing ancestors, answering typed like the walk does. */
function createStateDirectory(root: string): PrivateDirectoryChain {
  try {
    fs.mkdirSync(root, { recursive: true, mode: SCRIPT_DIR_MODE });
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    return {
      directory: path.dirname(root),
      exposure: code === 'ENOENT' ? 'unreachable' : 'not_a_directory',
    };
  }
  // `mkdir` ANDs its mode with the umask, so the exact mode is SAID again once the entry exists: the
  // umask of a shared checkout cannot leave the daemon's own state directory narrower or looser.
  repairPrivateMode(root, SCRIPT_DIR_MODE);
  return { directory: root, exposure: undefined };
}

/** Creates one missing level at 0700 INSIDE the level the walk just judged, never through a link. */
function createStateLevel(level: string): PrivateDirectoryChain {
  try {
    fs.mkdirSync(level, { mode: SCRIPT_DIR_MODE });
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'EEXIST') {
      return { directory: path.dirname(level), exposure: 'unreachable' };
    }
    // The name arrived beside this call. Whatever it is, it is judged by the same rule below, and this
    // call never changes a mode it did not create.
    return { directory: level, exposure: undefined };
  }
  repairPrivateMode(level, SCRIPT_DIR_MODE);
  return { directory: level, exposure: undefined };
}

/** The names the chain walks through below the state directory, shallowest first. */
function stateNamesBelow(spelled: SpelledStateChain): string[] {
  const below = path.relative(spelled.root, spelled.target);
  return below === '' ? [] : below.split(path.sep);
}

/**
 * The judgment one level earns, and the repair it earns first.
 *
 * A level this user owns that stands at any other mode is brought to {@link SCRIPT_DIR_MODE} before it is
 * judged, whenever the caller is establishing the chain: the shared checkout's umask 002 leaves a
 * mode-less `mkdir` at 0775, and a state directory a host left loose gets narrowed. A level root owns is
 * judged as it stands and never touched, and a level another user owns is refused without being touched:
 * tightening somebody else's directory is not this rule's to do.
 */
function judgeStateLevel(
  level: string,
  stats: fs.BigIntStats | undefined,
  trust: ScriptDestinationTrust,
  repair = false,
): PrivateDirectoryChain {
  if (stats === undefined) return { directory: level, exposure: 'unreachable' };
  if (stats.isSymbolicLink()) return { directory: level, exposure: 'planted_link' };
  if (!stats.isDirectory()) return { directory: level, exposure: 'not_a_directory' };
  const authority = directoryAuthority(stats);
  if (authority.uid !== 0 && authority.uid !== trust.uid) {
    return { directory: level, exposure: 'foreign_owned' };
  }
  if (repair && authority.uid === trust.uid && (authority.mode & 0o777) !== SCRIPT_DIR_MODE) {
    repairPrivateMode(level, SCRIPT_DIR_MODE);
    return judgeStateLevel(level, lstatEntry(level), trust);
  }
  if (otherUsersWriteTo(authority)) {
    return { directory: level, exposure: 'shared_writable' };
  }
  return { directory: level, exposure: undefined };
}

/**
 * A level whose group or world can write is open to other local users, whoever owns it and whether or not
 * a sticky bit stands on it.
 *
 * This is deliberately stricter than {@link othersCreateEntriesIn}, which the destination rule uses and
 * which lets a STICKY shared directory pass. Passing THROUGH one is safe there, because another user
 * cannot replace an entry the daemon made. Here the daemon creates names of its own choosing in the
 * level, so another local user can win the race to plant a link at `daemon-shutdown.json` or at a
 * marker's name first, and a sticky bit does not stop that: it only stops them replacing an entry they do
 * not own. The group bit counts because the group of a daemon-made directory is the daemon user's own
 * group, whose other members can add a name. Read and traverse bits are not this rule's concern: they
 * decide what another user can see, and the daemon's state files carry their own modes for that.
 */
function otherUsersWriteTo(authority: DirectoryAuthority): boolean {
  return (authority.mode & 0o022) !== 0;
}

/**
 * Forces `target` to the exact private `mode` it is asked for.
 *
 * The repair never decides an outcome, so EVERY failure is a skip with a diagnostic: a filesystem or a
 * host that cannot carry a mode, a path that went away, and a mount that refuses it are all ground the
 * judgment still reads as it stands. On Windows `chmod` only toggles the read-only bit, so it cannot make
 * a path private and no caller reaches here on that host.
 */
export function repairPrivateMode(target: string, mode: number): void {
  try {
    fs.chmodSync(target, mode);
  } catch (error) {
    emitDiagnostic({
      level: 'warn',
      phase: 'daemon_state_mode_repair_skipped',
      data: {
        path: target,
        error: error instanceof Error ? error.message : String(error),
      },
    });
  }
}

/** The typed reason a state-chain refusal answers with, named once for whoever reads it. */
export const PRIVATE_STATE_DIR_REASON = 'state_dir_untrusted';

/** Why each exposure makes that ground unsafe, in the caller's terms. */
const privateDirectoryWording: Record<PrivateDirectoryExposure, string> = {
  not_a_directory: 'a directory was expected there, and something else stands in the way.',
  planted_link:
    'a symbolic link stands in the way, so what would be written there is not inside the state directory.',
  foreign_owned: 'another local user owns that part of the state path.',
  shared_writable: 'another local user can add an entry to that part of the state path.',
  unreachable:
    'that part of the state path is not there and cannot be created there, so nothing has a place to be written.',
  outside_state_dir:
    'the state path steps out of the directory it starts in, so where it lands is not established.',
};

export function privateDirectoryWordingOf(exposure: PrivateDirectoryExposure): string {
  return privateDirectoryWording[exposure];
}

function assertSafeDestination(destination: string): void {
  const stats = lstatIfPresent(destination);
  if (stats?.isSymbolicLink()) {
    throw new Error(`Refusing to replace a durable file symbolic link: ${destination}`);
  }
  if (stats && !stats.isFile()) {
    throw new Error(
      `Refusing to replace a durable path that is not a regular file: ${destination}`,
    );
  }
}
