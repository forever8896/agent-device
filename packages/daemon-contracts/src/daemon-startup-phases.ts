import fs from 'node:fs';
import path from 'node:path';
import { normalizeError, type NormalizedError } from '@agent-device/kernel/errors';
import { isProcessAlive } from '@agent-device/host-kit/process';

/**
 * Startup phase markers: a per-launch record, named for the writing pid, of how far that startup
 * got, so a waiting client tells "slow but progressing" from "stuck" without a heartbeat. The
 * writer removes it on completion, the client after a joined exit, and each new registration
 * owner sweeps the files of provably dead pids.
 */
const DAEMON_STARTUP_PHASES = Object.freeze([
  'modules-loaded',
  'composition-loaded',
  'lock-acquired',
  'recovery-finished',
  'listening',
  'registered',
] as const);

export type DaemonStartupPhase = (typeof DAEMON_STARTUP_PHASES)[number];

const DAEMON_STARTUP_PHASE_SET: ReadonlySet<string> = new Set<string>(DAEMON_STARTUP_PHASES);

const DAEMON_STARTUP_PHASES_ENTRY = /^daemon-startup-phases-(\d*)\.jsonl$/;

/** The marker file the daemon process `pid` writes in `stateDir`; an absent file is no evidence. */
export function resolveDaemonStartupPhasesPath(stateDir: string, pid: number): string {
  return path.join(stateDir, `daemon-startup-phases-${pid}.jsonl`);
}

/**
 * Appends one phase marker; a refused append goes to `reportFailure`, never fatal to a startup.
 *
 * The marker's directory is the daemon's own state directory, which `launchDaemonProcess` establishes
 * at 0700 before this process exists; the `mkdir` here is the same claim spelled the same way, for a
 * daemon started without that launcher. What is still this call's to decide is the FINAL NAME: another
 * local user who can write that directory can plant a link at it, and an append would land in whatever
 * it points at. So the entry is opened only as a regular file, reached without following that link, and
 * created at 0600, the mode a state diagnostic carries.
 */
export function recordDaemonStartupMarker(
  startupPhasesPath: string,
  phase: DaemonStartupPhase,
  reportFailure?: (error: NormalizedError) => void,
): void {
  try {
    const timestampMs = Date.now();
    fs.mkdirSync(path.dirname(startupPhasesPath), { recursive: true, mode: PRIVATE_DIR_MODE });
    appendMarkerLine(
      startupPhasesPath,
      `${JSON.stringify({ data: { startupPhase: phase, timestampMs } })}\n`,
    );
  } catch (error) {
    reportFailure?.(normalizeError(error));
  }
}

const PRIVATE_DIR_MODE = 0o700;

/**
 * Appends through one descriptor that names a regular file, or refuses.
 *
 * `O_NOFOLLOW` is what makes the refusal mean something: without it the kernel resolves the final name
 * and an append lands in whatever a link there points at. The glue a crashed append needs is read
 * THROUGH THAT SAME DESCRIPTOR, so nothing is read at the name either. `lstat` judges the entry, the
 * descriptor is checked against that identity, and the file opened is the file judged.
 * `O_NOFOLLOW` is absent on Windows, where a directory link is a privileged operation this threat model
 * excludes; the regular-file check still runs there.
 */
function appendMarkerLine(startupPhasesPath: string, line: string): void {
  const descriptor = openMarkerForAppend(startupPhasesPath);
  try {
    // A crash mid-append can leave no trailing newline; glue two appends and both are lost.
    const offset = fs.fstatSync(descriptor).size;
    const glue = offset > 0 && !lastByteIsNewline(descriptor, offset) ? '\n' : '';
    fs.writeSync(descriptor, `${glue}${line}`);
  } finally {
    fs.closeSync(descriptor);
  }
}

function openMarkerForAppend(startupPhasesPath: string): number {
  const noFollow = fs.constants.O_NOFOLLOW;
  // READ-WRITE: the glue a crashed append needs is read back through this same descriptor, so the
  // marker is never read at its final name either.
  const appendFlags =
    fs.constants.O_RDWR |
    fs.constants.O_APPEND |
    (Number.isInteger(noFollow) && noFollow > 0 ? noFollow : 0);
  const existing = lstatIfPresent(startupPhasesPath);
  if (existing === undefined) {
    try {
      return openChecked(
        startupPhasesPath,
        appendFlags | fs.constants.O_CREAT | fs.constants.O_EXCL,
      );
    } catch (error) {
      // Somebody created it between the look and the open. It is judged below like any entry this
      // call did not make.
      if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error;
    }
  } else if (!existing.isFile()) {
    throw notARegularFile(startupPhasesPath);
  } else {
    return openChecked(startupPhasesPath, appendFlags, existing);
  }
  const raced = lstatIfPresent(startupPhasesPath);
  if (raced === undefined || !raced.isFile()) throw notARegularFile(startupPhasesPath);
  return openChecked(startupPhasesPath, appendFlags, raced);
}

/** Opens the marker and proves the descriptor reached the entry `lstat` described. */
function openChecked(startupPhasesPath: string, flags: number, before?: fs.Stats): number {
  const descriptor = fs.openSync(startupPhasesPath, flags, PRIVATE_FILE_MODE);
  try {
    const opened = fs.fstatSync(descriptor);
    if (!opened.isFile()) throw notARegularFile(startupPhasesPath);
    if (before && (before.dev !== opened.dev || before.ino !== opened.ino)) {
      throw new Error(`Startup marker identity changed as it was opened: ${startupPhasesPath}`);
    }
    return descriptor;
  } catch (error) {
    fs.closeSync(descriptor);
    throw error;
  }
}

function notARegularFile(startupPhasesPath: string): Error {
  return new Error(
    `Refusing to append the startup marker to a path that is not a regular file: ${startupPhasesPath}`,
  );
}

const PRIVATE_FILE_MODE = 0o600;

/** Whether the byte before `size` ends a line, read through the append descriptor itself. */
function lastByteIsNewline(descriptor: number, size: number): boolean {
  const buffer = Buffer.alloc(1);
  if (fs.readSync(descriptor, buffer, 0, 1, size - 1) !== 1) return true;
  return buffer[0] === 0x0a;
}

/** `lstat` that treats absence as `undefined`; every other errno propagates. */
function lstatIfPresent(pathname: string): fs.Stats | undefined {
  try {
    return fs.lstatSync(pathname);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return undefined;
    throw error;
  }
}

/**
 * Removes this launch's record: before its first marker (a per-pid name identifies a writer, not
 * a lifetime, so the entry claims its file first), and after a finished startup or joined exit.
 * A refused removal only reports through `reportFailure`; it never stops a startup.
 */
export function removeDaemonStartupPhasesFile(
  startupPhasesPath: string,
  reportFailure?: (error: NormalizedError) => void,
): void {
  try {
    fs.rmSync(startupPhasesPath, { force: true });
  } catch (error) {
    reportFailure?.(normalizeError(error));
  }
}

/** Sweeps marker files of provably dead (or unnameable) pids; a live pid's file is kept. */
export function sweepDeadDaemonStartupPhasesFiles(stateDir: string): void {
  let entries: string[];
  try {
    entries = fs.readdirSync(stateDir);
  } catch {
    return;
  }
  for (const entry of entries) {
    const match = DAEMON_STARTUP_PHASES_ENTRY.exec(entry);
    if (match === null) continue;
    const deadPid = Number(match[1]);
    if (deadPid === process.pid) continue;
    if (!Number.isSafeInteger(deadPid) || deadPid <= 0 || !isProcessAlive(deadPid)) {
      removeDaemonStartupPhasesFile(path.join(stateDir, entry));
    }
  }
}

/**
 * The phases observed in a marker tail, keeping each phase's earliest occurrence. Unknown and
 * unparsable lines are ignored: a client never fails a startup over a line it does not know.
 */
export function readDaemonStartupPhaseMarkers(
  markerTail: string,
): Partial<Record<DaemonStartupPhase, number>> {
  const phases: Partial<Record<DaemonStartupPhase, number>> = {};
  for (const line of markerTail.split('\n')) {
    if (!line.includes('"startupPhase"')) continue;
    let record: DaemonStartupMarkerRecord;
    try {
      record = JSON.parse(line) as DaemonStartupMarkerRecord;
    } catch {
      continue;
    }
    const phase = record.data?.startupPhase;
    const timestampMs = record.data?.timestampMs;
    if (
      typeof phase !== 'string' ||
      !DAEMON_STARTUP_PHASE_SET.has(phase) ||
      typeof timestampMs !== 'number' ||
      !Number.isFinite(timestampMs)
    ) {
      continue;
    }
    const seen = phases[phase as DaemonStartupPhase];
    if (seen === undefined || timestampMs < seen) phases[phase as DaemonStartupPhase] = timestampMs;
  }
  return phases;
}

type DaemonStartupMarkerRecord = {
  data?: { startupPhase?: unknown; timestampMs?: unknown };
};
