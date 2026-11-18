import { asAppError, normalizeError } from '@agent-device/kernel/errors';
import { daemonStartupExitCode, reportDaemonClose, startDaemonRuntime } from '@agent-device/daemon';
import { captureHostEnvironment } from '@agent-device/host-kit/process';
import {
  ensurePrivateDirectoryChain,
  privateDirectoryWordingOf,
} from '@agent-device/host-kit/file';
import {
  removeDaemonStartupPhasesFile,
  recordDaemonStartupMarker,
  resolveDaemonStartupPhasesPath,
} from '@agent-device/daemon-contracts/daemon-startup-phases';
import { resolveDaemonPaths } from '@agent-device/daemon-contracts/daemon-resolution';

// A refused marker append goes to stderr, which the launcher redirects into the daemon log.
const reportMarkerFailure = (error: unknown): void => {
  process.stderr.write(`Daemon startup marker write failed: ${normalizeError(error).message}\n`);
};

// Captured once: the earliest marker and the runtime resolve the state dir from this one host,
// so a relative AGENT_DEVICE_STATE_DIR cannot land the markers beside another directory's lock.
const host = captureHostEnvironment(process);
const ownStateDir = resolveDaemonPaths(host.env.AGENT_DEVICE_STATE_DIR, {
  env: host.env,
  cwd: host.cwd,
}).baseDir;
// Every state diagnostic this process writes from here on goes into that chain, so it is established
// before the first one: 0700 at every level whatever the umask, and the narrowest best-effort repair of
// a level this user owns. A chain the daemon does not own is written down and left as it is: a fact
// about the host never refuses a startup (#4649).
const stateDir = ensurePrivateDirectoryChain(ownStateDir);
if (stateDir.exposure) {
  process.stderr.write(
    `Daemon state dir ${stateDir.directory} is not private: ${privateDirectoryWordingOf(stateDir.exposure)}\n`,
  );
}
const ownPhasesPath = resolveDaemonStartupPhasesPath(ownStateDir, process.pid);
// The claim first: after pid reuse it is the only defense against a dead lifetime's phases.
removeDaemonStartupPhasesFile(ownPhasesPath, reportMarkerFailure);
recordDaemonStartupMarker(ownPhasesPath, 'modules-loaded', reportMarkerFailure);

// The executable owns the process: signals, fatal-error handlers and the exit code. The runtime
// only reports when it has closed, whoever closed it.
// The root's composition enters as a factory behind a function-scoped `await import`: the server
// calls it before it acquires the registration, so startup order is unchanged, and the eager
// closure of this entry stays exactly the operational server's (ADR 0019).
async function runDaemon(): Promise<void> {
  const runtime = await startDaemonRuntime({
    host,
    composeDeps: async (input) => {
      const deps = await (await import('./daemon-composition.ts')).createDaemonRuntimeDeps(input);
      recordDaemonStartupMarker(
        resolveDaemonStartupPhasesPath(input.baseDir, process.pid),
        'composition-loaded',
        reportMarkerFailure,
      );
      return deps;
    },
  });
  let exitCode = 0;
  const closeAndExit = (code: number, cause?: unknown): void => {
    exitCode = Math.max(exitCode, code);
    // A failed close is reported once, through `closed` below.
    void runtime.close({ cause }).catch(() => {});
  };
  const failFatally = (error: unknown): void => {
    process.stderr.write(`Daemon error: ${asAppError(error).message}\n`);
    closeAndExit(1, error);
  };
  process.on('SIGINT', () => closeAndExit(0));
  process.on('SIGTERM', () => closeAndExit(0));
  process.on('SIGHUP', () => closeAndExit(0));
  process.on('uncaughtException', failFatally);
  process.on('unhandledRejection', (reason) =>
    failFatally(reason instanceof Error ? reason : new Error(String(reason))),
  );
  // Unfinished work is written for every close, whoever started it: a signal, the idle reap or a
  // quiesce. The registration may be held on purpose, and this is the only record of why.
  if ((await reportDaemonClose({ closed: runtime.closed, stderr: process.stderr })).failed) {
    exitCode = 1;
  }
  process.exit(exitCode);
}

runDaemon().catch((error) => {
  process.stderr.write(`Daemon error: ${asAppError(error).message}\n`);
  process.exit(daemonStartupExitCode(error));
});
