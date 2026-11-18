// #4585: plain `close` owes a stop to the boot its own `open` caused, not to whichever boot the
// device is running now. Routed through the session command handler, so claim acquisition, renewal,
// boot stamping and close teardown all run against real claim files.
import { afterEach, beforeEach, expect, test, vi } from 'vitest';
import path from 'node:path';
import * as hostProcess from '@agent-device/host-kit/process';
import {
  bindTestCommandHost,
  createTestHostEnvironment,
  mkdtempForTestSync,
  pinOwnProcessStartTime,
} from '@agent-device/test-kit';

vi.mock('@agent-device/device-selection/dispatch-resolve', async (importOriginal) => {
  const actual =
    await importOriginal<typeof import('@agent-device/device-selection/dispatch-resolve')>();
  const { selectionFromResolveTargetDevice } =
    await import('../../../../__tests__/support/device-selection-stub.ts');
  const resolveTargetDevice = vi.fn();
  return {
    ...actual,
    resolveTargetDevice,
    resolveTargetDeviceSelection: vi.fn(selectionFromResolveTargetDevice(resolveTargetDevice)),
  };
});

import { fakeCreateCommandSurface } from '../../../../__tests__/support/command-surface-fake.ts';
import { daemonPlatformServicesFixture } from '../../../../__tests__/support/platform-services-fixture.ts';
import {
  handleSessionCommands,
  mockEnsureReadyRuntime,
  mockShutdownTargetRuntime,
} from '../../../../__tests__/support/handlers/session-command-harness.ts';
import {
  applicationLifecycleRuntimeFixture,
  type LifecycleOperationsLoader,
} from '../../../../__tests__/support/application-lifecycle-runtime-fixture.ts';
import {
  acquireDeviceClaim,
  clearDeviceClaim,
  inspectDeviceClaims,
} from '@agent-device/daemon-contracts/device-claims';
import type { DeviceBootObservation } from '@agent-device/contracts/device-boot';
import type { DaemonPlatformServices } from '../../../../core/platform-services.ts';
import { SessionStore } from '../../../../core/session-store.ts';
import { resolveTargetDevice } from '@agent-device/device-selection/dispatch-resolve';
import type { DeviceInfo } from '@agent-device/kernel/device';

pinOwnProcessStartTime(hostProcess);
bindTestCommandHost();

/** The clock every case runs on, so a boot epoch is a named instant rather than an elapsed guess. */
const CLOCK_START_MS = Date.UTC(2026, 0, 15, 10, 0, 0);
/** How far after the cold open a case places the emulator's next boot, and how long it has been up. */
const LATER_BOOT_DELAY_MS = 60_000;
const LATER_BOOT_UPTIME_MS = 45_000;
/** How long before a case's own boot a prior session's claim was taken. */
const PRIOR_CLAIM_GAP_MS = 30 * 60_000;

const SESSION = 'implicit-shutdown-session';

/** The boot epoch of an emulator restarted outside the session: past, and later than the open's. */
const LATER_BOOT_MS = CLOCK_START_MS + LATER_BOOT_DELAY_MS - LATER_BOOT_UPTIME_MS;
const REBOOTED: DeviceBootObservation = { observed: true, bootedAtMs: LATER_BOOT_MS };

/** The AVD as inventory lists it while stopped: addressed by its AVD name, not booted. */
const STOPPED_AVD: DeviceInfo = {
  platform: 'android',
  id: 'pixel-avd',
  name: 'Pixel_9_API_35',
  kind: 'emulator',
  booted: false,
};

/** The same emulator once it runs. An outside reboot keeps this identity and serial. */
const BOOTED_EMULATOR: DeviceInfo = {
  platform: 'android',
  id: 'emulator-5554',
  name: 'Pixel_9_API_35',
  kind: 'emulator',
  booted: true,
};

function createRoutedSession(
  observeBootTimeMs?: (device: DeviceInfo) => Promise<DeviceBootObservation>,
) {
  const stateDir = mkdtempForTestSync('agent-device-session-close-reboot-');
  const env: NodeJS.ProcessEnv = {
    ...process.env,
    AGENT_DEVICE_CLAIMS_DIR: path.join(stateDir, 'claims'),
  };
  // The close-specific platform port supplies the emulator's observed boot time.
  const boot: { current: DeviceBootObservation } = {
    current: { observed: false, reason: 'unobserved' },
  };
  let bootAsks = 0;
  const platformServices = daemonPlatformServicesFixture({
    observeBootTimeForImplicitShutdown: async (
      device: DeviceInfo,
    ): Promise<DeviceBootObservation> => {
      bootAsks += 1;
      return (await observeBootTimeMs?.(device)) ?? boot.current;
    },
  }) as unknown as DaemonPlatformServices;
  const sessionStore = new SessionStore(path.join(stateDir, 'sessions'), {
    env,
    cwd: process.cwd(),
  });

  async function run(command: {
    name: 'open' | 'close';
    flags?: Record<string, unknown>;
    /** Only a cold open selects a device, and that selection is what boots the stopped AVD. */
    selectsDevice?: boolean;
    beforeAppOpen?(): void;
    deviceShutdownDenied?: boolean;
  }) {
    if (command.selectsDevice) {
      vi.mocked(resolveTargetDevice).mockResolvedValue(STOPPED_AVD);
      mockEnsureReadyRuntime.mockResolvedValue(BOOTED_EMULATOR);
    }
    // Plain close is recorded at the lifecycle port the close dispatches, and the leaf
    // `shutdownTarget` stays the harness's own, so `mockShutdownTargetRuntime` counts the stop the
    // platform was actually asked to perform.
    const finalizeAsks: Array<Readonly<{ shutdownTarget: boolean; retainRunner: boolean }>> = [];
    const loader: LifecycleOperationsLoader = async (device, signal, shutdownTarget) => {
      const operations = await applicationLifecycleRuntimeFixture(device, signal, shutdownTarget);
      const finalizeApplicationClose = operations.finalizeApplicationClose;
      return Object.freeze({
        ...operations,
        openApplication: async (input) => {
          command.beforeAppOpen?.();
          return await operations.openApplication(input);
        },
        finalizeApplicationClose: async (input) => {
          finalizeAsks.push({
            shutdownTarget: input.shutdownTarget === true,
            retainRunner: input.retainRunner === true,
          });
          return await finalizeApplicationClose(input);
        },
      });
    };
    const response = await handleSessionCommands({
      host: createTestHostEnvironment({ env }),
      createCommandSurface: fakeCreateCommandSurface,
      platformServices,
      sessionStore,
      invoke: async () => ({ ok: true, data: {} }),
      lifecycleOperationsLoader: loader,
      ...(command.deviceShutdownDenied === undefined
        ? {}
        : { deviceShutdownDenied: command.deviceShutdownDenied }),
      req: {
        token: 't',
        command: command.name,
        session: SESSION,
        positionals: ['Demo'],
        flags: command.flags ?? {},
      },
      sessionName: SESSION,
      logPath: path.join(stateDir, 'daemon.log'),
    });
    return { response, finalizeAsks };
  }

  function sessionClaim() {
    const claim = inspectDeviceClaims({ serial: BOOTED_EMULATOR.id }, env)[0]?.claim;
    if (!claim) throw new Error('expected the session to hold its claim');
    return claim;
  }

  /** Claims on disk for this case's device, which a successful close releases with the session. */
  function sessionClaimCount() {
    return inspectDeviceClaims({ serial: BOOTED_EMULATOR.id }, env).length;
  }

  /**
   * Leaves a claim on disk for this device, taken by the same session name, workspace and daemon.
   * That is the shape a session inherits when a previous one ended without clearing its claim, and
   * the acquisition that follows renews that claim rather than taking a new one.
   */
  async function plantPriorClaim() {
    const acquired = await acquireDeviceClaim({
      device: BOOTED_EMULATOR,
      session: SESSION,
      workspace: process.cwd(),
      stateDir: sessionStore.resolveDaemonStateDir(),
      env,
      reconcileOrphanedDeviceClaim: async () => ({ status: 'reconciled' as const }),
    });
    if (acquired.status !== 'acquired') throw new Error('expected to plant a prior claim');
  }

  return {
    boot,
    /** Asks the boot-observation service answered, so a case can prove the device was not probed. */
    bootAsks: () => bootAsks,
    dropSessionClaim: async () => {
      const ownership = sessionStore.get(SESSION)?.deviceClaim;
      if (!ownership) throw new Error('expected the session to record its claim');
      await clearDeviceClaim(ownership, env);
    },
    plantPriorClaim,
    run,
    sessionClaim,
    sessionClaimCount,
    sessionStore,
  };
}

/**
 * Opens a stopped AVD through the cold route and leaves the emulator running on the boot this
 * session caused. The clock stays fake so a case can name a later boot instead of waiting one out.
 */
async function openBootedByThisSession(
  runs: ReturnType<typeof createRoutedSession>,
  beforeAppOpen?: () => void,
) {
  vi.useFakeTimers({ toFake: ['Date'] });
  vi.setSystemTime(CLOCK_START_MS);
  const opened = await runs.run({
    name: 'open',
    flags: { platform: 'android' },
    selectsDevice: true,
    beforeAppOpen,
  });
  expect(opened.response?.ok).toBe(true);
  const session = runs.sessionStore.get(SESSION);
  // The boot fact and the instant of the boot it describes are written together, and that pair is
  // the only thing close may compare against the device's own answer.
  expect(session?.bootedByOpen).toBe(true);
  const bootTime = session?.bootedByOpenAtMs;
  if (bootTime === undefined) throw new Error('open did not record Android readiness time');
  return bootTime;
}

function closeWarningMessages(response: { ok?: unknown; data?: unknown }): unknown {
  if (!response.ok) throw new Error('expected a successful close');
  return (response.data as { warnings?: string[] }).warnings;
}

beforeEach(() => {
  mockEnsureReadyRuntime.mockReset();
  mockEnsureReadyRuntime.mockResolvedValue(undefined);
});

afterEach(() => {
  vi.useRealTimers();
});

test('plain close leaves an emulator rebooted outside the session running and says why', async () => {
  const runs = createRoutedSession();
  await openBootedByThisSession(runs);

  // An outside actor restarts the emulator between two session commands. A reopen then proves the
  // session cannot recover the boot fact from what it owns: the reopen boots nothing, and its own
  // claim renewal vouches for the running device, so only the observed boot separates the boots.
  vi.advanceTimersByTime(LATER_BOOT_DELAY_MS);
  runs.boot.current = REBOOTED;
  const ref = runs.sessionStore.lookup(SESSION);
  expect(ref).toBeDefined();
  runs.sessionStore.updateOpenDevice(ref!, { ...BOOTED_EMULATOR, booted: false }, false);
  const reopened = await runs.run({ name: 'open', flags: { platform: 'android' } });
  expect(reopened.response?.ok).toBe(true);
  expect(mockEnsureReadyRuntime).toHaveBeenCalledTimes(1);
  expect(runs.sessionClaim().updatedAtMs).toBeGreaterThanOrEqual(LATER_BOOT_MS);
  // The reopen claims the running device as its own, yet keeps the stamp of the boot it did not
  // cause. That is what separates this session's boot from the outside one, and no claim timestamp
  // can do it: renewal restamps `updatedAtMs` to vouch for the reboot, and `createdAtMs` can
  // predate either.
  expect(runs.sessionStore.get(SESSION)?.bootedByOpenAtMs).toBe(CLOCK_START_MS);
  // Open and reopen settle their claims from the record alone, so neither has probed the device.
  expect(runs.bootAsks()).toBe(0);

  const closed = await runs.run({ name: 'close' });

  expect(closed.response?.ok).toBe(true);
  expect(closed.finalizeAsks).toEqual([{ shutdownTarget: false, retainRunner: false }]);
  expect(mockShutdownTargetRuntime).not.toHaveBeenCalled();
  expect(closeWarningMessages(closed.response!)).toEqual([
    "This session's open booted this device, but the device has been rebooted since then and close would stop that later boot, so it did not request a stop. The device is still running.",
  ]);
  if (closed.response?.ok) expect(closed.response.data).not.toHaveProperty('shutdown');
  // Close asks the device once, and only once: the implicit stop's own decision.
  expect(runs.bootAsks()).toBe(1);
}, 30_000);

test('plain close leaves an emulator rebooted outside the session running without any reopen', async () => {
  const runs = createRoutedSession();
  await openBootedByThisSession(runs);

  runs.boot.current = REBOOTED;
  const closed = await runs.run({ name: 'close' });

  expect(closed.response?.ok).toBe(true);
  expect(closed.finalizeAsks).toEqual([{ shutdownTarget: false, retainRunner: false }]);
  expect(mockShutdownTargetRuntime).not.toHaveBeenCalled();
  expect(closeWarningMessages(closed.response!)).toHaveLength(1);
}, 30_000);

test('plain close keeps a reboot that raced the first application launch', async () => {
  const runs = createRoutedSession();
  await openBootedByThisSession(runs, () => {
    vi.advanceTimersByTime(LATER_BOOT_DELAY_MS);
    runs.boot.current = REBOOTED;
  });

  const closed = await runs.run({ name: 'close' });

  expect(closed.response?.ok).toBe(true);
  expect(closed.finalizeAsks[0]?.shutdownTarget).toBe(false);
  expect(closeWarningMessages(closed.response!)).toHaveLength(1);
});

test('plain close stops the emulator this session booted while it still runs that boot', async () => {
  const runs = createRoutedSession();
  const ownBootMs = await openBootedByThisSession(runs);
  expect(ownBootMs).toBe(CLOCK_START_MS);

  // Same case except the boot the device reports: the one this session caused.
  runs.boot.current = { observed: true, bootedAtMs: ownBootMs };
  const closed = await runs.run({ name: 'close' });

  expect(closed.response?.ok).toBe(true);
  expect(closed.finalizeAsks).toEqual([{ shutdownTarget: true, retainRunner: false }]);
  expect(mockShutdownTargetRuntime).toHaveBeenCalledTimes(1);
  expect(closeWarningMessages(closed.response!)).toBeUndefined();
}, 30_000);

test('plain close keeps the stop it owes when the emulator cannot report its current boot', async () => {
  const runs = createRoutedSession();
  await openBootedByThisSession(runs);

  const closed = await runs.run({ name: 'close' });

  expect(closed.response?.ok).toBe(true);
  expect(closed.finalizeAsks).toEqual([{ shutdownTarget: true, retainRunner: false }]);
  expect(mockShutdownTargetRuntime).toHaveBeenCalledTimes(1);
}, 30_000);

test('plain close stops the emulator its own open booted even when the claim long predates that boot', async () => {
  const runs = createRoutedSession();
  vi.useFakeTimers({ toFake: ['Date'] });
  vi.setSystemTime(CLOCK_START_MS);
  // A previous session of this same name, workspace and daemon left its claim behind, so this
  // session's open renews that claim instead of taking a new one. Its creation time belongs to the
  // earlier session and describes nothing about the boot about to happen.
  await runs.plantPriorClaim();
  vi.advanceTimersByTime(PRIOR_CLAIM_GAP_MS);

  const ownBootMs = CLOCK_START_MS + PRIOR_CLAIM_GAP_MS;
  const opened = await runs.run({
    name: 'open',
    flags: { platform: 'android' },
    selectsDevice: true,
  });
  expect(opened.response?.ok).toBe(true);
  expect(runs.sessionStore.get(SESSION)?.bootedByOpen).toBe(true);
  expect(runs.sessionClaim().createdAtMs).toBe(CLOCK_START_MS);

  // The emulator reports the boot THIS open caused, which is what an uptime probe answers.
  runs.boot.current = { observed: true, bootedAtMs: ownBootMs };
  const closed = await runs.run({ name: 'close' });

  // The session still owns the boot the device is running, so it still owes the stop.
  expect(closed.response?.ok).toBe(true);
  expect(closed.finalizeAsks).toEqual([{ shutdownTarget: true, retainRunner: false }]);
  expect(mockShutdownTargetRuntime).toHaveBeenCalledTimes(1);
  expect(closeWarningMessages(closed.response!)).toBeUndefined();
}, 30_000);

test('close --shutdown stops a rebooted emulator and asks the device nothing', async () => {
  const runs = createRoutedSession();
  await openBootedByThisSession(runs);
  runs.boot.current = REBOOTED;
  const asksAfterOpen = runs.bootAsks();

  const closed = await runs.run({ name: 'close', flags: { shutdown: true } });

  expect(closed.response?.ok).toBe(true);
  expect(closed.finalizeAsks).toEqual([{ shutdownTarget: true, retainRunner: false }]);
  expect(mockShutdownTargetRuntime).toHaveBeenCalledTimes(1);
  expect(runs.bootAsks()).toBe(asksAfterOpen);
  expect(closeWarningMessages(closed.response!)).toBeUndefined();
}, 30_000);

test('a close whose device cannot be probed still stops the emulator it booted and keeps its session', async () => {
  const runs = createRoutedSession((device) =>
    Promise.reject(new Error(`adb is gone: ${device.id}`)),
  );
  await openBootedByThisSession(runs);

  const closed = await runs.run({ name: 'close' });

  // A probe that cannot be asked is not evidence of anything, and it never becomes the reason a
  // close fails: the stop the session owes is still owed, and nothing was half-torn down.
  expect(closed.response?.ok).toBe(true);
  expect(closed.finalizeAsks).toEqual([{ shutdownTarget: true, retainRunner: false }]);
  expect(mockShutdownTargetRuntime).toHaveBeenCalledTimes(1);
  expect(runs.sessionStore.get(SESSION)).toBeUndefined();
  expect(closeWarningMessages(closed.response!)).toBeUndefined();
}, 30_000);

test('close reaches no device or session step when it asks the boot observation', async () => {
  const runs = createRoutedSession();
  await openBootedByThisSession(runs);
  runs.boot.current = REBOOTED;

  const closed = await runs.run({ name: 'close' });

  // The probe is the close's first step and the only one it adds: the lifecycle ask sees the
  // decision it produced, and the session is retired as any successful close retires it.
  expect(closed.finalizeAsks).toEqual([{ shutdownTarget: false, retainRunner: false }]);
  expect(runs.bootAsks()).toBe(1);
  expect(runs.sessionStore.get(SESSION)).toBeUndefined();
  expect(runs.sessionClaimCount()).toBe(0);
}, 30_000);

test('a policy refusal stays the reported reason when the emulator was rebooted as well', async () => {
  const runs = createRoutedSession();
  await openBootedByThisSession(runs);
  runs.boot.current = REBOOTED;
  const asksBeforeClose = runs.bootAsks();

  const closed = await runs.run({ name: 'close', deviceShutdownDenied: true });

  expect(closed.response?.ok).toBe(true);
  expect(closed.finalizeAsks).toEqual([{ shutdownTarget: false, retainRunner: false }]);
  expect(mockShutdownTargetRuntime).not.toHaveBeenCalled();
  expect(closeWarningMessages(closed.response!)).toEqual([
    "This session's open booted this device and close would stop it, but this daemon's policy denies device-shutdown. The device is still running.",
  ]);
  expect(runs.bootAsks()).toBe(asksBeforeClose);
}, 30_000);

test('a lost claim stays the reported reason when the emulator was rebooted as well', async () => {
  const runs = createRoutedSession();
  await openBootedByThisSession(runs);
  runs.boot.current = REBOOTED;
  await runs.dropSessionClaim();
  const asksBeforeClose = runs.bootAsks();

  const closed = await runs.run({ name: 'close' });

  expect(closed.response?.ok).toBe(true);
  expect(closed.finalizeAsks).toEqual([{ shutdownTarget: false, retainRunner: false }]);
  expect(mockShutdownTargetRuntime).not.toHaveBeenCalled();
  expect(closeWarningMessages(closed.response!)).toEqual([
    "This session's open booted this device, but close could not verify its device claim and did not request a stop.",
  ]);
  // Losing the claim settles the stop without reaching the device, so the reboot adds nothing.
  expect(runs.bootAsks()).toBe(asksBeforeClose);
}, 30_000);
