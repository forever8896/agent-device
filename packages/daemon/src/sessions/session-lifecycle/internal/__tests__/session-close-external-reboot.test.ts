// #4585 reproducer: plain `close` after an external emulator reboot. This is a review artifact, not
// merged coverage. The external-reboot case fails on purpose until implicit-stop authority is tied to
// the boot this session caused. See the commit message for the recorded concrete results.
import { beforeEach, expect, test, vi } from 'vitest';
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
import { inspectDeviceClaims } from '@agent-device/daemon-contracts/device-claims';
import type { DeviceBootObservation } from '@agent-device/contracts/device-boot';
import type { DaemonPlatformServices } from '../../../../core/platform-services.ts';
import { SessionStore } from '../../../../core/session-store.ts';
import { resolveTargetDevice } from '@agent-device/device-selection/dispatch-resolve';
import type { DeviceInfo } from '@agent-device/kernel/device';

pinOwnProcessStartTime(hostProcess);
bindTestCommandHost();

/** The AVD as inventory lists it while stopped: addressed by its AVD name, not booted. */
const STOPPED_AVD: DeviceInfo = {
  platform: 'android',
  id: 'pixel-avd',
  name: 'Pixel_9_API_35',
  kind: 'emulator',
  booted: false,
};

/** The same emulator once it runs. An external reboot keeps this identity and serial. */
const BOOTED_EMULATOR: DeviceInfo = {
  platform: 'android',
  id: 'emulator-5554',
  name: 'Pixel_9_API_35',
  kind: 'emulator',
  booted: true,
};

type Runs = Readonly<{
  env: NodeJS.ProcessEnv;
  boot: { current: DeviceBootObservation };
  platformServices: DaemonPlatformServices;
  sessionStore: SessionStore;
  logPath: string;
}>;

function makeRuns(): Runs {
  const stateDir = mkdtempForTestSync('agent-device-external-reboot-');
  const env: NodeJS.ProcessEnv = {
    ...process.env,
    AGENT_DEVICE_CLAIMS_DIR: path.join(stateDir, 'claims'),
  };
  // The boot observation is the one fact a case changes. It is the service root composition gives
  // claim acquisition, and it already answers for an Android emulator through `/proc/uptime`. While
  // the emulator is stopped the host reports no boot epoch for its serial, which is why the cold
  // open's boot is the first observation any case gets.
  const boot: { current: DeviceBootObservation } = {
    current: { observed: false, reason: 'unobserved' },
  };
  const platformServices = daemonPlatformServicesFixture({
    deviceBootObservation: Object.freeze({
      observeBootTimeMs: async (): Promise<DeviceBootObservation> => boot.current,
    }),
  }) as unknown as DaemonPlatformServices;
  return {
    env,
    boot,
    platformServices,
    sessionStore: new SessionStore(path.join(stateDir, 'sessions'), {
      env,
      cwd: process.cwd(),
    }),
    logPath: path.join(stateDir, 'daemon.log'),
  };
}

/** Cold open of the stopped AVD through the session route: readiness boots it on its serial. */
async function coldOpen(runs: Runs, session: string) {
  vi.mocked(resolveTargetDevice).mockResolvedValue(STOPPED_AVD);
  mockEnsureReadyRuntime.mockImplementation(async () => BOOTED_EMULATOR);
  const response = await handleSessionCommands({
    host: createTestHostEnvironment({ env: runs.env }),
    createCommandSurface: fakeCreateCommandSurface,
    platformServices: runs.platformServices,
    sessionStore: runs.sessionStore,
    invoke: async () => ({ ok: true, data: {} }),
    req: {
      token: 't',
      command: 'open',
      session,
      positionals: ['Demo'],
      flags: { platform: 'android', device: STOPPED_AVD.name },
    },
    sessionName: session,
    logPath: runs.logPath,
  });
  expect(response?.ok).toBe(true);
}

/** Reopen the same session on the same device identity. No selector, so no new selection. */
function reopenSession(runs: Runs, session: string) {
  return handleSessionCommands({
    host: createTestHostEnvironment({ env: runs.env }),
    createCommandSurface: fakeCreateCommandSurface,
    platformServices: runs.platformServices,
    sessionStore: runs.sessionStore,
    invoke: async () => ({ ok: true, data: {} }),
    req: {
      token: 't',
      command: 'open',
      session,
      positionals: ['Demo'],
      flags: { platform: 'android' },
    },
    sessionName: session,
    logPath: runs.logPath,
  });
}

/**
 * Plain close, recording the finalization ask at the lifecycle port. The leaf `shutdownTarget` stays
 * the harness's own, so `mockShutdownTargetRuntime` counts the stop the platform was actually asked
 * to perform.
 */
async function closeSession(runs: Runs, session: string) {
  const finalizeAsks: Array<Readonly<{ shutdownTarget: boolean; retainRunner: boolean }>> = [];
  const loader: LifecycleOperationsLoader = async (device, signal, shutdownTarget) => {
    const operations = await applicationLifecycleRuntimeFixture(device, signal, shutdownTarget);
    const finalizeApplicationClose = operations.finalizeApplicationClose;
    return Object.freeze({
      ...operations,
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
    host: createTestHostEnvironment({ env: runs.env }),
    createCommandSurface: fakeCreateCommandSurface,
    platformServices: runs.platformServices,
    sessionStore: runs.sessionStore,
    invoke: async () => ({ ok: true, data: {} }),
    lifecycleOperationsLoader: loader,
    req: { token: 't', command: 'close', session, positionals: [], flags: {} },
    sessionName: session,
    logPath: runs.logPath,
  });
  return { response, finalizeAsks };
}

function storedClaim(runs: Runs) {
  return inspectDeviceClaims({ serial: BOOTED_EMULATOR.id }, runs.env)[0]?.claim;
}

/** Waits until the wall clock is past `instantMs`, so a boot epoch named here is already in the past. */
async function elapsedSince(instantMs: number): Promise<void> {
  while (Date.now() <= instantMs) {
    await new Promise((resolve) => setTimeout(resolve, 2));
  }
}

beforeEach(() => {
  mockEnsureReadyRuntime.mockReset();
  mockEnsureReadyRuntime.mockResolvedValue(undefined);
});

test('cold open boots the stopped AVD once, owns that boot, and claims the booted serial', async () => {
  const runs = makeRuns();
  await coldOpen(runs, 'external-reboot');

  const session = runs.sessionStore.get('external-reboot');
  expect(session?.device.id).toBe(BOOTED_EMULATOR.id);
  expect(session?.bootedByOpen).toBe(true);
  expect(mockEnsureReadyRuntime).toHaveBeenCalledTimes(1);
  const claim = storedClaim(runs);
  expect(claim?.session).toBe('external-reboot');
  expect(session?.deviceClaim?.ownerToken).toBe(claim?.ownerToken);
});

test('plain close does not stop an emulator another actor rebooted before this session reopened', async () => {
  const runs = makeRuns();
  await coldOpen(runs, 'external-reboot');
  const claimTakenAtMs = storedClaim(runs)?.createdAtMs ?? 0;

  // An outside actor stops and starts the same emulator: same serial, same claim file, new boot.
  // Its boot epoch is a past instant that postdates this session's claim, which is what an
  // `/proc/uptime` probe reports for an emulator that came back up between two session commands.
  await elapsedSince(claimTakenAtMs);
  const foreignBootMs = Date.now();
  runs.boot.current = { observed: true, bootedAtMs: foreignBootMs };

  const reopened = await reopenSession(runs, 'external-reboot');
  expect(reopened?.ok).toBe(true);

  // Result 1: this reopen booted nothing. It kept the same identity, claim and boot marker, and it
  // vouched for the device again — after the foreign boot, so a renewal stamp cannot tell the two
  // boots apart.
  expect(mockEnsureReadyRuntime).toHaveBeenCalledTimes(1);
  const session = runs.sessionStore.get('external-reboot');
  expect(session?.device.id).toBe(BOOTED_EMULATOR.id);
  expect(session?.bootedByOpen).toBe(true);
  const claim = storedClaim(runs);
  expect(claim?.ownerToken).toBe(session?.deviceClaim?.ownerToken);
  expect(claim?.createdAtMs ?? 0).toBe(claimTakenAtMs);
  expect((claim?.updatedAtMs ?? 0) >= foreignBootMs).toBe(true);

  // Result 2: what plain close asks the platform to do with the CURRENT boot.
  const { response, finalizeAsks } = await closeSession(runs, 'external-reboot');
  expect(response?.ok).toBe(true);
  expect(finalizeAsks).toEqual([{ shutdownTarget: false, retainRunner: false }]);
  expect(mockShutdownTargetRuntime).not.toHaveBeenCalled();
  if (response?.ok) expect(response.data?.shutdown).toBeUndefined();
});

test('control: a same-boot reopen keeps plain close stopping the emulator this session booted', async () => {
  const runs = makeRuns();
  await coldOpen(runs, 'same-boot');
  const ownBootMs = storedClaim(runs)?.createdAtMs ?? 0;

  // Identical case except the observed boot: the device still runs the boot this session caused.
  runs.boot.current = { observed: true, bootedAtMs: ownBootMs };

  const reopened = await reopenSession(runs, 'same-boot');
  expect(reopened?.ok).toBe(true);
  expect(mockEnsureReadyRuntime).toHaveBeenCalledTimes(1);
  expect(runs.sessionStore.get('same-boot')?.bootedByOpen).toBe(true);

  const { response, finalizeAsks } = await closeSession(runs, 'same-boot');
  expect(response?.ok).toBe(true);
  expect(finalizeAsks).toEqual([{ shutdownTarget: true, retainRunner: false }]);
  expect(mockShutdownTargetRuntime).toHaveBeenCalledTimes(1);
  if (response?.ok) expect(response.data?.shutdown).toBeDefined();
});
