/**
 * Boundary between React and citadel-core.
 *
 * M2:
 * - Inside Tauri webview → invoke mock-backed Rust commands
 * - Browser (`pnpm dev`) → in-process TS mock (same honesty rules)
 *
 * M3: swap command bodies to real citadel-core; keep this boundary.
 *
 * Frontend code must import from here — never call backend HTTP/WS directly
 * (PLAN-GROK-4.5: all security decisions stay in core).
 */

import { isTauri } from "@tauri-apps/api/core";
import { mockCitadelCore } from "@/mock/citadel-core-mock";
import type { CitadelCoreApi } from "@/mock/types";
import { createTauriMockCitadelCore } from "./tauri-core-client";

export type CoreTransport = "tauri-invoke" | "in-process-mock";

let cached: { transport: CoreTransport; api: CitadelCoreApi } | null = null;

/**
 * Detect which transport the shell should use.
 * Pure function for tests; production uses `getCitadelCore()`.
 */
export function resolveCoreTransport(inTauri: boolean): CoreTransport {
  return inTauri ? "tauri-invoke" : "in-process-mock";
}

/**
 * Returns the active core API (singleton per process).
 * Tauri path is still mock-backed — only the transport changes.
 */
export function getCitadelCore(): CitadelCoreApi {
  if (!cached) {
    const transport = resolveCoreTransport(isTauri());
    cached = {
      transport,
      api:
        transport === "tauri-invoke"
          ? createTauriMockCitadelCore()
          : mockCitadelCore,
    };
  }
  return cached.api;
}

/** Active transport label for chrome/footer diagnostics. */
export function getCoreTransport(): CoreTransport {
  if (!cached) {
    getCitadelCore();
  }
  return cached!.transport;
}

/**
 * Whether the shell is using a mock implementation (always true in M2).
 * UI chrome uses this for persistent MOCK labeling.
 */
export function isMockCore(): boolean {
  return true;
}

/** Test helper: drop the singleton so a new environment can be simulated. */
export function resetCoreClientForTests(): void {
  cached = null;
}
