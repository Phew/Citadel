/**
 * Boundary between React and citadel-core.
 *
 * M2: always the in-process MOCK (see src/mock/).
 * M3: detect Tauri and call real commands; drop mock default path.
 *
 * Frontend code must import from here — never call backend HTTP/WS directly
 * (PLAN-GROK-4.5: all security decisions stay in core).
 */

import { mockCitadelCore } from "@/mock/citadel-core-mock";
import type { CitadelCoreApi } from "@/mock/types";

/**
 * Returns the active core API.
 * Currently always mock; real Tauri wiring lands when citadel-core is ready.
 */
export function getCitadelCore(): CitadelCoreApi {
  return mockCitadelCore;
}

/**
 * Whether the shell is using the mock implementation.
 * UI chrome uses this for persistent MOCK labeling.
 */
export function isMockCore(): boolean {
  return true;
}
