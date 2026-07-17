import { describe, expect, it } from "vitest";
import { mapCoreStatus } from "./tauri-core-client";
import { resolveCoreTransport } from "./core-client";

describe("core transport selection", () => {
  it("uses tauri-invoke inside the webview", () => {
    expect(resolveCoreTransport(true)).toBe("tauri-invoke");
  });

  it("uses in-process mock for browser dev", () => {
    expect(resolveCoreTransport(false)).toBe("in-process-mock");
  });
});

describe("mapCoreStatus (invoke wire → UI)", () => {
  const honestWire = {
    mode: "mock",
    mockLabel: "MOCK — not connected",
    backend: "unavailable",
    session: null,
    encryptionStatus: "unavailable",
    coreVersion: "mock-0.1.0 (not citadel-core)",
  };

  it("maps honest mock status", () => {
    const status = mapCoreStatus(honestWire);
    expect(status.mode).toBe("mock");
    expect(status.backend).toBe("unavailable");
    expect(status.session).toBeNull();
    expect(status.encryptionStatus).toBe("unavailable");
  });

  it("refuses non-mock mode claims", () => {
    expect(() =>
      mapCoreStatus({ ...honestWire, mode: "live" }),
    ).toThrow(/Expected mock core mode/);
  });

  it("does not promote unknown backend strings to available", () => {
    const status = mapCoreStatus({
      ...honestWire,
      backend: "connected-to-prod",
    });
    expect(status.backend).toBe("unknown");
  });

  it("collapses unknown encryption claims to unavailable", () => {
    const status = mapCoreStatus({
      ...honestWire,
      encryptionStatus: "e2e-encrypted",
    });
    expect(status.encryptionStatus).toBe("unavailable");
  });
});
