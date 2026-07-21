import type { CoreStatus } from "@/mock/types";

interface Props {
  status: CoreStatus | null;
}

/**
 * Persistent, non-dismissible mock / disconnected banner.
 * INV-5: never implies a live encrypted session.
 */
export function MockBanner({ status }: Props) {
  const label = status?.mockLabel ?? "MOCK — status not loaded";
  const backend = status?.backend ?? "unknown";
  const encryption = status?.encryptionStatus ?? "unavailable";

  return (
    <div
      role="status"
      aria-live="polite"
      className="flex flex-wrap items-center gap-x-4 gap-y-1 border-b border-shell-warn/40 bg-shell-warn/10 px-4 py-2 text-xs text-shell-warn"
      data-testid="mock-banner"
    >
      <span className="font-semibold tracking-wide">MOCK MODE</span>
      <span className="text-shell-text/90">{label}</span>
      <span className="font-mono text-shell-muted">
        backend={backend} · encryption={encryption} · session=none
      </span>
    </div>
  );
}
