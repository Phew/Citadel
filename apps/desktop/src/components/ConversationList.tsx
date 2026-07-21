import type { ConversationSummary } from "@/mock/types";

interface Props {
  conversations: ConversationSummary[];
  selectedGroupId: string | null;
  loading: boolean;
  fixturesLoaded: boolean;
  onSelect: (groupId: string) => void;
  onLoadFixtures: () => void;
  onClearFixtures: () => void;
}

export function ConversationList({
  conversations,
  selectedGroupId,
  loading,
  fixturesLoaded,
  onSelect,
  onLoadFixtures,
  onClearFixtures,
}: Props) {
  return (
    <aside
      className="flex h-full w-72 shrink-0 flex-col border-r border-shell-border bg-shell-panel"
      data-testid="conversation-list"
    >
      <header className="flex items-center justify-between border-b border-shell-border px-3 py-3">
        <div>
          <h1 className="text-sm font-semibold text-shell-text">Citadel</h1>
          <p className="text-[11px] text-shell-muted">conversations</p>
        </div>
      </header>

      <div className="border-b border-shell-border px-3 py-2">
        <p className="mb-2 text-[11px] leading-snug text-shell-muted">
          Default state is empty. Fixtures are layout-only and labeled{" "}
          <span className="font-mono">[MOCK FIXTURE]</span>.
        </p>
        <div className="flex gap-2">
          {!fixturesLoaded ? (
            <button
              type="button"
              onClick={onLoadFixtures}
              className="rounded border border-shell-border bg-shell-bg px-2 py-1 text-[11px] text-shell-text hover:border-shell-accent"
              data-testid="load-fixtures"
            >
              Load mock fixtures
            </button>
          ) : (
            <button
              type="button"
              onClick={onClearFixtures}
              className="rounded border border-shell-border bg-shell-bg px-2 py-1 text-[11px] text-shell-text hover:border-shell-danger"
              data-testid="clear-fixtures"
            >
              Clear mock fixtures
            </button>
          )}
        </div>
      </div>

      <div className="shell-scroll flex-1 overflow-y-auto">
        {loading && (
          <p className="px-3 py-4 text-xs text-shell-muted">Loading…</p>
        )}

        {!loading && conversations.length === 0 && (
          <div
            className="px-3 py-6 text-center"
            data-testid="conversations-empty"
          >
            <p className="text-sm text-shell-text">No conversations</p>
            <p className="mt-1 text-[11px] leading-relaxed text-shell-muted">
              Honest empty state: the mock core has no session, no backend, and
              no real groups. Nothing is hidden behind a fake inbox.
            </p>
          </div>
        )}

        <ul className="py-1">
          {conversations.map((c) => {
            const selected = c.groupId === selectedGroupId;
            return (
              <li key={c.groupId}>
                <button
                  type="button"
                  onClick={() => onSelect(c.groupId)}
                  className={`w-full px-3 py-2.5 text-left transition-colors ${
                    selected
                      ? "bg-shell-accent/15"
                      : "hover:bg-shell-bg/80"
                  }`}
                  data-testid={`conversation-${c.groupId}`}
                >
                  <div className="flex items-center gap-2">
                    <span className="truncate text-sm font-medium text-shell-text">
                      {c.title}
                    </span>
                    {c.isMockFixture && (
                      <span className="shrink-0 rounded bg-shell-warn/20 px-1 py-0.5 text-[9px] font-semibold uppercase tracking-wide text-shell-warn">
                        mock
                      </span>
                    )}
                  </div>
                  <p className="mt-0.5 truncate text-[11px] text-shell-muted">
                    {c.lastPreview || "No messages"}
                  </p>
                  <p className="mt-0.5 text-[10px] uppercase tracking-wide text-shell-muted/80">
                    {c.kind}
                  </p>
                </button>
              </li>
            );
          })}
        </ul>
      </div>
    </aside>
  );
}
