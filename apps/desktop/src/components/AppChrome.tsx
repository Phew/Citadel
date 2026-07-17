import { getCoreTransport } from "@/lib/core-client";
import { useCitadelCore } from "@/hooks/useCitadelCore";
import { Composer } from "./Composer";
import { ConversationList } from "./ConversationList";
import { MessageView } from "./MessageView";
import { MockBanner } from "./MockBanner";

/**
 * Top-level desktop shell chrome.
 * Layout: mock banner · conversation list · message view + composer.
 */
export function AppChrome() {
  const shell = useCitadelCore();
  const transport = getCoreTransport();

  const selected =
    shell.conversations.find((c) => c.groupId === shell.selectedGroupId) ??
    null;

  const composerDisabled = !selected;
  const disabledReason = !selected
    ? "No conversation selected — empty/disconnected mock has nothing to send to."
    : null;

  return (
    <div className="flex h-full flex-col" data-testid="app-chrome">
      <MockBanner status={shell.status} />

      {shell.error && (
        <div
          role="alert"
          className="border-b border-shell-danger/40 bg-shell-danger/10 px-4 py-2 text-xs text-shell-danger"
          data-testid="shell-error"
        >
          {shell.error}
        </div>
      )}

      <div className="flex min-h-0 flex-1">
        <ConversationList
          conversations={shell.conversations}
          selectedGroupId={shell.selectedGroupId}
          loading={shell.loading}
          fixturesLoaded={shell.fixturesLoaded}
          onSelect={(id) => void shell.selectConversation(id)}
          onLoadFixtures={() => void shell.loadFixtures()}
          onClearFixtures={() => void shell.clearFixtures()}
        />

        <div className="flex min-w-0 flex-1 flex-col">
          <MessageView conversation={selected} messages={shell.messages} />
          <Composer
            disabled={composerDisabled}
            disabledReason={disabledReason}
            onSend={shell.sendMockLocal}
          />
        </div>
      </div>

      <footer className="flex items-center justify-between border-t border-shell-border bg-shell-panel px-4 py-1.5 text-[10px] text-shell-muted">
        <span data-testid="core-transport">
          transport={transport} · mode={shell.status?.mode ?? "…"} · core=
          {shell.status?.coreVersion ?? "…"}
        </span>
        <span>
          No direct backend fetches from UI · state via core API boundary only
        </span>
      </footer>
    </div>
  );
}
