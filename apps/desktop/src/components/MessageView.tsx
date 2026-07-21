import type { ConversationSummary, MessageViewModel } from "@/mock/types";

interface Props {
  conversation: ConversationSummary | null;
  messages: MessageViewModel[];
}

/**
 * Message pane. Does not show green "encrypted" chrome for mock rows
 * (encryptionStatus is always "unavailable" on the mock path).
 */
export function MessageView({ conversation, messages }: Props) {
  if (!conversation) {
    return (
      <section
        className="flex flex-1 flex-col items-center justify-center bg-shell-bg px-8 text-center"
        data-testid="message-view-empty"
      >
        <p className="text-sm text-shell-text">No conversation selected</p>
        <p className="mt-2 max-w-md text-xs leading-relaxed text-shell-muted">
          Select a mock fixture row to exercise layout, or leave empty. Real
          DMs and channels appear only after citadel-core is wired (M3).
        </p>
      </section>
    );
  }

  return (
    <section
      className="flex min-h-0 flex-1 flex-col bg-shell-bg"
      data-testid="message-view"
    >
      <header className="flex items-center justify-between border-b border-shell-border px-4 py-3">
        <div>
          <h2 className="text-sm font-semibold text-shell-text">
            {conversation.title}
          </h2>
          <p className="text-[11px] text-shell-muted">
            group={conversation.groupId} · encryption status unavailable (mock)
          </p>
        </div>
        {/* Explicit non-claim: do not paint a lock/secure badge here */}
        <span
          className="rounded border border-shell-border px-2 py-1 text-[10px] uppercase tracking-wide text-shell-muted"
          title="Real encryption indicators require citadel-core (not this mock)."
          data-testid="encryption-status-chip"
        >
          encryption: unavailable
        </span>
      </header>

      <div className="shell-scroll flex-1 space-y-3 overflow-y-auto px-4 py-4">
        {messages.length === 0 && (
          <p
            className="text-center text-xs text-shell-muted"
            data-testid="messages-empty"
          >
            No messages in this conversation.
          </p>
        )}

        {messages.map((m) => (
          <article
            key={m.localId}
            className="max-w-xl rounded-lg border border-shell-border bg-shell-panel px-3 py-2"
            data-testid={`message-${m.localId}`}
          >
            <div className="mb-1 flex flex-wrap items-center gap-2 text-[11px]">
              <span className="font-medium text-shell-accent">
                {m.senderLabel}
              </span>
              <time className="text-shell-muted" dateTime={m.sentAt}>
                {formatTime(m.sentAt)}
              </time>
              {m.isMock && (
                <span className="rounded bg-shell-warn/15 px-1 py-0.5 text-[9px] font-semibold uppercase text-shell-warn">
                  mock · not encrypted
                </span>
              )}
            </div>
            <p className="selectable text-sm leading-relaxed text-shell-text whitespace-pre-wrap">
              {m.body}
            </p>
          </article>
        ))}
      </div>
    </section>
  );
}

function formatTime(iso: string): string {
  try {
    return new Date(iso).toLocaleString();
  } catch {
    return iso;
  }
}
