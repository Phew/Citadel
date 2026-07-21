import { useState, type FormEvent, type KeyboardEvent } from "react";

interface Props {
  disabled: boolean;
  disabledReason: string | null;
  onSend: (body: string) => void | Promise<void>;
}

/**
 * Composer for mock-local send only.
 * Placeholder and helper text make clear that this is not a real E2E send path.
 */
export function Composer({ disabled, disabledReason, onSend }: Props) {
  const [body, setBody] = useState("");
  const [sending, setSending] = useState(false);

  async function submit() {
    if (disabled || sending) return;
    const trimmed = body.trim();
    if (!trimmed) return;
    setSending(true);
    try {
      await onSend(trimmed);
      setBody("");
    } finally {
      setSending(false);
    }
  }

  function onSubmit(e: FormEvent) {
    e.preventDefault();
    void submit();
  }

  function onKeyDown(e: KeyboardEvent<HTMLTextAreaElement>) {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      void submit();
    }
  }

  return (
    <form
      onSubmit={onSubmit}
      className="border-t border-shell-border bg-shell-panel px-4 py-3"
      data-testid="composer"
    >
      <p className="mb-2 text-[11px] text-shell-muted">
        Mock-local composer only — does not encrypt, does not deliver, does not
        create real users.{" "}
        {disabledReason && (
          <span className="text-shell-warn">{disabledReason}</span>
        )}
      </p>
      <div className="flex items-end gap-2">
        <textarea
          value={body}
          onChange={(e) => setBody(e.target.value)}
          onKeyDown={onKeyDown}
          disabled={disabled || sending}
          rows={2}
          placeholder={
            disabled
              ? "Select a mock fixture conversation to try local compose…"
              : "Type a mock-local message (Enter to send, Shift+Enter newline)"
          }
          className="shell-scroll min-h-[2.75rem] flex-1 resize-none rounded-md border border-shell-border bg-shell-bg px-3 py-2 text-sm text-shell-text placeholder:text-shell-muted/70 focus:border-shell-accent focus:outline-none disabled:opacity-50"
          data-testid="composer-input"
        />
        <button
          type="submit"
          disabled={disabled || sending || !body.trim()}
          className="rounded-md bg-shell-accent px-3 py-2 text-sm font-medium text-white disabled:cursor-not-allowed disabled:opacity-40"
          data-testid="composer-send"
        >
          {sending ? "…" : "Send (mock)"}
        </button>
      </div>
    </form>
  );
}
