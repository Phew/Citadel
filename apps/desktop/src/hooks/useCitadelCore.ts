import { useCallback, useEffect, useState } from "react";
import { getCitadelCore } from "@/lib/core-client";
import type {
  ConversationSummary,
  CoreStatus,
  MessageViewModel,
} from "@/mock/types";

export interface ShellState {
  status: CoreStatus | null;
  conversations: ConversationSummary[];
  selectedGroupId: string | null;
  messages: MessageViewModel[];
  loading: boolean;
  error: string | null;
  fixturesLoaded: boolean;
}

const initial: ShellState = {
  status: null,
  conversations: [],
  selectedGroupId: null,
  messages: [],
  loading: true,
  error: null,
  fixturesLoaded: false,
};

export function useCitadelCore() {
  const [state, setState] = useState<ShellState>(initial);
  const core = getCitadelCore();

  const refresh = useCallback(async () => {
    setState((s) => ({ ...s, loading: true, error: null }));
    try {
      const status = await core.getStatus();
      const { conversations } = await core.listConversations();
      setState((s) => ({
        ...s,
        status,
        conversations,
        loading: false,
        fixturesLoaded: conversations.some((c) => c.isMockFixture),
      }));
    } catch (e) {
      setState((s) => ({
        ...s,
        loading: false,
        error: e instanceof Error ? e.message : String(e),
      }));
    }
  }, [core]);

  const selectConversation = useCallback(
    async (groupId: string | null) => {
      setState((s) => ({ ...s, selectedGroupId: groupId, messages: [] }));
      if (!groupId) return;
      try {
        const { messages, status } = await core.listMessages(groupId);
        setState((s) => ({ ...s, messages, status }));
      } catch (e) {
        setState((s) => ({
          ...s,
          error: e instanceof Error ? e.message : String(e),
        }));
      }
    },
    [core],
  );

  const sendMockLocal = useCallback(
    async (body: string) => {
      const groupId = state.selectedGroupId;
      if (!groupId) {
        setState((s) => ({
          ...s,
          error: "No conversation selected (mock has no real groups).",
        }));
        return;
      }
      try {
        const { message, status } = await core.sendMockLocalMessage(
          groupId,
          body,
        );
        setState((s) => ({
          ...s,
          status,
          messages: [...s.messages, message],
          conversations: s.conversations.map((c) =>
            c.groupId === groupId
              ? {
                  ...c,
                  lastPreview: body.trim().slice(0, 80),
                  updatedAt: message.sentAt,
                }
              : c,
          ),
          error: null,
        }));
      } catch (e) {
        setState((s) => ({
          ...s,
          error: e instanceof Error ? e.message : String(e),
        }));
      }
    },
    [core, state.selectedGroupId],
  );

  const loadFixtures = useCallback(async () => {
    try {
      const { conversations, status } = await core.loadMockFixtures();
      setState((s) => ({
        ...s,
        conversations,
        status,
        fixturesLoaded: true,
        selectedGroupId: null,
        messages: [],
        error: null,
      }));
    } catch (e) {
      setState((s) => ({
        ...s,
        error: e instanceof Error ? e.message : String(e),
      }));
    }
  }, [core]);

  const clearFixtures = useCallback(async () => {
    try {
      const { conversations, status } = await core.clearMockFixtures();
      setState((s) => ({
        ...s,
        conversations,
        status,
        fixturesLoaded: false,
        selectedGroupId: null,
        messages: [],
        error: null,
      }));
    } catch (e) {
      setState((s) => ({
        ...s,
        error: e instanceof Error ? e.message : String(e),
      }));
    }
  }, [core]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  return {
    ...state,
    refresh,
    selectConversation,
    sendMockLocal,
    loadFixtures,
    clearFixtures,
  };
}
