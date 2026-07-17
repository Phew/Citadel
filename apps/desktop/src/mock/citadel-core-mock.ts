/**
 * ============================================================================
 * MOCK citadel-core — NOT a real MLS / network client.
 * ============================================================================
 *
 * This module exists so the desktop shell can be designed and reviewed while
 * Opus builds real citadel-core (M2 protocol) and M1 services land.
 *
 * Rules enforced here:
 * - mode is always "mock"
 * - backend is always "unavailable" (no REST/WS to services)
 * - session is always null (no real users)
 * - encryptionStatus is always "unavailable" (never claim E2E)
 * - any synthetic rows are tagged isMockFixture / isMock
 *
 * Swap: apps/desktop/src/lib/core-client.ts will point at Tauri commands in M3.
 */

import type {
  CitadelCoreApi,
  ConversationSummary,
  CoreStatus,
  ListConversationsResult,
  ListMessagesResult,
  MessageViewModel,
  SendMockLocalResult,
} from "./types";

export const MOCK_LABEL =
  "MOCK — not connected to citadel-core or backend services";

const MOCK_CORE_VERSION = "mock-0.1.0 (not citadel-core)";

function status(): CoreStatus {
  return {
    mode: "mock",
    mockLabel: MOCK_LABEL,
    backend: "unavailable",
    session: null,
    encryptionStatus: "unavailable",
    coreVersion: MOCK_CORE_VERSION,
  };
}

/** In-memory only. Never persisted as "real" history. */
let fixtureConversations: ConversationSummary[] = [];
const fixtureMessages = new Map<string, MessageViewModel[]>();
let localSeq = 0;

function emptyConversations(): ListConversationsResult {
  return {
    conversations: [...fixtureConversations],
    status: status(),
  };
}

/**
 * Layout-only fixtures. Titles and senders are explicitly mock-labeled so
 * they cannot be mistaken for real accounts or houses.
 */
function buildFixtures(): {
  conversations: ConversationSummary[];
  messages: Map<string, MessageViewModel[]>;
} {
  const now = new Date().toISOString();
  const g1 = "mock-group-fixture-1";
  const g2 = "mock-group-fixture-2";

  const conversations: ConversationSummary[] = [
    {
      groupId: g1,
      title: "[MOCK FIXTURE] Layout DM",
      kind: "dm",
      lastPreview: "Mock preview — not a real message",
      updatedAt: now,
      isMockFixture: true,
    },
    {
      groupId: g2,
      title: "[MOCK FIXTURE] Layout channel",
      kind: "channel",
      lastPreview: "",
      updatedAt: null,
      isMockFixture: true,
    },
  ];

  const messages = new Map<string, MessageViewModel[]>();
  messages.set(g1, [
    {
      localId: "mock-msg-1",
      groupId: g1,
      senderLabel: "[MOCK] fixture-sender",
      body: "This is mock layout copy. It was never encrypted or delivered.",
      sentAt: now,
      isMock: true,
      encryptionStatus: "unavailable",
    },
  ]);
  messages.set(g2, []);

  return { conversations, messages };
}

export function createMockCitadelCore(): CitadelCoreApi {
  return {
    async getStatus(): Promise<CoreStatus> {
      return status();
    },

    async listConversations(): Promise<ListConversationsResult> {
      return emptyConversations();
    },

    async listMessages(groupId: string): Promise<ListMessagesResult> {
      const messages = fixtureMessages.get(groupId) ?? [];
      return { messages: [...messages], status: status() };
    },

    async sendMockLocalMessage(
      groupId: string,
      body: string,
    ): Promise<SendMockLocalResult> {
      const trimmed = body.trim();
      if (!trimmed) {
        throw new Error("Mock local send rejected empty body");
      }

      // Ensure the conversation exists as a mock-local thread if the user
      // composes without loading fixtures (still empty list by default).
      if (!fixtureConversations.some((c) => c.groupId === groupId)) {
        throw new Error(
          "No conversation selected. Mock shell has no real groups; load mock fixtures or select a fixture row.",
        );
      }

      localSeq += 1;
      const message: MessageViewModel = {
        localId: `mock-local-${localSeq}`,
        groupId,
        senderLabel: "[MOCK] local-composer",
        body: trimmed,
        sentAt: new Date().toISOString(),
        isMock: true,
        encryptionStatus: "unavailable",
      };

      const existing = fixtureMessages.get(groupId) ?? [];
      existing.push(message);
      fixtureMessages.set(groupId, existing);

      const conv = fixtureConversations.find((c) => c.groupId === groupId);
      if (conv) {
        conv.lastPreview = trimmed.slice(0, 80);
        conv.updatedAt = message.sentAt;
      }

      return { message, status: status() };
    },

    async loadMockFixtures(): Promise<ListConversationsResult> {
      const built = buildFixtures();
      fixtureConversations = built.conversations;
      fixtureMessages.clear();
      for (const [k, v] of built.messages) {
        fixtureMessages.set(k, v);
      }
      return emptyConversations();
    },

    async clearMockFixtures(): Promise<ListConversationsResult> {
      fixtureConversations = [];
      fixtureMessages.clear();
      localSeq = 0;
      return emptyConversations();
    },
  };
}

/** Singleton used by the default UI wiring. Tests may call createMockCitadelCore(). */
export const mockCitadelCore: CitadelCoreApi = createMockCitadelCore();
