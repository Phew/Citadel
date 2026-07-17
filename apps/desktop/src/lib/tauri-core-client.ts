/**
 * Tauri-hosted mock citadel-core client.
 *
 * Used only when the UI runs inside the Tauri webview. Every call goes through
 * `invoke` to the Rust command scaffold, which is still a labeled MOCK
 * (no real MLS, no backend, no session).
 *
 * Browser `pnpm dev` keeps using the in-process TS mock instead.
 */

import { invoke } from "@tauri-apps/api/core";
import type {
  BackendReachability,
  CitadelCoreApi,
  ConversationKind,
  ConversationSummary,
  CoreStatus,
  EncryptionStatus,
  ListConversationsResult,
  ListMessagesResult,
  MessageViewModel,
  SendMockLocalResult,
} from "@/mock/types";

/** Wire shapes from serde(rename_all = "camelCase") on the Rust side. */
interface WireCoreStatus {
  mode: string;
  mockLabel: string;
  backend: string;
  session: { accountId: string | null; handle: string | null } | null;
  encryptionStatus: string;
  coreVersion: string;
}

interface WireConversation {
  groupId: string;
  title: string;
  kind: string;
  lastPreview: string;
  updatedAt: string | null;
  isMockFixture: boolean;
}

interface WireMessage {
  localId: string;
  groupId: string;
  senderLabel: string;
  body: string;
  sentAt: string;
  isMock: boolean;
  encryptionStatus: string;
}

interface WireListConversations {
  conversations: WireConversation[];
  status: WireCoreStatus;
}

interface WireListMessages {
  messages: WireMessage[];
  status: WireCoreStatus;
}

interface WireSendMockLocal {
  message: WireMessage;
  status: WireCoreStatus;
}

function asBackend(value: string): BackendReachability {
  if (value === "unavailable" || value === "unknown") return value;
  // Refuse to treat unexpected values as "connected".
  return "unknown";
}

function asEncryption(value: string): EncryptionStatus {
  if (value === "unavailable" || value === "unknown") return value;
  return "unavailable";
}

/**
 * Map host status into UI types, enforcing mock honesty.
 * Throws if the host claims a non-mock mode (should never happen on M2).
 */
export function mapCoreStatus(wire: WireCoreStatus): CoreStatus {
  if (wire.mode !== "mock") {
    throw new Error(
      `Expected mock core mode, got "${wire.mode}". Refusing to present non-mock status without real citadel-core.`,
    );
  }
  return {
    mode: "mock",
    mockLabel: wire.mockLabel,
    backend: asBackend(wire.backend),
    session: wire.session
      ? {
          accountId: wire.session.accountId,
          handle: wire.session.handle,
        }
      : null,
    encryptionStatus: asEncryption(wire.encryptionStatus),
    coreVersion: wire.coreVersion,
  };
}

function mapConversation(wire: WireConversation): ConversationSummary {
  const kind: ConversationKind = wire.kind === "channel" ? "channel" : "dm";
  return {
    groupId: wire.groupId,
    title: wire.title,
    kind,
    lastPreview: wire.lastPreview,
    updatedAt: wire.updatedAt,
    isMockFixture: wire.isMockFixture,
  };
}

function mapMessage(wire: WireMessage): MessageViewModel {
  return {
    localId: wire.localId,
    groupId: wire.groupId,
    senderLabel: wire.senderLabel,
    body: wire.body,
    sentAt: wire.sentAt,
    isMock: wire.isMock,
    encryptionStatus: asEncryption(wire.encryptionStatus),
  };
}

function mapListConversations(wire: WireListConversations): ListConversationsResult {
  return {
    conversations: wire.conversations.map(mapConversation),
    status: mapCoreStatus(wire.status),
  };
}

function mapListMessages(wire: WireListMessages): ListMessagesResult {
  return {
    messages: wire.messages.map(mapMessage),
    status: mapCoreStatus(wire.status),
  };
}

function mapSend(wire: WireSendMockLocal): SendMockLocalResult {
  return {
    message: mapMessage(wire.message),
    status: mapCoreStatus(wire.status),
  };
}

function invokeError(e: unknown): Error {
  if (e instanceof Error) return e;
  if (typeof e === "string") return new Error(e);
  return new Error(String(e));
}

/** CitadelCoreApi backed by Tauri invoke → Rust mock commands. */
export function createTauriMockCitadelCore(): CitadelCoreApi {
  return {
    async getStatus(): Promise<CoreStatus> {
      try {
        const wire = await invoke<WireCoreStatus>("core_get_status");
        return mapCoreStatus(wire);
      } catch (e) {
        throw invokeError(e);
      }
    },

    async listConversations(): Promise<ListConversationsResult> {
      try {
        const wire = await invoke<WireListConversations>("core_list_conversations");
        return mapListConversations(wire);
      } catch (e) {
        throw invokeError(e);
      }
    },

    async listMessages(groupId: string): Promise<ListMessagesResult> {
      try {
        const wire = await invoke<WireListMessages>("core_list_messages", {
          groupId,
        });
        return mapListMessages(wire);
      } catch (e) {
        throw invokeError(e);
      }
    },

    async sendMockLocalMessage(
      groupId: string,
      body: string,
    ): Promise<SendMockLocalResult> {
      try {
        const wire = await invoke<WireSendMockLocal>("core_send_mock_local", {
          groupId,
          body,
        });
        return mapSend(wire);
      } catch (e) {
        throw invokeError(e);
      }
    },

    async loadMockFixtures(): Promise<ListConversationsResult> {
      try {
        const wire = await invoke<WireListConversations>("core_load_mock_fixtures");
        return mapListConversations(wire);
      } catch (e) {
        throw invokeError(e);
      }
    },

    async clearMockFixtures(): Promise<ListConversationsResult> {
      try {
        const wire = await invoke<WireListConversations>("core_clear_mock_fixtures");
        return mapListConversations(wire);
      } catch (e) {
        throw invokeError(e);
      }
    },
  };
}
