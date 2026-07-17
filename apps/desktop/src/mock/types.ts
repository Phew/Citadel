/**
 * Typed surface the desktop UI expects from citadel-core.
 *
 * M2 uses a clearly labeled MOCK implementation only.
 * M3 will swap the transport to real Tauri commands backed by citadel-core.
 *
 * Security note (INV-4 / INV-5):
 * - UI must never invent encryption success, verified users, or backend reachability.
 * - Mock status always reports mode "mock" and encryptionStatus "unavailable".
 */

/** How the shell is talking to core. */
export type CoreMode = "mock";

/**
 * Honest connection picture for the shell.
 * "unavailable" means no real backend / no real core session — never "connected"
 * while running pure mock.
 */
export type BackendReachability = "unavailable" | "unknown";

/**
 * Encryption state as known to the UI.
 * Mock path must not claim messages are E2E encrypted.
 */
export type EncryptionStatus =
  | "unavailable" // real MLS status not available (mock / no session)
  | "unknown"; // reserved for future real-core transitional states

export interface CoreStatus {
  /** Always "mock" for this M2 scaffolding. */
  mode: CoreMode;
  /** Human-readable label forced into chrome so mock is never silent. */
  mockLabel: string;
  /** Backend services are not contacted from the mock shell. */
  backend: BackendReachability;
  /** No real account session in mock mode. */
  session: SessionInfo | null;
  /** Never "encrypted" in mock mode. */
  encryptionStatus: EncryptionStatus;
  /** citadel-core crate version when known; mock uses a fixed string. */
  coreVersion: string;
}

export interface SessionInfo {
  /** Null until a real core session exists. Mock keeps this null. */
  accountId: string | null;
  handle: string | null;
}

export type ConversationKind = "dm" | "channel";

/**
 * Conversation list row.
 * Mock fixtures (if any) must set `isMockFixture: true`.
 */
export interface ConversationSummary {
  groupId: string;
  title: string;
  kind: ConversationKind;
  /** Preview text — mock may use empty string. */
  lastPreview: string;
  /** ISO timestamp or null when empty. */
  updatedAt: string | null;
  /**
   * True when this row is synthetic layout data for UI development.
   * Never present as a real user or channel.
   */
  isMockFixture: boolean;
}

export interface MessageViewModel {
  localId: string;
  groupId: string;
  /** Display name of sender; mock fixtures use labeled placeholders only. */
  senderLabel: string;
  body: string;
  /** ISO timestamp. */
  sentAt: string;
  /**
   * True for any content that did not come from real MLS decrypt.
   * Mock local drafts and fixtures must set this.
   */
  isMock: boolean;
  /**
   * Encryption claim for this row. Mock always "unavailable".
   * UI must not render a green "encrypted" badge for "unavailable".
   */
  encryptionStatus: EncryptionStatus;
}

export interface ListConversationsResult {
  conversations: ConversationSummary[];
  status: CoreStatus;
}

export interface ListMessagesResult {
  messages: MessageViewModel[];
  status: CoreStatus;
}

export interface SendMockLocalResult {
  message: MessageViewModel;
  status: CoreStatus;
}

/**
 * Desktop-facing core API. Real implementation will call Tauri commands;
 * mock implementation lives in ./citadel-core-mock.ts.
 */
export interface CitadelCoreApi {
  getStatus(): Promise<CoreStatus>;
  listConversations(): Promise<ListConversationsResult>;
  listMessages(groupId: string): Promise<ListMessagesResult>;
  /**
   * Local-only mock send for exercising the composer UI.
   * Does not encrypt, does not hit a network, does not create real users.
   */
  sendMockLocalMessage(groupId: string, body: string): Promise<SendMockLocalResult>;
  /**
   * Optional: inject clearly labeled mock fixtures for layout work.
   * Default shell state remains empty / disconnected.
   */
  loadMockFixtures(): Promise<ListConversationsResult>;
  clearMockFixtures(): Promise<ListConversationsResult>;
}
