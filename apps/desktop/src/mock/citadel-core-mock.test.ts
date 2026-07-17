import { describe, expect, it } from "vitest";
import { createMockCitadelCore, MOCK_LABEL } from "./citadel-core-mock";

describe("mock citadel-core (honest empty / disconnected)", () => {
  it("reports mock mode, unavailable backend, no session, no encryption claim", async () => {
    const core = createMockCitadelCore();
    const status = await core.getStatus();

    expect(status.mode).toBe("mock");
    expect(status.mockLabel).toBe(MOCK_LABEL);
    expect(status.backend).toBe("unavailable");
    expect(status.session).toBeNull();
    expect(status.encryptionStatus).toBe("unavailable");
    expect(status.coreVersion).toMatch(/mock/i);
  });

  it("starts with an empty conversation list (no fake users/inbox)", async () => {
    const core = createMockCitadelCore();
    const { conversations, status } = await core.listConversations();

    expect(conversations).toEqual([]);
    expect(status.backend).toBe("unavailable");
    expect(status.encryptionStatus).toBe("unavailable");
  });

  it("labels fixture rows as mock fixtures, never as real accounts", async () => {
    const core = createMockCitadelCore();
    const { conversations } = await core.loadMockFixtures();

    expect(conversations.length).toBeGreaterThan(0);
    for (const c of conversations) {
      expect(c.isMockFixture).toBe(true);
      expect(c.title).toMatch(/\[MOCK FIXTURE\]/);
    }

    const first = conversations[0];
    const { messages, status } = await core.listMessages(first.groupId);
    expect(status.encryptionStatus).toBe("unavailable");
    for (const m of messages) {
      expect(m.isMock).toBe(true);
      expect(m.encryptionStatus).toBe("unavailable");
      expect(m.senderLabel).toMatch(/\[MOCK\]/);
    }
  });

  it("mock local send tags messages as mock and not encrypted", async () => {
    const core = createMockCitadelCore();
    const { conversations } = await core.loadMockFixtures();
    const groupId = conversations[0].groupId;

    const { message, status } = await core.sendMockLocalMessage(
      groupId,
      "hello mock",
    );

    expect(message.isMock).toBe(true);
    expect(message.encryptionStatus).toBe("unavailable");
    expect(message.senderLabel).toMatch(/\[MOCK\]/);
    expect(message.body).toBe("hello mock");
    expect(status.mode).toBe("mock");
    expect(status.session).toBeNull();
  });

  it("rejects mock send with no conversation (honest empty state)", async () => {
    const core = createMockCitadelCore();
    await expect(
      core.sendMockLocalMessage("missing", "x"),
    ).rejects.toThrow(/No conversation/i);
  });

  it("clearMockFixtures returns to empty disconnected state", async () => {
    const core = createMockCitadelCore();
    await core.loadMockFixtures();
    const cleared = await core.clearMockFixtures();
    expect(cleared.conversations).toEqual([]);
    expect(cleared.status.backend).toBe("unavailable");
    expect(cleared.status.session).toBeNull();
  });
});
