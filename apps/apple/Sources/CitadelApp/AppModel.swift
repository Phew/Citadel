import Foundation
import Citadel

/// The host-side state. Every call into the core happens off the main
/// thread; every published change lands back on it. The host never decides
/// who to trust: `lookup`/`createDm` succeed only after the core has
/// KT-verified the peer.
@MainActor
final class AppModel: ObservableObject {
    @Published var profile: Profile?
    @Published var conversations: [Conversation] = []
    @Published var selected: String?
    @Published var messages: [Message] = []
    @Published var status: String = "opening profile…"
    @Published var warning: String?
    @Published var connected = false
    @Published var busy = false

    private var client: Client?
    private var listener: Listener?

    init() {
        Task { await open() }
    }

    /// Profile root and credential-store service name, overridable so two
    /// instances can run on one machine during development.
    private static func profileRoot() -> String {
        if let root = ProcessInfo.processInfo.environment["CITADEL_PROFILE"], !root.isEmpty {
            return root
        }
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        return base.appendingPathComponent("Citadel", isDirectory: true).path
    }

    private static func credentialService() -> String {
        ProcessInfo.processInfo.environment["CITADEL_KEYCHAIN_SERVICE"].flatMap { $0.isEmpty ? nil : $0 } ?? "Citadel"
    }

    func open() async {
        do {
            let root = Self.profileRoot()
            try FileManager.default.createDirectory(atPath: root, withIntermediateDirectories: true)
            let service = Self.credentialService()
            let client = try await Task.detached { try Client.openDev(profileRoot: root, credentialService: service) }.value
            self.client = client
            self.profile = try client.profile()
            if profile != nil {
                await login()
            } else {
                status = "no profile on this device"
            }
        } catch {
            status = "open failed: \(error)"
        }
    }

    func register(handle: String) async {
        guard let client else { return }
        busy = true; defer { busy = false }
        do {
            let profile = try await Task.detached { try client.register(handle: handle) }.value
            self.profile = profile
            status = "registered \(profile.handle)"
            startGateway()
            refresh()
        } catch {
            warning = "register: \(error)"
        }
    }

    func login() async {
        guard let client else { return }
        busy = true; defer { busy = false }
        do {
            let profile = try await Task.detached { try client.login() }.value
            self.profile = profile
            status = "signed in as \(profile.handle)"
            startGateway()
            _ = try? await Task.detached { try client.sync() }.value
            refresh()
        } catch {
            status = "login failed: \(error)"
        }
    }

    func newDm(handles: [String], title: String?) async {
        guard let client else { return }
        busy = true; defer { busy = false }
        do {
            let groupId = try await Task.detached { try client.createDm(handles: handles, title: title) }.value
            refresh()
            selected = groupId
            select(groupId)
        } catch {
            warning = "new DM: \(error)"
        }
    }

    func send(_ text: String) async {
        guard let client, let group = selected, !text.isEmpty else { return }
        do {
            try await Task.detached { try client.send(groupId: group, text: text) }.value
            select(group)
        } catch {
            warning = "send: \(error)"
        }
    }

    func select(_ groupId: String) {
        selected = groupId
        guard let client else { return }
        messages = (try? client.messages(groupId: groupId)) ?? []
    }

    func refresh() {
        guard let client else { return }
        conversations = (try? client.conversations()) ?? []
        if let selected { messages = (try? client.messages(groupId: selected)) ?? [] }
    }

    private func startGateway() {
        guard let client else { return }
        let listener = Listener { [weak self] event in
            Task { @MainActor in self?.handle(event) }
        }
        self.listener = listener
        client.startGateway(listener: listener)
    }

    private func handle(_ event: Event) {
        switch event {
        case .gatewayConnected: connected = true
        case .gatewayDisconnected: connected = false
        case .conversationJoined, .conversationCreated, .epochAdvanced: refresh()
        case .messageReceived(let groupId, _, _):
            refresh()
            if groupId == selected { select(groupId) }
        case .messageSent: refresh()
        case .warning(let text): warning = text
        case .registered, .loggedIn: break
        }
    }
}

/// Bridges the core's callback interface to a closure. Called on a core thread.
final class Listener: EventListener, @unchecked Sendable {
    private let onEventClosure: @Sendable (Event) -> Void
    init(_ onEvent: @escaping @Sendable (Event) -> Void) { self.onEventClosure = onEvent }
    func onEvent(event: Event) { onEventClosure(event) }
}
