import SwiftUI
import Citadel

struct RootView: View {
    @EnvironmentObject var model: AppModel
    @State private var handle = ""
    @State private var peer = ""
    @State private var draft = ""
    @State private var showNewDm = false

    var body: some View {
        NavigationSplitView {
            List(selection: Binding(get: { model.selected }, set: { if let g = $0 { model.select(g) } })) {
                ForEach(model.conversations, id: \.groupId) { c in
                    VStack(alignment: .leading) {
                        Text(c.title ?? "Direct message").font(.headline)
                        Text("epoch \(c.epoch)").font(.caption).foregroundStyle(.secondary)
                    }
                    .tag(c.groupId)
                }
            }
            .navigationTitle(model.profile?.handle ?? "Citadel")
            .toolbar {
                ToolbarItem {
                    Button { showNewDm = true } label: { Label("New DM", systemImage: "square.and.pencil") }
                        .disabled(model.profile == nil)
                }
            }
            .frame(minWidth: 220)
        } detail: {
            if model.profile == nil {
                registerView
            } else if model.selected == nil {
                ContentUnavailableView("Pick a conversation", systemImage: "lock.shield", description: Text("or start a new DM with a KT-verified peer"))
            } else {
                conversationView
            }
        }
        .sheet(isPresented: $showNewDm) { newDmSheet }
        .safeAreaInset(edge: .bottom) { statusBar }
    }

    private var registerView: some View {
        VStack(spacing: 16) {
            Image(systemName: "lock.shield").font(.system(size: 48))
            Text("Register this device").font(.title2)
            Text("Your identity and device keys are generated here and never leave this Mac. The server only ever sees ciphertext.")
                .font(.callout).foregroundStyle(.secondary).multilineTextAlignment(.center).frame(maxWidth: 420)
            TextField("handle", text: $handle).textFieldStyle(.roundedBorder).frame(maxWidth: 280)
            Button("Register") { Task { await model.register(handle: handle) } }
                .keyboardShortcut(.defaultAction)
                .disabled(handle.isEmpty || model.busy)
        }
        .padding(40)
    }

    private var conversationView: some View {
        VStack(spacing: 0) {
            ScrollViewReader { proxy in
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 6) {
                        ForEach(model.messages, id: \.id) { m in
                            HStack {
                                if m.outgoing { Spacer(minLength: 80) }
                                Text(m.text)
                                    .padding(.horizontal, 12).padding(.vertical, 8)
                                    .background(m.outgoing ? Color.accentColor.opacity(0.25) : Color.secondary.opacity(0.15))
                                    .clipShape(RoundedRectangle(cornerRadius: 12))
                                if !m.outgoing { Spacer(minLength: 80) }
                            }
                            .id(m.id)
                        }
                    }
                    .padding()
                }
                .onChange(of: model.messages.count) { _, _ in
                    if let last = model.messages.last { proxy.scrollTo(last.id, anchor: .bottom) }
                }
            }
            Divider()
            HStack {
                TextField("Message (end-to-end encrypted)", text: $draft)
                    .textFieldStyle(.roundedBorder)
                    .onSubmit { sendDraft() }
                Button("Send") { sendDraft() }.disabled(draft.isEmpty)
            }
            .padding(10)
        }
    }

    private func sendDraft() {
        let text = draft
        draft = ""
        Task { await model.send(text) }
    }

    private var newDmSheet: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("New direct message").font(.title3)
            Text("The peer's identity key is verified against the key-transparency log before anything is sent.")
                .font(.caption).foregroundStyle(.secondary)
            TextField("peer handle", text: $peer).textFieldStyle(.roundedBorder)
            HStack {
                Spacer()
                Button("Cancel") { showNewDm = false }
                Button("Start") {
                    let h = peer
                    showNewDm = false
                    peer = ""
                    Task { await model.newDm(handles: [h], title: nil) }
                }
                .keyboardShortcut(.defaultAction)
                .disabled(peer.isEmpty)
            }
        }
        .padding(20)
        .frame(width: 380)
    }

    private var statusBar: some View {
        HStack(spacing: 8) {
            Circle().fill(model.connected ? Color.green : Color.gray).frame(width: 8, height: 8)
            Text(model.status).font(.caption).foregroundStyle(.secondary)
            if let warning = model.warning {
                Spacer()
                Text(warning).font(.caption).foregroundStyle(.orange).lineLimit(1)
                Button { model.warning = nil } label: { Image(systemName: "xmark.circle") }.buttonStyle(.plain)
            }
        }
        .padding(.horizontal, 12).padding(.vertical, 6)
        .background(.bar)
    }
}
