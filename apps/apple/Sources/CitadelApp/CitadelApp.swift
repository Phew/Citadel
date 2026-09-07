import SwiftUI
import Citadel

@main
struct CitadelMacApp: App {
    @StateObject private var model = AppModel()

    var body: some Scene {
        WindowGroup("Citadel") {
            RootView()
                .environmentObject(model)
                .frame(minWidth: 820, minHeight: 520)
        }
    }
}
