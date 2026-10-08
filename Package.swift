// swift-tools-version:5.10
import PackageDescription

let package = Package(
    name: "MugVPN",
    platforms: [.macOS(.v13)],
    targets: [
        // Shared by the app and the helper: config parsing and policy, the
        // management protocol, the XPC interface.
        .target(name: "MugVPNCore"),
        // The helper's logic, with the system behind protocols so it is testable.
        .target(name: "MugVPNHelperCore", dependencies: ["MugVPNCore"]),
        // The app's logic: management protocol, connection state machine,
        // profiles, settings. UI and system behind protocols, testable.
        .target(name: "MugVPNAppCore", dependencies: ["MugVPNCore"]),
        .executableTarget(name: "MugVPN", dependencies: ["MugVPNCore", "MugVPNAppCore"]),
        // The few system calls Swift cannot make: start openvpn as another user, open a utun.
        .target(name: "MugVPNSys"),
        .executableTarget(name: "MugVPNHelper", dependencies: ["MugVPNCore", "MugVPNHelperCore", "MugVPNSys"]),
        // Logic tests (layer L of the test plan). A plain executable: the Command
        // Line Tools ship without XCTest.
        .executableTarget(name: "MugVPNTests", dependencies: ["MugVPNCore", "MugVPNHelperCore", "MugVPNAppCore"],
                          path: "Tests/Logic"),
    ]
)
