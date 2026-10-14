import Foundation
import MugVPNAppCore
import MugVPNCore
import MugVPNUI
import ServiceManagement

// MugVPN: the interface (MugVPNUI) over the privileged helper, which runs openvpn.

#if MUGVPN_TESTING
/// The test build's subcommands of the helper's own registration.
func registration() -> [String: ([String]) -> Never] {
    let daemon = SMAppService.daemon(plistName: MugVPNIDs.helperPlist)
    func statusText(_ s: SMAppService.Status) -> String {
        switch s {
        case .notRegistered: return "not registered"
        case .enabled: return "enabled"
        case .requiresApproval: return "requires approval (System Settings > General > Login Items)"
        case .notFound: return "not found"
        @unknown default: return "unknown (\(s.rawValue))"
        }
    }
    return [
        "register": { _ in
            do { try daemon.register() } catch { print("register failed: \(error)") }
            print("helper: \(statusText(daemon.status))")
            exit(0)
        },
        "unregister": { _ in
            do { try daemon.unregister() } catch { print("unregister failed: \(error)") }
            print("helper: \(statusText(daemon.status))")
            exit(0)
        },
        "status": { args in
            print("helper: \(statusText(daemon.status))")
            if daemon.status == .enabled || args.contains("--xpc") {
                print("helper version: \(wait { XPCHelperClient.devProxy().version(reply: $0) })")
            }
            exit(0)
        },
    ]
}
let dev: (helper: (() -> MugVPNHelperProtocol)?, commands: [String: ([String]) -> Never]) = (XPCHelperClient.devProxy, registration())
#else
let dev: (helper: (() -> MugVPNHelperProtocol)?, commands: [String: ([String]) -> Never]) = (nil, [:])
#endif

MugVPNApp.run(Product(
    capabilities: .helper,
    makeBackend: {
        let helper = XPCHelperClient()
        return (Backend(helper: helper), ManagementTunnelTransport(UnixSocketTransport()))
    },
    makeHelperSetup: { SMHelperSetup() },
    runDir: MugVPNIDs.runDir,
    logsDir: "/Library/Logs/MugVPN",
    sharedDataPaths: [],
    systemParts: { keep in
        // Built step by step: the one-expression form crashed in release builds (Swift optimizer, 2026-10-07).
        var parts: [String] = [MugVPNIDs.runDir, MugVPNIDs.libexecDir, "/Library/Logs/MugVPN",
                               "/Library/LaunchDaemons/" + MugVPNIDs.helperPlist]
        if !keep { parts.append(MugVPNIDs.supportDir) }
        return parts
    },
    commandSocketPath: FileManager.default.homeDirectoryForCurrentUser.path + "/Library/Application Support/MugVPN/ipc/command.sock",
    engineVersion: { run in run(MugVPNIDs.libexecDir + "/openvpn", ["--version"]).components(separatedBy: "\n").first ?? "" },
    devHelper: dev.helper,
    devCommands: dev.commands))
