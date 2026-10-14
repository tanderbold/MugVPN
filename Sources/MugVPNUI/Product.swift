import Foundation
import MugVPNAppCore
import MugVPNCore

/// What a product puts under the interface: its backend and the places it keeps things. The interface asks
/// `capabilities` what to offer, never which product it is.
public struct Product {
    public var capabilities: BackendCapabilities
    /// The backend and the channel to its sessions' management (made once, when the app starts).
    public var makeBackend: () -> (backend: Backend, transport: TunnelTransport)
    /// Its system part's registration (a helper's, a VPN configuration's).
    public var makeHelperSetup: () -> HelperSetup
    /// Where each session's files are (its log: `<runDir>/<id>/openvpn.log`), and the backend's logs.
    public var runDir: String
    public var logsDir: String
    /// Files of the user's it keeps outside the user's own folders (removed on uninstall).
    public var sharedDataPaths: [String]
    /// What uninstalling removes beside the user's files, as told before (keepProfiles).
    public var systemParts: (Bool) -> [String]
    /// The socket `--command` reaches the running app on.
    public var commandSocketPath: String
    /// The VPN engine's version line (diagnostics), with a way to run a tool (its output; stopped if it hangs).
    public var engineVersion: (_ run: (String, [String]) -> String) -> String
    /// The test build's developer command line: the helper's calls, and subcommands of the product's own.
    public var devHelper: (() -> MugVPNHelperProtocol)?
    public var devCommands: [String: ([String]) -> Never]
    /// Another product's profiles, offered once to import (its name, its profiles' folder) while this one has none.
    public var importProfilesFrom: (name: String, folder: String)?

    public init(capabilities: BackendCapabilities, makeBackend: @escaping () -> (backend: Backend, transport: TunnelTransport),
                makeHelperSetup: @escaping () -> HelperSetup, runDir: String, logsDir: String, sharedDataPaths: [String],
                systemParts: @escaping (Bool) -> [String], commandSocketPath: String, engineVersion: @escaping (_ run: (String, [String]) -> String) -> String,
                devHelper: (() -> MugVPNHelperProtocol)? = nil, devCommands: [String: ([String]) -> Never] = [:],
                importProfilesFrom: (name: String, folder: String)? = nil) {
        self.importProfilesFrom = importProfilesFrom
        self.capabilities = capabilities
        self.makeBackend = makeBackend
        self.makeHelperSetup = makeHelperSetup
        self.runDir = runDir
        self.logsDir = logsDir
        self.sharedDataPaths = sharedDataPaths
        self.systemParts = systemParts
        self.commandSocketPath = commandSocketPath
        self.engineVersion = engineVersion
        self.devHelper = devHelper
        self.devCommands = devCommands
    }
}

/// The product this app is (set once, before anything else runs).
var product: Product!

/// This app's bundle id (each product has its own; MugVPN's when run outside a bundle).
let ownBundleID = Bundle.main.bundleIdentifier ?? MugVPNIDs.appBundleID
