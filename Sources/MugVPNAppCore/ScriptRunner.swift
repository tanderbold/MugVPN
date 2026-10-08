import Foundation
import MugVPNCore

/// The user's own scripts beside a profile: `<name>_pre.sh` before
/// connecting, `<name>_up.sh` once connected, `<name>_down.sh` before
/// disconnecting. They run as the user, never as root.
public enum ScriptRunner {
    public enum Phase: String, Sendable { case pre, up, down }

    public struct Plan: Equatable, Sendable {
        public var path: String
        public var logPath: String
        public var timeout: Int
        /// false: start it and go on without waiting for its exit code.
        public var waitForExit: Bool
    }

    public enum Exit: Equatable, Sendable { case exited(Int32), timedOut }
    public enum Outcome: Equatable, Sendable { case proceed, cancelConnection, connectedWithErrors }

    /// - entries: the names in a folder, as stored. A script runs only under its exact name:
    ///   the disk would also open "x_pre.\u{17F}h" or "X_PRE.SH" for "x_pre.sh".
    public static func plan(_ p: Profile, _ phase: Phase, settings: Settings, logsDir: String,
                            entries: (String) -> [String]) -> Plan? {
        let dir = (p.path as NSString).deletingLastPathComponent
        let name = "\(p.name)_\(phase.rawValue).sh"
        guard entries(dir).contains(where: { $0.unicodeScalars.elementsEqual(name.unicodeScalars) }) else { return nil }
        let path = "\(dir)/\(name)"
        let timeout: Int
        switch phase {
        case .pre: timeout = settings.preconnectScriptTimeout
        case .up: timeout = settings.connectScriptTimeout
        case .down: timeout = settings.disconnectScriptTimeout
        }
        return Plan(path: path, logPath: "\(logsDir)/\(p.name)_\(phase.rawValue).log", timeout: timeout,
                    waitForExit: timeout > 0)
    }

    public static func outcome(_ phase: Phase, _ exit: Exit) -> Outcome {
        let ok = exit == .exited(0)
        switch phase {
        case .pre: return ok ? .proceed : .cancelConnection
        case .up: return ok ? .proceed : .connectedWithErrors
        case .down: return .proceed
        }
    }

    /// Variables for the scripts: the profile's own `setenv`, what the server
    /// pushed (`echo setenv`), and the connection's details. A server cannot
    /// set variables that change how programs run (PATH, DYLD_*, ...).
    public static func environment(profile: Profile, directives: [ConfigDirective], pushed: [(String, String)],
                                   localIP: String, localIPv6: String) -> [String: String] {
        var env: [String: String] = [:]
        for d in directives where d.name == "setenv" && d.args.count == 2 && d.args[0] != "opt" && safeName(d.args[0])
            && !protected(d.args[0]) {
            env[d.args[0]] = d.args[1]
        }
        for (k, v) in pushed where safeName(k) && !protected(k) {
            env[k] = v
        }
        env["config"] = (profile.path as NSString).lastPathComponent
        env["profile"] = profile.name
        if !localIP.isEmpty { env["ifconfig_local"] = localIP }
        if !localIPv6.isEmpty { env["ifconfig_ipv6_local"] = localIPv6 }
        return env
    }

    static func safeName(_ s: String) -> Bool {
        guard let f = s.first, f.isLetter || f == "_" else { return false }
        return s.allSatisfy { $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "_") }
    }

    /// Variables that change how a shell or another program runs: neither a
    /// server nor a profile may set them for the user's scripts.
    static func protected(_ s: String) -> Bool {
        let u = s.uppercased()
        let names: Set<String> = [
            "PATH", "HOME", "USER", "LOGNAME", "SHELL", "IFS", "ENV", "BASH_ENV", "TMPDIR", "LANG", "SHELLOPTS",
            "BASHOPTS", "PS1", "PS2", "PS3", "PS4", "PROMPT_COMMAND", "CDPATH", "GLOBIGNORE", "HISTFILE", "ZDOTDIR",
            "MAIL", "MAILPATH", "OLDPWD", "PWD", "SHLVL", "TERMINFO", "TERM", "EDITOR", "VISUAL", "PAGER", "INPUTRC",
            "FPATH", "MANPATH", "POSIXLY_CORRECT", "TZDIR",
        ]
        let prefixes = ["DYLD_", "LD_", "LC_", "BASH_", "PERL", "PYTHON", "RUBY", "GEM_", "NODE_", "NPM_", "GIT_",
                        "SSH_", "OPENSSL_", "SSL_", "CURL_", "JAVA_", "_JAVA", "MALLOC", "XPC_", "__CF", "HTTP", "ZSH",
                        "DOCKER_", "KUBE", "AWS_", "AZURE_", "GOOGLE_", "GCLOUD", "CLOUDSDK_", "GNUPG", "GPG_", "XDG_",
                        "LUA_", "PHP", "TCL", "LESS", "GO", "CARGO", "RUST", "PIP_", "CONDA", "VAULT_", "TF_", "HELM_",
                        "ANSIBLE", "TERRAFORM", "NIX_", "HOMEBREW_", "SUDO_"]
        // Anything that points programs at hosts, certificates, keys, credentials or other configuration.
        let parts = ["PROXY", "CA_BUNDLE", "CA_CERT", "CAFILE", "CA_PATH", "CERT", "KEY", "TOKEN", "SECRET", "PASS",
                     "AUTH", "CRED", "CONFIG", "_HOST", "HOST_", "_URL", "URL_", "ENDPOINT", "_INIT", "RC", "PATH", "HOME",
                     "SOCK", "DIR"]
        return names.contains(u) || prefixes.contains { u.hasPrefix($0) } || parts.contains { u.contains($0) }
    }

    /// What a script starts with: nothing of the app's own environment, a fixed
    /// PATH and the user's basics, then the connection's variables.
    public static func processEnvironment(home: String, user: String, extra: [String: String]) -> [String: String] {
        let base = ["PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": home, "USER": user, "LOGNAME": user,
                    "SHELL": "/bin/sh", "TMPDIR": "/tmp", "LANG": "en_US.UTF-8"]
        return extra.merging(base) { $1 }
    }
}

/// Runs a script as the user (Process in the app, a fake in tests); kills it
/// at the plan's timeout and reports `.timedOut`. A plan that does not wait
/// reports `.exited(0)` at once.
public protocol ScriptExecutor: AnyObject {
    func run(_ plan: ScriptRunner.Plan, env: [String: String], completion: @escaping (ScriptRunner.Exit) -> Void)
}

/// What ConnectionManager needs to run the scripts.
public struct ScriptSupport {
    public var executor: ScriptExecutor
    public var settings: () -> Settings
    public var logsDir: String
    public var entries: (String) -> [String]

    public init(executor: ScriptExecutor, settings: @escaping () -> Settings, logsDir: String,
                entries: @escaping (String) -> [String]) {
        self.executor = executor
        self.settings = settings
        self.logsDir = logsDir
        self.entries = entries
    }

    func plan(_ p: Profile, _ phase: ScriptRunner.Phase) -> ScriptRunner.Plan? {
        ScriptRunner.plan(p, phase, settings: settings(), logsDir: logsDir, entries: entries)
    }
}
