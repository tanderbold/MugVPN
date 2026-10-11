import Foundation

/// The sandbox openvpn runs in (privilege separation). Reading files is denied but for the system's own
/// (libraries, frameworks, /private/etc, devices), its run folder and its binary; writing only its socket
/// folder; nothing started (also through launchd); no IPC, hardware or preferences; only the system services
/// name lookups need.
public enum OpenVPNSandbox {
    /// What the system's libraries read (dyld's cache, time zones, resolver and SSL settings, devices).
    static let systemReadable = ["/System", "/usr/lib", "/usr/share", "/private/etc", "/private/var/db/timezone",
                                 "/private/var/db/dyld", "/Library/Apple/System", "/dev"]
    /// (openvpn opens "/" itself: its listing names only the top-level folders.)
    static let systemReadableFiles = ["/", "/private/var/run/resolv.conf"]

    public static func profile(binary: String, runDir: String, lookups: [String]) -> String {
        func quoted(_ s: String) -> String {
            "\"" + s.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"") + "\""
        }
        let readable = (systemReadable + [runDir]).map { "(subpath \(quoted($0)))" }
            + (systemReadableFiles + [binary]).map { "(literal \(quoted($0)))" }
        return """
            (version 1)
            (allow default)
            (deny file-write* (require-not (require-any (subpath \(quoted(runDir + "/sock"))) (literal "/dev/null") (literal "/dev/dtracehelper"))))
            (deny file-read*)
            (allow file-read-metadata)
            (allow file-read* \(readable.joined(separator: " ")))
            (deny process-fork)
            (deny process-exec (require-not (literal \(quoted(binary)))))
            (deny job-creation)
            (deny iokit-open)
            (deny ipc-posix*)
            (deny ipc-sysv*)
            (deny user-preference-write)
            (deny mach-register)
            (deny mach-lookup (require-not (require-any \(lookups.map { "(global-name \(quoted($0)))" }.joined(separator: " ")))))
            (deny network-outbound (remote unix-socket (subpath "/Library/Application Support/MugVPN")))
            (deny network-bind (local unix-socket (require-not (subpath \(quoted(runDir + "/sock"))))))
            """
    }
}
