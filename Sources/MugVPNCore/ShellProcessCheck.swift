import Foundation

/// Process checks for MugVPN's shell scripts (the uninstall command without the helper, the boot cleanup).
public enum ShellProcessCheck {
    /// A pgrep -f/pkill -f pattern for `text` that never matches its own text: a shell running a script that holds
    /// it is never taken for the process. Unanchored: the helper registered through SMAppService runs with the
    /// relative argv[0] Contents/MacOS/MugVPNHelper, a plain launch daemon with an absolute one.
    public static func pattern(_ text: String) -> String {
        let escaped = text.map { ".[]()*+?^$|{}\\".contains($0) ? "\\\($0)" : String($0) }
        guard let last = escaped.last else { return "" }
        return escaped.dropLast().joined() + "[" + last + "]"
    }
    public static let helperPattern = pattern("Contents/MacOS/MugVPNHelper")

    /// `none_left PATTERN SECONDS`: returns 0 once no process matches (pgrep 1), 1 when one still does after SECONDS
    /// (looked at every half second); any other answer of pgrep tells nothing: `onError` runs and the script exits 1.
    public static func noneLeftFunction(onError: String) -> String {
        "none_left() { i=0; while :; do pgrep -f \"$1\" >/dev/null; r=$?; [ $r -eq 1 ] && return 0; "
            + "[ $r -eq 0 ] || { \(onError); exit 1; }; [ $i -ge $(($2 * 2)) ] && return 1; i=$((i + 1)); sleep 0.5; done; }; "
    }

    /// `gone_from_launchd LABEL SECONDS`: returns 0 once launchd says it has no such system service (status 113, or
    /// "Could not find service"), 1 when it still has it (or answers anything else) after SECONDS: a job bootout
    /// was asked for may take its time to stop (the helper takes its tunnels down first).
    public static let goneFromLaunchdFunction =
        "gone_from_launchd() { i=0; while :; do out=$(launchctl print \"system/$1\" 2>&1); r=$?; "
        + "{ [ $r -eq 113 ] || echo \"$out\" | grep -q 'Could not find service'; } && return 0; "
        + "[ $i -ge $(($2 * 2)) ] && return 1; i=$((i + 1)); sleep 0.5; done; }; "

    /// `text` single-quoted for sh.
    public static func quoted(_ text: String) -> String { "'" + text.replacingOccurrences(of: "'", with: "'\\''") + "'" }
}
