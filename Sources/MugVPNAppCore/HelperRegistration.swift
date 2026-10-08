import Foundation

/// Where the app may register its root helper from. launchd starts the helper
/// from the app bundle at every boot, so the bundle must stay where it was
/// registered and not be a disk image (anyone can mount another image under
/// the same /Volumes name) or a Downloads folder.
public enum HelperRegistration {
    /// Why the app cannot register from `bundlePath`, or nil when it can.
    public static func problem(bundlePath: String) -> String? {
        let path = (bundlePath as NSString).standardizingPath
        let parts = path.split(separator: "/")
        guard path.hasPrefix("/Applications/"), parts.count == 2, path.hasSuffix(".app") else {
            return "Move MugVPN to the Applications folder, open it from there and connect again."
        }
        return nil
    }
}
