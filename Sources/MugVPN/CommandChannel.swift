import Foundation
import MugVPNCore

/// `MugVPN --command ...` reaches the running app through a socket in the user's own
/// Library (a folder only the user can open), and the app answers only its own user:
/// not other users, not sandboxed apps (they cannot reach the folder).
enum CommandChannel {
    static var path: String {
        FileManager.default.homeDirectoryForCurrentUser.path + "/Library/Application Support/MugVPN/ipc/command.sock"
    }

    /// The app's end: every complete request (a JSON array of arguments) goes to `handle`, on the main queue.
    final class Server {
        private var listener: DispatchSourceRead?
        private let handle: ([String]) -> Void

        init(handle: @escaping ([String]) -> Void) { self.handle = handle }

        func start() {
            let dir = (CommandChannel.path as NSString).deletingLastPathComponent
            try? FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true,
                                                     attributes: [.posixPermissions: 0o700])
            chmod(dir, 0o700)
            unlink(CommandChannel.path)
            let sock = socket(AF_UNIX, SOCK_STREAM, 0)
            guard sock >= 0, var addr = CommandChannel.address() else { return }
            let rc = withUnsafePointer(to: &addr) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(sock, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) }
            }
            guard rc == 0, Darwin.listen(sock, 8) == 0 else { close(sock); return }
            chmod(CommandChannel.path, 0o600)
            let source = DispatchSource.makeReadSource(fileDescriptor: sock, queue: .global())
            source.setEventHandler { [weak self] in
                let client = accept(sock, nil, nil)
                guard client >= 0 else { return }
                setNoSigPipe(client)
                self?.serve(client)
            }
            source.setCancelHandler { close(sock) }
            source.resume()
            listener = source
        }

        private func serve(_ client: Int32) {
            defer { close(client) }
            var uid: uid_t = 0, gid: gid_t = 0
            guard getpeereid(client, &uid, &gid) == 0, uid == getuid() else { return }
            var tv = timeval(tv_sec: 5, tv_usec: 0)
            setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
            var data = Data()
            var chunk = [UInt8](repeating: 0, count: 4096)
            while !data.contains(0x0A), data.count < 1 << 16 {
                let n = read(client, &chunk, chunk.count)
                guard n > 0 else { return }
                data.append(contentsOf: chunk[0..<n])
            }
            guard let line = data.split(separator: 0x0A).first,
                  let args = try? JSONSerialization.jsonObject(with: Data(line)) as? [String] else { return }
            _ = "ok\n".withCString { write(client, $0, 3) }
            DispatchQueue.main.async { self.handle(args) }
        }
    }

    static func address() -> sockaddr_un? {
        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let bytes = Array(path.utf8)
        guard bytes.count < MemoryLayout.size(ofValue: addr.sun_path) else { return nil }
        withUnsafeMutableBytes(of: &addr.sun_path) { $0.copyBytes(from: bytes) }
        return addr
    }

    /// The command line's end: send, wait for the app's "ok" (it may still be starting: up to 10 s).
    static func send(_ args: [String]) -> Bool {
        guard let json = try? JSONSerialization.data(withJSONObject: args) else { return false }
        let deadline = Date().addingTimeInterval(10)
        while Date() < deadline {
            let sock = socket(AF_UNIX, SOCK_STREAM, 0)
            if sock >= 0, var addr = address() {
                setNoSigPipe(sock)
                let rc = withUnsafePointer(to: &addr) {
                    $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(sock, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) }
                }
                if rc == 0 {
                    // Only the app running as this user (the socket's owner) is talked to.
                    var uid: uid_t = 0, gid: gid_t = 0
                    if getpeereid(sock, &uid, &gid) == 0, uid == getuid() {
                        let msg = json + Data("\n".utf8)
                        _ = msg.withUnsafeBytes { write(sock, $0.baseAddress, $0.count) }
                        var reply = [UInt8](repeating: 0, count: 8)
                        var tv = timeval(tv_sec: 10, tv_usec: 0)
                        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
                        let n = read(sock, &reply, reply.count)
                        close(sock)
                        return n >= 2 && reply[0] == UInt8(ascii: "o") && reply[1] == UInt8(ascii: "k")
                    }
                }
                close(sock)
            }
            Thread.sleep(forTimeInterval: 0.3)
        }
        return false
    }
}
