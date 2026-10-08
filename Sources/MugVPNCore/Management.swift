import Foundation

/// A message from openvpn's management interface (doc/management-notes.txt).
public enum ManagementMessage: Equatable, Sendable {
    /// Real-time notification: `>TYPE:payload`.
    case realtime(type: String, payload: String)
    /// `SUCCESS: text` or `ERROR: text` answering a command.
    case success(String)
    case error(String)
    /// Any other line, e.g. part of a multi-line reply ended by `END`.
    case line(String)

    public static func parse(_ line: String) -> ManagementMessage {
        if line.hasPrefix(">"), let colon = line.firstIndex(of: ":") {
            let type = String(line[line.index(after: line.startIndex)..<colon])
            return .realtime(type: type, payload: String(line[line.index(after: colon)...]))
        }
        if line.hasPrefix("SUCCESS:") {
            return .success(line.dropFirst(8).trimmingCharacters(in: .whitespaces))
        }
        if line.hasPrefix("ERROR:") {
            return .error(line.dropFirst(6).trimmingCharacters(in: .whitespaces))
        }
        return .line(line)
    }
}

/// `>STATE:` payload: `time,state,description,local_ip,remote_ip,remote_port,local_port,local_ipv6`.
public struct ManagementState: Equatable, Sendable {
    public var time: Int
    public var name: String
    public var description: String
    public var localIP: String
    public var remoteIP: String
    public var localIPv6: String

    public init?(payload: String) {
        let f = payload.split(separator: ",", omittingEmptySubsequences: false).map(String.init)
        guard f.count >= 2, let t = Int(f[0]) else { return nil }
        time = t
        name = f[1]
        description = f.count > 2 ? f[2] : ""
        localIP = f.count > 3 ? f[3] : ""
        remoteIP = f.count > 4 ? f[4] : ""
        localIPv6 = f.count > 7 ? f[7] : ""
    }
}

/// Escape a string for a management command argument in double quotes.
public func managementQuote(_ s: String) -> String {
    "\"" + s.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"") + "\""
}

/// Blocking line client for a management Unix socket. The app's UI layer wraps
/// it in its own thread; the CLI uses it directly.
public final class ManagementConnection {
    private let fd: Int32
    private var buffer = Data()

    public init(socketPath: String, password: String?) throws {
        fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { throw POSIXError(.init(rawValue: errno) ?? .EIO) }
        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let bytes = Array(socketPath.utf8)
        guard bytes.count < MemoryLayout.size(ofValue: addr.sun_path) else {
            close(fd)
            throw POSIXError(.ENAMETOOLONG)
        }
        withUnsafeMutableBytes(of: &addr.sun_path) { raw in
            raw.copyBytes(from: bytes)
        }
        let rc = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                connect(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        guard rc == 0 else {
            let e = errno
            close(fd)
            throw POSIXError(.init(rawValue: e) ?? .EIO)
        }
        if let password {
            // openvpn prompts "ENTER PASSWORD:" without a newline, then answers SUCCESS.
            try send(password)
            while let line = try readLine() {
                if line.contains("SUCCESS: password is correct") { break }
                if line.contains("ERROR: bad password") { throw POSIXError(.EACCES) }
            }
        }
    }

    deinit { close(fd) }

    public func send(_ command: String) throws {
        let data = Array((command + "\n").utf8)
        var off = 0
        while off < data.count {
            let n = data[off...].withUnsafeBytes { write(fd, $0.baseAddress, $0.count) }
            guard n > 0 else { throw POSIXError(.init(rawValue: errno) ?? .EIO) }
            off += n
        }
    }

    /// A command with a descriptor for openvpn (the utun for OPENTUN).
    public func send(_ command: String, passing passed: Int32) throws {
        guard sendWithDescriptor(socket: fd, Data((command + "\n").utf8), passing: passed) else {
            throw POSIXError(.init(rawValue: errno) ?? .EIO)
        }
    }

    /// Next line, or nil when openvpn closed the socket. "ENTER PASSWORD:" has
    /// no newline, so it is returned as soon as it arrives.
    public func readLine() throws -> String? {
        while true {
            if let nl = buffer.firstIndex(of: 0x0A) {
                var lineData = buffer[buffer.startIndex..<nl]
                buffer.removeSubrange(buffer.startIndex...nl)
                if lineData.last == 0x0D { lineData = lineData.dropLast() }
                return String(decoding: lineData, as: UTF8.self)
            }
            let prompt = Data("ENTER PASSWORD:".utf8)
            if buffer.starts(with: prompt) {
                buffer.removeSubrange(buffer.startIndex..<buffer.startIndex + prompt.count)
                return "ENTER PASSWORD:"
            }
            var chunk = [UInt8](repeating: 0, count: 4096)
            let n = read(fd, &chunk, chunk.count)
            if n == 0 { return buffer.isEmpty ? nil : String(decoding: buffer.removeAllAndReturn(), as: UTF8.self) }
            guard n > 0 else {
                if errno == EINTR { continue }
                throw POSIXError(.init(rawValue: errno) ?? .EIO)
            }
            buffer.append(contentsOf: chunk[0..<n])
        }
    }
}

/// `data` and the descriptor in one message (SCM_RIGHTS), as openvpn's
/// man_recv_with_fd expects them. False if it was not all sent.
public func sendWithDescriptor(socket: Int32, _ data: Data, passing passed: Int32) -> Bool {
    var bytes = [UInt8](data)
    let space = MemoryLayout<cmsghdr>.size + MemoryLayout<Int32>.size
    var control = [UInt8](repeating: 0, count: (space + 7) & ~7)
    let sent: Int = bytes.withUnsafeMutableBytes { raw in
        control.withUnsafeMutableBytes { ctl in
            var iov = iovec(iov_base: raw.baseAddress, iov_len: raw.count)
            return withUnsafeMutablePointer(to: &iov) { iovp in
                var msg = msghdr()
                msg.msg_iov = iovp
                msg.msg_iovlen = 1
                msg.msg_control = ctl.baseAddress
                msg.msg_controllen = socklen_t(ctl.count)
                let cmsg = ctl.baseAddress!.assumingMemoryBound(to: cmsghdr.self)
                cmsg.pointee.cmsg_len = socklen_t(space)
                cmsg.pointee.cmsg_level = SOL_SOCKET
                cmsg.pointee.cmsg_type = SCM_RIGHTS
                (ctl.baseAddress! + MemoryLayout<cmsghdr>.size).storeBytes(of: passed, as: Int32.self)
                return sendmsg(socket, &msg, 0)
            }
        }
    }
    return sent == bytes.count
}

private extension Data {
    mutating func removeAllAndReturn() -> Data {
        defer { removeAll() }
        return self
    }
}
