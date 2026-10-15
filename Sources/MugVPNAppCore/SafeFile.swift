import Foundation

/// A file read with one open, then checked on that descriptor (not the path: it could be swapped between): a regular
/// file only (never follows a link in its last part, never waits on a FIFO or device), at most `limit` bytes — its
/// last ones (`tail`), or none when it is larger (nil).
public enum SafeFile {
    public static func read(_ path: String, limit: Int, tail: Bool = false) -> Data? {
        let fd = open(path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        guard fd >= 0 else { return nil }
        defer { close(fd) }
        var st = stat()
        guard fstat(fd, &st) == 0, (st.st_mode & S_IFMT) == S_IFREG else { return nil }
        let size = Int(st.st_size)
        if size > limit {
            guard tail else { return nil }
            lseek(fd, off_t(size - limit), SEEK_SET)
        }
        var data = Data()
        var buf = [UInt8](repeating: 0, count: 65536)
        while data.count < limit {
            let n = Darwin.read(fd, &buf, min(buf.count, limit - data.count))
            guard n > 0 else { break }
            data.append(contentsOf: buf[0..<n])
        }
        return data
    }
}
