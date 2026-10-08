import Foundation

// A small test runner (the Command Line Tools ship without XCTest). Each test
// is one case of the test plan and is registered under its ID:
//
//     test("CFG-01", "several tokens") { expect(...) }
//
// `MugVPNTests` runs everything; `MugVPNTests CFG POL-0` runs the IDs with
// those prefixes. A case fails if any expectation in it fails or it throws.

struct TestCase {
    let id: String
    let title: String
    let body: () throws -> Void
}

nonisolated(unsafe) var registry: [TestCase] = []
nonisolated(unsafe) var currentFailures: [String] = []

func test(_ id: String, _ title: String, _ body: @escaping () throws -> Void) {
    registry.append(TestCase(id: id, title: title, body: body))
}

func expect(_ cond: @autoclosure () throws -> Bool, _ what: String = "",
            file: String = #fileID, line: Int = #line) {
    do {
        if try !cond() { currentFailures.append("\(what.isEmpty ? "expectation" : what) (\(file):\(line))") }
    } catch {
        currentFailures.append("\(what) threw \(error) (\(file):\(line))")
    }
}

func expectEqual<T: Equatable>(_ a: @autoclosure () throws -> T, _ b: @autoclosure () throws -> T,
                               _ what: String = "", file: String = #fileID, line: Int = #line) {
    do {
        let x = try a(), y = try b()
        if x != y { currentFailures.append("\(what.isEmpty ? "" : what + ": ")\(x) != \(y) (\(file):\(line))") }
    } catch {
        currentFailures.append("\(what) threw \(error) (\(file):\(line))")
    }
}

/// Expect `body` to throw; `matching` checks the error's description.
func expectThrows(_ what: String = "", matching: String? = nil, file: String = #fileID, line: Int = #line,
                  _ body: () throws -> Void) {
    do {
        try body()
        currentFailures.append("\(what.isEmpty ? "call" : what) did not throw (\(file):\(line))")
    } catch {
        if let m = matching, !"\(error)".contains(m) {
            currentFailures.append("\(what): error \"\(error)\" lacks \"\(m)\" (\(file):\(line))")
        }
    }
}

func runTests(filters: [String]) -> Int32 {
    let selected = registry.filter { c in filters.isEmpty || filters.contains { c.id.hasPrefix($0) } }
    var failed: [String] = []
    for c in selected {
        currentFailures = []
        do { try c.body() } catch { currentFailures.append("threw \(error)") }
        if !currentFailures.isEmpty {
            failed.append(c.id)
            print("FAIL \(c.id) \(c.title)")
            currentFailures.forEach { print("     \($0)") }
        }
    }
    let ids = Set(selected.map(\.id))
    print("\(selected.count - failed.count)/\(selected.count) cases passed (\(ids.count) IDs)")
    return failed.isEmpty ? 0 : 1
}
