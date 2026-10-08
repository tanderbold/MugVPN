// MugVPN's menu bar icon, after the app icon: a mug, steaming when connected.
// Monochrome templates (macOS tints them for light/dark menu bars and highlight).
//   swift tools/icon/draw-menubar.swift <out-dir> [preview-size]
// Writes MenuIcon-{idle,connecting,connected}.png (18 px) and @2x (36 px);
// with preview-size, also a large preview of each.
//   idle        the mug's outline, no steam
//   connecting  the outline with dotted steam
//   connected   a filled mug with steam
import AppKit

let args = CommandLine.arguments
let outDir = args.count > 1 ? args[1] : "."
let preview = args.count > 2 ? Int(args[2]) : nil

enum State: String, CaseIterable { case idle, connecting, connected }

/// The mug's body on a 100x100 canvas (y up): straight sides, a rounded bottom.
func bodyPath() -> NSBezierPath {
    let p = NSBezierPath()
    let left: CGFloat = 12, right: CGFloat = 66, top: CGFloat = 60, bottom: CGFloat = 8, r: CGFloat = 14
    p.move(to: NSPoint(x: left, y: top))
    p.line(to: NSPoint(x: left, y: bottom + r))
    p.appendArc(withCenter: NSPoint(x: left + r, y: bottom + r), radius: r, startAngle: 180, endAngle: 270)
    p.line(to: NSPoint(x: right - r, y: bottom))
    p.appendArc(withCenter: NSPoint(x: right - r, y: bottom + r), radius: r, startAngle: 270, endAngle: 360)
    p.line(to: NSPoint(x: right, y: top))
    p.close()
    return p
}

/// The handle: a "D" on the right side of the body.
func handlePath() -> NSBezierPath {
    let p = NSBezierPath()
    p.move(to: NSPoint(x: 66, y: 50))
    p.curve(to: NSPoint(x: 66, y: 20), controlPoint1: NSPoint(x: 92, y: 52), controlPoint2: NSPoint(x: 92, y: 18))
    return p
}

/// Three wisps of steam above the mug.
func steamPaths() -> [NSBezierPath] {
    [24, 39, 54].map { (x: CGFloat) in
        let p = NSBezierPath()
        p.move(to: NSPoint(x: x, y: 70))
        p.curve(to: NSPoint(x: x, y: 94), controlPoint1: NSPoint(x: x + 9, y: 78), controlPoint2: NSPoint(x: x - 9, y: 86))
        return p
    }
}

func draw(_ state: State, px: Int, background: NSColor? = nil) -> NSBitmapImageRep {
    let rep = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: px, pixelsHigh: px, bitsPerSample: 8,
                               samplesPerPixel: 4, hasAlpha: true, isPlanar: false, colorSpaceName: .deviceRGB,
                               bytesPerRow: 0, bitsPerPixel: 0)!
    NSGraphicsContext.saveGraphicsState()
    let g = NSGraphicsContext(bitmapImageRep: rep)!
    NSGraphicsContext.current = g
    let ctx = g.cgContext
    if let background {
        background.setFill()
        NSRect(x: 0, y: 0, width: px, height: px).fill()
    }
    ctx.scaleBy(x: CGFloat(px) / 100, y: CGFloat(px) / 100)
    // Thicker lines at small sizes so they survive 18 px.
    let line: CGFloat = px <= 18 ? 9 : px <= 36 ? 7.5 : 6
    NSColor.black.set()

    let body = bodyPath(), handle = handlePath()
    handle.lineWidth = line
    handle.lineCapStyle = .round
    handle.stroke()
    if state == .connected {
        body.fill()
    } else {
        body.lineWidth = line
        body.lineJoinStyle = .round
        body.stroke()
    }
    if state != .idle {
        for s in steamPaths() {
            s.lineWidth = line * 0.8
            s.lineCapStyle = .round
            if state == .connecting { s.setLineDash([line * 0.1, line * 1.7], count: 2, phase: 0) }
            s.stroke()
        }
    }
    NSGraphicsContext.restoreGraphicsState()
    return rep
}

try? FileManager.default.createDirectory(atPath: outDir, withIntermediateDirectories: true)
func write(_ rep: NSBitmapImageRep, _ name: String) {
    try! rep.representation(using: .png, properties: [:])!.write(to: URL(fileURLWithPath: outDir + "/" + name))
}
for s in State.allCases {
    write(draw(s, px: 18), "MenuIcon-\(s.rawValue).png")
    write(draw(s, px: 36), "MenuIcon-\(s.rawValue)@2x.png")
    if let preview { write(draw(s, px: preview, background: .white), "preview-\(s.rawValue).png") }
}
print("==> \(outDir)")
