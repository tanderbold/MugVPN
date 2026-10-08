// Turn a square artwork that shows the icon's rounded tile on a solid
// background into a macOS app icon master: the tile cut out with
// transparent corners, scaled to 824 px and centred on a 1024 px canvas
// (Apple's icon grid), with a soft drop shadow.
//   swift tools/icon/prepare-icon.swift <artwork.png> <out-1024.png>
import AppKit

let args = CommandLine.arguments
guard args.count == 3, let src = NSImage(contentsOfFile: args[1]),
      let cg = src.cgImage(forProposedRect: nil, context: nil, hints: nil) else {
    print("usage: prepare-icon.swift <artwork.png> <out-1024.png>")
    exit(2)
}
let rep = NSBitmapImageRep(cgImage: cg)
let w = rep.pixelsWide, h = rep.pixelsHigh

func luma(_ x: Int, _ y: Int) -> CGFloat {
    guard let c = rep.colorAt(x: x, y: y)?.usingColorSpace(.sRGB) else { return 0 }
    return 0.2126 * c.redComponent + 0.7152 * c.greenComponent + 0.0722 * c.blueComponent
}

// The background is the colour at the corners; the tile starts where the
// middle row/column first clearly differs from it (lighter or darker).
let background = (luma(2, 2) + luma(w - 3, 2) + luma(2, h - 3) + luma(w - 3, h - 3)) / 4
func firstBright(_ points: [(Int, Int)]) -> Int {
    points.firstIndex { abs(luma($0.0, $0.1) - background) > 0.06 } ?? 0
}
let left = firstBright((0..<w).map { ($0, h / 2) })
let right = w - 1 - firstBright((0..<w).reversed().map { ($0, h / 2) })
let top = firstBright((0..<h).map { (w / 2, $0) })
let bottom = h - 1 - firstBright((0..<h).reversed().map { (w / 2, $0) })
let tileW = right - left + 1, tileH = bottom - top + 1
print("tile: x \(left)...\(right), y \(top)...\(bottom) (\(tileW)x\(tileH)) on \(w)x\(h), background luma \(String(format: "%.3f", background))")

// Pixel rows count from the top; CoreGraphics from the bottom.
let crop = cg.cropping(to: CGRect(x: left, y: top, width: tileW, height: tileH))!

let size = 1024, inner: CGFloat = 824, margin = (CGFloat(size) - inner) / 2
let out = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: size, pixelsHigh: size, bitsPerSample: 8, samplesPerPixel: 4,
                           hasAlpha: true, isPlanar: false, colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0)!
NSGraphicsContext.saveGraphicsState()
NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: out)
let ctx = NSGraphicsContext.current!.cgContext
ctx.interpolationQuality = .high
let rect = CGRect(x: margin, y: margin, width: inner, height: inner)
let shape = CGPath(roundedRect: rect, cornerWidth: inner * 0.2237, cornerHeight: inner * 0.2237, transform: nil)

ctx.saveGState()
ctx.setShadow(offset: CGSize(width: 0, height: -10), blur: 24, color: NSColor(white: 0, alpha: 0.3).cgColor)
ctx.addPath(shape)
ctx.setFillColor(NSColor.black.cgColor)
ctx.fillPath()
ctx.restoreGState()

ctx.saveGState()
ctx.addPath(shape)
ctx.clip()
// Slightly larger than the tile, so its own anti-aliased edge stays outside the clip.
ctx.draw(crop, in: rect.insetBy(dx: -inner * 0.006, dy: -inner * 0.006))
ctx.restoreGState()

NSGraphicsContext.restoreGraphicsState()
try! out.representation(using: .png, properties: [:])!.write(to: URL(fileURLWithPath: args[2]))
print("==> \(args[2])")
