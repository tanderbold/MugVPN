// The 1280x640 picture for link previews (GitHub social preview, og:image).
//   swift tools/icon/social-preview.swift <icon-1024.png> <out.png>
import AppKit

let args = CommandLine.arguments
guard args.count == 3, let icon = NSImage(contentsOfFile: args[1]) else {
    print("usage: social-preview.swift <icon-1024.png> <out.png>")
    exit(2)
}
let w = 1280, h = 640
let rep = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: w, pixelsHigh: h, bitsPerSample: 8, samplesPerPixel: 4,
                           hasAlpha: true, isPlanar: false, colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0)!
NSGraphicsContext.saveGraphicsState()
NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: rep)
NSColor(calibratedRed: 0.09, green: 0.07, blue: 0.06, alpha: 1).setFill()
NSRect(x: 0, y: 0, width: w, height: h).fill()
icon.draw(in: NSRect(x: 60, y: 120, width: 400, height: 400))
func text(_ s: String, _ size: CGFloat, _ weight: NSFont.Weight, _ color: NSColor, _ y: CGFloat) {
    let attrs: [NSAttributedString.Key: Any] = [.font: NSFont.systemFont(ofSize: size, weight: weight), .foregroundColor: color]
    NSAttributedString(string: s, attributes: attrs).draw(at: NSPoint(x: 500, y: y))
}
let cream = NSColor(calibratedRed: 0.99, green: 0.97, blue: 0.92, alpha: 1)
let amber = NSColor(calibratedRed: 0.98, green: 0.67, blue: 0.13, alpha: 1)
text("MugVPN", 104, .heavy, cream, 380)
text("Several VPN connections at once", 44, .semibold, amber, 300)
text("A free macOS menu-bar client for OpenVPN profiles:", 30, .regular, cream, 220)
text("split DNS per connection, kill switch, leak checks.", 30, .regular, cream, 178)
text("Open source · MIT · Apple silicon + Intel · macOS 13+", 26, .regular, NSColor(white: 0.7, alpha: 1), 110)
NSGraphicsContext.restoreGraphicsState()
try! rep.representation(using: .png, properties: [:])!.write(to: URL(fileURLWithPath: args[2]))
print("==> \(args[2])")
