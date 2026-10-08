import Foundation
import MugVPNHelperCore

// What `route -n get` printed on the stand (macOS 14, 2026-10-08): the helper deletes
// a route only if this says it is there exactly as added.

private let tunnelNet = """
   route to: 10.94.0.0
destination: 10.94.0.0
       mask: 255.255.255.0
  interface: utun4
      flags: <UP,DONE,STATIC,PRCLONING>
"""
private let bestMatchDefault = """
   route to: 10.94.0.0
destination: default
       mask: 128.0.0.0
  interface: utun4
      flags: <UP,DONE,STATIC,PRCLONING,GLOBAL>
"""
private let lowerHalf = """
   route to: default
destination: default
       mask: 128.0.0.0
  interface: utun4
"""
private let hostViaGateway = """
   route to: 203.0.113.77
destination: 203.0.113.77
       mask: 255.255.255.255
    gateway: 192.168.64.1
  interface: en0
      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING>
"""
private let hostOnLink = """
   route to: 198.51.100.9
destination: 198.51.100.9
       mask: 255.255.255.255
  interface: en0
      flags: <UP,DONE,CLONING,STATIC>
"""
private let ipv6 = """
   route to: fd00:94::
destination: fd00:94::
       mask: ffff:ffff:ffff::
  interface: utun4
"""
private let notInTable = "route: writing to routing socket: not in table\n"

func registerRouteGetTests() {
    test("RG-01", "a route is there only as added: destination, mask and the way out") {
        let t = TunnelRoute(kind: .tunnel, net: "10.94.0.0", mask: "255.255.255.0", via: "utun4")
        expect(RouteGet.matches(tunnelNet, t))
        expect(!RouteGet.matches(tunnelNet, TunnelRoute(kind: .tunnel, net: "10.94.0.0", mask: "255.255.255.0", via: "utun5")),
               "another utun's")
        expect(!RouteGet.matches(bestMatchDefault, TunnelRoute(kind: .tunnel, net: "10.94.0.0", mask: "255.255.0.0", via: "utun4")),
               "the best match is not the route")
        expect(RouteGet.matches(lowerHalf, TunnelRoute(kind: .tunnel, net: "0.0.0.0", mask: "128.0.0.0", via: "utun4")), "0/1 prints as default")
        expect(!RouteGet.matches(lowerHalf, TunnelRoute(kind: .tunnel, net: "0.0.0.0", mask: "0.0.0.0", via: "utun4")))
        expect(RouteGet.matches(hostViaGateway, TunnelRoute(kind: .host, net: "203.0.113.77", mask: "255.255.255.255", via: "192.168.64.1")))
        expect(!RouteGet.matches(hostViaGateway, TunnelRoute(kind: .host, net: "203.0.113.77", mask: "255.255.255.255", via: "192.168.64.9")))
        expect(RouteGet.matches(hostOnLink, TunnelRoute(kind: .onLink, net: "198.51.100.9", mask: "255.255.255.255", via: "en0")))
        expect(!RouteGet.matches(hostOnLink, TunnelRoute(kind: .host, net: "198.51.100.9", mask: "255.255.255.255", via: "192.168.64.1")),
               "on-link is not via a gateway")
        expect(RouteGet.matches(ipv6, TunnelRoute(kind: .tunnel6, net: "fd00:94::", mask: "48", via: "utun4")))
        expect(!RouteGet.matches(ipv6, TunnelRoute(kind: .tunnel6, net: "fd00:94::", mask: "64", via: "utun4")), "the prefix length counts")
        expect(!RouteGet.matches(notInTable, t))
        expect(!RouteGet.matches("", t))
    }
}
