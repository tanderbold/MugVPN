import Foundation
import MugVPNAppCore

// L-CERT: a warning before a profile's client certificate stops working.

private let soon = """
-----BEGIN CERTIFICATE-----
MIIBcjCCARegAwIBAgIUTNfpzIXzMkRyMSy1ufaOULblylwwCgYIKoZIzj0EAwIw
DjEMMAoGA1UEAwwDdDEwMB4XDTI2MTAwOTEwNTUzNFoXDTI2MTAxOTEwNTUzNFow
DjEMMAoGA1UEAwwDdDEwMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE0XUKhMns
SyI/QaP0cieWzzeOk+wgjjD7m4LpmLAUOiiHyra3xnqG7hcJNmR2FCBCyJWDw84p
yp7JXOTfdJH4caNTMFEwHQYDVR0OBBYEFF+2aFuvl0iubwubrHbTYpNSkJDcMB8G
A1UdIwQYMBaAFF+2aFuvl0iubwubrHbTYpNSkJDcMA8GA1UdEwEB/wQFMAMBAf8w
CgYIKoZIzj0EAwIDSQAwRgIhAIAWd3qjbOZre+3b8VH5TiHy5IzItQViE5KLfmCo
tA79AiEAtNDiOKdnF5YDdi01W91wn6BMR1WpUHA58PHwP++u98I=
-----END CERTIFICATE-----
"""   // notAfter Oct 19 10:55:34 2026 GMT (UTCTime)
private let late = """
-----BEGIN CERTIFICATE-----
MIIBeDCCAR+gAwIBAgIUXHj5IV3zK42mdi/higLatMXnop8wCgYIKoZIzj0EAwIw
ETEPMA0GA1UEAwwGdDEwMDAwMCAXDTI2MTAwOTEwNTUzNFoYDzIwNTQwMjI0MTA1
NTM0WjARMQ8wDQYDVQQDDAZ0MTAwMDAwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNC
AAQo4uW2qA0xA7854TCva/rdLrhEF4vJvPVQu5tTftafngzW2aElcSjQ2kKlPtIS
ordETRbI2x/TRp654FvXPmu2o1MwUTAdBgNVHQ4EFgQU7RzkZg38pzEAh6DV0Qt6
MfEUtK0wHwYDVR0jBBgwFoAU7RzkZg38pzEAh6DV0Qt6MfEUtK0wDwYDVR0TAQH/
BAUwAwEB/zAKBggqhkjOPQQDAgNHADBEAiByNLQOF7lKmsrJeEqR7H46kuQVIdjM
QvM+gA0BsjFzrwIgEETGZjfoU6IXecaG0t2iyrQqEQ8Nfskd4xBJLt+M70A=
-----END CERTIFICATE-----
"""   // notAfter Feb 24 10:55:34 2054 GMT (GeneralizedTime)

func registerCertificateTests() {
    func date(_ s: String) -> Date {
        let f = ISO8601DateFormatter()
        return f.date(from: s)!
    }
    test("CERT-01", "a certificate's end date, in both time forms") {
        expectEqual(CertificateExpiry.notAfter(pem: soon), date("2026-10-19T10:55:34Z"))
        expectEqual(CertificateExpiry.notAfter(pem: late), date("2054-02-24T10:55:34Z"))
        expectEqual(CertificateExpiry.notAfter(pem: "-----BEGIN CERTIFICATE-----\nQ0E=\n-----END CERTIFICATE-----"), nil)
        expectEqual(CertificateExpiry.notAfter(pem: "garbage"), nil)
    }
    test("CERT-02", "warned within 30 days of the end and after it, not before") {
        let end = date("2026-10-19T10:55:34Z")
        expectEqual(CertificateExpiry.warning(notAfter: end, now: date("2026-09-01T00:00:00Z")), nil)
        expectEqual(CertificateExpiry.warning(notAfter: end, now: date("2026-10-09T10:55:34Z")), .expiresSoon(days: 10))
        expectEqual(CertificateExpiry.warning(notAfter: end, now: date("2026-10-20T00:00:00Z")), .expired)
    }
    test("CERT-03", "the client certificate of a profile: inline or a file beside it") {
        let inline = "client\nremote a 1194\n<cert>\n" + soon + "\n</cert>\n"
        expectEqual(CertificateExpiry.clientCertificate(config: inline, read: { _ in nil })?.trimmingCharacters(in: .whitespacesAndNewlines), soon)
        let file = "client\nremote a 1194\ncert keys/me.crt\n"
        expectEqual(CertificateExpiry.clientCertificate(config: file, read: { $0 == "keys/me.crt" ? late : nil }), late)
        expectEqual(CertificateExpiry.clientCertificate(config: "client\nremote a 1194\n", read: { _ in soon }), nil)
    }
}
