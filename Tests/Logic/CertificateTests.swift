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

private let noPassP12 = Data(base64Encoded: "MIIEFAIBAzCCA8IGCSqGSIb3DQEHAaCCA7MEggOvMIIDqzCCAloGCSqGSIb3DQEHBqCCAkswggJHAgEAMIICQAYJKoZIhvcNAQcBMF8GCSqGSIb3DQEFDTBSMDEGCSqGSIb3DQEFDDAkBBD4FF2Q2kcoaFR3Wm2XMGHOAgIIADAMBggqhkiG9w0CCQUAMB0GCWCGSAFlAwQBKgQQvObjTVDAvou45XkU2mJLeoCCAdD2vlf0Mk2bUmHPeQl0cS3y0BnOYj9Zdcowkq9oeNkpVTfoOL6F+LJXM8as7hxCEChMLwnnjJupO1tFDRpDT2YN/V/ygxGjroRfJ09bXCYsV+sKHLLC6yM31gcl5frGaAkI9j78T3w1FXhs+o99YAzw3xLqSkKhnm9RgIvkb6vvTP4bXivxjjOBUYlKBV/vP2rKHf+OzOlixcsR+Piqjz368tQLsw/IzWq+qHVFL6zO8SclwzIj4O3/DojX0LeGwnNZDoqSJxXM27PJzXwsnv9ajgVtBGahGLEnhPvIU0TGC6cXv3jINs6shPhF1n5lHQnwjw7A6vBC8YbYIENiPD8kVV4SNM+LmbZ/qtdoviGr9xbQ/mr4TmsHOVfK7OOKzMBxQi/WHkkcO7rJAQv79B80aqujQKHaYKcrfO8AMk3C3GOs5c6TLSDTlNK0Jm0/zgtUTMR90mhelJBfrwz9sjUpBkube1A3wk2DUUkGvi+m9oa+Ac0L/ot5Jfa70MQPf4uudG/AIQS5YQwtyUK9Py+ePAyzRfpC0VgtntUmyujnFkyGSiXvlkH5f8OrZwrdUmkdOAOMrE1slzh7PjgAC1c/r5YGve709VoGQchCJ0IH4jCCAUkGCSqGSIb3DQEHAaCCAToEggE2MIIBMjCCAS4GCyqGSIb3DQEMCgECoIH3MIH0MF8GCSqGSIb3DQEFDTBSMDEGCSqGSIb3DQEFDDAkBBCdisDqmPPGA+BP/sTA0wEnAgIIADAMBggqhkiG9w0CCQUAMB0GCWCGSAFlAwQBKgQQF8m/OH42uPkKXxj+abK8ygSBkNhznbE/XB1ONGe4cuchtjnYTpTVg6zyBlenvJak/NS+1QDT7ZgAPTVAVK0U18Do4jvWtw8HJ7y+GHfIvFfS6v7MJrzJQwozs/FG83Y69b1dkocOfnPgQccZZWqo3S3TQKVNjMsWu/5785ep/9oPim6agzJhbu4OYHMsQ5HKXydmKUjJJXljKnsEi0he41rH9TElMCMGCSqGSIb3DQEJFTEWBBQqiu2WMB4161qjxNuV2C5YfipnbTBJMDEwDQYJYIZIAWUDBAIBBQAEILptNRB8S6JUT6G1QWMpLZpT2Csy1p8whtVl6BUEHrTPBBBVOEnS4S46CQCobwoPiBDOAgIIAA==")!
private let passP12 = Data(base64Encoded: "MIIEFAIBAzCCA8IGCSqGSIb3DQEHAaCCA7MEggOvMIIDqzCCAloGCSqGSIb3DQEHBqCCAkswggJHAgEAMIICQAYJKoZIhvcNAQcBMF8GCSqGSIb3DQEFDTBSMDEGCSqGSIb3DQEFDDAkBBASgbIWB+zJ/SmJprvrQrUzAgIIADAMBggqhkiG9w0CCQUAMB0GCWCGSAFlAwQBKgQQ7lVeE21n8BKi8f07MDMxS4CCAdDejuLOkQmOZ+XSg/RUaJEcnzFXyEaaSvO55VvmuExQ3YM4qpAudGQ5skVZVkZB4rAlPbgT5ODV0brPCMwHxVlv3uvoSPfavIMwuo25wWdo980sQsuYfzQO3K2nyuxciJQxBKCDvbDWcfyzb3m9IpVJ5bUBT0dfn9MJ6h7tWapdHBWG2EVOoRrICxNQMtP6WVnO9YPqxp+m6TOca+5M0NcUyUnOwPH50BTMPaD38pKYb/7yItiYXKWYGQkfphqW5OXbeUNxsm5vpWX/PR9qzjqHotdtVHMQZ6V61rxbUad8s6FjuH2QSXjoKZxLaLIRrxKHrir1FOBtyi+d47fYzsEAO41ZRKOFgyPBiVeTvvjHs0+e8ZXhtY7XXV1CxSjidK+rHUAAobVkcDXd0OVUTxQZ9tsXlJS++8JJNezwHnLVhi0AoQtgKeuGRUQHtO7AjviKTVcRQXYq7jyJv5cQ85i3DQfMtgZ4wyWcvx9EYAOPExdtcdTFDwXxtEiXMNJkg13O3l97WiR/zi1lBB4MlImXOTASJ7UX5gjM6idX7dsPG1aKl3Mw5xOs6bW+3zo6JltWUpayBafRCjKJv24+M59HHE0RFiP9WKXOi9w0WF1C1jCCAUkGCSqGSIb3DQEHAaCCAToEggE2MIIBMjCCAS4GCyqGSIb3DQEMCgECoIH3MIH0MF8GCSqGSIb3DQEFDTBSMDEGCSqGSIb3DQEFDDAkBBD00svnYXKx9gaKSefzQA11AgIIADAMBggqhkiG9w0CCQUAMB0GCWCGSAFlAwQBKgQQ63b5/X+2mQ2KGBFA4i+1LASBkFoYaUW/OMjxxW+WEyMEFxukx0VuDauRJPGCmCXV0HNST2jgoZBsJbn5z9p4C9o7Yvn2Y+/qLxRao3zZid+vSQRmVhj/7g8qEtrYZK3Y+hrdGV41Sm6zNvlPUxrrQ6Ylv2BoTyL+bO2zv6/WZlgBfeM64JVlhE9eI6V8wmte7xeTraMncPVM+85P176S1BCuEDElMCMGCSqGSIb3DQEJFTEWBBQqiu2WMB4161qjxNuV2C5YfipnbTBJMDEwDQYJYIZIAWUDBAIBBQAEIPd/Mr2VlqhLXGsi0n7IrYLCi0dfSq/C8x4BnkxPieLMBBBYqrsNOVXX28gip5kmjVQTAgIIAA==")!

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
    test("CERT-04", "a PKCS#12 file without a password: its certificate's end; with one: not known before it is asked") {
        func file(_ d: Data) -> String {
            let p = NSTemporaryDirectory() + "cert-04-\(UUID().uuidString).p12"
            FileManager.default.createFile(atPath: p, contents: d)
            return p
        }
        expectEqual(CertificateExpiry.notAfter(pkcs12File: file(noPassP12)), date("2026-10-19T10:55:34Z"))
        expectEqual(CertificateExpiry.notAfter(pkcs12File: file(passP12)), nil)
        expectEqual(CertificateExpiry.notAfter(pkcs12File: file(Data("junk".utf8))), nil)
        expectEqual(CertificateExpiry.notAfter(pkcs12File: "/nonexistent.p12"), nil)
        let config = "client\nremote a 1194\npkcs12 me.p12\n"
        expectEqual(CertificateExpiry.clientPKCS12(config: config), "me.p12")
        expectEqual(CertificateExpiry.clientPKCS12(config: "client\n<pkcs12>\nAAAA\n</pkcs12>\n"), nil, "inline: not a file name")
    }
}
