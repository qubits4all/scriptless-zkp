import unittest

from scriptless_zkp.ecc.curves import WeierstrassEllipticCurveContext, EllipticCurveContext
from scriptless_zkp.ecc.points import WeierstrassPoint2D


class EllipticCurveContextTests(unittest.TestCase):
    P256_G_X_HEX: str = "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296"
    P256_G_Y_HEX: str = "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5"

    def test_weierstrass_curve_p256_base_point(self):
        p256: WeierstrassEllipticCurveContext = EllipticCurveContext.p256()
        self.assertIsNotNone(
            p256,
            "Failed to construct Weierstrass elliptic curve context for the NIST P-256 prime-order curve."
        )

        # Verify against SEC 2 documented (compressed) SEC1-encoded base point.
        g_comp: WeierstrassPoint2D = WeierstrassPoint2D.deserialize(
            "P-256",
            b"\x03" + bytes.fromhex(
                self.P256_G_X_HEX  # x-coordinate (big-endian)
            )
        )
        self.assertEqual(
            g_comp,
            p256.base_point,
            "Constructed P-256 base point does not match the SEC 2 documented SEC1-encoded (compressed) point."
        )

        g_uncomp: WeierstrassPoint2D = WeierstrassPoint2D.deserialize(
            "P-256",
            b"\x04" + bytes.fromhex(  # x-coordinate (big-endian)
                self.P256_G_X_HEX  # x-coordinate (big-endian)
            ) + bytes.fromhex(
                self.P256_G_Y_HEX  # y-coordinate (big-endian)
            )
        )

        self.assertEqual(
            g_uncomp,
            p256.base_point,
            "Constructed P-256 base point does not match the SEC 2 documented SEC1-encoded (uncompressed) point."
        )

    def test_weierstrass_curve_p384_base_point(self):
        p384: WeierstrassEllipticCurveContext = WeierstrassEllipticCurveContext.p384()
        self.assertIsNotNone(
            p384,
            "Failed to construct Weierstrass elliptic curve context for the NIST P-384 prime-order curve."
        )

        # Verify against SEC 2 documented (compressed) SEC1-encoded base point.
        g_comp: WeierstrassPoint2D = WeierstrassPoint2D.deserialize(
            "P-384",
            b"\x03" + bytes.fromhex(  # x-coordinate (big-endian)
                "AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7"  # x-coordinate (big-endian)
            )
        )
        self.assertEqual(
            g_comp,
            p384.base_point,
            "Constructed P-384 base point does not match the SEC 2 documented SEC1-encoded (compressed) point."
        )

        g_uncomp: WeierstrassPoint2D = WeierstrassPoint2D.deserialize(
            "P-384",
            b"\x04" + bytes.fromhex(  # x-coordinate (big-endian)
                "AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7"  # x-coordinate (big-endian)
            ) + bytes.fromhex(
                "3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F"  # y-coordinate (big-endian)
            )
        )

        self.assertEqual(
            g_uncomp,
            p384.base_point,
            "Constructed P-384 base point does not match the SEC 2 documented SEC1-encoded (uncompressed) point."
        )


if __name__ == '__main__':
    unittest.main()
