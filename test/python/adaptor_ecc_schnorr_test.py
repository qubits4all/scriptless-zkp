import unittest

from typing import Optional

from scriptless_zkp.ecc.signatures.adaptor_schnorr import (
    AdaptorSchnorrContext, AdaptorSchnorrKeyPair, AdaptorSchnorrTweakPair, AdaptorSchnorrPreSignature,
    AdaptorSchnorrPublicKeys
)
from scriptless_zkp.ecc.signatures.schnorr import SchnorrPublicKey, SchnorrSignature
from scriptless_zkp.ecc.weierstrass_curves import WeierstrassEllipticCurveConfig


class AdaptorECCSchnorrTests(unittest.TestCase):
    context = AdaptorSchnorrContext(
        WeierstrassEllipticCurveConfig.secp256r1(),
        domain_separation_tag=AdaptorSchnorrContext.DEFAULT_DOMAIN_SEPARATOR
    )
    context_without_domain_sep = AdaptorSchnorrContext(
        WeierstrassEllipticCurveConfig.secp256r1(),
        domain_separation_tag=None
    )

    def test_adaptor_Schnorr_key_generation(self):
        key_pair = AdaptorSchnorrKeyPair.generate(self.context)

        self.assertEqual(key_pair.context, self.context)
        self.assertTrue(key_pair.ecc_key_pair.has_private())
        self.assertFalse(key_pair.public_key.has_private())

        # Verify `X != O` (i.e., the point-at-infinity).
        self.assertFalse(key_pair.public_key_point.is_point_at_infinity())

        # Verify `X = x * G`, where `x` is the private key scalar, `G` is the base point & `X` is the public key point.
        self.assertEqual(self.context.curve_config.base_point * key_pair.private_key, key_pair.public_key_point)

    def test_adaptor_tweak_pair_generation(self):
        tweak_pair = AdaptorSchnorrTweakPair.generate(self.context)

        self.assertEqual(tweak_pair.context, self.context)
        self.assertTrue(tweak_pair.tweak_key_pair.has_private())
        self.assertFalse(tweak_pair.public_tweak_key.has_private())

        # Verify `Y != O` (i.e., the point-at-infinity).
        self.assertFalse(tweak_pair.public_tweak.is_point_at_infinity())

        # Verify `Y = y * G`, where `y` is the private tweak, `G` is the base point & `Y` is the public tweak point.
        self.assertEqual(self.context.curve_config.base_point * tweak_pair.private_tweak, tweak_pair.public_tweak)

    def test_adaptor_signature_generation(self):
        key_pair = AdaptorSchnorrKeyPair.generate(self.context)
        tweak_pair = AdaptorSchnorrTweakPair.generate(self.context)

        test_message: bytes = b'foo'
        signature: AdaptorSchnorrPreSignature = key_pair.sign(tweak_pair.public_tweak_key, test_message)

        self.assertEqual(signature.context, self.context)

        # Verify `R' != O` (i.e., the point-at-infinity).
        self.assertFalse(signature.public_nonce.is_point_at_infinity())

        # Verify pre-signature scalar value is non-zero.
        self.assertNotEqual(signature.pre_signature, 0, "Pre-signature scalar value should not be zero.")

        # Verify `s' * G != O` (i.e., the point-at-infinity).
        self.assertFalse((self.context.curve_config.base_point * signature.pre_signature).is_point_at_infinity())

    def test_adaptor_signature_verification(self):
        key_pair = AdaptorSchnorrKeyPair.generate(self.context)
        tweak_pair = AdaptorSchnorrTweakPair.generate(self.context)

        adaptor_pub_keys = AdaptorSchnorrPublicKeys(self.context, key_pair.public_key, tweak_pair.public_tweak_key)

        test_message: bytes = b'foo'
        pre_sig: AdaptorSchnorrPreSignature = key_pair.sign(tweak_pair.public_tweak_key, test_message)

        # Verify the pre-signature via the verify_pre_signature(...) method on the public keys object.
        self.assertTrue(
            adaptor_pub_keys.verify_pre_signature(pre_sig, test_message),
            "Adaptor ECC Schnorr pre-signature verification failed."
        )

        # Verify the pre-signature via the verify(...) helper method on the pre-signature object.
        self.assertTrue(pre_sig.verify(adaptor_pub_keys, test_message))

    def test_pre_signature_adapt(self):
        key_pair = AdaptorSchnorrKeyPair.generate(self.context)
        tweak_pair = AdaptorSchnorrTweakPair.generate(self.context)

        test_message: bytes = b'foo'
        pre_sig: AdaptorSchnorrPreSignature = key_pair.sign(tweak_pair.public_tweak_key, test_message)

        # Adapt the pre-signature to a full signature using the private tweak key.
        signature: SchnorrSignature = pre_sig.adapt_to_signature(tweak_pair.private_tweak)

        schnorr_public_key = SchnorrPublicKey(self.context.as_schnorr_context(), key_pair.public_key)
        # Verify the adapted full signature using the public key.
        self.assertTrue(
            schnorr_public_key.verify_signature(signature, test_message),
            "ECC Schnorr signature verification failed."
        )

    def test_extract_adaptor_tweak(self):
        key_pair = AdaptorSchnorrKeyPair.generate(self.context)
        tweak_pair = AdaptorSchnorrTweakPair.generate(self.context)

        adaptor_pub_keys = AdaptorSchnorrPublicKeys(self.context, key_pair.public_key, tweak_pair.public_tweak_key)

        test_message: bytes = b'foo'
        pre_sig: AdaptorSchnorrPreSignature = key_pair.sign(tweak_pair.public_tweak_key, test_message)

        # Adapt the pre-signature to a full signature using the private tweak key.
        signature: SchnorrSignature = pre_sig.adapt_to_signature(tweak_pair.private_tweak)

        # Extract the adaptor tweak from the full signature.
        private_tweak: Optional[int] = pre_sig.extract_private_tweak(signature, adaptor_pub_keys)

        # Verify the extracted private tweak is correct.
        self.assertIsNotNone(private_tweak)
        self.assertEqual(
            private_tweak,
            tweak_pair.private_tweak,
            "Extracted private tweak does not match the original private tweak."
        )


if __name__ == '__main__':
    unittest.main()
