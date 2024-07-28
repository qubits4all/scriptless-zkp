###############################################################################
# (c) 2023, 2024 W. Spann Systems Consulting
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
###############################################################################

"""
Provides support for adaptor ECC Schnorr digital signatures (a.k.a. verifiable encrypted signatures).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from Cryptodome.PublicKey import ECC

from scriptless_zkp.ecc import ecc_utils
from scriptless_zkp.ecc.signatures.schnorr import SchnorrSignature, SchnorrContext
from scriptless_zkp.ecc.weierstrass_curves import WeierstrassEllipticCurveConfig
from scriptless_zkp.hashing import UniversalPrimeLengthHasher


class AdaptorSchnorrContext:
    curve_config: WeierstrassEllipticCurveConfig
    domain_separator: str
    hasher: UniversalPrimeLengthHasher

    DEFAULT_DOMAIN_SEPARATOR: str = "AdaptorECCSchnorr"

    def __init__(
            self,
            ecc_curve_config: WeierstrassEllipticCurveConfig,
            domain_separation_tag: str = DEFAULT_DOMAIN_SEPARATOR
    ):
        self.curve_config = ecc_curve_config
        self.domain_separator = domain_separation_tag
        self.hasher = UniversalPrimeLengthHasher.for_field_order(
            self.q,
            domain_separation_tag=self.domain_separator,
            deterministic=True  # ensure deterministic hashing for reproducibility
        )

    @property
    def q(self) -> int:
        """Returns the order of the configured elliptic curve's base point `G`."""
        return self.curve_config.order

    def generate_key_pair(self) -> AdaptorSchnorrKeyPair:
        return AdaptorSchnorrKeyPair.generate(self)

    def generate_adaptor_tweak_pair(self) -> AdaptorSchnorrTweakPair:
        return AdaptorSchnorrTweakPair.generate(self)

    def as_schnorr_context(self) -> SchnorrContext:
        return SchnorrContext(self.curve_config, message_hash_algorithm=self.hasher.hash_algo)


class AdaptorSchnorrKeyPair:
    context: AdaptorSchnorrContext
    ecc_key_pair: ECC.EccKey

    def __init__(self, context: AdaptorSchnorrContext, ecc_key_pair: ECC.EccKey):
        self.context = context
        self.ecc_key_pair = ecc_key_pair

    @classmethod
    def generate(cls, context: AdaptorSchnorrContext) -> AdaptorSchnorrKeyPair:
        return AdaptorSchnorrKeyPair(context, ECC.generate(curve=context.curve_config.curve))

    @property
    def private_key(self) -> int:
        return int(self.ecc_key_pair.d)

    @property
    def public_key_point(self) -> ECC.EccPoint:
        return self.ecc_key_pair.pointQ

    @property
    def public_key(self) -> ECC.EccKey:
        return self.ecc_key_pair.public_key()

    def sign(self, adaptor_public_tweak_key: ECC.EccKey, message: bytes) -> AdaptorSchnorrPreSignature:
        """
        Produce an adaptor Schnorr pre-signature using the provided public tweak key and message.
        :param adaptor_public_tweak_key: the adaptor public tweak key (`Y`) used to tweak the nonce point (`R`).
        :param message: the message to be signed.
        :return: an adaptor ECC Schnorr pre-signature composed of the tuple `(R', s')`, where `R'` is a tweaked public
                 nonce point `(R + Y)` and `s'` is the pre-signature scalar.
        """
        # Loop until a valid ECC Schnorr adaptor pre-signature is produced, repeating nonce generation as necessary.
        while True:
            private_nonce, public_nonce_point = ecc_utils.generate_random_nonce_pair(
                self.context.curve_config,
                exclude_one=True
            )

            # Compute the tweaked public nonce point: `R' := R + Y`, where `R` is the random public nonce point and `Y`
            # is the public tweak point.
            tweaked_public_nonce: ECC.EccPoint = public_nonce_point + adaptor_public_tweak_key.pointQ

            # Ensure the tweaked public nonce point is not the elliptic curve group's unit (i.e., point-at-infinity).
            if tweaked_public_nonce.is_point_at_infinity():
                continue

            # Ensure the hasher is reset before updating it, to calculate the pre-signature hash.
            if not self.context.hasher.is_reset():
                raise ValueError("Prime-length hasher has not been reset since its last use.")

            # Compute the pre-signature hash: `e' := H_q(X | R+Y | m)`, where `X` is the public key, `R` is the nonce
            # point, `Y` is the public tweak point, `m` is the message being signed, `|` denotes concatenation, and
            # `H_q(...)` is a prime-length hasher configured for the elliptic curve's sub-group order (`q`)
            # (i.e., to produce hashes in the range `[0, q-1]`).
            presig_hash: int = self.context.hasher.update(
                ecc_utils.encode_public_key(self.public_key)
            ).update(
                ecc_utils.encode_ecc_point(self.context.curve_config, tweaked_public_nonce)
            ).update(message).intdigest()

            # Ensure the pre-signature hash is non-zero, which is a requirement for producing a valid ECC Schnorr
            # adaptor pre-signature.
            if presig_hash == 0:
                continue

            # Compute the pre-signature scalar: `s' := k + e' * x mod q`, where `k` is the nonce scalar, `e'` is the
            # pre-signature hash, `x` is the private key, and `q` is the elliptic curve sub-group order.
            presig_scalar: int = (private_nonce + presig_hash * self.private_key) % self.context.q

            # Ensure the pre-signature scalar is non-zero, which is also a requirement for producing a valid ECC
            # Schnorr adaptor pre-signature.
            if presig_scalar != 0:
                break  # Break out of the loop on construction of a valid signature.

        return AdaptorSchnorrPreSignature(self.context, tweaked_public_nonce, presig_scalar)


class AdaptorSchnorrTweakPair:
    context: AdaptorSchnorrContext
    tweak_key_pair: ECC.EccKey

    def __init__(self, context: AdaptorSchnorrContext, adaptor_tweak_key_pair: ECC.EccKey):
        self.context: AdaptorSchnorrContext = context
        self.tweak_key_pair = adaptor_tweak_key_pair

    @classmethod
    def generate(cls, context: AdaptorSchnorrContext) -> AdaptorSchnorrTweakPair:
        return AdaptorSchnorrTweakPair(context, ECC.generate(curve=context.curve_config.curve))

    @property
    def private_tweak(self) -> int:
        return int(self.tweak_key_pair.d)

    @property
    def public_tweak(self) -> ECC.EccPoint:
        return self.tweak_key_pair.pointQ

    @property
    def public_tweak_key(self) -> ECC.EccKey:
        return self.tweak_key_pair.public_key()


class AdaptorSchnorrPublicKeys:
    context: AdaptorSchnorrContext
    public_ecc_key: ECC.EccKey
    public_tweak_key: ECC.EccKey

    def __init__(self, context: AdaptorSchnorrContext, public_key: ECC.EccKey, adaptor_public_tweak_key: ECC.EccKey):
        self.context = context
        self.public_ecc_key = public_key
        self.public_tweak_key = adaptor_public_tweak_key

    @property
    def public_tweak(self) -> ECC.EccPoint:
        return self.public_tweak_key.pointQ

    @property
    def public_key_point(self) -> ECC.EccPoint:
        return self.public_ecc_key.pointQ

    def verify_pre_signature(self, adaptor_pre_signature: AdaptorSchnorrPreSignature, message: bytes) -> bool:
        """
        Verifies an adaptor ECC Schnorr pre-signature against the provided message, given this
        `AdaptorSchnorrPublicKeys` object's public signature verification key and public tweak key/point.
        :param adaptor_pre_signature: the adaptor ECC Schnorr pre-signature to be verified.
        :param message: the message against which the pre-signature is to be verified.
        :return: whether the provided pre-signature is valid for the given message (and this object's public signature
                 verification key & public tweak key/point).
        """
        # Ensure the hasher is reset before updating it, to calculate the pre-signature hash.
        if not self.context.hasher.is_reset():
            raise ValueError("Prime-length hasher has not been reset since its last use.")

        # Re-compute the pre-signature hash: `e' := H_q(X | R' | m)`, where `X` is the public key, `R'` is the tweaked
        # public nonce point (i.e., `R' := R + Y`) taken directly from the pre-signature, `Y` is the public tweak point,
        # `m` is the message being signed, `|` denotes concatenation, and `H_q(...)` is a prime-length hasher configured
        # for the elliptic curve's sub-group order (`q`) (i.e., to produce hashes in the range `[0, q-1]`).
        presig_hash: int = self.context.hasher.update(
            ecc_utils.encode_public_key(self.public_ecc_key)
        ).update(
            ecc_utils.encode_ecc_point(self.context.curve_config, adaptor_pre_signature.public_nonce)
        ).update(message).intdigest()

        # If the pre-signature hash is zero, then the provided pre-signature is invalid (i.e., up to the given message,
        # public signature verification key & public tweak key/point).
        if presig_hash == 0:
            return False

        # Compute the pre-signature nonce-based verification EC point: `R' + e' * X`, where `R'` is the tweaked public
        # nonce point, `e'` is the pre-signature hash, and `X` is the public signature verification key.
        nonce_derived_verification_point: ECC.EccPoint = adaptor_pre_signature.public_nonce + (
            self.public_key_point * presig_hash
        )

        # If the pre-signature's nonce-based verification EC point is the elliptic curve group's unit
        # (i.e., the point-at-infinity), then the provided pre-signature is invalid.
        if nonce_derived_verification_point.is_point_at_infinity():
            return False

        presig_scalar_derived_verification_point: ECC.EccPoint = self.public_tweak + (
                self.context.curve_config.base_point * adaptor_pre_signature.pre_signature
        )

        # If the pre-signature's scalar-based verification EC point is the elliptic curve group's unit
        # (i.e., the point-at-infinity), then the provided pre-signature is invalid.
        if presig_scalar_derived_verification_point.is_point_at_infinity():
            return False

        # The pre-signature is valid (for the given message, public signature verification key & public tweak key/point)
        # if the pre-signature's nonce-based verification EC point matches the pre-signature's scalar-based verification
        # EC point. Otherwise, the pre-signature is invalid. (`s' * G + Y == R' + H_q(X | R' | m) * X`)
        return presig_scalar_derived_verification_point == nonce_derived_verification_point


@dataclass
class AdaptorSchnorrPreSignature:
    context: AdaptorSchnorrContext
    public_nonce: ECC.EccPoint
    pre_signature: int

    def __init__(
            self,
            context: AdaptorSchnorrContext,
            public_nonce: ECC.EccPoint,
            pre_signature_scalar: int
    ):
        self.context = context
        self.public_nonce = public_nonce
        self.pre_signature = pre_signature_scalar

    def verify(self, adaptor_public_key: AdaptorSchnorrPublicKeys, message: bytes) -> bool:
        return adaptor_public_key.verify_pre_signature(self, message)

    def adapt_to_signature(self, adaptor_private_tweak: int) -> SchnorrSignature:
        """
        Adapts an adaptor ECC Schnorr pre-signature to a full signature, using the provided adaptor private tweak.
        """
        # Adapt pre-signature scalar using adaptor private tweak: `s := s' + y`
        full_sig_scalar: int = (self.pre_signature + adaptor_private_tweak) % self.context.q

        return SchnorrSignature(self.context.as_schnorr_context(), self.public_nonce, full_sig_scalar)

    def extract_private_tweak(
            self,
            full_signature: SchnorrSignature,
            adaptor_public_keys: AdaptorSchnorrPublicKeys
    ) -> Optional[int]:
        """
        Attempts to extract the adaptor private tweak, given a full signature adapted from this pre-signature
        (i.e., via the `adapt_to_signature(...)` method; returning `None` if a valid private tweak could not be
        calculated via the given signature.
        :param full_signature: a full ECC Schnorr signature adapted from this adaptor pre-signature.
        :param adaptor_public_keys: the ECC Schnorr public key and adaptor public tweak key. The latter is used to
                verify the adaptor private tweak extracted from the provided signature is valid before returning it.
        :return: the extracted adaptor private tweak, if it could be calculated and verified; otherwise, `None`.
        :raises ValueError: if the provided full signature was constructed using a different elliptic curve than was
                used to construct this adaptor pre-signature.
        """

        if self.context.curve_config.has_curve_name(full_signature.context.ecc_curve_config.curve):
            raise ValueError(
                f"Unable to extract the adaptor private tweak from the provided ECC Schnorr signature constructed using"
                f" a different elliptic curve than was used to construct this adaptor pre-signature."
            )

        private_tweak: int = (full_signature.signature - self.pre_signature) % self.context.q

        # Compute the verification point: `Y' := y' * G`, where `y'` is the extracted private tweak, and `Y'` is the
        # verification point, which should equal the adaptor public tweak point if the extracted private tweak is valid.
        verification_point: ECC.EccPoint = self.context.curve_config.base_point * private_tweak

        # If the calculated verification point is unequal to the adaptor public tweak point, or is the elliptic curve
        # group's unit (i.e., the point-at-infinity), then the extracted private tweak is invalid.
        #
        if verification_point != adaptor_public_keys.public_tweak or verification_point.is_point_at_infinity():
            return None
        else:
            # Return a valid adaptor private tweak if the following is true: `y' * G == Y`
            return private_tweak
