###############################################################################
# (c) 2024 W. Spann Systems Consulting
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
Implements an interactive zero-knowledge (ZK) range proof protocol for proving that a committed integer `x` value falls
within a specified range `[0, q)`, for an integer `x` in `[0, l]` where ``l := floor(q/3)``.

This module implements the prover and verifier components of the ZK range proof protocol, as well as the common context
that encapsulates pre-shared parameters. The protocol implemented is that of Yehuda Lindell, as described in his
paper "Fast Secure Two-Party ECDSA Signing" (https://eprint.iacr.org/2019/114.pdf).
"""

from __future__ import annotations

import uuid

from dataclasses import dataclass

from uuid import UUID

from scriptless_zkp.commitments.hmac_commitments import KeyedHashCommitment
from scriptless_zkp.he import paillier

DEFAULT_RANGE_PROOF_SECURITY_PARAM = 40


class ZKRangeProofContext:
    membership_proof_max: int  # upper limit `q` (exclusive) of range committed value will be proven to fall within
    committed_value_max: int   # upper limit `l` (exclusive) of the committed value's range (`floor(q/3)`)
    security_param: int        # security parameter `t` (default 40)

    def __init__(self, membership_interval_max: int, security_parameter: int = DEFAULT_RANGE_PROOF_SECURITY_PARAM):
        self.membership_proof_max = membership_interval_max
        self.committed_value_max = membership_interval_max // 3
        self.security_param = security_parameter


@dataclass
class RandomWitnesses:
    group1: list[int]
    group2: list[int]

    def __init__(self, context: ZKRangeProofContext, witness_group1: list[int]):
        self.group1 = witness_group1
        self.group2 = [w1 - context.committed_value_max for w1 in witness_group1]

    @classmethod
    def generate_random_witnesses(cls, committed_value_max: int) -> RandomWitnesses:
        pass

    def encrypt_witnesses(self, paillier_pub_key: paillier.PaillierPublicKey) -> RandomWitnessCiphertexts:
        pass

    def witness_group(self, group_num: int) -> list[int]:
        return self.group1 if group_num == 1 else self.group2

    def witness_group_size(self) -> int:
        return len(self.group1)

    def witness_at(self, group_num: int, index: int) -> int:
        return self.group1[index] if group_num == 1 else self.group2[index]


@dataclass
class RandomWitnessCiphertexts:
    group1: list[paillier.EncryptedUnsignedInteger]
    group2: list[paillier.EncryptedUnsignedInteger]

    def __init__(
            self,
            witness_group1: list[paillier.EncryptedUnsignedInteger],
            witness_group2: list[paillier.EncryptedUnsignedInteger]
    ):
        self.group1 = witness_group1
        self.group2 = witness_group2

    def ciphertext_group(self, group_num: int) -> list[paillier.EncryptedUnsignedInteger]:
        return self.group1 if group_num == 1 else self.group2

    def ciphertext_group_size(self) -> int:
        return len(self.group1)

    def ciphertext_at(self, group_num: int, index: int) -> paillier.EncryptedUnsignedInteger:
        return self.group1[index] if group_num == 1 else self.group2[index]


class ZKRangeProofProverSession:
    session_id: UUID
    paillier_key_pair: paillier.PaillierKeyPair
    random_witnesses: RandomWitnesses | None = None
    verifier_challenge_commitment: KeyedHashCommitment | None = None
    verifier_challenge: int | None = None

    def __init__(self, paillier_key_pair: paillier.PaillierKeyPair, session_id: UUID = uuid.uuid4()):
        self.paillier_key_pair = paillier_key_pair
        self.session_id = session_id


class ZKRangeProofVerifierSession:
    session_id: UUID
    paillier_public_key: paillier.PaillierPublicKey
    witness_ciphertexts: RandomWitnessCiphertexts | None = None
    verifier_challenge: int | None = None

    def __init__(self, paillier_public_key: paillier.PaillierPublicKey, session_id: UUID = uuid.uuid4()):
        self.paillier_public_key = paillier_public_key
        self.session_id = session_id


class ZKRangeProofProver:
    context: ZKRangeProofContext
    session: ZKRangeProofProverSession

    def __init__(self, context: ZKRangeProofContext, paillier_key_pair: paillier.PaillierKeyPair):
        self.context = context
        self.session = ZKRangeProofProverSession(paillier_key_pair)

    @property
    def session_id(self) -> UUID:
        return self.session.session_id

    def init_proof_protocol(
            self,
            committed_secret: int,
            committed_secret_ciphertext: paillier.EncryptedUnsignedInteger
    ) -> (list[paillier.EncryptedUnsignedInteger], list[paillier.EncryptedUnsignedInteger]):
        pass


class ZKRangeProofVerifier:
    context: ZKRangeProofContext
    session: ZKRangeProofVerifierSession

    def __init__(self, context: ZKRangeProofContext, paillier_public_key: paillier.PaillierPublicKey):
        self.context = context
        self.session = ZKRangeProofVerifierSession(paillier_public_key)

    @property
    def session_id(self) -> UUID:
        return self.session.session_id

    def init_proof_protocol(
            self,
            committed_secret_ciphertext: paillier.EncryptedUnsignedInteger
    ) -> KeyedHashCommitment:
        pass
