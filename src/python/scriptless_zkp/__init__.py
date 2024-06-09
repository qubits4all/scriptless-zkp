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

"""Common constants and type aliases used in the 'scriptless_zkp' package."""

from typing import Literal

PartyId = Literal[1, 2]
"""Alias to the party ID literal type, which must be either 1 (initiator) or 2 (responder)."""

STRING_ENCODING_FIELD_DELIMITER: str = ':'
"""Default field delimiter used in string encodings."""
