###############################################################################
# (c) 2022, 2023, 2024 W. Spann Systems Consulting
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

"""Custom exception classes used by cryptography classes."""


class InvalidHasherStateException(Exception):
    def __init__(self, msg: str):
        super().__init__(msg)
        self.msg = msg

    def __repr__(self) -> str:
        return f"{type(self).__name__}: {self.msg}"
