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
This module provides number-theoretic functions that are used by various modules.
"""
import os
import time

from concurrent import futures
from concurrent.futures import ThreadPoolExecutor, Future
from concurrent.futures.process import ProcessPoolExecutor
from typing import Optional

from Cryptodome.Util import number

from libnum import sqrtmod_prime_power

from scriptless_zkp import utils

DEFAULT_FERMAT_PRIMALITY_ROUNDS: int = 10_000
"""Default number of rounds for the Fermat primality test."""


def legendre_symbol(a: int, prime_modulus: int) -> int:
    """
    Computes the Legendre symbol of `a` modulo `p`, where `p` is an odd prime. This function returns 1 if `a` is a
    quadratic residue modulo `p`, -1 if `a` is a quadratic non-residue modulo `p`, and 0 if `a` is divisible by `p`.
    :param a: the integer for which the Legendre symbol is computed.
    :param prime_modulus: the odd prime modulus `p` for the Legendre symbol computation.
    :return: the Legendre symbol of `a` modulo `p`, for a prime modulus `p`.
    """
    if prime_modulus < 3:
        raise ValueError("The Legendre symbol is only defined for an odd prime modulus.")

    if a == 0 or a % prime_modulus == 0:
        return 0
    elif a == 1 or a % prime_modulus == 1:
        return 1
    # Applying the law of quadratic reciprocity (1st supplement): `a == -1 or a == p - 1 (mod p)`
    elif a == -1 or a % prime_modulus == prime_modulus - 1:
        if prime_modulus % 4 == 1:
            return 1
        else:  # prime_modulus % 4 == 3
            return -1
    # Applying the law of quadratic reciprocity (2nd supplement):
    elif a == 2:
        if prime_modulus % 8 in {1, 7}:
            return 1
        else:  # prime_modulus % 8 in {3, 5}
            return -1
    # Applying special formula for a == 3 & p != 3:
    elif a == 3 and prime_modulus != 3:
        if prime_modulus % 12 in {1, 11}:
            return 1
        else:  # prime_modulus % 12 in {5, 7}
            return -1
    # Applying special formula for a == 5 & p != 5:
    elif a == 5 and prime_modulus != 5:
        if prime_modulus % 5 in {1, 4}:
            return 1
        else:  # prime_modulus % 5 in {2, 3}
            return -1
    # Using Euler's criterion: `a^((p - 1) / 2) mod p`
    else:
        return pow(a, (prime_modulus - 1) // 2, prime_modulus)


def is_quadratic_residue(a: int, prime_modulus: int) -> bool:
    """
    Determines whether the given integer `a` is a quadratic residue modulo the odd prime `prime_modulus`.
    :param a: the integer to be tested for being a quadratic residue.
    :param prime_modulus: the odd prime modulus for the quadratic residue test.
    :return: True if `a` is a quadratic residue modulo `prime_modulus`, False otherwise.
    """
    return legendre_symbol(a, prime_modulus) == 1


def is_quadratic_nonresidue(a: int, prime_modulus: int) -> bool:
    """
    Determines whether the given integer `a` is a quadratic non-residue modulo the odd prime `prime_modulus`.
    :param a: the integer to be tested for being a quadratic non-residue.
    :param prime_modulus: the odd prime modulus for the quadratic non-residue test.
    :return: True if `a` is a quadratic non-residue modulo `prime_modulus`, False otherwise.
    """
    return legendre_symbol(a, prime_modulus) == -1


def has_mod_sqrt(a: int, prime_modulus: int) -> bool:
    """
    Determines whether the given integer `a` has a square root modulo the given prime `prime_modulus` (i.e., whether
    there exists an integer `n` such that `n² == a mod p`, where `==` here represents congruence).
    :param a: an integer for which the existence of a modular square root `n` is to be determined.
    :param prime_modulus: a prime modulus `p` for which the existence of a modular square root `n` is to be determined.
    :return: True if `a` has a modular square root modulo `prime_modulus`, False otherwise.
    """
    if a in {0, 1}:
        return True
    # Special case for prime modulus 2:
    elif prime_modulus == 2:  # note: The Legendre symbol used below is not defined for p == 2.
        return True
    # Special case for `a == 0 mod p` or `a == 1 mod p`:
    elif a % prime_modulus in {0, 1}:
        return True
    else:
        # Otherwise, the integer `a` has a modular square root modulo `p` if and only if it's a quadratic residue.
        return legendre_symbol(a, prime_modulus) == 1


def mod_sqrt(a: int, prime_modulus: int) -> tuple[int, ...]:
    """
    Computes the modular square root of the integer `a` modulo the odd prime `prime_modulus`, using the Tonelli-Shanks
    algorithm. This function returns the positive square root of `a` modulo `prime_modulus`.
    :param a: the integer for which the modular square root is computed.
    :param prime_modulus: the odd prime modulus for the modular square root computation.
    :return: the positive square root of `a` modulo `prime_modulus`.
    """
    if is_quadratic_nonresidue(a, prime_modulus):
        raise ValueError(
            f"The integer {a} has no square root modulo {prime_modulus}, as it is a quadratic non-residue."
        )

    if a == 0 or a % prime_modulus == 0:
        return (0,)
    elif prime_modulus == 2:
        return (1,)
    elif a == 1 or a % prime_modulus == 1:
        return 1, prime_modulus - 1
    elif prime_modulus % 4 == 3:
        # Compute modular square root using the following identity of Lagrange, for p == 3 mod 4:
        #     `sqrt(a) mod p == +/- a^((p + 1) / 4) mod p`
        positive_root: int = pow(a, (prime_modulus + 1) // 4, prime_modulus)

        return positive_root, prime_modulus - positive_root
    elif prime_modulus % 8 == 5:
        # If `a` is a quartic (biquadratic) residue modulo `p`, then the square roots can be computed using the
        # following identity of Legendre, for p == 5 mod 8:
        if is_quartic_residue(a, prime_modulus):  # i.e., there exists an integer `x` such that `x⁴ == a mod p`
            # Compute modular square root using the following identity, if `a` is a quartic residue modulo `p`:
            #     `sqrt(a) mod p == +/- a^((p + 3) / 8) mod p`
            positive_root: int = pow(a, (prime_modulus + 3) // 8, prime_modulus) % prime_modulus
        else:  # o.w. `a` is a quartic non-residue (i.e., there exists no integer `x` such that `x⁴ == a mod p`)
            # Compute modular square root using the following identity, if `a` is a quartic non-residue modulo `p`:
            #     `sqrt(a) mod p == +/- (2a) * (4a)^((p - 5) / 8) mod p`
            positive_root: int = (2 * a * pow(4 * a, (prime_modulus - 5) // 8, prime_modulus)) % prime_modulus

        return positive_root, prime_modulus - positive_root
    else:  # prime_modulus % 8 == 1
        return tuple(
            sqrtmod_prime_power(a, prime_modulus)  # note: this libnum function returns a Generator
        )


def quartic_residue_symbol(a: int, prime_modulus: int) -> int:
    """
    Computes the rational quartic (biquadratic) residue symbol of the integer `a` modulo the odd prime `prime_modulus`.
    This function returns +1 if `a` is a quartic residue modulo `prime_modulus`, and -1 if `a` is a quartic non-residue
    modulo `prime_modulus`. A quartic residue is an integer `a` such that `n⁴ == a mod p` has an integer solution `n`
    for prime modulus `p`.
    :param a: the integer for which the quartic residue symbol is computed.
    :param prime_modulus: the odd prime modulus for the quartic residue symbol computation.
    :return: the quartic residue symbol of `a` modulo `prime_modulus`.
    """
    if prime_modulus % 4 == 1 and is_quadratic_residue(a, prime_modulus):
        # For `p == 1 mod 4`, we can compute the quartic residue symbol using the following identity:
        #    `a^((p - 1) / 4) mod p`, where `^` denotes exponentiation.
        return pow(a, (prime_modulus - 1) // 4, prime_modulus)  # either +1 or -1
    else:
        return -1  # `a` is a quartic non-residue modulo `prime_modulus`


def is_quartic_residue(a: int, prime_modulus: int) -> bool:
    """
    Determines whether the given integer `a` is a quartic (biquadratic) residue modulo the odd prime `prime_modulus`
    (i.e., whether there exists an integer `n` such that `n⁴ == a mod p`).
    :param a: an integer to be tested for being a quartic residue.
    :param prime_modulus: an odd prime modulus for the quartic residue test.
    :return: whether `a` is a quartic residue modulo the odd prime `prime_modulus`.
    """
    return quartic_residue_symbol(a, prime_modulus) == 1


def is_quartic_nonresidue(a: int, prime_modulus: int) -> bool:
    """
    Determines whether the given integer `a` is a quartic (biquadratic) non-residue modulo the odd prime
    `prime_modulus` (i.e., whether there exists no integer `n` such that `n⁴ == a mod p`).
    :param a: an integer to be tested for being a quartic non-residue.
    :param prime_modulus: an odd prime modulus for the quartic non-residue test.
    :return: whether `a` is a quartic non-residue modulo the odd prime `prime_modulus`.
    """
    return quartic_residue_symbol(a, prime_modulus) == -1


def mod_inverse(a: int, modulus: int) -> int:
    """
    Computes the modular inverse of the integer `a` modulo `modulus`, if it exists; raising an exception otherwise.
    This function calculates the solution to the equation `a * x == 1 mod n`, where `==` represents congruence and `n`
    is the modulus, which may be prime or composite.
    :param a: an integer for which the modular inverse will be computed.
    :param modulus: a modulus for the modular inverse computation, which may be prime or composite.
    :return: the modular inverse of `a` modulo `modulus`.
    :raises ValueError: if the modular inverse of `a` modulo `modulus` does not exist, which can occur for composite
            moduli when `a` is not coprime to the modulus.
    """
    return number.inverse(a, modulus)


def is_coprime(a: int, b: int) -> bool:
    """
    Determines whether the two integers `a` and `b` are coprime (i.e., whether their greatest common divisor is 1).
    :param a: the first integer to be tested for co-primality (with the second integer `b`).
    :param b: the second integer to be tested for co-primality (with the first integer `a`).
    :return: whether the integers `a` and `b` are coprime.
    """
    return number.GCD(a, b) == 1


def random_prime_of_size(size_bits: int, parallel: bool = False) -> int:
    """
    Generates a random prime number of the specified size in bits, specifically a prime lying in the range:
        `[2^(size_bits-1) + 1, 2^size_bits - 1]`

    :param size_bits: The number of bits to use in the prime number to be generated.
    :param parallel: Whether to generate the random prime number using parallel processing (default is False).
    :return: A random prime number of the specified bit size.
    """
    if parallel:
        return _parallel_random_prime_of_size(size_bits)
    else:
        # i: int = 0
        while True:
            prime_candidate: Optional[int] = _attempt_probable_prime_generation(size_bits)

            # DEBUG
            # print(f"DEBUG: Attempt #{i} to generate a random prime of size {size_bits} bits.")

            if prime_candidate is not None:
                return prime_candidate

            # i += 1


def _attempt_probable_prime_generation(size_bits: int) -> Optional[int]:
    assert size_bits >= 2, "The size for the prime to be generated must be at least 2 bits."

    # DEBUG
    # ts_start = time.perf_counter_ns()

    rand_odd_int: int = utils.random_positive_integer_of_size(size_bits) | 1  # set LSb to ensure integer is odd

    probable_prime: Optional[int] = rand_odd_int if is_probable_prime(rand_odd_int) else None

    # DEBUG
    # ts_end = time.perf_counter_ns()
    # if probable_prime is not None:
    #     print(f"DEBUG: Time to generate probable prime: {(ts_end - ts_start)/1_000_000_000:.9f} secs.")
    # else:
    #     print(f"DEBUG: Time to generate probable prime (no prime found): {(ts_end - ts_start)/1_000_000_000:.9f} secs.")

    return probable_prime


def _parallel_random_prime_of_size(size_bits: int, thread_count: Optional[int] = None) -> int:
    if thread_count is None:
        thread_count = min(32, (os.cpu_count() or 1) + 4)

    threadpool_exec = ThreadPoolExecutor(max_workers=thread_count)

    prime_futures: list[Future] = []
    try:
        while True:
            for _ in range(thread_count):
                prime_futures.append(
                    threadpool_exec.submit(_attempt_probable_prime_generation, size_bits)
                )

            for future in futures.as_completed(prime_futures):
                prime: Optional[int] = future.result()
                if prime is not None:
                    return prime
            else:
                prime_futures.clear()
    finally:
        # Wait for the first prime to complete being generated.
        done, not_done = futures.wait(prime_futures, return_when=futures.FIRST_COMPLETED)
        # Cancel any remaining, unfinished prime generation attempts.
        for running in not_done:
            running.cancel()

        threadpool_exec.shutdown()


def random_strong_prime(size_bits: int) -> int:
    """
    Generates a random "strong" prime number of the specified size in bits, specifically a prime `p` such that `p - 1`
    `p + 1` both have at least one large prime factor.

    :param size_bits: The number of bits to use in the prime number to be generated.
    :return: A random "strong" prime number of the specified bit size.
    """
    return number.getStrongPrime(size_bits)


def random_safe_prime(
        size_bits: int,
        parallel: bool = False,
        attempts_per_worker: int = 4,
        worker_tasks: Optional[int] = None
) -> int:
    """
    Generates a random "safe" prime number of the specified size in bits, specifically a prime `p` such that
    ``p = 2*q + 1``, where `q` is also prime (i.e., where ``q = (p - 1) / 2`` is prime). The associated prime `q`,
    where ``q = (p-1)/2``, is thereby a Sophie Germain prime.

    This function generates a random (size_bits-1)-bit (strongly) probable prime `q` (verified with Miller-Rabin
    primality test), and then applies Pocklington's criterion for primality to test whether ``p = 2*q + 1`` is prime,
    the latter of which requires only a single-round Fermat primality test for the base 2 in this case.

    :see: `Pocklington's criterion <https://en.wikipedia.org/wiki/Pocklington_primality_test#Pocklington_criterion>`_
    :see: `Fast check of safe primes or Sophie Germain primes
          <https://math.stackexchange.com/questions/870626/fast-check-of-safe-primes-or-sophie-germain-primes>`_
    :see: `Fermat primality test <https://en.wikipedia.org/wiki/Fermat_primality_test>`_

    :param size_bits: The number of bits to use in the prime number to be generated.
    :param parallel: Whether to generate the random safe prime number using parallel processing (default is False).
    :return: A random "safe" prime number of the specified bit size (i.e., a prime `p` such that `p = 2*q + 1`, where
            `q` is also prime).
    """
    if parallel:
        return _parallel_random_safe_prime(
            size_bits,
            attempts_per_worker=attempts_per_worker,
            worker_count=worker_tasks
        )
    else:
        # DEBUG:
        ts_start: float = time.perf_counter()

        i = 0
        # Attempt to generate a random safe prime of the specified size in bits.
        while (p := _attempt_safe_prime_generation(size_bits, attempts=1, parallel=False)) is None:
            i += 1

        # DEBUG:
        ts_end: float = time.perf_counter()
        print(
            f'\nDEBUG: Total time to generate a "safe" prime ({size_bits} bits): {ts_end - ts_start:.6f} secs.'
            f' [iterations={i}]'
        )

        return p


def _attempt_safe_prime_generation(size_bits: int, attempts: int = 4, parallel: bool = False) -> Optional[int]:
    assert size_bits >= 2, "The size for the safe prime to be generated must be at least 2 bits."

    # DEBUG:
    ts_start: float = time.perf_counter()

    for i in range(attempts):
        # Generate a random probable prime `q` of size `size_bits-1` bits. (Uses the Miller-Rabin primality test,
        # following a limited prime factor search.)
        q: int = random_prime_of_size(size_bits - 1, parallel=parallel)
        p: int = 2 * q + 1

        assert p.bit_length() == size_bits, \
            f"Generated prime has {p.bit_length()} bits, not the expected {size_bits} bits."

        # Test if `p` is prime using a single-round Fermat primality test for the base 2, which is sufficient for
        # satisfying Pocklington's criteria for primality, given that `q` is prime and ``p = 2*q + 1``.
        if _fermat_primality_one_round(p, base=2):
            # DEBUG:
            ts_end: float = time.perf_counter()
            print(f'\nDEBUG: Time to generate a "safe" prime ({size_bits} bits): {ts_end - ts_start:.6f} secs.')

            return p  # `p` is a safe prime
        else:
            # DEBUG:
            ts_end: float = time.perf_counter()
            print(
                f'DEBUG: Time to generate probable prime ({size_bits} bits) & check if "safe" prime (not "safe" prime):'
                f' {ts_end - ts_start:.6f} secs.'
            )
    else:
        # Indicate failure to generate a "safe" prime, after the specified number of attempts.
        return None


def _parallel_random_safe_prime(
        size_bits: int,
        attempts_per_worker: int = 4,
        worker_count: Optional[int] = None
) -> int:
    if worker_count is None:
        worker_count = min(32, (os.cpu_count() or 1) + 4)

    with ProcessPoolExecutor(max_workers=worker_count) as process_pool_exec:  # auto-cleanup executor & workers
        # DEBUG:
        ts_start: float = time.perf_counter()

        i = 0
        while True:
            # Submit worker_count worker tasks to ProcessPoolExecutor, each generating a probable prime, then testing
            # if it's a valid "safe" prime.
            safe_prime_futures: list[Future[Optional[int]]] = [
                process_pool_exec.submit(
                    _attempt_safe_prime_generation,
                    size_bits=size_bits,
                    attempts=attempts_per_worker,
                    parallel=False        # don't perform Miller-Rabin primality tests in parallel
                )
                for _ in range(worker_count)
            ]

            j = 0
            for future in futures.as_completed(safe_prime_futures):
                safe_prime_candidate: Optional[int] = future.result()

                if safe_prime_candidate is not None:
                    # DEBUG:
                    ts_end: float = time.perf_counter()
                    print(
                        f'\nDEBUG: Total time to generate a "safe" prime ({size_bits} bits): {ts_end - ts_start:.6f}'
                        f' secs. [batches={i}, iterations={i*worker_count + j}]'
                    )

                    return safe_prime_candidate  # Return found safe prime.

                j += 1
            i += 1


def is_probable_prime(n: int) -> bool:
    """
    Determines whether the given integer `n` is a (strongly) probable prime, using the Miller-Rabin primality test.

    :see: `Miller-Rabin primality test <https://en.wikipedia.org/wiki/Miller-Rabin_primality_test>`_

    :param n: the integer to be tested for (strongly) probable primality via the Miller-Rabin primality test.
    :return: whether the integer `n` is a (strongly) probable prime (with high probability), or definitely composite.
    """
    return number.isPrime(n)  # uses the Miller-Rabin primality test, following a limited prime factor search


def fermat_primality_test(n: int, rounds: int = DEFAULT_FERMAT_PRIMALITY_ROUNDS) -> bool:
    """
    Determines whether the given integer `n` is possibly prime by the Fermat primality test, or definitely composite.
    This function performs multiple rounds of the Fermat primality test to increase the confidence in the primality of
    the given integer `n`.

    Note: The Fermat primality test is a probabilistic primality test, and is not guaranteed to correctly identify all
    composite numbers. It is possible for a composite number to pass the Fermat primality test, in which case it is
    known as a Fermat pseudoprime. (In fact there exist an infinite number of composite integers, known as Carmichael
    numbers, which will pass the Fermat primality test for _all_ bases co-prime with n, and yet are composite.)

    The number of rounds of the Fermat primality test can be adjusted to increase the confidence in the primality of the
    given integer `n`. However, if high confidence is required, it is recommended to use a more rigorous primality test
    such as the Miller-Rabin primality test.

    :see: `Fermat primality test <https://en.wikipedia.org/wiki/Fermat_primality_test>`_

    :param n: the integer to be tested for possible primality by the Fermat primality (pseudoprime) test.
    :param rounds: the number of rounds of the Fermat primality test to perform (default is
           `DEFAULT_FERMAT_PRIMALITY_ROUNDS`).
    :return: whether the integer `n` is possibly prime by the Fermat primality test, or definitely composite.
    """
    for _ in range(rounds):
        # Choose a random base for the Fermat primality test, in the range: [2, n-2]
        base: int = utils.random_integer_in_range(2, n - 1)
        if not _fermat_primality_one_round(n, base):
            return False  # n is definitely composite

    return True  # n is possibly prime (but may be a composite Fermat pseudoprime)


def _fermat_primality_one_round(n: int, base: int = 2) -> bool:
    """
    Computes one round of the Fermat primality test, which can determine if the given integer `n` is composite
    (i.e., not prime), or can provide evidence it may be prime. This function returns True if the Fermat primality test
    is passed, and False if the test fails (i.e., `n` is definitely composite).

    This function is intended for internal use by the `fermat_primality` function, which performs multiple rounds of
    the Fermat primality test to increase the confidence in the primality of the given integer `n`.

    :param n: the integer to be tested for being a possible prime (or a composite Fermat pseudoprime), or a composite
           integer.
    :param base: the base for the Fermat primality test (default is 2).
    :return: whether the integer `n` is possibly prime by the Fermat primality test, or definitely composite.
    """
    if n < 2:
        raise ValueError("The Fermat primality test is only defined for integers greater than or equal to 2.")
    if n == 2:
        return True
    elif n % 2 == 0:
        return False
    elif base % n == 0:
        raise ValueError("The base for the Fermat primality test must be coprime to the integer being tested.")
    else:
        return pow(base, n - 1, n) == 1
