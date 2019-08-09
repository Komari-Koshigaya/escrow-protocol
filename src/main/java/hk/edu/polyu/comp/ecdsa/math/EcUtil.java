package hk.edu.polyu.comp.ecdsa.math;

/**
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import java.math.BigInteger;
import java.security.GeneralSecurityException;

/**
 * Some utilities for testing Elliptic curve crypto. This code is for testing only and hasn't been
 * reviewed for production.
 */
public class EcUtil {

  /**
   * Compute the Legendre symbol of x mod p. This implementation is slow. Faster would be the
   * computation for the Jacobi symbol.
   *
   * @param x an integer
   * @param p a prime modulus
   * @return 1 if x is a quadratic residue, -1 if x is a non-quadratic residue and 0 if x and p are
   *     not coprime.
   * @throws GeneralSecurityException when the computation shows that p is not prime.
   */
  public static int legendre(BigInteger x, BigInteger p) throws GeneralSecurityException {
    BigInteger q = p.subtract(BigInteger.ONE).shiftRight(1);
    BigInteger t = x.modPow(q, p);
    if (t.equals(BigInteger.ONE)) {
      return 1;
    } else if (t.equals(BigInteger.ZERO)) {
      return 0;
    } else if (t.add(BigInteger.ONE).equals(p)) {
      return -1;
    } else {
      throw new GeneralSecurityException("p is not prime");
    }
  }

  /**
   * Computes a modular square root. Timing and exceptions can leak information about the inputs.
   * Therefore this method must only be used in tests.
   *
   * @param x the square
   * @param p the prime modulus
   * @return a value s such that s^2 mod p == x mod p
   * @throws GeneralSecurityException if the square root could not be found.
   */
  public static BigInteger modSqrt(BigInteger x, BigInteger p) throws GeneralSecurityException {
    if (p.signum() != 1) {
      throw new GeneralSecurityException("p must be positive");
    }
    x = x.mod(p);
    BigInteger squareRoot = null;
    // Special case for x == 0.
    // This check is necessary for Cipolla's algorithm.
    if (x.equals(BigInteger.ZERO)) {
      return x;
    }
    if (p.testBit(0) && p.testBit(1)) {
      // Case p % 4 == 3
      // q = (p + 1) / 4
      BigInteger q = p.add(BigInteger.ONE).shiftRight(2);
      squareRoot = x.modPow(q, p);
    } else if (p.testBit(0) && !p.testBit(1)) {
      // Case p % 4 == 1
      // For this case we use Cipolla's algorithm.
      // This alogorithm is preferrable to Tonelli-Shanks for primes p where p-1 is divisible by
      // a large power of 2, which is a frequent choice since it simplifies modular reduction.
      BigInteger a = BigInteger.ONE;
      BigInteger d = null;
      while (true) {
        d = a.multiply(a).subtract(x).mod(p);
        // Computes the Legendre symbol. Using the Jacobi symbol would be a faster. Using Legendre
        // has the advantage, that it detects a non prime p with high probability.
        // On the other hand if p = q^2 then the Jacobi (d/p)==1 for almost all d's and thus
        // using the Jacobi symbol here can result in an endless loop with invalid inputs.
        int t = legendre(d, p);
        if (t == -1) {
          break;
        } else {
          a = a.add(BigInteger.ONE);
        }
      }
      // Since d = a^2 - n is a non-residue modulo p, we have
      //   a - sqrt(d) == (a+sqrt(d))^p (mod p),
      // and hence
      //   n == (a + sqrt(d))(a - sqrt(d) == (a+sqrt(d))^(p+1) (mod p).
      // Thus if n is square then (a+sqrt(d))^((p+1)/2) (mod p) is a square root of n.
      BigInteger q = p.add(BigInteger.ONE).shiftRight(1);
      BigInteger u = a;
      BigInteger v = BigInteger.ONE;
      for (int bit = q.bitLength() - 2; bit >= 0; bit--) {
        // Compute (u + v sqrt(d))^2
        BigInteger tmp = u.multiply(v);
        u = u.multiply(u).add(v.multiply(v).mod(p).multiply(d)).mod(p);
        v = tmp.add(tmp).mod(p);
        if (q.testBit(bit)) {
          tmp = u.multiply(a).add(v.multiply(d)).mod(p);
          v = a.multiply(v).add(u).mod(p);
          u = tmp;
        }
      }
      squareRoot = u;
    }
    // The methods used to compute the square root only guarantee a correct result if the
    // preconditions (i.e. p prime and x is a square) are satisfied. Otherwise the value is
    // undefined. Hence, it is important to verify that squareRoot is indeed a square root.
    if (squareRoot != null && squareRoot.multiply(squareRoot).mod(p).compareTo(x) != 0) {   	
        throw new GeneralSecurityException("Could not find square root");
    }
    return squareRoot;
  }

}