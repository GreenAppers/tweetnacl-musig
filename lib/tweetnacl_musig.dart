/// Copyright 2019 tweetnacl-musig developers
/// Use of this source code is governed by a MIT-style license that can be found in the LICENSE file.

/// TweetNaCl: A crypto library in 100 tweets
/// Bernstein, D. (2013) https://tweetnacl.cr.yp.to/tweetnacl-20131229.pdf
///
/// MuSig, a multi-signature scheme based on Schnorr signatures
/// Maxwell, G. (2018) https://eprint.iacr.org/2018/068.pdf
///
/// Based off the implementation by Mark Huetsch: https://github.com/HyperspaceApp/ed25519
library tweetnacl_musig;

import 'dart:math';
import 'dart:typed_data';

import 'package:meta/meta.dart';
import 'package:tweetnacl/tweetnacl.dart';

const int publicKeySize = 32;
const int privateKeySize = 64;
const int signatureSize = 64;
const int adaptorSize = 32;
const int curvePointSize = 32;
const int scalarSize = 32;

/// Ed25519 public key, 32 bytes.
@immutable
class PublicKey {
  final Uint8List data;

  /// Fully specified constructor.
  PublicKey(this.data) {
    if (data.length != publicKeySize) throw FormatException();
  }
}

/// Ed25519 public key, 64 bytes.
@immutable
class PrivateKey {
  final Uint8List data;

  /// Fully specified constructor.
  PrivateKey(this.data) {
    if (data.length != privateKeySize) throw FormatException();
  }

  PrivateKey.fromKeyPair(Uint8List privateKey, Uint8List publicKey)
      : this(Uint8List.fromList(privateKey + publicKey));

  /// Creates a [PrivateKey] from a secret.
  PrivateKey.fromSeed(Uint8List seed)
      : this(Signature.keyPair_fromSeed(seed).secretKey);

  /// The second half of an Ed25519 private key is the public key.
  PublicKey get publicKey =>
      PublicKey(data.buffer.asUint8List(privateKeySize - publicKeySize));

  Uint8List get privateKeyData =>
      data.buffer.asUint8List(0, privateKeySize - publicKeySize);
}

/// Schnorr signature: (R,s) = (rG, r + H(X,R,m)x).
@immutable
class SchnorrSignature {
  final Uint8List data;

  /// Fully specified constructor.
  SchnorrSignature(Uint8List R, Uint8List s)
      : data = Uint8List.fromList(R + s) {
    if (data.length != signatureSize) throw FormatException();
  }

  Uint8List get R => data.buffer.asUint8List(0, curvePointSize);
  Uint8List get s => data.buffer.asUint8List(curvePointSize);
}

/// Point representation in extended twisted Edwards coordinates, radix 2^16.
class CurvePoint {
  List<Int64List> data = <Int64List>[
    Int64List(16),
    Int64List(16),
    Int64List(16),
    Int64List(16)
  ];
  CurvePoint();

  /// Clones a deep-copy of [x].
  CurvePoint.copy(CurvePoint x)
      : data = <Int64List>[
          Int64List.fromList(x.x),
          Int64List.fromList(x.y),
          Int64List.fromList(x.z),
          Int64List.fromList(x.t)
        ];

  /// Unpacks negative RFC 8032 encoded ed25519 [point].
  CurvePoint.unpackneg(Uint8List point) {
    if (TweetNaclFast.unpackneg(data, point) != 0) throw FormatException();
  }

  /// Unpacks RFC 8032 encoded ed25519 [point].
  CurvePoint.unpack(Uint8List point) {
    /// TweetNacl has identity: x = pack(unpackneg(pack(unpackneg(x)))).
    if (TweetNaclFast.unpackneg(data, point) != 0) throw FormatException();

    /// Undo the final [x] coordinate negation performed by [TweetNaclFast.unpackneg].
    for (int i = 0; i < x.length; i++) {
      x[i] = 0 - x[i];
    }

    /// Re-calculate [t] for updated [x].
    TweetNaclFast.M_off(t, 0, x, 0, y, 0);
  }

  /// Returns result of scalar multiplication of the base point by integer [n].
  CurvePoint.fromScalar(Uint8List n) {
    TweetNaclFast.scalarbase(data, n, 0);
  }

  Int64List get x => data[0];
  Int64List get y => data[1];
  Int64List get z => data[2];
  Int64List get t => data[3];

  /// Returns result of scalar multiplication of [CurvePoint] by integer [n].
  CurvePoint scalarMultiply(Uint8List n) {
    CurvePoint r = CurvePoint();
    TweetNaclFast.scalarmult(r.data, data, n, 0);
    return r;
  }

  /// Adds points on the Edwards curve.  Returns sum of points.
  CurvePoint add(CurvePoint q) {
    CurvePoint r = CurvePoint.copy(this);
    TweetNaclFast.add(r.data, q.data);
    return r;
  }

  Uint8List pack() {
    Uint8List ret = Uint8List(curvePointSize);
    TweetNaclFast.pack(ret, data);
    return ret;
  }

  String toString() => 'CurvePoint(\n  x=$x,\n  y=$y,\n  z=$z,\n  t=$t)';

  /// Clamps the lower and upper bits as required by the specification.
  static Uint8List clampScalarBits(Uint8List data) {
    data[0] &= 248;
    data[31] &= 127;
    data[31] |= 64;
    return data;
  }

  /// Returns ([a] * [b] + [c]) mod l, where l = 2^252 + 27742317777372353535851937790883648493.
  static Uint8List multiplyAddScalars(Uint8List a, Uint8List b,
      [Uint8List c, bool negateC = false]) {
    /// Copied from end of [TweetNacl.crypto_sign] code.
    Int64List r = Int64List(64);
    if (c != null) {
      if (negateC) {
        for (int i = 0; i < scalarSize; i++) {
          r[i] = 0 - (c[i] & 0xff).toInt();
        }
      } else {
        for (int i = 0; i < scalarSize; i++) {
          r[i] = (c[i] & 0xff).toInt();
        }
      }
    }
    for (int i = 0; i < scalarSize; i++) {
      for (int j = 0; j < scalarSize; j++) {
        r[i + j] += (a[i] & 0xff) * (b[j] & 0xff).toInt();
      }
    }
    Uint8List ret = Uint8List(scalarSize);
    TweetNaclFast.modL(ret, 0, r);
    return ret;
  }

  static Uint8List multiplyScalars(Uint8List a, Uint8List b) =>
      multiplyAddScalars(a, b);

  static Uint8List addScalars(Uint8List a, Uint8List b,
      [bool negateB = false]) {
    final Uint8List one = Uint8List(32);
    one[0] = 1;
    return multiplyAddScalars(a, one, b, negateB);
  }

  static Uint8List subtractScalars(Uint8List a, Uint8List b) =>
      addScalars(a, b, true);
}

/// https://blockstream.com/2018/01/23/musig-key-aggregation-schnorr-signatures.html
class JointKey {
  /// n modified pubkeys: X'i = H(L,Xi)Xi.
  List<PublicKey> primePublicKeys = List<PublicKey>();

  /// Call X the sum of all H(L,Xi)Xi
  PublicKey jointPublicKey;

  /// H(L,Xi)xi for i = [primePrivateKeyIndex].
  PrivateKey primePrivateKey;

  /// The [primePublicKeys] index that [primePrivateKey] corresponds to.
  int primePrivateKeyIndex;

  /// Accepts n pubkeys: X1, X2, …, Xn, and xi where i = [primePrivateKeyIndex].
  JointKey.generate(List<PublicKey> publicKeys, PrivateKey privateKey,
      this.primePrivateKeyIndex) {
    // Call L = H(X1,X2,…).
    final Uint8List jointHash = Hash.sha512(
        Uint8List.fromList(publicKeys.expand((x) => x.data).toList()));

    Uint8List myPrimeDigest;
    final List<CurvePoint> primeKeyPoints = <CurvePoint>[];
    for (int i = 0; i < publicKeys.length; i++) {
      // Call primeDigest[i] = H(L,Xi)
      final Uint8List primeDigest =
          Hash.sha512(Uint8List.fromList(jointHash + publicKeys[i].data));
      TweetNaclFast.reduce(primeDigest);

      /// Save our [primeDiest] for generating [primePrivateKey].
      if (i == primePrivateKeyIndex) {
        myPrimeDigest = Uint8List.fromList(primeDigest);
      }

      // X'i = H(L,Xi)Xi.
      final CurvePoint X = CurvePoint.unpack(publicKeys[i].data);
      primeKeyPoints.add(X.scalarMultiply(primeDigest.sublist(0, scalarSize)));
      primePublicKeys.add(PublicKey(primeKeyPoints.last.pack()));
    }

    // Call X the sum of all H(L,Xi)Xi
    CurvePoint jointPublicKeyPoint = primeKeyPoints[0].add(primeKeyPoints[1]);
    for (int i = 2; i < primeKeyPoints.length; i++) {
      jointPublicKeyPoint = jointPublicKeyPoint.add(primeKeyPoints[i]);
    }
    jointPublicKey = PublicKey(jointPublicKeyPoint.pack());

    // Here we calculate H(L,Xi)xi.  Note that Xi = G * H(xi).
    Uint8List digest = Hash.sha512(privateKey.privateKeyData);
    CurvePoint.clampScalarBits(digest);
    primePrivateKey = PrivateKey.fromKeyPair(
        CurvePoint.multiplyScalars(digest, myPrimeDigest), jointPublicKey.data);
  }
}

/// Returned from [generateAdaptor].
class Adaptor {
  Uint8List secret;
  CurvePoint point;

  Adaptor.generate(Uint8List seed) {
    Uint8List adaptor = Hash.sha512(seed);
    CurvePoint.clampScalarBits(adaptor);

    /// Without this [TweetNaclFast.reduce()] the resulting [x] would be equivalent
    /// to the [KeyPair.publicKey] returned from [Signature.keyPair_fromSeed()].
    /// But then we couldn't recover either adaptor from subtracting their sum.
    TweetNaclFast.reduce(adaptor);

    secret = adaptor.sublist(0, adaptorSize);
    point = CurvePoint.fromScalar(adaptor);
  }
}

/// Same r calculation as in [TweetNaclFast.crypto_sign].
Uint8List generateNonce(PrivateKey privateKey, Uint8List message) {
  final Uint8List digest = Hash.sha512(privateKey.privateKeyData);
  final Uint8List messageDigest =
      Hash.sha512(Uint8List.fromList(digest.sublist(32) + message));
  TweetNaclFast.reduce(messageDigest);
  return messageDigest;
}

/// Each signer computes si = ri + H(X,R,m)H(L,Xi)xi.
SchnorrSignature jointSign(PrivateKey privateKey, JointKey jointKey,
    List<CurvePoint> noncePoints, Uint8List message) {
  assert(noncePoints.length >= 2);

  /// Call R the sum of the Ri points.
  CurvePoint summedR = noncePoints[0].add(noncePoints[1]);
  for (int i = 2; i < noncePoints.length; i++) {
    summedR = summedR.add(noncePoints[i]);
  }

  /// e = H(X,R,m).
  final Uint8List e = Hash.sha512(Uint8List.fromList(
      summedR.pack() + jointKey.jointPublicKey.data + message));
  TweetNaclFast.reduce(e);

  /// Each MuSig signer computes si = ri + H(X,R,m)H(L,Xi)xi.
  final Uint8List r = generateNonce(privateKey, message);
  final CurvePoint R = CurvePoint.fromScalar(r);
  final Uint8List s = CurvePoint.multiplyAddScalars(
      e, jointKey.primePrivateKey.privateKeyData, r);

  /// Schnorr signatures are (R,s) = (rG, r + H(X,R,m)x).
  return SchnorrSignature(R.pack(), s);
}

/// The final signature is (R,s) where s is the sum of the si values.
SchnorrSignature addSignatures(
    SchnorrSignature signature1, SchnorrSignature signature2) {
  final Uint8List s = CurvePoint.addScalars(signature1.s, signature2.s);
  final CurvePoint R =
      CurvePoint.unpack(signature1.R).add(CurvePoint.unpack(signature2.R));
  return SchnorrSignature(R.pack(), s);
}

// e = H(R_A + R_B + T || J(A, B) || m)
// s_A = r_A + e * x_A'
// s_B' = r_B + e * x_B'
SchnorrSignature jointSignWithAdaptor(
    PrivateKey privateKey,
    JointKey jointKey,
    CurvePoint noncePoint1,
    CurvePoint noncePoint2,
    CurvePoint adaptorPoint,
    Uint8List message) {
  List<CurvePoint> noncePoints = <CurvePoint>[
    noncePoint1,
    noncePoint2,
    adaptorPoint
  ];
  return jointSign(privateKey, jointKey, noncePoints, message);
}

// e = H(R_A + R_B + T || J(A, B) || m)
// s_B' * G ?= R_B + e * P_B'
// So R_B ?= S_B' - e * P_B'?
bool verifyAdaptorSignature(
    PublicKey primeKey,
    PublicKey jointPublicKey,
    CurvePoint noncePoint1,
    CurvePoint noncePoint2,
    CurvePoint adaptorPoint,
    Uint8List message,
    SchnorrSignature sig) {
  CurvePoint summedR = noncePoint1.add(noncePoint2);
  summedR = summedR.add(adaptorPoint);

  // e = H(R_A + R_B + T || J(A, B) || m)
  final Uint8List e = Hash.sha512(
      Uint8List.fromList(summedR.pack() + jointPublicKey.data + message));
  TweetNaclFast.reduce(e);

  // e * -P_B'
  CurvePoint hramA = CurvePoint.unpackneg(primeKey.data).scalarMultiply(e);

  // R_B = - H(R_A+R_B+T,P_B',m)P_B' + s_b'*BASE_POINT
  CurvePoint R = hramA.add(CurvePoint.fromScalar(sig.s));
  return equalUint8List(R.pack(), sig.R);
}

/// Returns [n] random bytes.
Uint8List randBytes(int n) {
  final Random generator = Random.secure();
  final Uint8List random = Uint8List(n);
  for (int i = 0; i < random.length; i++) {
    random[i] = generator.nextInt(255);
  }
  return random;
}

/// Returns true if [x] and [y] are equivalent.
bool equalUint8List(Uint8List x, Uint8List y) {
  if (x.length != y.length) return false;
  for (int i = 0; i < x.length; ++i) {
    if (x[i] != y[i]) return false;
  }
  return true;
}
