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

import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:convert/convert.dart';
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
  PublicKey getPublicKey() =>
      PublicKey(data.buffer.asUint8List(privateKeySize - publicKeySize));

  Uint8List getPrivateKeyData() =>
      data.buffer.asUint8List(0, privateKeySize - publicKeySize);
}

/// Point representation in extended twisted Edwards coordinates.
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
    for (int i = 0; i < x.length; i++) x[i] = 0 - x[i];

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

  static Uint8List addScalars(Uint8List a, Uint8List b,
      [bool negateB = false]) {
    final Uint8List one = Uint8List(32);
    one[0] = 1;
    return multiplyAddScalars(a, one, b, negateB);
  }

  static Uint8List subtractScalars(Uint8List a, Uint8List b) =>
      addScalars(a, b, true);
}

/// Returned by [generateJointPublicKey].
class JointPublicKey {
  PublicKey jointPublicKey;
  List<PublicKey> primeKeys = List<PublicKey>();
}

/// Returned from [generateAdaptor].
class Adaptor {
  Uint8List secret;
  CurvePoint point;
  Adaptor(this.secret, this.point);
}

/// Takes n pubkeys: P1, P2, ..., Pn
/// Returns n+1 pubkeys: an aggregate joint key, J, as well as
/// n modified pubkeys: P'1, P'2, ..., P'n
/// Implemented as described in:
/// https://blockstream.com/2018/01/23/musig-key-aggregation-schnorr-signatures.html
JointPublicKey generateJointPublicKey(List<PublicKey> publicKeys) {
  JointPublicKey ret = JointPublicKey();

  // L = H(P1 || P2 || ... || Pn)
  final Uint8List jointHash = Hash.sha512(
      Uint8List.fromList(publicKeys.expand((x) => x.data).toList()));

  final List<CurvePoint> primeKeys = <CurvePoint>[];
  for (PublicKey publicKey in publicKeys) {
    // P'i = H(L || Pi) * Pi - here we calculate
    // primeDigests[i] = H(L || Pi)
    final Uint8List primeDigest =
        Hash.sha512(Uint8List.fromList(jointHash + publicKey.data));

    // reduce our primeDigests to proper scalars
    TweetNaclFast.reduce(primeDigest);

    // P'i = H(L || Pi) * Pi - here we calculate P'i
    primeKeys.add(CurvePoint.unpack(publicKey.data)
        .scalarMultiply(primeDigest.sublist(0, scalarSize)));
    ret.primeKeys.add(PublicKey(primeKeys.last.pack()));
  }

  // as well as J = Sum(P'i)
  CurvePoint jointPublicKey = primeKeys[0].add(primeKeys[1]);
  for (int i = 2; i < primeKeys.length; i++) {
    jointPublicKey = jointPublicKey.add(primeKeys[i]);
  }

  ret.jointPublicKey = PublicKey(jointPublicKey.pack());
  return ret;
}

Uint8List generateJointPrivateKey(
    List<PublicKey> publicKeys, PrivateKey privateKey, int n) {
  // L = H(P1 || P2 || ... || Pn)
  final Uint8List jointHash = Hash.sha512(
      Uint8List.fromList(publicKeys.expand((x) => x.data).toList()));

  // x'i = H(L || Pi) * xi
  // this calculates H(L || Pi)
  final Uint8List primeDigest =
      Hash.sha512(Uint8List.fromList(jointHash + publicKeys[n].data));

  // here we reduce to a proper scalar
  TweetNaclFast.reduce(primeDigest);

  // here we calculate H(L || Pi) * xi
  Uint8List digest = Hash.sha512(privateKey.getPrivateKeyData());
  CurvePoint.clampScalarBits(digest);
  return CurvePoint.multiplyAddScalars(digest, primeDigest);
}

Uint8List generateNonce(PrivateKey privateKey, Uint8List message) {
  final Uint8List digest = Hash.sha512(privateKey.getPrivateKeyData());
  final Uint8List messageDigest =
      Hash.sha512(Uint8List.fromList(digest.sublist(32) + message));
  TweetNaclFast.reduce(messageDigest);
  return messageDigest;
}

// H(R1 + R2 + ... + Rn || J(P1, P2, ..., Pn) || m) = e
// si = ri + e * x'i
Uint8List jointSign(PrivateKey privateKey, PrivateKey jointPrivateKey,
    List<CurvePoint> noncePoints, Uint8List message) {
  assert(noncePoints.length >= 2);

  // R = Sum(Ri)
  CurvePoint summedR = noncePoints[0].add(noncePoints[1]);
  for (int i = 2; i < noncePoints.length; i++) {
    summedR = summedR.add(noncePoints[i]);
  }

  // e = H(R1 + R2 + ... + Rn || J(P1, P2, ..., Pn) || m)
  final Uint8List e = Hash.sha512(Uint8List.fromList(
      summedR.pack() + jointPrivateKey.getPublicKey().data + message));
  TweetNaclFast.reduce(e);

  final Uint8List r = generateNonce(privateKey, message);
  final Uint8List s =
      CurvePoint.multiplyAddScalars(e, jointPrivateKey.getPrivateKeyData(), r);
  return Uint8List.fromList(CurvePoint.fromScalar(r).pack() + s);
}

// s_agg = s_A + s_B
// R_agg = R_A + R_B
Uint8List addSignatures(Uint8List signature1, Uint8List signature2) {
  // s1 * 1 + s2 = s1 + s2
  final Uint8List s =
      CurvePoint.addScalars(signature1.sublist(32), signature2.sublist(32));

  final CurvePoint R = CurvePoint.unpack(signature1.sublist(0, 32))
      .add(CurvePoint.unpack(signature2.sublist(0, 32)));

  return Uint8List.fromList(R.pack() + s);
}

Adaptor generateAdaptor(Uint8List seed) {
  Uint8List adaptor = Hash.sha512(seed);
  CurvePoint.clampScalarBits(adaptor);
  TweetNaclFast.reduce(adaptor);
  adaptor = adaptor.sublist(0, adaptorSize);
  CurvePoint x = CurvePoint.fromScalar(adaptor);
  return Adaptor(adaptor, x);
}

// e = H(R_A + R_B + T || J(A, B) || m)
// s_A = r_A + e * x_A'
// s_B' = r_B + e * x_B'
Uint8List jointSignWithAdaptor(
    PrivateKey privateKey,
    PrivateKey jointPrivateKey,
    CurvePoint noncePoint1,
    CurvePoint noncePoint2,
    CurvePoint adaptorPoint,
    Uint8List message) {
  List<CurvePoint> noncePoints = <CurvePoint>[
    noncePoint1,
    noncePoint2,
    adaptorPoint
  ];
  return jointSign(privateKey, jointPrivateKey, noncePoints, message);
}

// e = H(R_A + R_B + T || J(A, B) || m)
// s_B' * G ?= R_B + e * P_B'
// So R_B ?= S_B' - e * P_B'?
bool verifyAdaptorSignature(
    PublicKey publicKey,
    PublicKey jointPublicKey,
    CurvePoint noncePoint1,
    CurvePoint noncePoint2,
    CurvePoint adaptorPoint,
    Uint8List message,
    Uint8List sig) {
  CurvePoint summedR = noncePoint1.add(noncePoint2);
  summedR = summedR.add(adaptorPoint);

  // e = H(R_A + R_B + T || J(A, B) || m)
  final Uint8List e = Hash.sha512(
      Uint8List.fromList(summedR.pack() + jointPublicKey.data + message));
  TweetNaclFast.reduce(e);

  // e * -P_B'
  CurvePoint hramA = CurvePoint.unpackneg(publicKey.data).scalarMultiply(e);

  // R_B = - H(R_A+R_B+T,P_B',m)P_B' + s_b'*BASE_POINT
  CurvePoint R = hramA.add(CurvePoint.fromScalar(sig.sublist(32)));
  return equalUint8List(R.pack(), sig.sublist(0, 32));
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
