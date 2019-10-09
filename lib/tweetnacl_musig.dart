// Copyright 2019 tweetnacl-musig developers
// Use of this source code is governed by a MIT-style license that can be found in the LICENSE file.

/// TweetNaCl: A crypto library in 100 tweets
/// Bernstein, D. (2013) https://tweetnacl.cr.yp.to/tweetnacl-20131229.pdf
///
/// MuSig, a multi-signature scheme based on Schnorr signatures
/// Maxwell, G. (2018) https://eprint.iacr.org/2018/068.pdf
///
/// Based off the implementation by Mark Huetsch: https://github.com/HyperspaceApp/ed25519
library tweetnacl_musig;

import 'dart:convert';
import 'dart:typed_data';

import 'package:convert/convert.dart';
import 'package:meta/meta.dart';
import 'package:tweetnacl/tweetnacl.dart';

const int publicKeySize = 32;
const int privateKeySize = 64;

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

  /// Creates a [PrivateKey] from a secret.
  PrivateKey.fromSeed(Uint8List seed)
      : this(Signature.keyPair_fromSeed(seed).secretKey);

  /// The second half of an Ed25519 private key is the public key.
  PublicKey getPublicKey() =>
      PublicKey(data.buffer.asUint8List(privateKeySize - publicKeySize));
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
    Uint8List ret = Uint8List(32);
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
}

/// Returned by [generateJointPublicKey].
class JointPublicKey {
  PublicKey jointPublicKey;
  List<PublicKey> primeKeys = List<PublicKey>();
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
        .scalarMultiply(primeDigest.sublist(0, 32)));
    ret.primeKeys.add(PublicKey(primeKeys.last.pack()));
  }

  // as well as J = Sum(P'i)
  CurvePoint jointPublicKey = primeKeys[0].add(primeKeys[1]);

  /// TODO handle publicKeys.length > 2
  ret.jointPublicKey = PublicKey(jointPublicKey.pack());
  return ret;
}

PrivateKey generateJointPrivateKey(
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
  Uint8List digest = Hash.sha512(privateKey.data.sublist(0, 32));
  CurvePoint.clampScalarBits(digest);

  return null;
}
