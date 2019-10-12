/// Copyright 2019 tweetnacl-musig developers
/// Use of this source code is governed by a MIT-style license that can be found in the LICENSE file.

import 'dart:convert';
import 'dart:typed_data';

import 'package:convert/convert.dart';
import 'package:test/test.dart';
import 'package:tweetnacl/tweetnacl.dart';

import 'package:tweetnacl_musig/tweetnacl_musig.dart';

void main() {
  /// https://www.di-mgt.com.au/sha_testvectors.html
  test('sha512', () {
    expect(hex.encode(Hash.sha512(utf8.encode('abc'))),
        'ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f');
  });

  test('ed25519', () {
    final CurvePoint p = CurvePoint.fromScalar(
        base64.decode('BW9J+gBeuhTrhZoJOKe2zbvRSlhTYm+spPqcSQvuYQI='));
    expect(base64.encode(p.pack()),
        'fNE5KpDgvPVZX/lnVIku95qADUfYlKPIxfTuXsTB7hg=');
    expect(base64.encode(p.pack()),
        base64.encode(CurvePoint.unpack(p.pack()).pack()));

    final Uint8List message = utf8.encode('test message');
    final PrivateKey priv = PrivateKey.fromSeed(Uint8List(32));
    final Uint8List sig =
        Signature(null, priv.data).sign(message).buffer.asUint8List(0, 64);
    expect(Signature(priv.publicKey.data, null).detached_verify(message, sig),
        true);

    final Uint8List wrongMessage = utf8.encode('wrong message');
    expect(
        Signature(priv.publicKey.data, null).detached_verify(wrongMessage, sig),
        false);
  });

  test('adaptor', () {
    final Adaptor adaptor1 = Adaptor.generate(randBytes(32));
    final Adaptor adaptor2 = Adaptor.generate(randBytes(32));
    final Uint8List scalarSum =
        CurvePoint.addScalars(adaptor1.secret, adaptor2.secret);
    expect(
        equalUint8List(CurvePoint.subtractScalars(scalarSum, adaptor2.secret),
            adaptor1.secret),
        true);
    expect(
        equalUint8List(CurvePoint.subtractScalars(scalarSum, adaptor1.secret),
            adaptor2.secret),
        true);

    final CurvePoint sumB = CurvePoint.fromScalar(scalarSum);
    final CurvePoint sum = adaptor1.point.add(adaptor2.point);
    expect(equalUint8List(sum.pack(), sumB.pack()), true);
  });

  /// https://github.com/HyperspaceApp/ed25519/blob/master/ed25519_test.go#L206
  test('ed25519 join sign verify', () {
    final PrivateKey priv1 = PrivateKey.fromSeed(Uint8List(32));
    final PrivateKey priv2 = PrivateKey.fromSeed(hex.decode(
        '0101010101010101010101010101010101010101010101010101010101010101'));
    final PublicKey pub1 = priv1.publicKey, pub2 = priv2.publicKey;
    expect(base64.encode(pub1.data),
        'O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik=');
    expect(base64.encode(pub2.data),
        'iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w=');

    final List<PublicKey> publicKeys = <PublicKey>[pub1, pub2];
    final JointKey jointKey1 = JointKey.generate(publicKeys, priv1, 0);
    final JointKey jointKey2 = JointKey.generate(publicKeys, priv2, 1);

    expect(base64.encode(jointKey1.primePublicKeys[0].data),
        'hFVljNya6b8nSXxy3VHjxGgm3X2JgzbMeQX+CDGR/H8=');
    expect(base64.encode(jointKey1.primePublicKeys[1].data),
        'qCo70Um1BSY+E563zPVbISQStaGmCvgDwpmac209dtc=');
    expect(jointKey2.primePublicKeys.length, jointKey1.primePublicKeys.length);
    for (int i = 0; i < jointKey1.primePublicKeys.length; i++) {
      expect(
          equalUint8List(jointKey1.primePublicKeys[i].data,
              jointKey2.primePublicKeys[i].data),
          true);
    }

    expect(base64.encode(jointKey1.jointPublicKey.data),
        'xK8i62dTBuOVOBtdwSJpbpXKoTaZ+k3OPdPhWI5nMko=');
    expect(
        equalUint8List(
            jointKey1.jointPublicKey.data, jointKey2.jointPublicKey.data),
        true);

    expect(base64.encode(jointKey1.primePrivateKey.data),
        'k1it5L3rRSjpo5zWn1nCDUKFpwy3sRW1ZlfW2eOphgTEryLrZ1MG45U4G13BImlulcqhNpn6Tc490+FYjmcySg==');
    expect(base64.encode(jointKey2.primePrivateKey.data),
        'Ic704M42z2eH0IEaG2xrxxMF8z5oadZ8q+3WGPYRwwzEryLrZ1MG45U4G13BImlulcqhNpn6Tc490+FYjmcySg==');

    // P_A' should equal x_A' * G
    expect(
        equalUint8List(
            CurvePoint.fromScalar(jointKey1.primePrivateKey.privateKeyData)
                .pack(),
            jointKey1.primePublicKeys[0].data),
        true);

    // P_B' should equal x_B' * G
    expect(
        equalUint8List(
            CurvePoint.fromScalar(jointKey2.primePrivateKey.privateKeyData)
                .pack(),
            jointKey1.primePublicKeys[1].data),
        true);

    // J(A, B) should equal P_A' + P_B'
    expect(
        equalUint8List(
            CurvePoint.unpack(jointKey1.primePublicKeys[0].data)
                .add(CurvePoint.unpack(jointKey1.primePublicKeys[1].data))
                .pack(),
            jointKey1.jointPublicKey.data),
        true);

    final Uint8List message = utf8.encode('Hello, world!');
    final CurvePoint noncePoint1 =
        CurvePoint.fromScalar(generateNonce(priv1, message));
    final CurvePoint noncePoint2 =
        CurvePoint.fromScalar(generateNonce(priv2, message));
    List<CurvePoint> noncePoints = <CurvePoint>[noncePoint1, noncePoint2];
    expect(base64.encode(noncePoint1.pack()),
        'ncPXqaIC/a3hItLZusUD7Flcn5+FTsluh5Y3wjQxhj4=');
    expect(base64.encode(noncePoint2.pack()),
        's4jZio8iIvJcNJW9a5dazXOKSNGMsz/r61Yir7i6mew=');

    // check (r0 + r_1)B == rB
    expect(
        equalUint8List(
            CurvePoint.fromScalar(CurvePoint.addScalars(
                    generateNonce(priv1, message),
                    generateNonce(priv2, message)))
                .pack(),
            noncePoint1.add(noncePoint2).pack()),
        true);

    // check (x0 + x1)B == A
    expect(
        equalUint8List(
            CurvePoint.fromScalar(CurvePoint.addScalars(
                    jointKey1.primePrivateKey.privateKeyData,
                    jointKey2.primePrivateKey.privateKeyData))
                .pack(),
            jointKey1.jointPublicKey.data),
        true);

    final SchnorrSignature sig1 =
        jointSign(priv1, jointKey1, noncePoints, message);
    final SchnorrSignature sig2 =
        jointSign(priv2, jointKey2, noncePoints, message);
    expect(base64.encode(sig1.data),
        'ncPXqaIC/a3hItLZusUD7Flcn5+FTsluh5Y3wjQxhj7CUVSyYtKksFL8TSAEyQoOJyHSYjItlcWxJujrvunJDw==');
    expect(base64.encode(sig2.data),
        's4jZio8iIvJcNJW9a5dazXOKSNGMsz/r61Yir7i6meyRY+waZBsZ/q2Kt1PgLKEvUAwKeXwqYsnFmD9y+eHYAw==');

    final SchnorrSignature sig = addSignatures(sig1, sig2);
    expect(base64.encode(sig.data),
        'HLRNppYR5sb1w0r0MymzwRz0Zhw2ynj79oNvKW517ERm4UpwrIqrVirqDdEF/Mwody3c265X9453vydeuMuiAw==');
    expect(
        Signature(jointKey1.jointPublicKey.data, null)
            .detached_verify(message, sig.data),
        true);

    final Adaptor adaptor = Adaptor.generate(randBytes(32));
    final SchnorrSignature adaptorSig1 = jointSignWithAdaptor(
        priv1, jointKey1, noncePoint1, noncePoint2, adaptor.point, message);
    final SchnorrSignature adaptorSig2 = jointSignWithAdaptor(
        priv2, jointKey2, noncePoint1, noncePoint2, adaptor.point, message);
    expect(
        verifyAdaptorSignature(
            jointKey1.primePublicKeys[0],
            jointKey1.jointPublicKey,
            noncePoint1,
            noncePoint2,
            adaptor.point,
            message,
            adaptorSig1),
        true);
    expect(
        verifyAdaptorSignature(
            jointKey1.primePublicKeys[1],
            jointKey1.jointPublicKey,
            noncePoint1,
            noncePoint2,
            adaptor.point,
            message,
            adaptorSig2),
        true);

    final CurvePoint aggR = noncePoint1.add(noncePoint2).add(adaptor.point);
    final Uint8List aggS = CurvePoint.addScalars(
        CurvePoint.addScalars(adaptorSig1.s, adaptorSig2.s), adaptor.secret);
    final Uint8List aggSig = Uint8List.fromList(aggR.pack() + aggS);
    expect(
        Signature(jointKey1.jointPublicKey.data, null)
            .detached_verify(message, aggSig),
        true);

    final Uint8List reducedAdaptor =
        Uint8List.fromList(adaptor.secret + Uint8List(32));
    TweetNaclFast.reduce(reducedAdaptor);
    final Uint8List checkAdaptor = CurvePoint.subtractScalars(
        CurvePoint.subtractScalars(aggS, adaptorSig1.s), adaptorSig2.s);
    expect(equalUint8List(checkAdaptor, reducedAdaptor.sublist(0, 32)), true);
  });
}
