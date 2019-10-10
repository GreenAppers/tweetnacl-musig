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
    expect(
        Signature(priv.getPublicKey().data, null).detached_verify(message, sig),
        true);

    final Uint8List wrongMessage = utf8.encode('wrong message');
    expect(
        Signature(priv.getPublicKey().data, null)
            .detached_verify(wrongMessage, sig),
        false);
  });

  test('adaptor', () {
    final Adaptor adaptor1 = generateAdaptor(randBytes(32));
    final Adaptor adaptor2 = generateAdaptor(randBytes(32));
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
    final PublicKey pub1 = priv1.getPublicKey(), pub2 = priv2.getPublicKey();
    expect(base64.encode(pub1.data),
        'O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik=');
    expect(base64.encode(pub2.data),
        'iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w=');

    final List<PublicKey> publicKeys = <PublicKey>[pub1, pub2];
    final JointPublicKey jointKey = generateJointPublicKey(publicKeys);
    expect(base64.encode(jointKey.primeKeys[0].data),
        'hFVljNya6b8nSXxy3VHjxGgm3X2JgzbMeQX+CDGR/H8=');
    expect(base64.encode(jointKey.primeKeys[1].data),
        'qCo70Um1BSY+E563zPVbISQStaGmCvgDwpmac209dtc=');
    expect(base64.encode(jointKey.jointPublicKey.data),
        'xK8i62dTBuOVOBtdwSJpbpXKoTaZ+k3OPdPhWI5nMko=');

    final PrivateKey jointPriv1 = PrivateKey.fromKeyPair(
        generateJointPrivateKey(publicKeys, priv1, 0),
        jointKey.jointPublicKey.data);
    final PrivateKey jointPriv2 = PrivateKey.fromKeyPair(
        generateJointPrivateKey(publicKeys, priv2, 1),
        jointKey.jointPublicKey.data);
    expect(base64.encode(jointPriv1.data),
        'k1it5L3rRSjpo5zWn1nCDUKFpwy3sRW1ZlfW2eOphgTEryLrZ1MG45U4G13BImlulcqhNpn6Tc490+FYjmcySg==');
    expect(base64.encode(jointPriv2.data),
        'Ic704M42z2eH0IEaG2xrxxMF8z5oadZ8q+3WGPYRwwzEryLrZ1MG45U4G13BImlulcqhNpn6Tc490+FYjmcySg==');

    // P_A' should equal x_A' * G
    expect(
        equalUint8List(
            CurvePoint.fromScalar(jointPriv1.getPrivateKeyData()).pack(),
            jointKey.primeKeys[0].data),
        true);

    // P_B' should equal x_B' * G
    expect(
        equalUint8List(
            CurvePoint.fromScalar(jointPriv2.getPrivateKeyData()).pack(),
            jointKey.primeKeys[1].data),
        true);

    // J(A, B) should equal P_A' + P_B'
    expect(
        equalUint8List(
            CurvePoint.unpack(jointKey.primeKeys[0].data)
                .add(CurvePoint.unpack(jointKey.primeKeys[1].data))
                .pack(),
            jointKey.jointPublicKey.data),
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

    final Uint8List sig1 = jointSign(priv1, jointPriv1, noncePoints, message);
    final Uint8List sig2 = jointSign(priv2, jointPriv2, noncePoints, message);
    expect(base64.encode(sig1),
        'ncPXqaIC/a3hItLZusUD7Flcn5+FTsluh5Y3wjQxhj7CUVSyYtKksFL8TSAEyQoOJyHSYjItlcWxJujrvunJDw==');
    expect(base64.encode(sig2),
        's4jZio8iIvJcNJW9a5dazXOKSNGMsz/r61Yir7i6meyRY+waZBsZ/q2Kt1PgLKEvUAwKeXwqYsnFmD9y+eHYAw==');

    final Uint8List sig = addSignatures(sig1, sig2);
    expect(base64.encode(sig),
        'HLRNppYR5sb1w0r0MymzwRz0Zhw2ynj79oNvKW517ERm4UpwrIqrVirqDdEF/Mwody3c265X9453vydeuMuiAw==');
    expect(
        Signature(jointKey.jointPublicKey.data, null)
            .detached_verify(message, sig),
        true);

    final Adaptor adaptor = generateAdaptor(randBytes(32));
    final Uint8List adaptorSig1 = jointSignWithAdaptor(
        priv1, jointPriv1, noncePoint1, noncePoint2, adaptor.point, message);
    final Uint8List adaptorSig2 = jointSignWithAdaptor(
        priv2, jointPriv2, noncePoint1, noncePoint2, adaptor.point, message);
    expect(
        verifyAdaptorSignature(jointKey.primeKeys[1], jointKey.jointPublicKey,
            noncePoint1, noncePoint2, adaptor.point, message, adaptorSig2),
        true);

    final CurvePoint aggR = noncePoint1.add(noncePoint2).add(adaptor.point);
    final Uint8List aggS = CurvePoint.addScalars(
        CurvePoint.addScalars(adaptorSig1.sublist(32), adaptorSig2.sublist(32)),
        adaptor.secret);
    final Uint8List aggSig = Uint8List.fromList(aggR.pack() + aggS);
    expect(
        Signature(jointKey.jointPublicKey.data, null)
            .detached_verify(message, aggSig),
        true);

    final Uint8List reducedAdaptor =
        Uint8List.fromList(adaptor.secret + Uint8List(32));
    TweetNaclFast.reduce(reducedAdaptor);
    final Uint8List checkAdaptor = CurvePoint.subtractScalars(
        CurvePoint.subtractScalars(aggS, adaptorSig1.sublist(32)),
        adaptorSig2.sublist(32));
    expect(equalUint8List(checkAdaptor, reducedAdaptor.sublist(0, 32)), true);
  });
}
