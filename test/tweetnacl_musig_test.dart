// Copyright 2019 tweetnacl-musig developers
// Use of this source code is governed by a MIT-style license that can be found in the LICENSE file.

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
    expect(
        base64.encode(CurvePoint.fromScalar(
                base64.decode('BW9J+gBeuhTrhZoJOKe2zbvRSlhTYm+spPqcSQvuYQI='))
            .pack()),
        'fNE5KpDgvPVZX/lnVIku95qADUfYlKPIxfTuXsTB7hg=');
  });

  /// https://github.com/HyperspaceApp/ed25519/blob/master/ed25519_test.go#L206
  test('ed25519 join sign verify', () {
    PrivateKey priv1 = PrivateKey.fromSeed(Uint8List(32));
    PrivateKey priv2 = PrivateKey.fromSeed(hex.decode(
        '0101010101010101010101010101010101010101010101010101010101010101'));
    PublicKey pub1 = priv1.getPublicKey(), pub2 = priv2.getPublicKey();
    expect(base64.encode(pub1.data),
        'O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik=');
    expect(base64.encode(pub2.data),
        'iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w=');

    List<PublicKey> publicKeys = <PublicKey>[pub1, pub2];
    JointPublicKey jointKey = generateJointPublicKey(publicKeys);
    expect(base64.encode(jointKey.primeKeys[0].data),
        'hFVljNya6b8nSXxy3VHjxGgm3X2JgzbMeQX+CDGR/H8=');
    expect(base64.encode(jointKey.primeKeys[1].data),
        'qCo70Um1BSY+E563zPVbISQStaGmCvgDwpmac209dtc=');
    expect(base64.encode(jointKey.jointPublicKey.data),
        'xK8i62dTBuOVOBtdwSJpbpXKoTaZ+k3OPdPhWI5nMko=');

    PrivateKey jointPriv1 = generateJointPrivateKey(publicKeys, priv1, 0);
    PrivateKey jointPriv2 = generateJointPrivateKey(publicKeys, priv2, 1);
    expect(base64.encode(jointPriv1.data), 'k1it5L3rRSjpo5zWn1nCDUKFpwy3sRW1ZlfW2eOphgQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==');
    expect(base64.encode(jointPriv2.data), 'Ic704M42z2eH0IEaG2xrxxMF8z5oadZ8q+3WGPYRwwwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==');
  });
}
