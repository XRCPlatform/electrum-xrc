from . import SequentialTestCase
from electrum import keystore
from electrum import bip47, bip32, constants
from electrum.bitcoin import EncodeBase58Check, DecodeBase58Check, pubkey_to_address
from electrum import ecc
import hashlib

constants.set_btc_mainnet()

KEYSTORE_A = keystore.from_bip39_seed('response seminar brave tip suit recall often sound stick owner lottery motion', '',
                                      keystore.bip44_derivation(0, bip43_purpose=47), xtype='standard')
KEYSTORE_B = keystore.from_bip39_seed('reward upper indicate eight swift arch injury crystal super wrestle already dentist', '',
                                      keystore.bip44_derivation(0, bip43_purpose=47), xtype='standard')

KEYSTORE_A_PCODE = 'PM8TJTLJbPRGxSbc8EJi42Wrr6QbNSaSSVJ5Y3E4pbCYiTHUskHg13935Ubb7q8tx9GVbh2UuRnBc3WSyJHhUrw8KhprKnn9eDznYGieTzFcwQRya4GA'
KEYSTORE_B_PCODE = 'PM8TJS2JxQ5ztXUpBBRnpTbcUXbUHy2T1abfrb3KkAAtMEGNbey4oumH7Hc578WgQJhPjBxteQ5GHHToTYHE3A1w6p7tU6KSoFmWBVbFGjKPisZDbP97'

KEYSTORE_A_ECDH_PARAM = (
    ('8d6a8ecd8ee5e0042ad0cb56e3a971c760b5145c3917a8e7beaf0ed92d7a520c',
     '0353883a146a23f988e0f381a9507cbdb3e3130cd81b3ce26daf2af088724ce683',)
)

KEYSTORE_B_ECDH_PARAM = (
    ('04448fd1be0c9c13a5ca0b530e464b619dc091b299b98c5cab9978b32b4a1b8b',
     '024ce8e3b04ea205ff49f529950616c3db615b1e37753858cc60c1ce64d17e2ad8',)
)

# k = BIP32Node.from_xkey(mpk)
# a = keystore.from_xpub(mpk) or k = BIP32_KeyStore() and k.xpub = mpk
# pk = k.derive_pubkey(False, 0)
# address = bitcoin.pubkey_to_address('p2pkh', pk)


# a0 = bip32.BIP32Node.from_xkey(KEYSTORE_A.xprv).subkey_at_private_derivation('0').eckey.get_secret_bytes().hex()
# B0 = bip47.PaymentCode.parse(KEYSTORE_B_PCODE).get_master_public_key().subkey_at_public_derivation('0')

# B0ec = B0.subkey_at_public_derivation('0').eckey
# secret2 = int.from_bytes(a0, 'big') * ecc.Point(curve = ecc.curve_secp256k1, x = B0ec.point()[0], y = B0ec.point()[1]))

class PaymentCodeTestCase(SequentialTestCase):
    def test_payment_code(self):
        pass

    def test_xor_mask(self):
        pass


class Bip47TestCase(SequentialTestCase):
    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_match_payment_code(self):
        self.assertEqual(KEYSTORE_A_PCODE,
                         bip47.PaymentCode(KEYSTORE_A.get_master_public_key()).to_base58())
        self.assertEqual(len(bip47.PaymentCode(
            KEYSTORE_A.get_master_public_key()).to_base58()), 116)

    def test_is_valid(self):
        for pcode in (KEYSTORE_A_PCODE, KEYSTORE_B_PCODE):
            decoded = bytearray(DecodeBase58Check(pcode))

            # self.assertTrue(bip47.PaymentCode.valid_code(pcode))
            # self.assertFalse(bip47.PaymentCode.valid_code("Prandom"))
            self.assertFalse(bip47.PaymentCode.valid_code(
                pcode.replace("P", "R")))

            decoded[3] = 0x04
            self.assertFalse(bip47.PaymentCode.valid_code(
                EncodeBase58Check(decoded)))

    def test_parse(self):
        for keystore, ecdh in ((KEYSTORE_A, KEYSTORE_A_ECDH_PARAM, ), (KEYSTORE_B, KEYSTORE_B_ECDH_PARAM, ), ):
            payment_code = bip47.PaymentCode(keystore.get_master_public_key())
            parsed_pcode = bip47.PaymentCode.parse(payment_code.to_base58())
            self.assertEqual(payment_code.public_key, parsed_pcode.public_key)
            self.assertEqual(payment_code.chain_code, parsed_pcode.chain_code)

            derived_pubkey = payment_code.get_master_public_key().subkey_at_public_derivation('0')
            derived_pubkey_parsed = parsed_pcode.get_master_public_key(
            ).subkey_at_public_derivation('0')

            self.assertEqual(derived_pubkey.eckey.get_public_key_bytes().hex(
            ), derived_pubkey_parsed.eckey.get_public_key_bytes().hex())

            print(derived_pubkey)

            x0, X0 = ecdh
            # Test derived private key (this is not essential, just illustrative)
            self.assertEqual(bip32.BIP32Node.from_xkey(
                keystore.xprv).subkey_at_private_derivation('0').eckey.get_secret_bytes().hex(), x0)

            # Test derived public key
            self.assertEqual(
                derived_pubkey_parsed.eckey.get_public_key_bytes().hex(), X0)

    def test_address_at(self):
        pass

    def test_sharing_same_send_and_receives_via_two_pcodes(self):
        pass

    def test_ecdh(self):
        priv1 = KEYSTORE_A.get_private_key([0, 0], None)
        pub1 = KEYSTORE_A.derive_pubkey(False, 0)

        priv2 = KEYSTORE_B.get_private_key([0, 1], None)
        pub2 = KEYSTORE_B.derive_pubkey(False, 1)

        print(bip47.get_shared_key(priv1, pub2))
        print(bip47.get_shared_key(priv2, pub1))
        self.assertEqual(bip47.get_shared_key(priv1, pub2),
                         bip47.get_shared_key(priv2, pub1))

    def convert_to_point(self, eckey):
        return ecc.Point(curve=ecc.curve_secp256k1, x=eckey.point()[0], y=eckey.point()[1])

    def test_secret_point_generation(self):
        a0 = bip32.BIP32Node.from_xkey(KEYSTORE_A.xprv).subkey_at_private_derivation(
            '0').eckey.get_secret_bytes()

        self.assertEqual(
            a0.hex(), '8d6a8ecd8ee5e0042ad0cb56e3a971c760b5145c3917a8e7beaf0ed92d7a520c')

        B0 = bip47.PaymentCode.parse(
            KEYSTORE_B_PCODE).get_master_public_key().subkey_at_public_derivation('0')

        self.assertEqual(
            B0.eckey.get_public_key_bytes(
            ).hex(), '024ce8e3b04ea205ff49f529950616c3db615b1e37753858cc60c1ce64d17e2ad8'
        )

        # S = aB
        secret = int.from_bytes(
            a0, 'big') * self.convert_to_point(B0.eckey)

        # Sx
        secretX = secret.x().to_bytes(32, 'big')

        self.assertEqual(
            secretX.hex(), 'f5bb84706ee366052471e6139e6a9a969d586e5fe6471a9b96c3d8caefe86fef')

        # SHA256(Sx)
        hash = hashlib.sha256(secretX).digest()

        # B' = B + sG
        sec_point = self.convert_to_point(
            B0.eckey) + (int.from_bytes(hash, 'big') * ecc.generator_secp256k1)

        result = ecc.ECPubkey.from_point(
            sec_point).get_public_key_bytes().hex()

        self.assertEqual(
            pubkey_to_address('p2pkh', result), '141fi7TY3h936vRUKh1qfUZr8rSBuYbVBK')
