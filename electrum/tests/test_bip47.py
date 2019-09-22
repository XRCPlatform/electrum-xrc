from . import SequentialTestCase
from electrum import keystore
from electrum import bip47, bip32
from electrum.bitcoin import EncodeBase58Check, DecodeBase58Check

KEYSTORE_A = keystore.from_bip39_seed('zero tomato region sorry one trip satoshi hotel lizard before gown script', '',
                                      keystore.bip44_derivation(0, bip43_purpose=47), xtype='standard')
KEYSTORE_B = keystore.from_bip39_seed('famous melody jar empty give output kitchen dinosaur verify monkey embody alone', '',
                                      keystore.bip44_derivation(0, bip43_purpose=47), xtype='standard')

KEYSTORE_A_PCODE = 'PM8TJcfgVBRBp9jesTcM4TRGPAEm3nF37kyxUbNJswWPqBF1FoiXRvTFQ9T5oumCsdLRB2BSyyUpV3aBMPS51Fripjzhazs7sPPVFEXnuN2Y5JZmp6gD'

# k = BIP32Node.from_xkey(mpk)
# a = keystore.from_xpub(mpk) or k = BIP32_KeyStore() and k.xpub = mpk
#pk = k.derive_pubkey(False, 0)
#address = bitcoin.pubkey_to_address('p2pkh', pk)


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
        decoded = bytearray(DecodeBase58Check(KEYSTORE_A_PCODE))

        self.assertTrue(bip47.PaymentCode.valid_code(KEYSTORE_A_PCODE))
        self.assertFalse(bip47.PaymentCode.valid_code("Prandom"))
        self.assertFalse(bip47.PaymentCode.valid_code(
            KEYSTORE_A_PCODE.replace("P", "R")))

        decoded[3] = 0x04
        self.assertFalse(bip47.PaymentCode.valid_code(
            EncodeBase58Check(decoded)))

    def test_parse(self):
        payment_code = bip47.PaymentCode(KEYSTORE_A.get_master_public_key())
        parsed_pcode = bip47.PaymentCode.parse(payment_code.to_base58())
        self.assertEqual(payment_code.public_key, parsed_pcode.public_key)
        self.assertEqual(payment_code.chain_code, parsed_pcode.chain_code)

        print(bip32.BIP32Node.from_xkey(KEYSTORE_A.get_master_public_key()))

        new_mpk = parsed_pcode.get_master_public_key()
        self.assertEqual(KEYSTORE_A.get_master_public_key(), new_mpk)

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
