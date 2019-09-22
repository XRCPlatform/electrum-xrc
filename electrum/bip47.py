import hmac
import ecdsa
from hashlib import sha512
from . import keystore, bip32, ecc, util, bitcoin
from .bitcoin import EncodeBase58Check, DecodeBase58Check

# Based off of Samourai implementation : https://github.com/Samourai-Wallet/ExtLibJ/tree/develop/java/com/samourai/wallet/bip47/rpc


class PaymentCodeError(Exception):
    pass


class BIP47_KeyStore(keystore.BIP32_KeyStore):
    type = 'bip47'


PUBLIC_KEY_Y_OFFSET = 2
PUBLIC_KEY_X_OFFSET = 3
CHAIN_OFFSET = 35
PUBLIC_KEY_X_LEN = 32
PUBLIC_KEY_Y_LEN = 1
CHAIN_LEN = 32
PAYLOAD_LEN = 80


def make_point_from_privkey(priv):
    return ecc.ECPubkey.from_point(priv * ecdsa.ecdsa.generator_secp256k1)


def get_shared_key(aPriv, bPub):
    """ 
    aPriv is the key probably generated from a prng, bPub was computed with the curve generator.
    """
    return int.from_bytes(aPriv[0], 'big') * ecc.ECPubkey(util.bfh(bPub))


class PaymentCode(object):
    """
    Represents a single payment code, either from my wallet or your wallet.
    The intent is to represent and re-encode the payment code, to derive the base
    addresses and to setup notification transactions.
    """
    master_public_key: str
    public_key: bytes
    chain_code: bytes

    def __init__(self, master_public_key: str, version=0x01):
        """
         - master_public_key: Base58Check version of master public key.
         - version: Payment code version. Defaults to 1.
        """

        self.master_public_key = None
        self.public_key = None
        self.chain_code = None

        if master_public_key and len(master_public_key) != 111:
            raise PaymentCodeError(
                "master_public_key must be length of 111 bytes")
        elif master_public_key:
            self.master_public_key = master_public_key

            self.node = bip32.BIP32Node.from_xkey(master_public_key)
            self.chain_code = self.node.chaincode
            self.public_key = self.node.eckey.get_public_key_bytes()
        self.version = version

    @classmethod
    def valid_code(self, code: str) -> bool:
        if len(code) != 116:
            return False
        try:
            pcode_bytes = DecodeBase58Check(code)
        except:
            return False
        if not pcode_bytes[0] == 0x47:
            return False
        pub = pcode_bytes[3]
        if pub == 0x02 or pub == 0x03:
            return True

    @classmethod
    def parse(self, code: str) -> "PaymentCode":
        if not PaymentCode.valid_code(code):
            return None

        payment_code = DecodeBase58Check(code)
        pcode_prefix = payment_code[0:1]
        version = payment_code[2:1]
        chain_code = payment_code[36:68]
        public_key = payment_code[3:36]

        ret = PaymentCode(None, version)
        ret.public_key = public_key
        ret.chain_code = chain_code

        return ret

    def public_key_and_chain_code(self):
        mpk = DecodeBase58Check(self.master_public_key)
        return (
            mpk[45:78],  # public key
            mpk[13:45]  # chain code
        )

    def get_master_public_key(self):
        if self.master_public_key:
            return self.master_public_key

        # similar to call BIP32Node.from_xkey(base_mpk)
        return bip32.BIP32Node(xtype='standard',  # fixing it to xpub only for now
                               eckey=ecc.ECPubkey(self.public_key),
                               chaincode=self.chain_code,
                               # depth and fingerprint is not available unless you
                               # explicitly have a parent BIP32Node. We are assuming
                               # this is the root from m/47'/x'/0
                               depth=0x03,
                               fingerprint=bytes([54, 0xbe, 0xbb, 0xa1]),
                               child_number=bytes(
                                   [0x80, 0x00, 0x00, 0x00])).to_xpub()

    def generate(self):
        return bytes([
            0x47,  # payment code version, base58: P
            self.version,
            0x00,  # bitmessage
            *self.public_key,
            *self.chain_code,
            *[0x00]*13
        ])

    def to_base58(self):
        return EncodeBase58Check(self.generate())

    def notification_address(self) -> bytes:
        return self.address_at(0)

    # Returns the public key from the payment code only.
    # This could be my pcode or it can be someone else's pcode. The
    # purpose is to get the pubkey from it.
    def address_at(self, idx) -> bytes:
        node = bip32.BIP32Node.from_xkey(self.master_public_key())
        return node.eckey.get_public_key_bytes()

    def payment_send_address_at(self, wallet: keystore.BIP32_KeyStore, idx, account) -> bytes:
        """
        Returns a send address from a keystore and the payment code. 
        """
        pass

    def payment_receive_address_at(self, wallet: keystore.BIP32_KeyStore, idx) -> bytes:
        pass

    def payment_address(self, idx, address):
        pass

    def mask(self, s_point: bytes, o_point: bytes) -> bytes:
        return hmac.new(o_point, s_point, sha512)

    def blind(self, payload: bytes, mask: bytes) -> bytes:
        # public static void arraycopy(Object src, int srcPos, Object dest, int destPos, int length)
        # System.arraycopy(payload, 0, ret, 0, PAYLOAD_LEN);

        # System.arraycopy(payload, PUBLIC_KEY_X_OFFSET, pubkey, 0, PUBLIC_KEY_X_LEN);
        # System.arraycopy(payload, CHAIN_OFFSET, chain, 0, CHAIN_LEN);
        # System.arraycopy(mask, 0, buf0, 0, PUBLIC_KEY_X_LEN);
        # System.arraycopy(mask, PUBLIC_KEY_X_LEN, buf1, 0, CHAIN_LEN);

        # System.arraycopy(xor(pubkey, buf0), 0, ret, PUBLIC_KEY_X_OFFSET, PUBLIC_KEY_X_LEN);
        # System.arraycopy(xor(chain, buf1), 0, ret, CHAIN_OFFSET, CHAIN_LEN);

        pubkey = payload[PUBLIC_KEY_X_OFFSET:PUBLIC_KEY_X_LEN]
        chain = payload[CHAIN_OFFSET:CHAIN_LEN]
        buf0 = mask[0:PUBLIC_KEY_X_LEN]
        buf1 = mask[PUBLIC_KEY_X_LEN:CHAIN_LEN]

        ret = self.xor(pubkey, buf0)[PUBLIC_KEY_X_OFFSET, PUBLIC_KEY_X_LEN]
        ret = ret + self.xor(chain, buf1)[CHAIN_OFFSET, CHAIN_LEN]

        return ret

    def xor(a: bytes, b: bytes) -> bytes:
        if len(a) != len(b):
            return None
        return bytes(*[b[idx] ^ val for idx, val in a])


class SecretPoint(object):
    def __init__(self, priv: bytes, pub: bytes):
        self.priv = priv
        self.pub = pub


class PaymentAddress(object):

    def __init__(self, payment_code: PaymentCode, index: int, private_key: bytes):
        self.payment_code = payment_code
        self.index = index
        self.private_key = private_key  # this is a key from my HD wallet

    def send_ec_key(self):
        pass

    def receive_ec_key(self):
        pass

    def shared_secret(self):
        # return secretPointFactory.newSecretPoint(privKey, paymentCode.addressAt(index, params).getPubKey());

        pass

    def secret_point(self):
        pass

    def ec_point(self):
        return ecc.ECPubkey(self.payment_code.address_at(0))

    def hashed_shared_secret(self):
        pass

    def sG(self, s: int):
        pass

    def add_secp256k1(self, b1: int, b2: int):
        self
