import hashlib
import secrets
from typing import Tuple

from ecdsa import SigningKey, SECP256k1, VerifyingKey
import ecdsa
import hashlib as _hashlib

WORDLIST = [
    "apple","axis","balance","battery","beyond","binary","blade","bright","cable","cactus",
    "camera","candle","carbon","castle","cell","circle","cloud","coffee","copper","cosmic",
    "crystal","delta","desert","digital","dolphin","dragon","eagle","earth","ember","energy",
    "fabric","feather","fiction","flame","forest","galaxy","gamma","garden","glacier","gravity",
    "harbor","harvest","helium","honey","horizon","ice","impact","indigo","iris","island",
    "jungle","kiwi","kernel","ladder","laser","lava","legend","lemon","lunar","magnet",
    "marine","matrix","meadow","meteor","mirror","monkey","nebula","neuron","night","noble",
    "oasis","ocean","olive","omega","onion","orbit","panda","pearl","pepper","photon",
    "pixel","planet","plasma","poetry","polar","quartz","quantum","raven","record","reef",
    "rocket","ruby","sahara","saturn","shadow","signal","silicon","silver","solar","spark",
    "sphere","spice","spirit","stable","star","stone","storm","sugar","sunset","system",
    "tiger","tunnel","turbo","ultra","unity","valley","velvet","vortex","wave","whisper",
    "willow","window","xenon","yonder","zenith","zinc"
]

def normalise_seed(seed_phrase: str) -> str:
    words = seed_phrase.strip().lower().split()
    return " ".join(words)

def generate_seed(num_words: int = 12) -> str:
    return " ".join(secrets.choice(WORDLIST) for _ in range(num_words))

def seed_to_privkey(seed_phrase: str) -> SigningKey:
    norm = normalise_seed(seed_phrase)
    digest = hashlib.sha256(norm.encode("utf-8")).digest()
    return SigningKey.from_string(digest, curve=SECP256k1, hashfunc=hashlib.sha256)

def priv_to_pubkey(sk: SigningKey) -> VerifyingKey:
    return sk.verifying_key

def address_from_pubkey_bytes(pub_bytes: bytes) -> str:
    sha = _hashlib.sha256(pub_bytes).digest()
    ripe = _hashlib.new("ripemd160", sha).hexdigest()
    return "MARS" + ripe

def wallet_from_seed(seed_phrase: str) -> Tuple[str, str, str, str]:
    norm = normalise_seed(seed_phrase)
    sk = seed_to_privkey(norm)
    vk = priv_to_pubkey(sk)
    pub_bytes = vk.to_string()  # 64 bytes
    priv_hex = sk.to_string().hex()
    pub_hex = pub_bytes.hex()
    addr = address_from_pubkey_bytes(pub_bytes)
    return norm, priv_hex, pub_hex, addr

def sign_message(priv_hex: str, message_hash_hex: str) -> str:
    sk = SigningKey.from_string(bytes.fromhex(priv_hex), curve=SECP256k1, hashfunc=hashlib.sha256)
    sig = sk.sign_digest(bytes.fromhex(message_hash_hex), sigencode=ecdsa.util.sigencode_der)
    return sig.hex()

def verify_signature(pub_hex: str, message_hash_hex: str, signature_hex: str) -> bool:
    try:
        pub_bytes = bytes.fromhex(pub_hex)
        vk = VerifyingKey.from_string(pub_bytes, curve=SECP256k1)
        sig = bytes.fromhex(signature_hex)
        return vk.verify_digest(sig, bytes.fromhex(message_hash_hex), sigdecode=ecdsa.util.sigdecode_der)
    except Exception:
        return False
