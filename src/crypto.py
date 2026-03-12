from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
from typing import Optional
import hmac
import os
import struct

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes, hmac as crypto_hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


# =============================================================================
# Constants
# =============================================================================

NONCE_LEN = 12              # AES-GCM standard nonce length
AUTH_TAG_LEN = 4            # External short auth tag used by Trilobyte
DEFAULT_MASTER_KEY_LEN = 32 # 256-bit base key
FID_LEN = 16                # Internal fixed-length file identifier
CID_LEN = 8                 # Example contact/client identifier length


# =============================================================================
# Segment types
# =============================================================================

class SegmentType(IntEnum):
    DAT = 1
    REQ = 2
    REP = 3
    ACK = 4


# =============================================================================
# Dataclasses
# =============================================================================

@dataclass
class DATSegment:
    fid: bytes
    last: bool
    seq: int
    data: bytes


@dataclass
class ACKSegment:
    fid: bytes
    seq: int


@dataclass
class REQSegment:
    client_id: bytes
    account_id: bytes
    session_key: bytes
    payment_id: bytes
    content_descriptor: bytes


@dataclass
class REPSegment:
    remaining_segments: int
    fee_units: int


@dataclass
class PackedCiphertext:
    """
    Encoded object carried by the thumbnail channel.

    Layout:
        nonce (12 bytes) || ciphertext_and_gcm_tag (variable)
    """
    nonce: bytes
    ciphertext: bytes

    def to_bytes(self) -> bytes:
        return self.nonce + self.ciphertext

    @staticmethod
    def from_bytes(blob: bytes) -> "PackedCiphertext":
        if len(blob) < NONCE_LEN + 16:  # AES-GCM ciphertext includes 16-byte tag
            raise ValueError("Ciphertext blob too short.")
        return PackedCiphertext(
            nonce=blob[:NONCE_LEN],
            ciphertext=blob[NONCE_LEN:],
        )


@dataclass
class HiddenSegment:
    """
    Final on-channel segment format:
        enc || auth

    where:
        enc  = AES-GCM(nonce || ciphertext)
        auth = first 4 bytes of HMAC-SHA256(auth_key, enc)

    This is slightly more standard than "first 4 bytes of E_Ka(enc)" while
    preserving the short external authenticator idea in the paper.
    """
    enc: bytes
    auth: bytes

    def to_bytes(self) -> bytes:
        return self.enc + self.auth

    @staticmethod
    def from_bytes(blob: bytes) -> "HiddenSegment":
        if len(blob) < AUTH_TAG_LEN + NONCE_LEN + 16:
            raise ValueError("Hidden segment too short.")
        return HiddenSegment(
            enc=blob[:-AUTH_TAG_LEN],
            auth=blob[-AUTH_TAG_LEN:],
        )


# =============================================================================
# Key derivation
# =============================================================================

def hkdf_derive(key_material: bytes, info: bytes, length: int = 32, salt: Optional[bytes] = None) -> bytes:
    """
    Domain-separated HKDF derivation.
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info,
    )
    return hkdf.derive(key_material)


def derive_trilobyte_keys(master_key: bytes) -> tuple[bytes, bytes]:
    """
    Derive separate encryption and authentication keys from a shared master key.
    """
    enc_key = hkdf_derive(master_key, b"trilobyte-encryption", length=32)
    auth_key = hkdf_derive(master_key, b"trilobyte-authentication", length=32)
    return enc_key, auth_key


def derive_server_keys(session_key: bytes) -> dict[str, bytes]:
    """
    Derive per-request keys for the server extension.
    """
    return {
        "password": hkdf_derive(session_key, b"password", length=32),
        "encryption": hkdf_derive(session_key, b"encryption", length=32),
        "schedule": hkdf_derive(session_key, b"schedule", length=32),
    }


# =============================================================================
# Utility helpers
# =============================================================================

def random_key(length: int = DEFAULT_MASTER_KEY_LEN) -> bytes:
    return os.urandom(length)


def random_fid() -> bytes:
    return os.urandom(FID_LEN)


def compute_short_auth_tag(auth_key: bytes, enc_blob: bytes) -> bytes:
    """
    Compute the external 4-byte authentication tag.
    """
    h = crypto_hmac.HMAC(auth_key, hashes.SHA256())
    h.update(enc_blob)
    full = h.finalize()
    return full[:AUTH_TAG_LEN]


def verify_short_auth_tag(auth_key: bytes, enc_blob: bytes, tag: bytes) -> bool:
    expected = compute_short_auth_tag(auth_key, enc_blob)
    return hmac.compare_digest(expected, tag)


# =============================================================================
# Serialization
# =============================================================================

def _pack_bool(value: bool) -> int:
    return 1 if value else 0


def serialize_dat_segment(seg: DATSegment) -> bytes:
    """
    DAT layout:
        type:    1 byte
        fid:     16 bytes
        last:    1 byte
        seq:     4 bytes unsigned int
        dlen:    4 bytes unsigned int
        data:    variable
    """
    if len(seg.fid) != FID_LEN:
        raise ValueError(f"fid must be {FID_LEN} bytes.")
    header = struct.pack("!B16sBII", SegmentType.DAT, seg.fid, _pack_bool(seg.last), seg.seq, len(seg.data))
    return header + seg.data


def deserialize_dat_segment(blob: bytes) -> DATSegment:
    min_len = struct.calcsize("!B16sBII")
    if len(blob) < min_len:
        raise ValueError("DAT blob too short.")
    seg_type, fid, last_flag, seq, dlen = struct.unpack("!B16sBII", blob[:min_len])
    if seg_type != SegmentType.DAT:
        raise ValueError("Not a DAT segment.")
    data = blob[min_len:min_len + dlen]
    if len(data) != dlen:
        raise ValueError("DAT data length mismatch.")
    return DATSegment(fid=fid, last=bool(last_flag), seq=seq, data=data)


def serialize_ack_segment(seg: ACKSegment) -> bytes:
    """
    ACK layout:
        type: 1 byte
        fid:  16 bytes
        seq:  4 bytes
    """
    return struct.pack("!B16sI", SegmentType.ACK, seg.fid, seg.seq)


def deserialize_ack_segment(blob: bytes) -> ACKSegment:
    expected_len = struct.calcsize("!B16sI")
    if len(blob) != expected_len:
        raise ValueError("ACK blob has invalid length.")
    seg_type, fid, seq = struct.unpack("!B16sI", blob)
    if seg_type != SegmentType.ACK:
        raise ValueError("Not an ACK segment.")
    return ACKSegment(fid=fid, seq=seq)


def serialize_rep_segment(seg: REPSegment) -> bytes:
    """
    REP layout:
        type:               1 byte
        remaining_segments: 4 bytes
        fee_units:          8 bytes
    """
    return struct.pack("!B IQ", SegmentType.REP, seg.remaining_segments, seg.fee_units)


def deserialize_rep_segment(blob: bytes) -> REPSegment:
    expected_len = struct.calcsize("!B IQ")
    if len(blob) != expected_len:
        raise ValueError("REP blob has invalid length.")
    seg_type, remaining_segments, fee_units = struct.unpack("!B IQ", blob)
    if seg_type != SegmentType.REP:
        raise ValueError("Not a REP segment.")
    return REPSegment(remaining_segments=remaining_segments, fee_units=fee_units)


def serialize_req_segment(seg: REQSegment) -> bytes:
    """
    REQ layout:
        type:               1 byte
        client_id_len:      2 bytes
        account_id_len:     2 bytes
        session_key_len:    2 bytes
        payment_id_len:     2 bytes
        descriptor_len:     2 bytes
        fields:             variable
    """
    header = struct.pack(
        "!BHHHHH",
        SegmentType.REQ,
        len(seg.client_id),
        len(seg.account_id),
        len(seg.session_key),
        len(seg.payment_id),
        len(seg.content_descriptor),
    )
    return header + seg.client_id + seg.account_id + seg.session_key + seg.payment_id + seg.content_descriptor


def deserialize_req_segment(blob: bytes) -> REQSegment:
    header_len = struct.calcsize("!BHHHHH")
    if len(blob) < header_len:
        raise ValueError("REQ blob too short.")
    seg_type, l1, l2, l3, l4, l5 = struct.unpack("!BHHHHH", blob[:header_len])
    if seg_type != SegmentType.REQ:
        raise ValueError("Not a REQ segment.")

    offset = header_len
    client_id = blob[offset:offset + l1]
    offset += l1
    account_id = blob[offset:offset + l2]
    offset += l2
    session_key = blob[offset:offset + l3]
    offset += l3
    payment_id = blob[offset:offset + l4]
    offset += l4
    content_descriptor = blob[offset:offset + l5]
    offset += l5

    if offset != len(blob):
        raise ValueError("REQ blob length mismatch.")

    return REQSegment(
        client_id=client_id,
        account_id=account_id,
        session_key=session_key,
        payment_id=payment_id,
        content_descriptor=content_descriptor,
    )


def detect_and_deserialize_segment(blob: bytes):
    """
    Inspect the first byte and dispatch to the proper deserializer.
    """
    if not blob:
        raise ValueError("Empty segment blob.")

    seg_type = blob[0]
    if seg_type == SegmentType.DAT:
        return deserialize_dat_segment(blob)
    if seg_type == SegmentType.ACK:
        return deserialize_ack_segment(blob)
    if seg_type == SegmentType.REP:
        return deserialize_rep_segment(blob)
    if seg_type == SegmentType.REQ:
        return deserialize_req_segment(blob)

    raise ValueError(f"Unknown segment type: {seg_type}")


# =============================================================================
# Encryption / decryption
# =============================================================================

def encrypt_segment_payload(enc_key: bytes, plaintext_segment: bytes, aad: Optional[bytes] = None) -> bytes:
    """
    Returns:
        nonce || ciphertext_and_gcm_tag
    """
    nonce = os.urandom(NONCE_LEN)
    aesgcm = AESGCM(enc_key)
    ciphertext = aesgcm.encrypt(nonce, plaintext_segment, aad)
    return PackedCiphertext(nonce=nonce, ciphertext=ciphertext).to_bytes()


def decrypt_segment_payload(enc_key: bytes, enc_blob: bytes, aad: Optional[bytes] = None) -> bytes:
    packed = PackedCiphertext.from_bytes(enc_blob)
    aesgcm = AESGCM(enc_key)
    return aesgcm.decrypt(packed.nonce, packed.ciphertext, aad)


def build_hidden_segment(enc_key: bytes, auth_key: bytes, plaintext_segment: bytes, aad: Optional[bytes] = None) -> HiddenSegment:
    enc_blob = encrypt_segment_payload(enc_key, plaintext_segment, aad=aad)
    auth_tag = compute_short_auth_tag(auth_key, enc_blob)
    return HiddenSegment(enc=enc_blob, auth=auth_tag)


def open_hidden_segment(enc_key: bytes, auth_key: bytes, hidden_blob: bytes, aad: Optional[bytes] = None):
    hidden = HiddenSegment.from_bytes(hidden_blob)

    if not verify_short_auth_tag(auth_key, hidden.enc, hidden.auth):
        raise ValueError("Authentication tag verification failed.")

    plaintext = decrypt_segment_payload(enc_key, hidden.enc, aad=aad)
    return detect_and_deserialize_segment(plaintext)


# =============================================================================
# High-level helpers for DAT segments
# =============================================================================

def build_dat_hidden_segment(
    enc_key: bytes,
    auth_key: bytes,
    fid: bytes,
    seq: int,
    last: bool,
    data: bytes,
    aad: Optional[bytes] = None,
) -> bytes:
    dat = DATSegment(fid=fid, last=last, seq=seq, data=data)
    plaintext = serialize_dat_segment(dat)
    hidden = build_hidden_segment(enc_key, auth_key, plaintext, aad=aad)
    return hidden.to_bytes()


def parse_dat_hidden_segment(
    enc_key: bytes,
    auth_key: bytes,
    hidden_blob: bytes,
    aad: Optional[bytes] = None,
) -> DATSegment:
    segment = open_hidden_segment(enc_key, auth_key, hidden_blob, aad=aad)
    if not isinstance(segment, DATSegment):
        raise ValueError("Hidden segment did not contain a DAT payload.")
    return segment


# =============================================================================
# Simple self-test
# =============================================================================

def _self_test() -> None:
    master = random_key()
    enc_key, auth_key = derive_trilobyte_keys(master)

    fid = random_fid()
    payload = b"hello from trilobyte"
    hidden_blob = build_dat_hidden_segment(
        enc_key=enc_key,
        auth_key=auth_key,
        fid=fid,
        seq=0,
        last=True,
        data=payload,
    )

    recovered = parse_dat_hidden_segment(
        enc_key=enc_key,
        auth_key=auth_key,
        hidden_blob=hidden_blob,
    )

    assert recovered.fid == fid
    assert recovered.seq == 0
    assert recovered.last is True
    assert recovered.data == payload
    print("crypto.py self-test passed.")


if __name__ == "__main__":
    _self_test()
