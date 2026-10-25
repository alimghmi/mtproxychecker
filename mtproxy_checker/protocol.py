from __future__ import annotations

import hashlib
import os
import struct
import time
from typing import Any, Protocol

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .errors import ProtocolError
from .logging import get_logger, key_fingerprint
from .models import Mode
from .parser import short_hex

PROTO_ABRIDGED = b"\xef\xef\xef\xef"
PROTO_INTERMEDIATE = b"\xee\xee\xee\xee"
PROTO_SECURE = b"\xdd\xdd\xdd\xdd"

REQ_PQ_MULTI = 0xBE7E8EF1
RES_PQ = 0x05162463

MAX_FRAME = 2 * 1024 * 1024

logger = get_logger(__name__)


class ReadableTransport(Protocol):
    def read_exact(self, n: int) -> bytes: ...


def aes_ctr(key: bytes, iv: bytes) -> Any:
    return Cipher(algorithms.AES(key), modes.CTR(iv)).encryptor()


def protocol_tag_for_mode(mode: Mode) -> bytes:
    if mode == Mode.FAKETLS:
        mode = Mode.SECURE

    if mode == Mode.SECURE:
        return PROTO_SECURE

    if mode == Mode.ABRIDGED:
        return PROTO_ABRIDGED

    if mode == Mode.INTERMEDIATE:
        return PROTO_INTERMEDIATE

    raise ProtocolError(f"unsupported mode: {mode}")


def make_obfuscated2_handshake(
    secret: bytes,
    mode: Mode,
    dc_id: int,
) -> tuple[bytes, Any, Any]:
    proto_tag = protocol_tag_for_mode(mode)

    forbidden_first4 = {
        b"GET ",
        b"POST",
        b"HEAD",
        b"OPTI",
        b"\x00\x00\x00\x00",
        PROTO_ABRIDGED,
        PROTO_INTERMEDIATE,
        PROTO_SECURE,
    }

    while True:
        init = bytearray(os.urandom(64))

        if init[0] == 0xEF:
            continue

        if bytes(init[:4]) in forbidden_first4:
            continue

        if bytes(init[4:8]) == b"\x00\x00\x00\x00":
            continue

        break

    init[56:60] = proto_tag
    init[60] = dc_id & 0xFF
    init[61:64] = b"\x00\x00\x00"

    encrypt_key_material = bytes(init[8:40])
    encrypt_iv = bytes(init[40:56])
    decrypt_key_material = bytes(init[55:23:-1])
    decrypt_iv = bytes(init[23:7:-1])

    enc_key = hashlib.sha256(encrypt_key_material + secret).digest()
    dec_key = hashlib.sha256(decrypt_key_material + secret).digest()

    enc = aes_ctr(enc_key, encrypt_iv)
    dec = aes_ctr(dec_key, decrypt_iv)

    encrypted_init = enc.update(bytes(init))
    init[56:64] = encrypted_init[56:64]

    logger.debug(
        "obfuscated2 handshake created",
        extra={
            "event": "obfuscated2_handshake_created",
            "mode": mode.value,
            "dc": dc_id,
            "proto_tag": proto_tag.hex(),
            "key_id": key_fingerprint(secret),
        },
    )

    return bytes(init), enc, dec


def make_unencrypted_req_pq_multi() -> tuple[bytes, bytes]:
    nonce = os.urandom(16)
    payload = struct.pack("<I", REQ_PQ_MULTI) + nonce
    msg_id = int(time.time() * (2**32)) & ~3
    mtproto_message = (
        b"\x00" * 8
        + struct.pack("<Q", msg_id)
        + struct.pack("<I", len(payload))
        + payload
    )

    logger.debug(
        "req_pq_multi created",
        extra={
            "event": "req_pq_multi_created",
            "nonce": nonce.hex(),
            "msg_id": msg_id,
            "mtproto_len": len(mtproto_message),
            "packet_hex": mtproto_message.hex(),
        },
    )

    return nonce, mtproto_message


def frame_message(data: bytes, mode: Mode) -> bytes:
    if mode == Mode.SECURE:
        padding_len = os.urandom(1)[0] % 4
        padding = os.urandom(padding_len)
        frame = struct.pack("<I", len(data) + padding_len) + data + padding
        logger.debug(
            "secure frame created",
            extra={
                "event": "secure_frame_created",
                "payload_len": len(data),
                "padding_len": padding_len,
                "total_after_len": len(data) + padding_len,
            },
        )
        return frame

    if mode == Mode.INTERMEDIATE:
        logger.debug(
            "intermediate frame created",
            extra={"event": "intermediate_frame_created", "payload_len": len(data)},
        )
        return struct.pack("<I", len(data)) + data

    if mode == Mode.ABRIDGED:
        if len(data) % 4:
            raise ProtocolError("abridged payload length must be divisible by 4")

        length_words = len(data) // 4

        if length_words < 127:
            header = struct.pack("<B", length_words)
        else:
            header = b"\x7f" + struct.pack("<I", length_words)[:3]

        logger.debug(
            "abridged frame created",
            extra={
                "event": "abridged_frame_created",
                "payload_len": len(data),
                "length_words": length_words,
                "header": header.hex(),
            },
        )
        return header + data

    raise ProtocolError(f"unsupported mode: {mode}")


def read_frame(transport: ReadableTransport, dec: Any, mode: Mode) -> bytes:
    if mode in (Mode.SECURE, Mode.INTERMEDIATE):
        encrypted_len = transport.read_exact(4)
        length_bytes = dec.update(encrypted_len)
        frame_len = struct.unpack("<I", length_bytes)[0]
        logger.debug(
            "frame length read",
            extra={
                "event": "frame_length_read",
                "encrypted_len": encrypted_len.hex(),
                "decrypted_len": length_bytes.hex(),
                "frame_len": frame_len,
            },
        )

        if frame_len > 0x80000000:
            frame_len -= 0x80000000
            logger.debug(
                "frame length high bit adjusted",
                extra={"event": "frame_length_adjusted", "frame_len": frame_len},
            )

        if frame_len <= 0 or frame_len > MAX_FRAME:
            raise ProtocolError(
                f"bad frame length: {frame_len}, decrypted_len_hex={length_bytes.hex()}"
            )

        encrypted_payload = transport.read_exact(frame_len)
        payload = bytes(dec.update(encrypted_payload))
        logger.debug(
            "frame payload read",
            extra={
                "event": "frame_payload_read",
                "encrypted_payload": short_hex(encrypted_payload),
                "decrypted_payload": short_hex(payload),
            },
        )
        return payload

    if mode == Mode.ABRIDGED:
        encrypted_first = transport.read_exact(1)
        first = bytes(dec.update(encrypted_first))[0]
        logger.debug(
            "abridged first byte read",
            extra={
                "event": "abridged_first_byte_read",
                "encrypted_first": encrypted_first.hex(),
                "first": f"{first:02x}",
            },
        )

        if first < 127:
            frame_len = first * 4
        else:
            encrypted_rest = transport.read_exact(3)
            rest = bytes(dec.update(encrypted_rest))
            frame_len = struct.unpack("<I", rest + b"\x00")[0] * 4
            logger.debug(
                "abridged long length read",
                extra={
                    "event": "abridged_long_length_read",
                    "encrypted_rest": encrypted_rest.hex(),
                    "decrypted_rest": rest.hex(),
                    "frame_len": frame_len,
                },
            )

        if frame_len <= 0 or frame_len > MAX_FRAME:
            raise ProtocolError(f"bad abridged frame length: {frame_len}")

        encrypted_payload = transport.read_exact(frame_len)
        payload = bytes(dec.update(encrypted_payload))
        logger.debug(
            "abridged frame payload read",
            extra={
                "event": "abridged_frame_payload_read",
                "encrypted_payload": short_hex(encrypted_payload),
                "decrypted_payload": short_hex(payload),
            },
        )
        return payload

    raise ProtocolError(f"unsupported mode: {mode}")


def parse_res_pq(frame: bytes, expected_nonce: bytes) -> str:
    if len(frame) < 40:
        raise ProtocolError(
            f"short MTProto response: {len(frame)} bytes, frame={short_hex(frame)}"
        )

    auth_key_id = frame[:8]

    if auth_key_id != b"\x00" * 8:
        raise ProtocolError(
            "response is not an unencrypted MTProto packet, "
            f"auth_key_id={auth_key_id.hex()}"
        )

    msg_len = struct.unpack("<I", frame[16:20])[0]
    logger.debug(
        "res_pq response parsed",
        extra={
            "event": "res_pq_response_parsed",
            "msg_id": struct.unpack("<Q", frame[8:16])[0],
            "msg_len": msg_len,
            "frame_len": len(frame),
        },
    )

    if msg_len <= 0 or msg_len > len(frame) - 20:
        raise ProtocolError(
            f"bad MTProto message length: {msg_len}, "
            f"frame_len={len(frame)}, frame={short_hex(frame)}"
        )

    body = frame[20 : 20 + msg_len]

    if len(body) < 36:
        raise ProtocolError(
            f"short MTProto body: {len(body)} bytes, body={short_hex(body)}"
        )

    constructor = struct.unpack("<I", body[:4])[0]

    if constructor != RES_PQ:
        raise ProtocolError(
            f"unexpected constructor: 0x{constructor:08x}, body={short_hex(body)}"
        )

    response_nonce = body[4:20]

    if response_nonce != expected_nonce:
        raise ProtocolError(
            "nonce mismatch in resPQ, "
            f"expected={expected_nonce.hex()} got={response_nonce.hex()}"
        )

    return body[20:36].hex()
