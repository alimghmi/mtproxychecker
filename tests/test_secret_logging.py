import base64
import hashlib
import io
import logging
import struct
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import MagicMock, patch

from mtproxy_checker import check_proxy
from mtproxy_checker.cli import main
from mtproxy_checker.logging import (
    configure_cli_logging,
    get_logger,
    key_fingerprint,
)
from mtproxy_checker.parser import decode_secret


class SecretLoggingTests(unittest.TestCase):
    secret = bytes.fromhex("00112233445566778899aabbccddeeff")

    def tearDown(self) -> None:
        logger = get_logger()
        logger.handlers.clear()
        logger.addHandler(logging.NullHandler())
        logger.setLevel(logging.NOTSET)

    def secret_encodings(self) -> list[str]:
        payloads = (
            self.secret,
            b"\xdd" + self.secret,
            b"\xee" + self.secret + b"example.com",
            self.secret + b"example.com",
        )
        return [
            encoded
            for payload in payloads
            for encoded in (
                payload.hex(),
                base64.b64encode(payload).decode(),
                base64.urlsafe_b64encode(payload).decode().rstrip("="),
            )
        ]

    def assert_no_secret_material(self, output: str, encoded: str) -> None:
        # All values here are synthetic. The old trace output included these
        # values and field names even when a custom formatter was used.
        derived_key = hashlib.sha256(b"q" * 32 + self.secret).hexdigest()
        for value in (
            encoded,
            self.secret.hex(),
            self.secret.hex()[:14],
            base64.b64encode(self.secret).decode(),
            derived_key,
            "secret_prefix",
            "secret_raw",
            "decoded_hex",
            "encrypt_key_material",
            "decrypt_key_material",
            "encrypt_iv",
            "decrypt_iv",
            "enc_key",
            "dec_key",
            "init_packet",
        ):
            self.assertNotIn(value, output)

    def test_fingerprint_is_stable_and_distinguishes_keys(self) -> None:
        expected = hashlib.sha256(self.secret).hexdigest()[:12]
        self.assertEqual(key_fingerprint(self.secret), expected)
        self.assertNotEqual(key_fingerprint(b"x" * 16), expected)
        for encoded in self.secret_encodings():
            with self.subTest(encoded=encoded):
                self.assertEqual(
                    key_fingerprint(decode_secret(encoded).raw_secret), expected
                )

    def test_logs_keep_fingerprint_without_secret_on_success_and_error(self) -> None:
        nonce = b"n" * 16
        body = struct.pack("<I", 0x05162463) + nonce + b"s" * 16
        response = b"\x00" * 8 + struct.pack("<QI", 4, len(body)) + body
        for encoded in self.secret_encodings():
            for level in (logging.WARNING, logging.INFO, logging.DEBUG):
                for json_logs in (False, True):
                    for success in (False, True):
                        with self.subTest(
                            encoded=encoded,
                            level=level,
                            json_logs=json_logs,
                            success=success,
                        ):
                            stream = io.StringIO()
                            configure_cli_logging(
                                level, json_logs=json_logs, stream=stream
                            )
                            sock = MagicMock()
                            sock.__enter__.return_value = sock
                            with (
                                patch(
                                    "mtproxy_checker.checker.socket.create_connection",
                                    return_value=sock,
                                ),
                                patch(
                                    "mtproxy_checker.transports.FakeTlsTransport.handshake"
                                ),
                                patch(
                                    "mtproxy_checker.protocol.os.urandom",
                                    side_effect=lambda n: b"q" * n,
                                ),
                                patch(
                                    "mtproxy_checker.checker.make_unencrypted_req_pq_multi",
                                    return_value=(nonce, b"req"),
                                ),
                                patch(
                                    "mtproxy_checker.checker.read_frame",
                                    return_value=response if success else b"bad",
                                ),
                            ):
                                result = check_proxy(
                                    "https://t.me/proxy?server=example.com"
                                    f"&port=443&secret={encoded}"
                                )
                            self.assertEqual(result.ok, success)
                            output = stream.getvalue()
                            self.assert_no_secret_material(output, encoded)
                            if level <= logging.INFO:
                                self.assertIn(key_fingerprint(self.secret), output)
                                self.assertIn("target_selected", output)
                                self.assertIn("attempt_started", output)

    def test_log_records_do_not_expose_secret_to_custom_handlers(self) -> None:
        logger = get_logger()
        with (
            self.assertLogs(logger, level=logging.DEBUG) as captured,
            patch(
                "mtproxy_checker.checker.socket.create_connection",
                side_effect=OSError("unreachable"),
            ),
        ):
            check_proxy(
                "https://t.me/proxy?server=example.com&port=443"
                f"&secret={self.secret.hex()}"
            )
        self.assert_no_secret_material(
            repr([record.__dict__ for record in captured.records]),
            self.secret.hex(),
        )

    def test_invalid_secrets_are_not_logged(self) -> None:
        for encoded in ("ee001122334455", "dd001122334455", "00112233", "invalid!"):
            for level in (logging.WARNING, logging.INFO, logging.DEBUG):
                for json_logs in (False, True):
                    with self.subTest(
                        encoded=encoded, level=level, json_logs=json_logs
                    ):
                        stream = io.StringIO()
                        configure_cli_logging(level, json_logs=json_logs, stream=stream)
                        result = check_proxy(
                            "https://t.me/proxy?server=example.com&port=443"
                            f"&secret={encoded}"
                        )
                        self.assertFalse(result.ok)
                        self.assertNotIn(encoded, stream.getvalue())

    def test_cli_modes_do_not_print_secret_on_success_or_failure(self) -> None:
        for flags in ([], ["--verbose"], ["--trace"]):
            for success in (False, True):
                with self.subTest(flags=flags, success=success):
                    out, err = io.StringIO(), io.StringIO()
                    with (
                        redirect_stdout(out),
                        redirect_stderr(err),
                        patch(
                            "mtproxy_checker.checker.check_once",
                            return_value=(1.0, "nonce"),
                            side_effect=None if success else OSError("unreachable"),
                        ),
                    ):
                        code = main(["example.com", "443", self.secret.hex(), *flags])
                    self.assertEqual(code, 0 if success else 2)
                    self.assert_no_secret_material(
                        out.getvalue() + err.getvalue(), self.secret.hex()
                    )
