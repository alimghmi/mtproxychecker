from __future__ import annotations

import argparse
import base64
import urllib.parse

from .errors import InvalidInputError, InvalidSecretError
from .logging import get_logger
from .models import ParsedSecret, ProxyTarget, SecretKind

DEFAULT_DCS = (2, 1, 3, 4, 5)
DEFAULT_FAST_DCS = (2,)
FAKETLS_DEFAULT_DOMAIN = "www.google.com"

COMMON_TLDS = (
    ".com",
    ".net",
    ".org",
    ".ir",
    ".ru",
    ".io",
    ".co",
    ".dev",
    ".app",
    ".cloud",
    ".me",
    ".info",
)

logger = get_logger(__name__)


def parse_query_preserve_plus(url: str) -> dict[str, str]:
    parsed = urllib.parse.urlparse(url)
    result: dict[str, str] = {}

    for part in parsed.query.split("&"):
        if not part:
            continue

        if "=" in part:
            key, value = part.split("=", 1)
        else:
            key, value = part, ""

        result[urllib.parse.unquote(key)] = urllib.parse.unquote(value)

    return result


def extract_first_domain(blob: bytes) -> str:
    text = blob.rstrip(b"\x00").decode("ascii", "ignore")
    text = "".join(ch for ch in text if ch.isprintable())
    text = text.lstrip("\x00\r\n\t ")

    if not text:
        return FAKETLS_DEFAULT_DOMAIN

    best_pos: int | None = None
    best_end: int | None = None

    for tld in COMMON_TLDS:
        pos = text.find(tld)

        if pos == -1:
            continue

        end = pos + len(tld)

        if (
            best_pos is None
            or pos < best_pos
            or (pos == best_pos and best_end is not None and end > best_end)
        ):
            best_pos = pos
            best_end = end

    if best_end is None:
        allowed = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-"
        cleaned = "".join(ch for ch in text if ch in allowed)
        return cleaned or FAKETLS_DEFAULT_DOMAIN

    domain = text[:best_end]

    while domain and not domain[0].isalnum():
        domain = domain[1:]

    return domain or FAKETLS_DEFAULT_DOMAIN


def decode_secret(secret: str) -> ParsedSecret:
    s = secret.strip()
    lower = s.lower()

    logger.info(
        "secret input",
        extra={
            "event": "secret_input",
            "secret_length": len(s),
        },
    )

    if not s:
        raise InvalidSecretError("empty secret")

    try:
        raw_hex_bytes = bytes.fromhex(lower)
        logger.info(
            "secret parsed",
            extra={
                "event": "secret_parsed",
                "secret_encoding": "hex",
                "decoded_len": len(raw_hex_bytes),
            },
        )

        if lower.startswith("ee"):
            if len(lower) < 34:
                raise InvalidSecretError("EE/FakeTLS secret is too short")

            domain = ""

            if len(lower) > 34:
                try:
                    domain = (
                        bytes.fromhex(lower[34:])
                        .decode("ascii", "ignore")
                        .rstrip("\x00")
                    )
                except ValueError:  # pragma: no cover
                    domain = ""

            return ParsedSecret(
                raw_secret=bytes.fromhex(lower[2:34]),
                display=lower,
                is_faketls=True,
                faketls_domain=domain or FAKETLS_DEFAULT_DOMAIN,
                kind=SecretKind.FAKETLS,
            )

        if lower.startswith("dd"):
            if len(lower) < 34:
                raise InvalidSecretError("DD secret is too short")

            return ParsedSecret(
                raw_secret=bytes.fromhex(lower[2:34]),
                display=lower,
                kind=SecretKind.DD_SECURE,
            )

        if len(raw_hex_bytes) > 16:
            return ParsedSecret(
                raw_secret=raw_hex_bytes[:16],
                display=raw_hex_bytes[:16].hex(),
                kind=SecretKind.EXTENDED_RAW,
            )

        if len(raw_hex_bytes) != 16:
            raise InvalidSecretError(
                f"hex secret decoded to {len(raw_hex_bytes)} bytes, expected 16"
            )

        return ParsedSecret(raw_secret=raw_hex_bytes, display=lower)

    except ValueError:
        logger.info(
            "secret hex parse failed, trying base64/base64url",
            extra={"event": "secret_hex_parse_failed"},
        )

    b64 = s.replace("-", "+").replace("_", "/")
    padding = "=" * ((4 - len(b64) % 4) % 4)

    try:
        raw = base64.b64decode(b64 + padding, validate=False)
    except Exception as exc:
        raise InvalidSecretError(
            f"secret is neither valid hex nor base64: {exc}"
        ) from exc

    logger.info(
        "secret parsed",
        extra={
            "event": "secret_parsed",
            "secret_encoding": "base64",
            "decoded_len": len(raw),
        },
    )

    if len(raw) == 16:
        return ParsedSecret(raw_secret=raw, display=raw.hex())

    if len(raw) >= 17 and raw[0] == 0xDD:
        raw_secret = raw[1:17]
        return ParsedSecret(
            raw_secret=raw_secret,
            display="dd" + raw_secret.hex(),
            kind=SecretKind.DD_SECURE,
        )

    if len(raw) >= 17 and raw[0] == 0xEE:
        domain = extract_first_domain(raw[17:])
        return ParsedSecret(
            raw_secret=raw[1:17],
            display="ee" + raw[1:17].hex(),
            is_faketls=True,
            faketls_domain=domain,
            kind=SecretKind.FAKETLS,
        )

    if len(raw) > 16:
        return ParsedSecret(
            raw_secret=raw[:16],
            display=raw[:16].hex(),
            kind=SecretKind.EXTENDED_RAW,
        )

    raise InvalidSecretError(
        f"base64 secret decoded to {len(raw)} bytes, expected at least 16"
    )


def parse_proxy_url(url: str) -> ProxyTarget:
    qs = parse_query_preserve_plus(url)

    try:
        host = qs["server"]
        port = int(qs["port"])
        secret = decode_secret(qs["secret"])
    except KeyError as exc:
        raise InvalidInputError(
            f"bad proxy URL, missing query parameter: {exc}"
        ) from exc
    except ValueError as exc:
        raise InvalidInputError(f"bad proxy URL, invalid port: {exc}") from exc

    return make_target(host, port, secret)


def make_target(
    host: str | None,
    port: int | str | None,
    secret: ParsedSecret | str | None,
) -> ProxyTarget:
    if not host or port is None or secret is None:
        raise InvalidInputError("use either --url or host port secret")

    try:
        parsed_port = int(port)
    except ValueError as exc:
        raise InvalidInputError("bad proxy input, invalid port") from exc

    if parsed_port < 1 or parsed_port > 65535:
        raise InvalidInputError("bad proxy input, port must be between 1 and 65535")

    parsed_secret = (
        secret if isinstance(secret, ParsedSecret) else decode_secret(secret)
    )
    return ProxyTarget(host=host, port=parsed_port, secret=parsed_secret)


def parse_dcs(value: str) -> tuple[int, ...]:
    if not value:
        return DEFAULT_DCS

    dcs: list[int] = []

    for part in value.split(","):
        part = part.strip()

        if not part:
            continue

        try:
            dcs.append(int(part))
        except ValueError as exc:
            raise argparse.ArgumentTypeError("DC ids must be integers") from exc

    if not dcs:
        raise argparse.ArgumentTypeError("empty DC list")

    return tuple(dcs)


def short_hex(data: bytes, limit: int = 64) -> str:
    h = data.hex()

    if len(h) > limit * 2:
        return h[: limit * 2] + f"...({len(data)} bytes)"

    return h
