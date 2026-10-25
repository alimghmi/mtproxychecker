from __future__ import annotations

import socket
import time

from .attempts import (
    build_attempts,
    describe_secret,
    effective_inner_mode,
    format_attempts,
)
from .errors import (
    InvalidInputError,
    NetworkCheckError,
    classify_exception,
    public_message,
)
from .logging import get_logger, key_fingerprint
from .models import (
    AttemptResult,
    CheckOptions,
    CheckResult,
    ErrorCode,
    Mode,
    ProxyTarget,
)
from .parser import parse_proxy_url
from .protocol import (
    frame_message,
    make_obfuscated2_handshake,
    make_unencrypted_req_pq_multi,
    parse_res_pq,
    read_frame,
)
from .transports import FakeTlsTransport, PlainTransport

logger = get_logger(__name__)


def check_proxy(
    target: ProxyTarget | str,
    options: CheckOptions | None = None,
) -> CheckResult:
    options = options or CheckOptions()

    try:
        parsed_target = parse_proxy_url(target) if isinstance(target, str) else target
        attempts = build_attempts(
            parsed_target.secret,
            options.mode,
            options.dc,
            options.dcs,
            options.exhaustive,
        )
    except Exception as exc:
        code, message, detail = classify_exception(exc)
        return CheckResult(
            ok=False,
            error_code=code,
            error_message=message,
            attempts=(
                AttemptResult(
                    dc=options.dc or 0,
                    mode=Mode.SECURE,
                    error_code=code,
                    error_message=message,
                    detail=detail,
                ),
            )
            if code == ErrorCode.UNSUPPORTED_MODE
            else (),
        )

    logger.info(
        "target selected",
        extra={
            "event": "target_selected",
            "host": parsed_target.host,
            "port": parsed_target.port,
        },
    )
    logger.info(
        "secret type selected",
        extra={
            "event": "secret_type_selected",
            "secret_type": describe_secret(parsed_target.secret),
            "secret_kind": parsed_target.secret.kind.value,
            "faketls_domain": parsed_target.secret.faketls_domain,
            "key_id": key_fingerprint(parsed_target.secret.raw_secret),
        },
    )
    logger.info(
        "attempts selected",
        extra={"event": "attempts_selected", "attempts": format_attempts(attempts)},
    )
    logger.info(
        "timeouts selected",
        extra={
            "event": "timeouts_selected",
            "connect_timeout_s": options.connect_timeout,
            "response_timeout_s": options.response_timeout,
        },
    )

    failures: list[AttemptResult] = []

    for dc_id, mode in attempts:
        try:
            elapsed_ms, server_nonce = check_once(
                target=parsed_target,
                dc_id=dc_id,
                connect_timeout=options.connect_timeout,
                response_timeout=options.response_timeout,
                mode=mode,
            )
        except Exception as exc:
            code, message, detail = classify_exception(exc)
            failure = AttemptResult(
                dc=dc_id,
                mode=mode,
                error_code=code,
                error_message=message,
                detail=detail,
            )
            failures.append(failure)
            logger.info(
                "attempt failed",
                extra={
                    "event": "attempt_failed",
                    "dc": dc_id,
                    "mode": mode.value,
                    "error_code": code.value,
                    "detail": detail,
                },
            )
            continue

        success = AttemptResult(
            dc=dc_id,
            mode=mode,
            ok=True,
            rtt_ms=elapsed_ms,
            server_nonce=server_nonce,
        )
        return CheckResult(
            ok=True,
            target=parsed_target,
            mode=mode,
            dc=dc_id,
            rtt_ms=elapsed_ms,
            server_nonce=server_nonce,
            attempts=(*failures, success),
        )

    error_code = ErrorCode.NETWORK_ERROR

    if failures and failures[-1].error_code:
        error_code = failures[-1].error_code
    return CheckResult(
        ok=False,
        target=parsed_target,
        attempts=tuple(failures),
        error_code=error_code,
        error_message=public_message(error_code),
    )


def check_once(
    target: ProxyTarget,
    dc_id: int,
    connect_timeout: float,
    response_timeout: float,
    mode: Mode,
) -> tuple[float, str]:
    started = time.monotonic()
    inner_mode = effective_inner_mode(mode)

    logger.info(
        "attempt started",
        extra={
            "event": "attempt_started",
            "host": target.host,
            "port": target.port,
            "dc": dc_id,
            "mode": mode.value,
        },
    )

    try:
        sock = socket.create_connection(
            (target.host, target.port),
            timeout=connect_timeout,
        )
    except TimeoutError as exc:
        raise NetworkCheckError(
            ErrorCode.CONNECT_TIMEOUT,
            str(exc) or "timed out",
        ) from exc
    except OSError as exc:
        raise NetworkCheckError(ErrorCode.NETWORK_ERROR, str(exc)) from exc

    with sock:
        sock.settimeout(response_timeout)
        logger.info(
            "tcp connected",
            extra={
                "event": "tcp_connected",
                "host": target.host,
                "port": target.port,
            },
        )

        try:
            transport: FakeTlsTransport | PlainTransport

            if mode == Mode.FAKETLS:
                transport = FakeTlsTransport(
                    sock,
                    target.secret.raw_secret,
                    target.secret.faketls_domain,
                )
                transport.handshake()
                logger.info(
                    "faketls handshake complete",
                    extra={
                        "event": "faketls_handshake_complete",
                        "domain": target.secret.faketls_domain,
                    },
                )
            else:
                transport = PlainTransport(sock)

            init_packet, enc, dec = make_obfuscated2_handshake(
                target.secret.raw_secret,
                inner_mode,
                dc_id,
            )
            transport.write(init_packet)
            logger.info(
                "sent obfuscated2 init",
                extra={
                    "event": "obfuscated2_init_sent",
                    "packet_len": len(init_packet),
                },
            )

            nonce, req = make_unencrypted_req_pq_multi()
            encrypted_req = enc.update(frame_message(req, inner_mode))
            logger.debug(
                "encrypted request frame",
                extra={
                    "event": "encrypted_request_frame",
                    "frame_hex": encrypted_req.hex(),
                },
            )
            transport.write(encrypted_req)
            logger.info(
                "sent encrypted req_pq_multi frame",
                extra={
                    "event": "req_pq_multi_sent",
                    "frame_len": len(encrypted_req),
                },
            )

            frame = read_frame(transport, dec, inner_mode)
            server_nonce = parse_res_pq(frame, nonce)
        except TimeoutError as exc:
            raise NetworkCheckError(
                ErrorCode.RESPONSE_TIMEOUT,
                str(exc) or "timed out",
            ) from exc
        except OSError as exc:
            raise NetworkCheckError(ErrorCode.NETWORK_ERROR, str(exc)) from exc

    elapsed_ms = (time.monotonic() - started) * 1000
    return elapsed_ms, server_nonce


def require_target(target: ProxyTarget | None) -> ProxyTarget:
    if target is None:
        raise InvalidInputError()

    return target
