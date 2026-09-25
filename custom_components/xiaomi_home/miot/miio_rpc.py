# -*- coding: utf-8 -*-
"""
Copyright (C) 2024 Xiaomi Corporation.

The ownership and intellectual property rights of Xiaomi Home Assistant
Integration and related Xiaomi cloud service API interface provided under this
license, including source code and object code (collectively, "Licensed Work"),
are owned by Xiaomi. Subject to the terms and conditions of this License, Xiaomi
hereby grants you a personal, limited, non-exclusive, non-transferable,
non-sublicensable, and royalty-free license to reproduce, use, modify, and
distribute the Licensed Work only for your use of Home Assistant for
non-commercial purposes. For the avoidance of doubt, Xiaomi does not authorize
you to use the Licensed Work for any other purpose, including but not limited
to use Licensed Work to develop applications (APP), Web services, and other
forms of software.

You may reproduce and distribute copies of the Licensed Work, with or without
modifications, whether in source or object form, provided that you must give
any other recipients of the Licensed Work a copy of this License and retain all
copyright and disclaimers.

Xiaomi provides the Licensed Work on an "AS IS" BASIS, WITHOUT WARRANTIES OR
CONDITIONS OF ANY KIND, either express or implied, including, without
limitation, any warranties, undertakes, or conditions of TITLE, NO ERROR OR
OMISSION, CONTINUITY, RELIABILITY, NON-INFRINGEMENT, MERCHANTABILITY, or
FITNESS FOR A PARTICULAR PURPOSE. In any event, you are solely responsible
for any direct, indirect, special, incidental, or consequential damages or
losses arising from the use or inability to use the Licensed Work.

Xiaomi reserves all rights not expressly granted to you in this License.
Except for the rights expressly granted by Xiaomi under this License, Xiaomi
does not authorize you in any form to use the trademarks, copyrights, or other
forms of intellectual property rights of Xiaomi and its affiliates, including,
without limitation, without obtaining other written permission from Xiaomi, you
shall not use "Xiaomi", "Mijia" and other words related to Xiaomi or words that
may make the public associate with Xiaomi in any form to publicize or promote
the software or hardware devices that use the Licensed Work.

Xiaomi has the right to immediately terminate all your authorization under this
License in the event:
1. You assert patent invalidation, litigation, or other claims against patents
or other intellectual property rights of Xiaomi or its affiliates; or,
2. You make, have made, manufacture, sell, or offer to sell products that knock
off Xiaomi or its affiliates' products.

Direct miIO UDP calls for profile devices such as chuangmi.ir.v2.
"""
from __future__ import annotations

import asyncio
import json
import socket
import struct
from typing import Any, Optional

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .miot_error import MIoTClientError

OT_PORT = 54321
OT_HEADER = 0x2131
_HEADER_LEN = 32
# python-miio MiIOProtocol.discover hello. Profile devices such as
# chuangmi.ir.v2 answer this and ignore the newer MDID probe.
_HELLO = bytes.fromhex(
    '21310020ffffffffffffffffffffffffffffffffffffffffffffffffffffffff')
_RETRY = 3


def _md5(data: bytes) -> bytes:
    hasher = hashes.Hash(hashes.MD5(), default_backend())
    hasher.update(data)
    return hasher.finalize()


def _cipher(token: bytes) -> Cipher:
    aes_key = _md5(token)
    aes_iv = _md5(aes_key + token)
    return Cipher(
        algorithms.AES128(aes_key), modes.CBC(aes_iv), default_backend())


def build_miio_packet(
    device_id: bytes, token: str, payload: dict, stamp: int
) -> bytes:
    """Build one classic miIO datagram.

    python-miio EncryptionAdapter appends a NUL before PKCS7. The header
    unknown field stays 0 and device_id is the 4 bytes from the handshake.
    """
    if len(device_id) != 4:
        raise ValueError('device id must be 4 bytes')
    token_bytes = bytes.fromhex(token)
    clear = json.dumps(payload).encode('utf-8') + b'\x00'
    padder = padding.PKCS7(algorithms.AES128.block_size).padder()
    padded = padder.update(clear) + padder.finalize()
    encryptor = _cipher(token_bytes).encryptor()
    encrypted = encryptor.update(padded) + encryptor.finalize()
    data_len = _HEADER_LEN + len(encrypted)
    packet = bytearray(data_len)
    packet[:16] = struct.pack(
        '>HHI4sI', OT_HEADER, data_len, 0, device_id, stamp & 0xFFFFFFFF)
    packet[16:32] = token_bytes
    packet[32:data_len] = encrypted
    packet[16:32] = _md5(packet[:data_len])
    return bytes(packet)


def decrypt_miio_packet(token: str, packet: bytes) -> dict:
    """Decrypt one miIO datagram."""
    token_bytes = bytes.fromhex(token)
    data = bytearray(packet)
    data_len = struct.unpack('>H', data[2:4])[0]
    md5_orig = bytes(data[16:32])
    data[16:32] = token_bytes
    if _md5(data[:data_len]) != md5_orig:
        raise ValueError('invalid miIO checksum')
    decryptor = _cipher(token_bytes).decryptor()
    padded = decryptor.update(data[32:data_len]) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithms.AES128.block_size).unpadder()
    clear = unpadder.update(padded) + unpadder.finalize()
    return json.loads(clear.rstrip(b'\x00'))


def hello_identity(packet: bytes) -> Optional[tuple[bytes, int]]:
    """Return the 4-byte device id and stamp from a classic hello.

    Layout matches python-miio Message: unknown at bytes 4-8, device id
    at bytes 8-12, timestamp at bytes 12-16.
    """
    if len(packet) < 32 or packet[:2] != b'\x21\x31':
        return None
    length = struct.unpack('>H', packet[2:4])[0]
    if length < 32:
        return None
    return bytes(packet[8:12]), struct.unpack('>I', packet[12:16])[0]


def hello_matches(device_id: bytes, did: str) -> bool:
    """True when the hello id is the cloud did, or its lower 32 bits."""
    got = struct.unpack('>I', device_id)[0]
    return got == (int(did) & 0xFFFFFFFF)


def command_stamp(hello_stamp: int, attempt: int = 0) -> int:
    """Return the timestamp python-miio sends: handshake time plus 1s."""
    return (hello_stamp + 1 + attempt) & 0xFFFFFFFF


async def _recv(loop, sock, deadline: float):
    remain = deadline - loop.time()
    if remain <= 0:
        raise asyncio.TimeoutError
    return await asyncio.wait_for(
        loop.sock_recvfrom(sock, 4096), timeout=remain)


async def _handshake(loop, sock, did: str, address: str, timeout: float):
    """Send the classic hello and return device id, stamp, and peer."""
    broadcast = address == '255.255.255.255'
    deadline = loop.time() + timeout
    await loop.sock_sendto(sock, _HELLO, (address, OT_PORT))
    fallback = None
    while loop.time() < deadline:
        try:
            data, addr = await _recv(loop, sock, deadline)
        except asyncio.TimeoutError:
            break
        ident = hello_identity(data)
        if not ident:
            continue
        device_id, stamp = ident
        if hello_matches(device_id, did):
            return device_id, stamp, addr[0]
        if not broadcast and fallback is None:
            # Unicast: python-miio keeps the id the device announced.
            fallback = (device_id, stamp, addr[0])
    if fallback:
        return fallback
    raise TimeoutError('miIO hello timeout')


async def _await_reply(
    loop, sock, token: str, msg_id: int, peer: str, timeout: float
):
    """Return the decrypted reply for msg_id, or None on timeout."""
    deadline = loop.time() + timeout
    bad_token = 0
    while loop.time() < deadline:
        try:
            data, addr = await _recv(loop, sock, deadline)
        except asyncio.TimeoutError:
            break
        if addr[0] != peer or len(data) <= 32:
            continue
        try:
            reply = decrypt_miio_packet(token, data)
        except (ValueError, json.JSONDecodeError):
            bad_token += 1
            continue
        if reply.get('id') == msg_id:
            return reply, bad_token
    return None, bad_token


async def _rpc_to(
    did: str, token: str, method: str, params: Any,
    address: str, timeout: float
) -> dict:
    """Handshake, then send one miIO method the way python-miio does."""
    loop = asyncio.get_running_loop()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.bind(('0.0.0.0', 0))
        sock.setblocking(False)
        window = min(5.0, timeout)
        device_id = None
        hello_stamp = 0
        peer = address
        for _ in range(_RETRY):
            try:
                device_id, hello_stamp, peer = await _handshake(
                    loop, sock, did, address, window)
                break
            except TimeoutError:
                continue
        if device_id is None:
            raise TimeoutError('miIO hello timeout')
        msg_id = 1
        bad_token = 0
        if params is None:
            params = []
        for attempt in range(_RETRY):
            payload = {'id': msg_id, 'method': method, 'params': params}
            packet = build_miio_packet(
                device_id, token, payload,
                command_stamp(hello_stamp))
            await loop.sock_sendto(sock, packet, (peer, OT_PORT))
            reply, rejects = await _await_reply(
                loop, sock, token, msg_id, peer, window)
            bad_token += rejects
            if reply is not None:
                return reply
            # python-miio retries with id += 100 and a fresh handshake.
            msg_id += 100
            try:
                device_id, hello_stamp, peer = await _handshake(
                    loop, sock, did, peer, window)
            except TimeoutError:
                hello_stamp = command_stamp(hello_stamp, attempt)
        if bad_token:
            raise MIoTClientError(
                'the remote answered but the device token was rejected. '
                'Update the device list and try again.')
        raise TimeoutError(f'miIO call timeout, peer {peer}')
    finally:
        sock.close()


async def miio_rpc_async(
    did: str, token: str, method: str, params: Any,
    ip: Optional[str] = None, timeout_ms: int = 10000
) -> dict:
    """Send a miIO method without the integration LAN-control service.

    The universal remote has no cloud spec action. A central hub gateway
    or cloud control mode turns that service off, so this talks to the
    device directly with the token from the cloud device list.
    """
    if not did.isdigit():
        raise MIoTClientError(f'invalid device id, {did}')
    if not isinstance(token, str) or len(token) != 32:
        raise MIoTClientError(
            'device token is missing, update the device list')
    timeout = max(timeout_ms, 1000) / 1000
    targets = []
    if isinstance(ip, str) and ip:
        targets.append(ip)
    targets.append('255.255.255.255')
    last_error: Optional[Exception] = None
    for address in targets:
        try:
            return await _rpc_to(
                did, token, method, params, address, timeout)
        except (TimeoutError, OSError) as err:
            last_error = err
    raise MIoTClientError(
        'remote was not found on the local network. Home Assistant must '
        'reach the remote on UDP port 54321. If it runs in Docker, use '
        f'host network. ({last_error})')
