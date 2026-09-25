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
import secrets
import socket
import struct
import time
from typing import Any, Optional

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .miot_error import MIoTClientError

OT_PORT = 54321
OT_HEADER = 0x2131
_HEADER_LEN = 32


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
    did: str, token: str, payload: dict, stamp: int
) -> bytes:
    """Build one encrypted miIO datagram."""
    token_bytes = bytes.fromhex(token)
    clear = json.dumps(payload, ensure_ascii=False).encode('utf-8')
    padder = padding.PKCS7(algorithms.AES128.block_size).padder()
    padded = padder.update(clear) + padder.finalize()
    encryptor = _cipher(token_bytes).encryptor()
    encrypted = encryptor.update(padded) + encryptor.finalize()
    data_len = _HEADER_LEN + len(encrypted)
    packet = bytearray(data_len)
    packet[:_HEADER_LEN] = struct.pack(
        '>HHQI16s', OT_HEADER, data_len, int(did), stamp, token_bytes)
    packet[_HEADER_LEN:data_len] = encrypted
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


def _probe(virtual_did: int) -> bytes:
    buf = bytearray(32)
    buf[:20] = (
        b'!1\x00\x20\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFFMDID')
    buf[20:28] = struct.pack('>Q', virtual_did)
    return bytes(buf)


def _hello_did(packet: bytes) -> Optional[tuple[str, int]]:
    if len(packet) < 32 or packet[:2] != b'\x21\x31':
        return None
    did = str(struct.unpack('>Q', packet[4:12])[0])
    stamp = struct.unpack('>I', packet[12:16])[0]
    return did, stamp


async def _rpc_to(
    did: str, token: str, method: str, params: Any,
    address: str, timeout: float
) -> dict:
    """Hello the device, then send one miIO method."""
    loop = asyncio.get_running_loop()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.bind(('0.0.0.0', 0))
        sock.setblocking(False)
        virtual_did = secrets.randbits(63)
        await loop.sock_sendto(sock, _probe(virtual_did), (address, OT_PORT))
        deadline = loop.time() + timeout
        stamp: Optional[int] = None
        hello_at = time.monotonic()
        while loop.time() < deadline:
            remain = deadline - loop.time()
            try:
                data, _addr = await asyncio.wait_for(
                    loop.sock_recvfrom(sock, 4096), timeout=remain)
            except asyncio.TimeoutError:
                break
            hello = _hello_did(data)
            if hello and hello[0] == str(int(did)):
                stamp = hello[1]
                hello_at = time.monotonic()
                break
        if stamp is None:
            raise TimeoutError('miIO hello timeout')
        msg_id = secrets.randbelow(0x7FFFFFFF) + 1
        payload = {'id': msg_id, 'method': method, 'params': params}
        device_stamp = stamp + int(time.monotonic() - hello_at)
        packet = build_miio_packet(did, token, payload, device_stamp)
        await loop.sock_sendto(sock, packet, (address, OT_PORT))
        while loop.time() < deadline:
            remain = max(0.1, deadline - loop.time())
            try:
                data, _addr = await asyncio.wait_for(
                    loop.sock_recvfrom(sock, 4096), timeout=remain)
            except asyncio.TimeoutError:
                break
            if len(data) <= 32:
                continue
            try:
                reply = decrypt_miio_packet(token, data)
            except (ValueError, json.JSONDecodeError):
                continue
            if reply.get('id') == msg_id:
                return reply
        raise TimeoutError('miIO call timeout')
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
