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

Infrared code storage and Pronto conversion for chuangmi.ir.v2.
"""
from __future__ import annotations

import base64
import re
from typing import Any, Optional, Union

from construct import (
    Adapter,
    Array,
    BitsInteger,
    BitStruct,
    Computed,
    Const,
    Int16ub,
    Int16ul,
    Int32ul,
    Rebuild,
    Struct,
    len_,
    this,
)

from .miot_error import MIoTErrorCode

DEFAULT_FREQUENCY = 38400
B64_PREFIX = 'b64:'
LEARN_SLOT = '1000000'
LEARN_TIMEOUT = -5003
NO_CODE = -5002

PRONTO_RE = re.compile(
    r'^([\da-f]{4}\s?){3,}([\da-f]{4})$', re.IGNORECASE)

CodeValue = Union[str, list]


class ProntoPulseAdapter(Adapter):
    """Convert Pronto ticks to microseconds."""

    def _decode(self, obj, context, path):
        return int(obj * context._.modulation_period)

    def _encode(self, obj, context, path):
        raise RuntimeError('Not implemented')


ChuangmiIrSignal = Struct(
    Const(0xA567, Int16ul),
    'edge_count' / Rebuild(Int16ul, len_(this.edge_pairs) * 2 - 1),
    'times_index' / Array(16, Int32ul),
    'edge_pairs' / Array(
        (this.edge_count + 1) // 2,
        BitStruct(
            'gap' / BitsInteger(4),
            'pulse' / BitsInteger(4))),
)

ProntoBurstPair = Struct(
    'pulse' / ProntoPulseAdapter(Int16ub),
    'gap' / ProntoPulseAdapter(Int16ub),
)

Pronto = Struct(
    Const(0, Int16ub),
    '_ticks' / Int16ub,
    'modulation_period' / Computed(this._ticks * 0.241246),
    'frequency' / Computed(1000000 / this.modulation_period),
    'intro_len' / Int16ub,
    'repeat_len' / Int16ub,
    'intro' / Array(this.intro_len, ProntoBurstPair),
    'repeat' / Array(this.repeat_len, ProntoBurstPair),
)


def is_pronto(command: str) -> bool:
    """Return True when command is a Pronto hex string."""
    return bool(PRONTO_RE.match(command.strip()))


def pronto_to_raw(pronto: str, repeats: int = 1) -> tuple[str, int]:
    """Convert a raw Pronto hex string into a chuangmi code.

    Only Pronto format 0000 is supported. The conversion follows the
    chuangmi payload used by python-miio.
    """
    if repeats < 0:
        raise ValueError('Invalid repeats value')
    try:
        pronto_data = Pronto.parse(bytearray.fromhex(pronto))
    except Exception as err:  # pylint: disable=broad-exception-caught
        raise ValueError('Invalid Pronto command') from err

    if len(pronto_data.intro) == 0:
        repeats += 1

    times: set[int] = set()
    burst = (
        list(pronto_data.intro)
        + list(pronto_data.repeat) * (1 if repeats else 0))
    for pair in burst:
        times.add(pair.pulse)
        times.add(pair.gap)
    if len(times) > 16:
        raise ValueError('Pronto command has too many distinct times')

    times_sorted = sorted(times)
    times_map = {item: idx for idx, item in enumerate(times_sorted)}
    edge_pairs = []
    for pair in list(pronto_data.intro) + list(pronto_data.repeat) * repeats:
        edge_pairs.append({
            'pulse': times_map[pair.pulse],
            'gap': times_map[pair.gap],
        })
    if not edge_pairs:
        raise ValueError('Invalid Pronto command')

    signal = ChuangmiIrSignal.build({
        'times_index': times_sorted + [0] * (16 - len(times_sorted)),
        'edge_pairs': edge_pairs,
    })
    return base64.b64encode(signal).decode(), int(round(pronto_data.frequency))


def timings_to_chuangmi(
    timings: list, frequency: int = DEFAULT_FREQUENCY
) -> tuple[str, int]:
    """Convert signed microsecond timings into a chuangmi code.

    Positive values are marks and negative values are spaces. Older
    infrared-protocols builds yield Timing objects with high_us/low_us.
    """
    signed: list[int] = []
    for item in timings:
        if isinstance(item, int):
            signed.append(item)
            continue
        signed.append(int(item.high_us))
        low = int(getattr(item, 'low_us', 0))
        if low:
            signed.append(-low)
    pairs = []
    index = 0
    while index < len(signed):
        pulse = abs(signed[index])
        gap = abs(signed[index + 1]) if index + 1 < len(signed) else 0
        pairs.append((pulse, gap))
        index += 2
    if not pairs:
        raise ValueError('infrared command has no timings')
    times = sorted({value for pair in pairs for value in pair})
    if len(times) > 16:
        raise ValueError('infrared command has too many distinct times')
    times_map = {item: idx for idx, item in enumerate(times)}
    signal = ChuangmiIrSignal.build({
        'times_index': times + [0] * (16 - len(times)),
        'edge_pairs': [
            {'pulse': times_map[pulse], 'gap': times_map[gap]}
            for pulse, gap in pairs
        ],
    })
    freq = frequency if frequency and frequency > 0 else DEFAULT_FREQUENCY
    return base64.b64encode(signal).decode(), int(freq)


def parse_inline_command(command: str) -> Optional[tuple[str, int]]:
    """Parse a raw, b64 or Pronto command.

    Stored command names return None so the caller can look them up.
    """
    command = command.strip()
    if command.startswith(B64_PREFIX):
        code = command[len(B64_PREFIX):]
        if not code:
            raise ValueError('empty b64 code')
        return code, DEFAULT_FREQUENCY
    if ':' in command:
        command_type, payload, *args = command.split(':')
        if len(args) > 2:
            raise ValueError('Invalid command arguments count')
        if command_type == 'raw':
            freq = int(args[0]) if args else DEFAULT_FREQUENCY
            return payload, freq
        if command_type == 'pronto':
            repeats = int(args[0]) if args else 1
            return pronto_to_raw(payload, repeats)
        raise ValueError('Invalid command type')
    if is_pronto(command):
        return pronto_to_raw(command)
    return None


def ir_code_from_read(result: dict) -> Optional[str]:
    """Return a learned code, or None when the slot is still empty.

    Raises TimeoutError when learning timed out or the LAN call timed out.
    """
    if not isinstance(result, dict):
        raise ValueError('invalid miIO result')
    if result.get('code') == MIoTErrorCode.CODE_TIMEOUT.value:
        raise TimeoutError(result.get('error') or 'timeout')
    error = result.get('error')
    if isinstance(error, dict):
        err_code = error.get('code')
        if err_code == NO_CODE:
            return None
        if err_code == LEARN_TIMEOUT:
            raise TimeoutError(error.get('message') or 'learn timeout')
        raise ValueError(error.get('message') or str(error))
    if isinstance(error, str):
        raise TimeoutError(error)
    payload = result.get('result', None)
    if isinstance(payload, dict):
        code = payload.get('code')
        if isinstance(code, str) and code:
            return code
    return None


def ensure_miio_ok(result: dict) -> dict:
    """Raise when a miIO reply is an error or a timeout."""
    if not isinstance(result, dict):
        raise ValueError('invalid miIO result')
    if result.get('code') == MIoTErrorCode.CODE_TIMEOUT.value:
        raise TimeoutError(result.get('error') or 'timeout')
    error = result.get('error')
    if isinstance(error, dict):
        raise ValueError(error.get('message') or str(error))
    if isinstance(error, str):
        raise TimeoutError(error)
    return result


class IrCodeBook:
    """Learned IR codes grouped by device name, Broadlink-style."""

    def __init__(
        self,
        codes: Optional[dict] = None,
        toggles: Optional[dict] = None,
    ) -> None:
        self.codes: dict[str, dict[str, CodeValue]] = codes or {}
        self.toggles: dict[str, dict[str, int]] = toggles or {}

    def dump(self) -> dict:
        """Return the code map stored on disk."""
        return self.codes

    def dump_toggles(self) -> dict:
        """Return the toggle index map stored on disk."""
        return self.toggles

    @classmethod
    def load(
        cls,
        codes: Optional[dict],
        toggles: Optional[dict] = None,
    ) -> 'IrCodeBook':
        """Restore a book from storage."""
        if not isinstance(codes, dict):
            codes = {}
        if not isinstance(toggles, dict):
            toggles = {}
        return cls(codes=codes, toggles=toggles)

    def set_command(
        self, device: str, command: str, code: CodeValue
    ) -> None:
        """Store one command, or a two-code toggle list."""
        self.codes.setdefault(device, {})[command] = code
        self.toggles.setdefault(device, {}).pop(command, None)

    def delete(self, device: str, commands: list[str]) -> None:
        """Delete stored commands."""
        bucket = self.codes.get(device)
        if bucket is None:
            raise ValueError(f'Device not found: {device!r}')
        for command in commands:
            if command not in bucket:
                raise ValueError(f'Command not found: {command!r}')
            bucket.pop(command)
            self.toggles.get(device, {}).pop(command, None)
        if not bucket:
            self.codes.pop(device, None)
            self.toggles.pop(device, None)

    def resolve(self, device: Optional[str], command: str) -> tuple[str, int]:
        """Return the chuangmi code and carrier frequency to play."""
        inline = parse_inline_command(command)
        if inline is not None:
            return inline
        if not device or device not in self.codes:
            raise ValueError(f'Command not found: {command!r}')
        stored: Any = self.codes[device].get(command)
        if stored is None:
            raise ValueError(f'Command not found: {command!r}')
        if isinstance(stored, list):
            if not stored:
                raise ValueError(f'Command not found: {command!r}')
            indexes = self.toggles.setdefault(device, {})
            index = indexes.get(command, 0) % len(stored)
            indexes[command] = (index + 1) % len(stored)
            stored = stored[index]
        if not isinstance(stored, str) or not stored:
            raise ValueError(f'Command not found: {command!r}')
        parsed = parse_inline_command(stored)
        if parsed is not None:
            return parsed
        return stored, DEFAULT_FREQUENCY
