# -*- coding: utf-8 -*-
"""Unit test for infrared code storage and command parsing."""
import pytest

# pylint: disable=import-outside-toplevel


@pytest.mark.github
def test_inline_and_stored_commands():
    from miot.ir_code import (
        DEFAULT_FREQUENCY, IrCodeBook, ir_code_from_read)

    book = IrCodeBook()
    book.set_command('television', 'power', 'AAAA')
    book.set_command('television', 'input', ['BBBB', 'CCCC'])
    restored = IrCodeBook.load(book.dump(), book.dump_toggles())

    assert restored.resolve(None, 'b64:ZZZZ') == ('ZZZZ', DEFAULT_FREQUENCY)
    assert restored.resolve('television', 'power') == (
        'AAAA', DEFAULT_FREQUENCY)
    assert restored.resolve(
        'television', 'raw:DDDD:36000') == ('DDDD', 36000)

    first, _ = restored.resolve('television', 'input')
    second, _ = restored.resolve('television', 'input')
    third, _ = restored.resolve('television', 'input')
    assert first == 'BBBB'
    assert second == 'CCCC'
    assert third == 'BBBB'

    dumped = restored.dump_toggles()
    again = IrCodeBook.load(restored.dump(), dumped)
    assert again.resolve('television', 'input')[0] == 'CCCC'

    restored.delete('television', ['power'])
    with pytest.raises(ValueError):
        restored.resolve('television', 'power')

    assert ir_code_from_read(
        {'result': {'key': '1000000', 'code': 'Z6WP'}}) == 'Z6WP'
    assert ir_code_from_read(
        {'error': {'code': -5002, 'message': 'no code'}}) is None
    with pytest.raises(TimeoutError):
        ir_code_from_read(
            {'error': {'code': -5003, 'message': 'learn timeout'}})


@pytest.mark.github
def test_miio_packet_roundtrip():
    from miot.miio_rpc import build_miio_packet, decrypt_miio_packet

    token = '00112233445566778899aabbccddeeff'
    payload = {
        'id': 7,
        'method': 'miIO.ir_read',
        'params': {'key': '1000000'},
    }
    packet = build_miio_packet('12345', token, payload, 1700000000)
    assert decrypt_miio_packet(token, packet) == payload


@pytest.mark.github
def test_ir_remote_urn_without_spec():
    from miot.const import IR_REMOTE_STUB_URN, ir_remote_urn

    assert ir_remote_urn('chuangmi.ir.v2', None) == IR_REMOTE_STUB_URN
    assert ir_remote_urn('chuangmi.ir.v2', '') == IR_REMOTE_STUB_URN
    assert ir_remote_urn('chuangmi.ir.v2', ' urn:real ') == 'urn:real'
    assert ir_remote_urn('chuangmi.plug.m1', None) is None


@pytest.mark.github
def test_pronto_to_raw():
    from miot.ir_code import parse_inline_command, pronto_to_raw

    pronto = '0000 006C 0000 0001 000A 000A'
    code, freq = pronto_to_raw(pronto)
    assert code
    assert freq > 0
    assert parse_inline_command(pronto) == (code, freq)
    with pytest.raises(ValueError):
        pronto_to_raw('0000 006C')
    with pytest.raises(ValueError):
        parse_inline_command('b64:')
    assert parse_inline_command('power') is None
