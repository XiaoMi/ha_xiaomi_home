# -*- coding: utf-8 -*-
"""Unit test for miot_lan.py."""
import logging
from typing import Any
import pytest
import asyncio
from zeroconf import IPVersion
from zeroconf.asyncio import AsyncZeroconf

_LOGGER = logging.getLogger(__name__)

# pylint: disable=import-outside-toplevel, unused-argument


@pytest.mark.parametrize('test_devices', [{
    # specv2 model
    '123456': {
        'token': '11223344556677d9a03d43936fc384205',
        'model': 'xiaomi.gateway.hub1'
    },
    # profile model
    '123457': {
        'token': '11223344556677d9a03d43936fc384205',
        'model': 'yeelink.light.lamp9'
    },
    '123458': {
        'token': '11223344556677d9a03d43936fc384205',
        'model': 'zhimi.heater.ma1'
    },
    # Non -digital did
    'group.123456': {
        'token': '11223344556677d9a03d43936fc384205',
        'model': 'mijia.light.group3'
    },
    'proxy.123456.1': {
        'token': '11223344556677d9a03d43936fc384205',
        'model': 'xiaomi.light.p1'
    },
    'miwifi_123456': {
        'token': '11223344556677d9a03d43936fc384205',
        'model': 'xiaomi.light.p1'
    }
}])
@pytest.mark.asyncio
async def test_lan_async(test_devices: dict):
    """
    Use the central hub gateway as a test equipment, and through the local area 
    network control central hub gateway indicator light switch. Please replace 
    it for your own device information (did, token) during testing.
    xiaomi.gateway.hub1 spec define: 
    http://poc.miot-spec.srv/miot-spec-v2/instance?type=urn:miot-spec-v2:device:gateway:0000A019:xiaomi-hub1:3
    """
    from miot.miot_network import MIoTNetwork
    from miot.miot_lan import MIoTLan
    from miot.miot_mdns import MipsService

    # Your central hub gateway did
    test_did = '111111'
    # Your central hub gateway token
    test_token = '11223344556677d9a03d43936fc384205'
    test_model = 'xiaomi.gateway.hub1'
    # Your computer interface list, such as enp3s0, wlp5s0
    test_if_names = ['enp3s0', 'wlp5s0']

    # Check test params
    assert int(test_did) > 0

    evt_push_available: asyncio.Event
    evt_push_unavailable: asyncio.Event

    miot_network = MIoTNetwork()
    await miot_network.init_async()
    _LOGGER.info('miot_network, %s', miot_network.network_info)
    mips_service = MipsService(
        aiozc=AsyncZeroconf(ip_version=IPVersion.V4Only))
    await mips_service.init_async()
    miot_lan = MIoTLan(
        net_ifs=test_if_names,
        network=miot_network,
        mips_service=mips_service,
        enable_subscribe=True)
    evt_push_available = asyncio.Event()
    evt_push_unavailable = asyncio.Event()
    await miot_lan.vote_for_lan_ctrl_async(key='test', vote=True)

    async def device_state_change(did: str, state: dict, ctx: Any):
        _LOGGER.info('device state change, %s, %s', did, state)
        if did != test_did:
            return
        if (
            state.get('online', False)
            and state.get('push_available', False)
        ):
            # Test sub prop
            miot_lan.sub_prop(
                did=did, siid=3, piid=1, handler=lambda msg, ctx:
                    _LOGGER.info('sub prop.3.1 msg, %s=%s', did, msg))
            miot_lan.sub_prop(
                did=did, handler=lambda msg, ctx:
                    _LOGGER.info('sub all device msg, %s=%s', did, msg))
            evt_push_available.set()
        else:
            # miot_lan.unsub_prop(did=did, siid=3, piid=1)
            # miot_lan.unsub_prop(did=did)
            evt_push_unavailable.set()

    async def lan_state_change(state: bool):
        _LOGGER.info('lan state change, %s', state)
        if not state:
            return
        miot_lan.update_devices(devices={
            test_did: {
                'token': test_token,
                'model': test_model
            },
            **test_devices
        })

        # Test sub device state
        miot_lan.sub_device_state(
            'test', device_state_change)

    miot_lan.sub_lan_state('test', lan_state_change)
    if miot_lan.init_done:
        await lan_state_change(True)

    await evt_push_available.wait()
    result = await miot_lan.get_dev_list_async()
    assert test_did in result
    result = await miot_lan.set_prop_async(
        did=test_did, siid=3, piid=1, value=True)
    assert result.get('code', -1) == 0
    await asyncio.sleep(0.2)
    result = await miot_lan.set_prop_async(
        did=test_did, siid=3, piid=1, value=False)
    assert result.get('code', -1) == 0
    await asyncio.sleep(0.2)

    evt_push_unavailable = asyncio.Event()
    await miot_lan.update_subscribe_option(enable_subscribe=False)

    await evt_push_unavailable.wait()
    result = await miot_lan.get_dev_list_async()
    assert test_did in result
    result = await miot_lan.set_prop_async(
        did=test_did, siid=3, piid=1, value=True)
    assert result.get('code', -1) == 0
    await asyncio.sleep(0.2)
    result = await miot_lan.set_prop_async(
        did=test_did, siid=3, piid=1, value=False)
    assert result.get('code', -1) == 0
    await asyncio.sleep(0.2)

    await miot_lan.deinit_async()
    await mips_service.deinit_async()
    await miot_network.deinit_async()
