# -*- coding: utf-8 -*-
"""Unit test for miot_client.py."""
import sys
from types import ModuleType
from typing import Any
import pytest

# pylint: disable=import-outside-toplevel, unused-argument, protected-access

GROUP_ID: str = 'test_group_id'
DID: str = '123456789'


def _stub_missing_modules() -> None:
    """miot_client imports homeassistant and aiohttp, which the github tests
    do not install. Stub only the modules that are missing."""
    stubs: dict[str, dict[str, Any]] = {
        'aiohttp': {'ClientSession': object},
        'homeassistant': {},
        'homeassistant.core': {'HomeAssistant': object},
        'homeassistant.components': {},
        'homeassistant.components.zeroconf': {},
    }
    for name, attrs in stubs.items():
        try:
            __import__(name)
        except ImportError:
            module = ModuleType(name)
            module.__dict__.update(attrs)
            sys.modules[name] = module
            parent, _, child = name.rpartition('.')
            if parent:
                setattr(sys.modules[parent], child, module)


class _FakeGateway:
    """Central hub gateway that pushes the last event again when a topic is
    subscribed, which is what a resubscription after a reconnect causes."""

    def __init__(self) -> None:
        self.handler = None
        self.last_event = None
        self.sub_count = 0

    def sub_prop(self, did: str, handler: Any) -> None:
        pass

    def unsub_prop(self, did: str) -> None:
        pass

    def sub_event(self, did: str, handler: Any) -> None:
        self.sub_count += 1
        self.handler = handler
        if self.last_event:
            handler(self.last_event, None)

    def unsub_event(self, did: str) -> None:
        self.handler = None

    def press(self) -> None:
        self.last_event = {
            'did': DID, 'siid': 2, 'eiid': 1, 'arguments': []}
        if self.handler:
            self.handler(self.last_event, None)


@pytest.mark.github
@pytest.mark.asyncio
async def test_cloud_disconnect_does_not_resub_gateway_event():
    _stub_missing_modules()
    from miot.common import MIoTMatcher
    from miot.miot_client import CtrlMode, MIoTClient

    gateway = _FakeGateway()
    client = object.__new__(MIoTClient)
    client._ctrl_mode = CtrlMode.AUTO
    client._device_list_cache = {DID: {'online': True}}
    client._device_list_cloud = {DID: {'online': True}}
    client._device_list_gateway = {DID: {
        'online': True, 'push_available': True, 'group_id': GROUP_ID}}
    client._device_list_lan = {}
    client._sub_source_list = {}
    client._sub_tree = MIoTMatcher()
    client._mips_local = {GROUP_ID: gateway}
    client._MIoTClient__request_show_devices_changed_notify = (
        lambda *args, **kwargs: None)

    fired: list[dict] = []
    client.sub_event(
        did=DID, handler=lambda params, ctx: fired.append(params),
        siid=2, eiid=1)
    client._MIoTClient__update_device_msg_sub(did=DID)
    assert client._sub_source_list[DID] == GROUP_ID

    gateway.press()
    assert len(fired) == 1

    # The cloud MIPS disconnects, the gateway connection stays up.
    await client._MIoTClient__on_mips_cloud_state_changed('key', False)
    assert gateway.sub_count == 1
    assert len(fired) == 1

    # A real press after the cloud disconnect still fires.
    gateway.press()
    assert len(fired) == 2

    # Both gateway update paths must restore an unchanged subscription.
    for filter_dids, sub_count in (([DID], 2), ([], 3)):
        await client._MIoTClient__update_devices_from_gw_async(
            gw_list={DID: {'online': True, 'push_available': True}},
            group_id=GROUP_ID, filter_dids=filter_dids)
        assert gateway.sub_count == sub_count

    # An unchanged cloud subscription must not be refreshed with the gateway.
    client._device_list_gateway[DID]['push_available'] = False
    client._device_list_cloud[DID]['online'] = True
    client._mips_cloud = gateway
    client._MIoTClient__update_device_msg_sub(did=DID)
    client._MIoTClient__update_device_msg_sub(did=DID, gw_refresh=True)
    assert gateway.sub_count == 4
