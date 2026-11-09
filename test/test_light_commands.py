"""Regression tests for configurable light command ordering and batch writes.

Run with Home Assistant and pytest-asyncio installed. The lightweight MIoT CI
environment does not install Home Assistant and skips this module.
"""
import asyncio
from pathlib import Path
import sys
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest

pytest.importorskip('homeassistant')
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

# pylint: disable=wrong-import-position, protected-access, redefined-outer-name
from homeassistant.core import State
from homeassistant.helpers.restore_state import RestoreEntity

from custom_components.xiaomi_home import light as light_module
from custom_components.xiaomi_home.light import Light
from custom_components.xiaomi_home.select import LightCommandSendMode
from custom_components.xiaomi_home.miot.const import DOMAIN
from custom_components.xiaomi_home.miot.miot_client import CtrlMode, MIoTClient
from custom_components.xiaomi_home.miot.miot_device import (
    MIoTDevice, MIoTEntityData)
from custom_components.xiaomi_home.miot.miot_error import MIoTClientError
from custom_components.xiaomi_home.miot.miot_mdns import MipsService
from custom_components.xiaomi_home.miot.miot_network import MIoTNetwork
from custom_components.xiaomi_home.miot.miot_spec import (
    MIoTSpecInstance, MIoTSpecProperty, MIoTSpecService)
from custom_components.xiaomi_home.miot.miot_storage import MIoTStorage

pytestmark = [pytest.mark.github, pytest.mark.asyncio]


@pytest.fixture
def make_light(monkeypatch):
    """Build real entities/specs with only HA state and transport mocked."""
    def build(mode='Send Together', old_brightness=200):
        transport = SimpleNamespace(
            main_loop=asyncio.get_running_loop(), area_name_rule='none',
            cloud_server='cn', set_props_async=AsyncMock(return_value=True),
            set_prop_async=AsyncMock(return_value=True),
            sub_device_state=Mock())
        instance = MIoTSpecInstance(
            urn='urn:miot-spec-v2:device:light:0000A001:test-light:1',
            name='light', description='Light', description_trans='Light')
        service = MIoTSpecService({
            'iid': 2, 'type': 'urn:miot-spec-v2:service:light:00007802',
            'name': 'light', 'description': 'Light',
            'description_trans': 'Light'})
        props = {}
        for iid, name, format_, value_range in (
            (1, 'on', 'bool', None),
            (2, 'brightness', 'uint8', [1, 255, 1]),
            (3, 'color-temperature', 'uint32', [2700, 6500, 1]),
            (4, 'color', 'uint32', None),
            (5, 'mode', 'uint8', [0, 3, 1]),
        ):
            props[name] = MIoTSpecProperty(
                spec={
                    'iid': iid, 'name': name, 'description': name,
                    'type': f'urn:miot-spec-v2:property:{name}:00000000'},
                service=service, format_=format_, access=['read', 'write'],
                value_range=value_range)
        service.properties = list(props.values())
        instance.services = [service]
        device = MIoTDevice(
            miot_client=transport,
            device_info={
                'did': '123456', 'name': 'Test light',
                'model': 'test.light.v1', 'online': True},
            spec_instance=instance)
        data = MIoTEntityData(platform='light', spec=service)
        data.props = set(props.values())
        states = Mock()
        # A user-renamed entity must still be found through its unique ID.
        mode_entity_id = 'select.bedroom_command_mode'
        states.get.return_value = State(mode_entity_id, mode)
        hass = SimpleNamespace(states=states)
        registry = Mock()
        registry.async_get_entity_id.return_value = mode_entity_id
        monkeypatch.setattr(
            light_module, 'async_get_entity_registry', lambda _: registry)
        light = Light(miot_device=device, entity_data=data, hass=hass)
        light.set_prop_value(props['brightness'], old_brightness)
        monkeypatch.setattr(light, 'async_write_ha_state', Mock())
        return light, transport, props, registry
    return build


@pytest.mark.parametrize('mode', [
    'Send One by One', 'Send Turn On First', 'Send Together'])
@pytest.mark.parametrize('brightness', [100, 240])
async def test_light_command_order(make_light, mode, brightness):
    """Dimming precedes color changes; brightening follows them in batches."""
    light, transport, props, _ = make_light(mode)
    await light.async_turn_on(
        brightness=brightness, color_temp_kelvin=4000, effect='mode 1')

    if mode == 'Send One by One':
        transport.set_props_async.assert_not_awaited()
        sent = [
            call.kwargs for call in transport.set_prop_async.await_args_list]
        expected_names = ['on', 'brightness', 'color-temperature', 'mode']
    else:
        transport.set_prop_async.assert_not_awaited()
        transport.set_props_async.assert_awaited_once()
        sent = transport.set_props_async.await_args.args[0]
        settings = (['brightness', 'color-temperature'] if brightness == 100
                    else ['color-temperature', 'brightness'])
        expected_names = ['mode', *settings]
        if mode == 'Send Together':
            expected_names.append('on')
        else:
            expected_names.insert(0, 'on')

    assert [item['piid'] for item in sent] == [
        props[name].iid for name in expected_names]
    assert all(item['did'] == '123456' and item['siid'] == 2 for item in sent)
    assert {item['piid']: item['value'] for item in sent} == {
        1: True, 2: brightness, 3: 4000, 5: 1}
    assert light.brightness == brightness
    assert light.is_on is True


async def test_renamed_mode_select_and_rgb(make_light):
    """Resolve the stored unique ID even after the mode entity is renamed."""
    light, transport, _, registry = make_light('Send Together')
    await light.async_turn_on(rgb_color=(12, 34, 56))
    registry.async_get_entity_id.assert_called_once_with(
        'select', DOMAIN,
        f'select.light_{light.miot_device.did_tag}_command_send_mode')
    light.hass.states.get.assert_called_once_with('select.bedroom_command_mode')
    sent = transport.set_props_async.await_args.args[0]
    assert [(item['piid'], item['value']) for item in sent] == [
        (4, 0x0C2238), (1, True)]
    assert light.rgb_color == (12, 34, 56)


@pytest.mark.parametrize(('saved', 'expected'), [
    ('Send Together', 'Send Together'),
    ('Send Turn On First', 'Send Turn On First'),
    ('unavailable', 'Send One by One'),
])
async def test_restore_mode_selection(monkeypatch, saved, expected):
    """Restore a valid selection and reject an unavailable stored state."""
    monkeypatch.setattr(RestoreEntity, 'async_added_to_hass', AsyncMock())
    select = LightCommandSendMode(hass=Mock(), device_id='cn_123456')
    monkeypatch.setattr(select, 'async_get_last_state', AsyncMock(
        return_value=State(select.entity_id, saved)))
    await select.async_added_to_hass()
    assert select.current_option == expected
    assert select.unique_id == 'select.light_cn_123456_command_send_mode'


@pytest.mark.parametrize(('value', 'expected'), [(6, 7), (10, 10)])
async def test_batch_values_use_spec_precision(make_light, value, expected):
    """Round using the nonzero range origin from the upstream precision fix."""
    light, transport, props, _ = make_light()
    props['brightness'].value_range = [1, 100, 3]
    await light.set_properties_async([
        {'prop': props['brightness'], 'value': value}])
    sent = transport.set_props_async.await_args.args[0]
    assert sent == [{'did': '123456', 'siid': 2, 'piid': 2, 'value': expected}]
    assert light.get_prop_value(props['brightness']) == expected


@pytest.fixture
def make_client():
    """Initialize the real router without making network connections."""
    def build(route, result):
        transport = Mock()
        transport.set_props_async = AsyncMock(return_value=result)
        client = MIoTClient(
            entry_id='test', entry_data={'uid': '123', 'cloud_server': 'cn'},
            network=Mock(spec=MIoTNetwork), storage=Mock(spec=MIoTStorage),
            mips_service=Mock(spec=MipsService), miot_lan=transport)
        client._device_list_cache = {'123456': {}}
        client._ctrl_mode = CtrlMode.AUTO
        client._device_list_cloud = {'123456': {'online': True}}
        client._http = transport
        client._i18n = Mock()
        client._i18n.translate.side_effect = lambda key: key
        if route == 'gateway':
            client._device_list_gateway = {'123456': {
                'online': True, 'specv2_access': True, 'group_id': 'group'}}
            client._mips_local = {'group': transport}
        elif route == 'lan':
            client._device_list_lan = {'123456': {'online': True}}
        return client, transport
    return build


@pytest.mark.parametrize('route', ['gateway', 'lan', 'cloud'])
async def test_batch_success_accepts_completed_and_pending(make_client, route):
    """Preserve both successful MIoT result codes on every transport."""
    client, transport = make_client(route, [{'code': 0}, {'code': 1}])
    props = [
        {'did': '123456', 'siid': 2, 'piid': 2, 'value': 100},
        {'did': '123456', 'siid': 2, 'piid': 1, 'value': True}]
    assert await client.set_props_async(props) is True
    transport.set_props_async.assert_awaited_once()


@pytest.mark.parametrize('route', ['gateway', 'lan'])
async def test_batch_transport_error_dict_is_reported(make_client, route):
    """A transport failure must be a MIoT error, never an AttributeError."""
    client, _ = make_client(
        route, {'code': -10000, 'message': 'Invalid result'})
    with pytest.raises(MIoTClientError):
        await client.set_props_async([
            {'did': '123456', 'siid': 2, 'piid': 1, 'value': True}])


@pytest.mark.parametrize(('route', 'result'), [
    ('gateway', None),
    ('gateway', {'code': 0}),
    ('lan', []),
    ('lan', [{'code': 0}]),
    ('cloud', [{'code': 0}, {}]),
    ('cloud', [{'code': 0}, 'invalid']),
])
async def test_incomplete_batch_result_is_not_success(
        make_client, route, result):
    """Missing, short and malformed replies cannot confirm all writes."""
    client, _ = make_client(route, result)
    with pytest.raises(MIoTClientError):
        await client.set_props_async([
            {'did': '123456', 'siid': 2, 'piid': 2, 'value': 100},
            {'did': '123456', 'siid': 2, 'piid': 1, 'value': True}])


@pytest.mark.parametrize('code', [-704010000, -704042011])
async def test_cloud_offline_schedules_refresh(make_client, monkeypatch, code):
    """Offline errors schedule device refresh and retain the MIoT error."""
    client, _ = make_client('cloud', [{'code': code}])
    refresh = AsyncMock(return_value=True)
    monkeypatch.setattr(
        client, '_MIoTClient__refresh_cloud_device_with_dids_async', refresh)
    with pytest.raises(MIoTClientError):
        await client.set_props_async([
            {'did': '123456', 'siid': 2, 'piid': 1, 'value': True}])
    await asyncio.sleep(0)
    refresh.assert_awaited_once_with(dids=['123456'])
