# -*- coding: utf-8 -*-
"""Climate fan mode regressions with synthetic Specs and mocked HA/MIoT I/O."""
import importlib.util
from pathlib import Path
import sys
from types import ModuleType, SimpleNamespace
from unittest.mock import AsyncMock
import pytest

# pylint: disable=import-outside-toplevel, protected-access

pytestmark = pytest.mark.github


class _ServiceEntity:
    """Mock the service entity boundary, retaining actual climate methods."""

    def __init__(self, miot_device, entity_data):
        self.miot_device = miot_device
        self.entity_data = entity_data
        self.entity_id = 'climate.test_fan'
        self._attr_supported_features = 0
        self.values = {}
        self.set_property_async = AsyncMock(return_value=True)

    def get_prop_value(self, prop):
        return self.values.get(prop)

    @staticmethod
    def get_map_key(map_, value):
        return next(
            (key for key, label in map_.items() if label == value), None)

    @staticmethod
    def get_map_value(map_, key):
        return map_.get(key)


@pytest.fixture(name='climate_module')
def climate_module_fixture(monkeypatch):
    """Import the real platform with boundary stubs for the lightweight CI."""
    from miot.miot_spec import MIoTSpecProperty

    package_name = '_xiaomi_climate_test'
    module_attrs = {
        'homeassistant': {},
        'homeassistant.config_entries': {'ConfigEntry': object},
        'homeassistant.core': {'HomeAssistant': object},
        'homeassistant.const': {'UnitOfTemperature': object},
        'homeassistant.helpers': {},
        'homeassistant.helpers.entity_platform': {
            'AddEntitiesCallback': object},
        'homeassistant.components': {},
        'homeassistant.components.climate': {
            'ClimateEntity': type('ClimateEntity', (), {}),
            'ClimateEntityFeature': SimpleNamespace(FAN_MODE=8),
            'FAN_ON': 'on', 'FAN_OFF': 'off',
            'SWING_OFF': 'off', 'SWING_BOTH': 'both',
            'SWING_VERTICAL': 'vertical', 'SWING_HORIZONTAL': 'horizontal',
            'ATTR_TEMPERATURE': 'temperature',
            'HVACMode': object, 'HVACAction': object},
        package_name: {'__path__': []},
        f'{package_name}.miot': {'__path__': []},
        f'{package_name}.miot.const': {'DOMAIN': 'xiaomi_home'},
        f'{package_name}.miot.miot_device': {
            'MIoTDevice': object, 'MIoTServiceEntity': _ServiceEntity,
            'MIoTEntityData': object},
        f'{package_name}.miot.miot_spec': {
            'MIoTSpecProperty': MIoTSpecProperty}}
    for name, attributes in module_attrs.items():
        module = ModuleType(name)
        module.__dict__.update(attributes)
        monkeypatch.setitem(sys.modules, name, module)
    source = (Path(__file__).resolve().parents[1] / 'custom_components' /
              'xiaomi_home' / 'climate.py')
    spec = importlib.util.spec_from_file_location(
        f'{package_name}.climate', source)
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, spec.name, module)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(name='make_fan_property')
def make_fan_property_fixture():
    """Build actual Spec properties without a cloud connection."""
    from miot.miot_spec import MIoTSpecProperty

    def make(service='fan-control', name='fan-level', value_range=None,
             value_list=None, precision=0):
        return MIoTSpecProperty(
            spec={'iid': 2, 'name': name, 'description': 'Fan Level',
                  'type': 'urn:miot-spec-v2:property:fan-level:00000016'},
            service=SimpleNamespace(iid=5, name=service),
            format_='float' if precision else 'uint8',
            access=['read', 'write', 'notify'], value_range=value_range,
            value_list=value_list, precision=precision)
    return make


@pytest.mark.parametrize('service', ['fan-control', 'thermostat'])
@pytest.mark.parametrize('value_range,precision,values,labels', [
    ([1, 5, 1], 0, [1, 2, 3, 4, 5], ['1', '2', '3', '4', '5']),
    ([0.1, 0.3, 0.1], 1, [0.1, 0.2, 0.3], ['0.1', '0.2', '0.3']),
    ([1, 6, 2], 0, [1, 3, 5], ['1', '3', '5']),
    ([2, 2, 1], 0, [2], ['2'])])
@pytest.mark.asyncio
async def test_numeric_fan_modes(climate_module, make_fan_property, service,
                                 value_range, precision, values, labels):
    prop = make_fan_property(service=service, value_range=value_range,
                             precision=precision)
    fan = climate_module.FeatureFanMode(None, SimpleNamespace(props=[prop]))
    assert fan._attr_supported_features & 8
    assert fan._attr_fan_modes == labels
    for value, label in zip(values, labels):
        fan.values[prop] = value
        assert fan.fan_mode == label
        await fan.async_set_fan_mode(label)
        fan.set_property_async.assert_awaited_with(prop=prop, value=value)


@pytest.mark.parametrize('service', ['fan-control', 'thermostat'])
@pytest.mark.asyncio
async def test_enumerated_fan_modes(climate_module, make_fan_property, service):
    prop = make_fan_property(
        service=service, value_range=[1, 5, 1], value_list=[
            {'value': 2, 'description': 'Low'},
            {'value': 7, 'description': 'High'}])
    fan = climate_module.FeatureFanMode(None, SimpleNamespace(props=[prop]))
    assert fan._attr_fan_modes == ['Low', 'High']
    fan.values[prop] = 7
    assert fan.fan_mode == 'High'
    await fan.async_set_fan_mode('High')
    fan.set_property_async.assert_awaited_once_with(prop=prop, value=7)


@pytest.mark.parametrize(
    'value_range', [None, [1, 5, 0], [1, 5, -1], [5, 1, 1]])
def test_invalid_fan_ranges(climate_module, make_fan_property, value_range):
    prop = make_fan_property(value_range=value_range)
    fan = climate_module.FeatureFanMode(None, SimpleNamespace(props=[prop]))
    assert not fan._attr_supported_features & 8
    assert fan._attr_fan_modes is None
    assert fan.fan_mode is None


@pytest.mark.asyncio
async def test_numeric_fan_off(climate_module, make_fan_property):
    level = make_fan_property(value_range=[1, 5, 1])
    power = make_fan_property(name='on')
    fan = climate_module.FeatureFanMode(
        None, SimpleNamespace(props=[level, power]))
    assert fan._attr_fan_modes == ['1', '2', '3', '4', '5', 'off']
    await fan.async_set_fan_mode('off')
    fan.set_property_async.assert_awaited_once_with(prop=power, value=False)


@pytest.mark.asyncio
async def test_invalid_numeric_fan_mode(climate_module, make_fan_property):
    prop = make_fan_property(value_range=[1, 5, 1])
    fan = climate_module.FeatureFanMode(None, SimpleNamespace(props=[prop]))
    with pytest.raises(RuntimeError, match='set climate prop.fan_mode failed'):
        await fan.async_set_fan_mode('6')
    fan.set_property_async.assert_not_awaited()
