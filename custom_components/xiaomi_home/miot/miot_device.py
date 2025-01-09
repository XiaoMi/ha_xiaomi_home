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

MIoT device instance.
"""
import asyncio
from abc import abstractmethod
from typing import Any, Callable, Optional
import logging

from homeassistant.helpers.entity import Entity
from homeassistant.const import (
    CONCENTRATION_MICROGRAMS_PER_CUBIC_METER,
    CONCENTRATION_MILLIGRAMS_PER_CUBIC_METER,
    CONCENTRATION_PARTS_PER_BILLION,
    CONCENTRATION_PARTS_PER_MILLION,
    LIGHT_LUX,
    PERCENTAGE,
    SIGNAL_STRENGTH_DECIBELS,
    UnitOfEnergy,
    UnitOfElectricCurrent,
    UnitOfElectricPotential,
    UnitOfInformation,
    UnitOfLength,
    UnitOfMass,
    UnitOfSpeed,
    UnitOfTime,
    UnitOfTemperature,
    UnitOfPressure,
    UnitOfPower,
    UnitOfVolume,
    UnitOfVolumeFlowRate,
)
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.components.switch import SwitchDeviceClass
from homeassistant.util import slugify

# pylint: disable=relative-beyond-top-level
from .specs.specv2entity import (
    SPEC_ACTION_TRANS_MAP,
    SPEC_DEVICE_TRANS_MAP,
    SPEC_EVENT_TRANS_MAP,
    SPEC_PROP_TRANS_MAP,
    SPEC_SERVICE_TRANS_MAP
)
from .const import DOMAIN
from .miot_client import MIoTClient
from .miot_error import MIoTClientError, MIoTDeviceError
from .miot_mips import MIoTDeviceState
from .miot_spec import (
    MIoTSpecAction,
    MIoTSpecEvent,
    MIoTSpecInstance,
    MIoTSpecProperty,
    MIoTSpecService
)

_LOGGER = logging.getLogger(__name__)


class MIoTEntityData:
    """MIoT Entity Data."""
    platform: str
    device_class: Any
    spec: MIoTSpecInstance | MIoTSpecService

    props: set[MIoTSpecProperty]
    events: set[MIoTSpecEvent]
    actions: set[MIoTSpecAction]

    def __init__(
        self, platform: str, spec: MIoTSpecInstance | MIoTSpecService
    ) -> None:
        self.platform = platform
        self.spec = spec
        self.device_class = None
        self.props = set()
        self.events = set()
        self.actions = set()


class MIoTDevice:
    """MIoT Device Instance."""
    # pylint: disable=unused-argument
    miot_client: MIoTClient
    spec_instance: MIoTSpecInstance

    _online: bool

    _did: str
    _name: str
    _model: str
    _model_strs: list[str]
    _manufacturer: str
    _fw_version: str

    _icon: str
    _home_id: str
    _home_name: str
    _room_id: str
    _room_name: str

    _suggested_area: str

    _device_state_sub_list: dict[str, Callable[[str, MIoTDeviceState], None]]

    _entity_list: dict[str, list[MIoTEntityData]]
    _prop_list: dict[str, list[MIoTSpecProperty]]
    _event_list: dict[str, list[MIoTSpecEvent]]
    _action_list: dict[str, list[MIoTSpecAction]]

    def __init__(
        self, miot_client: MIoTClient,
        device_info: dict[str, str],
        spec_instance: MIoTSpecInstance
    ) -> None:
        self.miot_client = miot_client
        self.spec_instance = spec_instance

        self._online = device_info.get('online', False)
        self._did = device_info['did']
        self._name = device_info['name']
        self._model = device_info['model']
        self._model_strs = self._model.split('.')
        self._manufacturer = device_info.get('manufacturer', None)
        self._fw_version = device_info.get('fw_version', None)

        self._icon = device_info.get('icon', None)
        self._home_id = device_info.get('home_id', None)
        self._home_name = device_info.get('home_name', None)
        self._room_id = device_info.get('room_id', None)
        self._room_name = device_info.get('room_name', None)
        match self.miot_client.area_name_rule:
            case 'home_room':
                self._suggested_area = (
                    f'{self._home_name} {self._room_name}'.strip())
            case 'home':
                self._suggested_area = self._home_name.strip()
            case 'room':
                self._suggested_area = self._room_name.strip()
            case _:
                self._suggested_area = None

        self._device_state_sub_list = {}
        self._entity_list = {}
        self._prop_list = {}
        self._event_list = {}
        self._action_list = {}

        # Sub devices name
        sub_devices: dict[str, dict] = device_info.get('sub_devices', None)
        if isinstance(sub_devices, dict) and sub_devices:
            for service in spec_instance.services:
                sub_info = sub_devices.get(f's{service.iid}', None)
                if sub_info is None:
                    continue
                _LOGGER.debug(
                    'miot device, update service sub info, %s, %s',
                    self.did, sub_info)
                service.description_trans = sub_info.get(
                    'name', service.description_trans)

        # Sub device state
        self.miot_client.sub_device_state(
            self._did, self.__on_device_state_changed)

        _LOGGER.debug('miot device init %s', device_info)

    @property
    def online(self) -> bool:
        return self._online

    @property
    def entity_list(self) -> dict[str, list[MIoTEntityData]]:
        return self._entity_list

    @property
    def prop_list(self) -> dict[str, list[MIoTSpecProperty]]:
        return self._prop_list

    @property
    def event_list(self) -> dict[str, list[MIoTSpecEvent]]:
        return self._event_list

    @property
    def action_list(self) -> dict[str, list[MIoTSpecAction]]:
        return self._action_list

    async def action_async(self, siid: int, aiid: int, in_list: list) -> list:
        return await self.miot_client.action_async(
            did=self._did, siid=siid, aiid=aiid, in_list=in_list)

    def sub_device_state(
        self, key: str, handler: Callable[[str, MIoTDeviceState], None]
    ) -> bool:
        self._device_state_sub_list[key] = handler
        return True

    def unsub_device_state(self, key: str) -> bool:
        self._device_state_sub_list.pop(key, None)
        return True

    def sub_property(
        self, handler: Callable[[dict, Any], None], siid: int = None,
        piid: int = None, handler_ctx: Any = None
    ) -> bool:
        return self.miot_client.sub_prop(
            did=self._did, handler=handler, siid=siid, piid=piid,
            handler_ctx=handler_ctx)

    def unsub_property(self, siid: int = None, piid: int = None) -> bool:
        return self.miot_client.unsub_prop(did=self._did, siid=siid, piid=piid)

    def sub_event(
        self, handler: Callable[[dict, Any], None], siid: int = None,
        eiid: int = None, handler_ctx: Any = None
    ) -> bool:
        return self.miot_client.sub_event(
            did=self._did, handler=handler, siid=siid, eiid=eiid,
            handler_ctx=handler_ctx)

    def unsub_event(self, siid: int = None, eiid: int = None) -> bool:
        return self.miot_client.unsub_event(
            did=self._did, siid=siid, eiid=eiid)

    @property
    def device_info(self) -> DeviceInfo:
        """information about this entity/device."""
        return DeviceInfo(
            identifiers={(DOMAIN, self.did_tag)},
            name=self._name,
            sw_version=self._fw_version,
            model=self._model,
            manufacturer=self._manufacturer,
            suggested_area=self._suggested_area,
            configuration_url=(
                f'https://home.mi.com/webapp/content/baike/product/index.html?'
                f'model={self._model}')
        )

    @property
    def did(self) -> str:
        """Device Id."""
        return self._did

    @property
    def did_tag(self) -> str:
        return slugify(f'{self.miot_client.cloud_server}_{self._did}')

    @staticmethod
    def gen_did_tag(cloud_server: str, did: str) -> str:
        return slugify(f'{cloud_server}_{did}')

    def gen_device_entity_id(self, ha_domain: str) -> str:
        return (
            f'{ha_domain}.{self._model_strs[0][:9]}_{self.did_tag}_'
            f'{self._model_strs[-1][:20]}')

    def gen_service_entity_id(self, ha_domain: str, siid: int) -> str:
        return (
            f'{ha_domain}.{self._model_strs[0][:9]}_{self.did_tag}_'
            f'{self._model_strs[-1][:20]}_s_{siid}')

    def gen_prop_entity_id(
        self, ha_domain: str, spec_name: str, siid: int, piid: int
    ) -> str:
        return (
            f'{ha_domain}.{self._model_strs[0][:9]}_{self.did_tag}_'
            f'{self._model_strs[-1][:20]}_{slugify(spec_name)}_p_{siid}_{piid}')

    def gen_event_entity_id(
        self, ha_domain: str, spec_name: str, siid: int, eiid: int
    ) -> str:
        return (
            f'{ha_domain}.{self._model_strs[0][:9]}_{self.did_tag}_'
            f'{self._model_strs[-1][:20]}_{slugify(spec_name)}_e_{siid}_{eiid}')

    def gen_action_entity_id(
        self, ha_domain: str, spec_name: str, siid: int, aiid: int
    ) -> str:
        return (
            f'{ha_domain}.{self._model_strs[0][:9]}_{self.did_tag}_'
            f'{self._model_strs[-1][:20]}_{slugify(spec_name)}_a_{siid}_{aiid}')

    @property
    def name(self) -> str:
        return self._name

    @property
    def model(self) -> str:
        return self._model

    @property
    def icon(self) -> str:
        return self._icon

    def append_entity(self, entity_data: MIoTEntityData) -> None:
        self._entity_list.setdefault(entity_data.platform, [])
        self._entity_list[entity_data.platform].append(entity_data)

    def append_prop(self, prop: MIoTSpecProperty) -> None:
        self._prop_list.setdefault(prop.platform, [])
        self._prop_list[prop.platform].append(prop)

    def append_event(self, event: MIoTSpecEvent) -> None:
        self._event_list.setdefault(event.platform, [])
        self._event_list[event.platform].append(event)

    def append_action(self, action: MIoTSpecAction) -> None:
        self._action_list.setdefault(action.platform, [])
        self._action_list[action.platform].append(action)

    def parse_miot_device_entity(
        self, spec_instance: MIoTSpecInstance
    ) -> Optional[MIoTEntityData]:
        if spec_instance.name not in SPEC_DEVICE_TRANS_MAP:
            return None
        spec_name: str = spec_instance.name
        if isinstance(SPEC_DEVICE_TRANS_MAP[spec_name], str):
            spec_name = SPEC_DEVICE_TRANS_MAP[spec_name]
        # 1. The device shall have all required services.
        required_services = SPEC_DEVICE_TRANS_MAP[spec_name]['required'].keys()
        if not {
                service.name for service in spec_instance.services
        }.issuperset(required_services):
            return None
        optional_services = SPEC_DEVICE_TRANS_MAP[spec_name]['optional'].keys()

        platform = SPEC_DEVICE_TRANS_MAP[spec_name]['entity']
        entity_data = MIoTEntityData(platform=platform, spec=spec_instance)
        for service in spec_instance.services:
            if service.platform:
                continue
            # 2. The service shall have all required properties, actions.
            if service.name in required_services:
                required_properties: dict = SPEC_DEVICE_TRANS_MAP[spec_name][
                    'required'].get(
                        service.name, {}
                ).get('required', {}).get('properties', {})
                optional_properties = SPEC_DEVICE_TRANS_MAP[spec_name][
                    'required'].get(
                        service.name, {}
                ).get('optional', {}).get('properties', set({}))
                required_actions = SPEC_DEVICE_TRANS_MAP[spec_name][
                    'required'].get(
                        service.name, {}
                ).get('required', {}).get('actions', set({}))
                optional_actions = SPEC_DEVICE_TRANS_MAP[spec_name][
                    'required'].get(
                        service.name, {}
                ).get('optional', {}).get('actions', set({}))
            elif service.name in optional_services:
                required_properties: dict = SPEC_DEVICE_TRANS_MAP[spec_name][
                    'optional'].get(
                        service.name, {}
                ).get('required', {}).get('properties', {})
                optional_properties = SPEC_DEVICE_TRANS_MAP[spec_name][
                    'optional'].get(
                        service.name, {}
                ).get('optional', {}).get('properties', set({}))
                required_actions = SPEC_DEVICE_TRANS_MAP[spec_name][
                    'optional'].get(
                        service.name, {}
                ).get('required', {}).get('actions', set({}))
                optional_actions = SPEC_DEVICE_TRANS_MAP[spec_name][
                    'optional'].get(
                    service.name, {}
                ).get('optional', {}).get('actions', set({}))
            else:
                continue
            if not {
                prop.name for prop in service.properties if prop.access
            }.issuperset(set(required_properties.keys())):
                return None
            if not {
                action.name for action in service.actions
            }.issuperset(required_actions):
                return None
            # 3. The required property shall have all required access mode.
            for prop in service.properties:
                if prop.name in required_properties:
                    if not set(prop.access).issuperset(
                            required_properties[prop.name]):
                        return None
            # property
            for prop in service.properties:
                if prop.name in set.union(
                        set(required_properties.keys()), optional_properties):
                    if prop.unit:
                        prop.external_unit = self.unit_convert(prop.unit)
                        prop.icon = self.icon_convert(prop.unit)
                    prop.platform = platform
                    entity_data.props.add(prop)
            # action
            for action in service.actions:
                if action.name in set.union(
                        required_actions, optional_actions):
                    action.platform = platform
                    entity_data.actions.add(action)
            # event
            # No events is in SPEC_DEVICE_TRANS_MAP now.
            service.platform = platform
        return entity_data

    def parse_miot_service_entity(
        self, service_instance: MIoTSpecService
    ) -> Optional[MIoTEntityData]:
        service = service_instance
        if service.platform or (service.name not in SPEC_SERVICE_TRANS_MAP):
            return None

        service_name = service.name
        if isinstance(SPEC_SERVICE_TRANS_MAP[service_name], str):
            service_name = SPEC_SERVICE_TRANS_MAP[service_name]
        # 1. The service shall have all required properties.
        required_properties: dict = SPEC_SERVICE_TRANS_MAP[service_name][
            'required'].get('properties', {})
        if not {
            prop.name for prop in service.properties if prop.access
        }.issuperset(set(required_properties.keys())):
            return None
        # 2. The required property shall have all required access mode.
        for prop in service.properties:
            if prop.name in required_properties:
                if not set(prop.access).issuperset(
                        required_properties[prop.name]):
                    return None
        platform = SPEC_SERVICE_TRANS_MAP[service_name]['entity']
        entity_data = MIoTEntityData(platform=platform, spec=service_instance)
        optional_properties = SPEC_SERVICE_TRANS_MAP[service_name][
            'optional'].get('properties', set({}))
        for prop in service.properties:
            if prop.name in set.union(
                    set(required_properties.keys()), optional_properties):
                if prop.unit:
                    prop.external_unit = self.unit_convert(prop.unit)
                    prop.icon = self.icon_convert(prop.unit)
                prop.platform = platform
                entity_data.props.add(prop)
        # action
        # event
        # No actions or events is in SPEC_SERVICE_TRANS_MAP now.
        service.platform = platform
        return entity_data

    def parse_miot_property_entity(
        self, property_instance: MIoTSpecProperty
    ) -> Optional[dict[str, str]]:
        prop = property_instance
        if (
            prop.platform
            or (prop.name not in SPEC_PROP_TRANS_MAP['properties'])
        ):
            return None

        prop_name = prop.name
        if isinstance(SPEC_PROP_TRANS_MAP['properties'][prop_name], str):
            prop_name = SPEC_PROP_TRANS_MAP['properties'][prop_name]
        platform = SPEC_PROP_TRANS_MAP['properties'][prop_name]['entity']
        prop_access: set = set({})
        if prop.readable:
            prop_access.add('read')
        if prop.writable:
            prop_access.add('write')
        if prop_access != (SPEC_PROP_TRANS_MAP[
                'entities'][platform]['access']):
            return None
        if prop.format_ not in SPEC_PROP_TRANS_MAP[
                'entities'][platform]['format']:
            return None
        if prop.unit:
            prop.external_unit = self.unit_convert(prop.unit)
            prop.icon = self.icon_convert(prop.unit)
        device_class = SPEC_PROP_TRANS_MAP['properties'][prop_name][
            'device_class']
        result = {'platform': platform, 'device_class': device_class}
        # optional:
        if 'optional' in SPEC_PROP_TRANS_MAP['properties'][prop_name]:
            optional = SPEC_PROP_TRANS_MAP['properties'][prop_name]['optional']
            if 'state_class' in optional:
                result['state_class'] = optional['state_class']
            if not prop.unit and 'unit_of_measurement' in optional:
                result['unit_of_measurement'] = optional['unit_of_measurement']
        return result

    def spec_transform(self) -> None:
        """Parse service, property, event, action from device spec."""
        # STEP 1: device conversion
        device_entity = self.parse_miot_device_entity(
            spec_instance=self.spec_instance)
        if device_entity:
            self.append_entity(entity_data=device_entity)
        # STEP 2: service conversion
        for service in self.spec_instance.services:
            service_entity = self.parse_miot_service_entity(
                service_instance=service)
            if service_entity:
                self.append_entity(entity_data=service_entity)
            # STEP 3.1: property conversion
            for prop in service.properties:
                if prop.platform or not prop.access:
                    continue
                if prop.unit:
                    prop.external_unit = self.unit_convert(prop.unit)
                    prop.icon = self.icon_convert(prop.unit)
                prop_entity = self.parse_miot_property_entity(
                    property_instance=prop)
                if prop_entity:
                    prop.platform = prop_entity['platform']
                    prop.device_class = prop_entity['device_class']
                    if 'state_class' in prop_entity:
                        prop.state_class = prop_entity['state_class']
                    if 'unit_of_measurement' in prop_entity:
                        prop.external_unit = self.unit_convert(
                            prop_entity['unit_of_measurement'])
                        prop.icon = self.icon_convert(
                            prop_entity['unit_of_measurement'])
                # general conversion
                if not prop.platform:
                    if prop.writable:
                        if prop.format_ == 'str':
                            prop.platform = 'text'
                        elif prop.format_ == 'bool':
                            prop.platform = 'switch'
                            prop.device_class = SwitchDeviceClass.SWITCH
                        elif prop.value_list:
                            prop.platform = 'select'
                        elif prop.value_range:
                            prop.platform = 'number'
                        else:
                            # Irregular property will not be transformed.
                            pass
                    elif prop.readable or prop.notifiable:
                        prop.platform = 'sensor'
                if prop.platform:
                    self.append_prop(prop=prop)
            # STEP 3.2: event conversion
            for event in service.events:
                if event.platform:
                    continue
                event.platform = 'event'
                if event.name in SPEC_EVENT_TRANS_MAP:
                    event.device_class = SPEC_EVENT_TRANS_MAP[event.name]
                self.append_event(event=event)
            # STEP 3.3: action conversion
            for action in service.actions:
                if action.platform:
                    continue
                if action.name in SPEC_ACTION_TRANS_MAP:
                    continue
                if action.in_:
                    action.platform = 'notify'
                else:
                    action.platform = 'button'
                self.append_action(action=action)

    def unit_convert(self, spec_unit: str) -> Optional[str]:
        """Convert MIoT unit to Home Assistant unit."""
        unit_map = {
            'percentage': PERCENTAGE,
            'weeks': UnitOfTime.WEEKS,
            'days': UnitOfTime.DAYS,
            'hours': UnitOfTime.HOURS,
            'minutes': UnitOfTime.MINUTES,
            'seconds': UnitOfTime.SECONDS,
            'ms': UnitOfTime.MILLISECONDS,
            'μs': UnitOfTime.MICROSECONDS,
            'celsius': UnitOfTemperature.CELSIUS,
            'fahrenheit': UnitOfTemperature.FAHRENHEIT,
            'kelvin': UnitOfTemperature.KELVIN,
            'μg/m3': CONCENTRATION_MICROGRAMS_PER_CUBIC_METER,
            'mg/m3': CONCENTRATION_MILLIGRAMS_PER_CUBIC_METER,
            'ppm': CONCENTRATION_PARTS_PER_MILLION,
            'ppb': CONCENTRATION_PARTS_PER_BILLION,
            'lux': LIGHT_LUX,
            'pascal': UnitOfPressure.PA,
            'bar': UnitOfPressure.BAR,
            'watt': UnitOfPower.WATT,
            'L': UnitOfVolume.LITERS,
            'mL': UnitOfVolume.MILLILITERS,
            'km/h': UnitOfSpeed.KILOMETERS_PER_HOUR,
            'm/s': UnitOfSpeed.METERS_PER_SECOND,
            'kWh': UnitOfEnergy.KILO_WATT_HOUR,
            'A': UnitOfElectricCurrent.AMPERE,
            'mA': UnitOfElectricCurrent.MILLIAMPERE,
            'V': UnitOfElectricPotential.VOLT,
            'mV': UnitOfElectricPotential.MILLIVOLT,
            'm': UnitOfLength.METERS,
            'km': UnitOfLength.KILOMETERS,
            'm3/h': UnitOfVolumeFlowRate.CUBIC_METERS_PER_HOUR,
            'gram': UnitOfMass.GRAMS,
            'dB': SIGNAL_STRENGTH_DECIBELS,
            'kB': UnitOfInformation.KILOBYTES,
        }

        # Handle UnitOfConductivity separately since
        # it might not be available in all HA versions
        try:
            # pylint: disable=import-outside-toplevel
            from homeassistant.const import UnitOfConductivity
            unit_map['μS/cm'] = UnitOfConductivity.MICROSIEMENS_PER_CM
        except Exception:  # pylint: disable=broad-except
            unit_map['μS/cm'] = 'μS/cm'

        return unit_map.get(spec_unit, None)

    def icon_convert(self, spec_unit: str) -> Optional[str]:
        if spec_unit in ['percentage']:
            return 'mdi:percent'
        if spec_unit in [
                'weeks', 'days', 'hours', 'minutes', 'seconds', 'ms', 'μs']:
            return 'mdi:clock'
        if spec_unit in ['celsius']:
            return 'mdi:temperature-celsius'
        if spec_unit in ['fahrenheit']:
            return 'mdi:temperature-fahrenheit'
        if spec_unit in ['kelvin']:
            return 'mdi:temperature-kelvin'
        if spec_unit in ['μg/m3', 'mg/m3', 'ppm', 'ppb']:
            return 'mdi:blur'
        if spec_unit in ['lux']:
            return 'mdi:brightness-6'
        if spec_unit in ['pascal', 'megapascal', 'bar']:
            return 'mdi:gauge'
        if spec_unit in ['watt']:
            return 'mdi:flash-triangle'
        if spec_unit in ['L', 'mL']:
            return 'mdi:gas-cylinder'
        if spec_unit in ['km/h', 'm/s']:
            return 'mdi:speedometer'
        if spec_unit in ['kWh']:
            return 'mdi:transmission-tower'
        if spec_unit in ['A', 'mA']:
            return 'mdi:current-ac'
        if spec_unit in ['V', 'mV']:
            return 'mdi:current-dc'
        if spec_unit in ['m', 'km']:
            return 'mdi:ruler'
        if spec_unit in ['rgb']:
            return 'mdi:palette'
        if spec_unit in ['m3/h', 'L/s']:
            return 'mdi:pipe-leak'
        if spec_unit in ['μS/cm']:
            return 'mdi:resistor-nodes'
        if spec_unit in ['gram']:
            return 'mdi:weight'
        if spec_unit in ['dB']:
            return 'mdi:signal-distance-variant'
        if spec_unit in ['times']:
            return 'mdi:counter'
        if spec_unit in ['mmol/L']:
            return 'mdi:dots-hexagon'
        if spec_unit in ['arcdegress']:
            return 'mdi:angle-obtuse'
        if spec_unit in ['kB']:
            return 'mdi:network-pos'
        if spec_unit in ['calorie', 'kCal']:
            return 'mdi:food'
        return None

    def __on_device_state_changed(
        self, did: str, state: MIoTDeviceState, ctx: Any
    ) -> None:
        self._online = state
        for key, handler in self._device_state_sub_list.items():
            self.miot_client.main_loop.call_soon_threadsafe(
                handler, key, state)


class MIoTServiceEntity(Entity):
    """MIoT Service Entity."""
    # pylint: disable=unused-argument
    # pylint: disable=inconsistent-quotes
    miot_device: MIoTDevice
    entity_data: MIoTEntityData

    _main_loop: asyncio.AbstractEventLoop
    _prop_value_map: dict[MIoTSpecProperty, Any]

    _event_occurred_handler: Callable[[MIoTSpecEvent, dict], None]
    _prop_changed_subs: dict[
        MIoTSpecProperty, Callable[[MIoTSpecProperty, Any], None]]

    _pending_write_ha_state_timer: Optional[asyncio.TimerHandle]

    def __init__(
        self, miot_device: MIoTDevice, entity_data: MIoTEntityData
    ) -> None:
        if (
            miot_device is None
            or entity_data is None
            or entity_data.spec is None
        ):
            raise MIoTDeviceError('init error, invalid params')
        self.miot_device = miot_device
        self.entity_data = entity_data
        self._main_loop = miot_device.miot_client.main_loop
        self._prop_value_map = {}
        # Gen entity id
        if isinstance(entity_data.spec, MIoTSpecInstance):
            self.entity_id = miot_device.gen_device_entity_id(DOMAIN)
            self._attr_name = f' {self.entity_data.spec.description_trans}'
        elif isinstance(entity_data.spec, MIoTSpecService):
            self.entity_id = miot_device.gen_service_entity_id(
                DOMAIN, siid=entity_data.spec.iid)
            self._attr_name = (
                f'{"* "if self.entity_data.spec.proprietary else " "}'
                f'{self.entity_data.spec.description_trans}')
        # Set entity attr
        self._attr_unique_id = self.entity_id
        self._attr_should_poll = False
        self._attr_has_entity_name = True
        self._attr_available = miot_device.online

        self._event_occurred_handler = None
        self._prop_changed_subs = {}
        self._pending_write_ha_state_timer = None
        _LOGGER.info(
            'new miot service entity, %s, %s, %s, %s',
            self.miot_device.name, self._attr_name, self.entity_data.spec.name,
            self.entity_id)

    @property
    def event_occurred_handler(self) -> Callable[[MIoTSpecEvent, dict], None]:
        return self._event_occurred_handler

    @event_occurred_handler.setter
    def event_occurred_handler(self, func) -> None:
        self._event_occurred_handler = func

    def sub_prop_changed(
        self, prop: MIoTSpecProperty,
        handler: Callable[[MIoTSpecProperty, Any], None]
    ) -> None:
        if not prop or not handler:
            _LOGGER.error(
                'sub_prop_changed error, invalid prop/handler')
            return
        self._prop_changed_subs[prop] = handler

    def unsub_prop_changed(self, prop: MIoTSpecProperty) -> None:
        self._prop_changed_subs.pop(prop, None)

    @property
    def device_info(self) -> dict:
        return self.miot_device.device_info

    async def async_added_to_hass(self) -> None:
        state_id = 's.0'
        if isinstance(self.entity_data.spec, MIoTSpecService):
            state_id = f's.{self.entity_data.spec.iid}'
        self.miot_device.sub_device_state(
            key=state_id, handler=self.__on_device_state_changed)
        # Sub prop
        for prop in self.entity_data.props:
            if not prop.notifiable and not prop.readable:
                continue
            self.miot_device.sub_property(
                handler=self.__on_properties_changed,
                siid=prop.service.iid, piid=prop.iid)
        # Sub event
        for event in self.entity_data.events:
            self.miot_device.sub_event(
                handler=self.__on_event_occurred,
                siid=event.service.iid, eiid=event.iid)

        # Refresh value
        if self._attr_available:
            self.__refresh_props_value()

    async def async_will_remove_from_hass(self) -> None:
        if self._pending_write_ha_state_timer:
            self._pending_write_ha_state_timer.cancel()
            self._pending_write_ha_state_timer = None
        state_id = 's.0'
        if isinstance(self.entity_data.spec, MIoTSpecService):
            state_id = f's.{self.entity_data.spec.iid}'
        self.miot_device.unsub_device_state(key=state_id)
        # Unsub prop
        for prop in self.entity_data.props:
            if not prop.notifiable and not prop.readable:
                continue
            self.miot_device.unsub_property(
                siid=prop.service.iid, piid=prop.iid)
        # Unsub event
        for event in self.entity_data.events:
            self.miot_device.unsub_event(
                siid=event.service.iid, eiid=event.iid)

    def get_map_description(self, map_: dict[int, Any], key: int) -> Any:
        if map_ is None:
            return None
        return map_.get(key, None)

    def get_map_value(
        self, map_: dict[int, Any], description: Any
    ) -> Optional[int]:
        if map_ is None:
            return None
        for key, value in map_.items():
            if value == description:
                return key
        return None

    def get_prop_value(self, prop: MIoTSpecProperty) -> Any:
        if not prop:
            _LOGGER.error(
                'get_prop_value error, property is None, %s, %s',
                self._attr_name, self.entity_id)
            return None
        return self._prop_value_map.get(prop, None)

    def set_prop_value(self, prop: MIoTSpecProperty, value: Any) -> None:
        if not prop:
            _LOGGER.error(
                'set_prop_value error, property is None, %s, %s',
                self._attr_name, self.entity_id)
            return
        self._prop_value_map[prop] = value

    async def set_property_async(
        self, prop: MIoTSpecProperty, value: Any, update: bool = True
    ) -> bool:
        value = prop.value_format(value)
        if not prop:
            raise RuntimeError(
                f'set property failed, property is None, '
                f'{self.entity_id}, {self.name}')
        if prop not in self.entity_data.props:
            raise RuntimeError(
                f'set property failed, unknown property, '
                f'{self.entity_id}, {self.name}, {prop.name}')
        if not prop.writable:
            raise RuntimeError(
                f'set property failed, not writable, '
                f'{self.entity_id}, {self.name}, {prop.name}')
        try:
            await self.miot_device.miot_client.set_prop_async(
                did=self.miot_device.did, siid=prop.service.iid,
                piid=prop.iid, value=value)
        except MIoTClientError as e:
            raise RuntimeError(
                f'{e}, {self.entity_id}, {self.name}, {prop.name}') from e
        if update:
            self._prop_value_map[prop] = value
            self.async_write_ha_state()
        return True

    async def get_property_async(self, prop: MIoTSpecProperty) -> Any:
        if not prop:
            _LOGGER.error(
                'get property failed, property is None, %s, %s',
                self.entity_id, self.name)
            return None
        if prop not in self.entity_data.props:
            _LOGGER.error(
                'get property failed, unknown property, %s, %s, %s',
                self.entity_id, self.name, prop.name)
            return None
        if not prop.readable:
            _LOGGER.error(
                'get property failed, not readable, %s, %s, %s',
                self.entity_id, self.name, prop.name)
            return None
        result = prop.value_format(
            await self.miot_device.miot_client.get_prop_async(
                did=self.miot_device.did, siid=prop.service.iid, piid=prop.iid))
        if result != self._prop_value_map[prop]:
            self._prop_value_map[prop] = result
            self.async_write_ha_state()
        return result

    async def action_async(
        self, action: MIoTSpecAction, in_list: Optional[list] = None
    ) -> bool:
        if not action:
            raise RuntimeError(
                f'action failed, action is None, {self.entity_id}, {self.name}')
        try:
            await self.miot_device.miot_client.action_async(
                did=self.miot_device.did, siid=action.service.iid,
                aiid=action.iid, in_list=in_list or [])
        except MIoTClientError as e:
            raise RuntimeError(
                f'{e}, {self.entity_id}, {self.name}, {action.name}') from e
        return True

    def __on_properties_changed(self, params: dict, ctx: Any) -> None:
        _LOGGER.debug('properties changed, %s', params)
        for prop in self.entity_data.props:
            if (
                prop.iid != params['piid']
                or prop.service.iid != params['siid']
            ):
                continue
            value: Any = prop.value_format(params['value'])
            self._prop_value_map[prop] = value
            if prop in self._prop_changed_subs:
                self._prop_changed_subs[prop](prop, value)
            break
        if not self._pending_write_ha_state_timer:
            self.async_write_ha_state()

    def __on_event_occurred(self, params: dict, ctx: Any) -> None:
        _LOGGER.debug('event occurred, %s', params)
        if self._event_occurred_handler is None:
            return
        for event in self.entity_data.events:
            if (
                event.iid != params['eiid']
                or event.service.iid != params['siid']
            ):
                continue
            trans_arg = {}
            for item in params['arguments']:
                for prop in event.argument:
                    if prop.iid == item['piid']:
                        trans_arg[prop.description_trans] = item['value']
                        break
            self._event_occurred_handler(event, trans_arg)
            break

    def __on_device_state_changed(
        self, key: str, state: MIoTDeviceState
    ) -> None:
        state_new = state == MIoTDeviceState.ONLINE
        if state_new == self._attr_available:
            return
        self._attr_available = state_new
        if not self._attr_available:
            self.async_write_ha_state()
            return
        self.__refresh_props_value()

    def __refresh_props_value(self) -> None:
        for prop in self.entity_data.props:
            if not prop.readable:
                continue
            self.miot_device.miot_client.request_refresh_prop(
                did=self.miot_device.did, siid=prop.service.iid, piid=prop.iid)
        if self._pending_write_ha_state_timer:
            self._pending_write_ha_state_timer.cancel()
        self._pending_write_ha_state_timer = self._main_loop.call_later(
            1, self.__write_ha_state_handler)

    def __write_ha_state_handler(self) -> None:
        self._pending_write_ha_state_timer = None
        self.async_write_ha_state()


class MIoTPropertyEntity(Entity):
    """MIoT Property Entity."""
    # pylint: disable=unused-argument
    # pylint: disable=inconsistent-quotes
    miot_device: MIoTDevice
    spec: MIoTSpecProperty
    service: MIoTSpecService

    _main_loop: asyncio.AbstractEventLoop
    # {'min':int, 'max':int, 'step': int}
    _value_range: dict[str, int]
    # {Any: Any}
    _value_list: dict[Any, Any]
    _value: Any

    _pending_write_ha_state_timer: Optional[asyncio.TimerHandle]

    def __init__(self, miot_device: MIoTDevice, spec: MIoTSpecProperty) -> None:
        if miot_device is None or spec is None or spec.service is None:
            raise MIoTDeviceError('init error, invalid params')
        self.miot_device = miot_device
        self.spec = spec
        self.service = spec.service
        self._main_loop = miot_device.miot_client.main_loop
        self._value_range = spec.value_range
        if spec.value_list:
            self._value_list = {
                item['value']: item['description'] for item in spec.value_list}
        else:
            self._value_list = None
        self._value = None
        self._pending_write_ha_state_timer = None
        # Gen entity_id
        self.entity_id = self.miot_device.gen_prop_entity_id(
            ha_domain=DOMAIN, spec_name=spec.name,
            siid=spec.service.iid, piid=spec.iid)
        # Set entity attr
        self._attr_unique_id = self.entity_id
        self._attr_should_poll = False
        self._attr_has_entity_name = True
        self._attr_name = (
            f'{"* "if self.spec.proprietary else " "}'
            f'{self.service.description_trans} {spec.description_trans}')
        self._attr_available = miot_device.online

        _LOGGER.info(
            'new miot property entity, %s, %s, %s, %s, %s, %s, %s',
            self.miot_device.name, self._attr_name, spec.platform,
            spec.device_class, self.entity_id, self._value_range,
            self._value_list)

    @property
    def device_info(self) -> dict:
        return self.miot_device.device_info

    async def async_added_to_hass(self) -> None:
        # Sub device state changed
        self.miot_device.sub_device_state(
            key=f'{ self.service.iid}.{self.spec.iid}',
            handler=self.__on_device_state_changed)
        # Sub value changed
        self.miot_device.sub_property(
            handler=self.__on_value_changed,
            siid=self.service.iid, piid=self.spec.iid)
        # Refresh value
        if self._attr_available:
            self.__request_refresh_prop()

    async def async_will_remove_from_hass(self) -> None:
        if self._pending_write_ha_state_timer:
            self._pending_write_ha_state_timer.cancel()
            self._pending_write_ha_state_timer = None
        self.miot_device.unsub_device_state(
            key=f'{ self.service.iid}.{self.spec.iid}')
        self.miot_device.unsub_property(
            siid=self.service.iid, piid=self.spec.iid)

    def get_vlist_description(self, value: Any) -> str:
        if not self._value_list:
            return None
        return self._value_list.get(value, None)

    def get_vlist_value(self, description: str) -> Any:
        if not self._value_list:
            return None
        for key, value in self._value_list.items():
            if value == description:
                return key
        return None

    async def set_property_async(self, value: Any) -> bool:
        if not self.spec.writable:
            raise RuntimeError(
                f'set property failed, not writable, '
                f'{self.entity_id}, {self.name}')
        value = self.spec.value_format(value)
        try:
            await self.miot_device.miot_client.set_prop_async(
                did=self.miot_device.did, siid=self.spec.service.iid,
                piid=self.spec.iid, value=value)
        except MIoTClientError as e:
            raise RuntimeError(
                f'{e}, {self.entity_id}, {self.name}') from e
        self._value = value
        self.async_write_ha_state()
        return True

    async def get_property_async(self) -> Any:
        if not self.spec.readable:
            _LOGGER.error(
                'get property failed, not readable, %s, %s',
                self.entity_id, self.name)
            return None
        return self.spec.value_format(
            await self.miot_device.miot_client.get_prop_async(
                did=self.miot_device.did, siid=self.spec.service.iid,
                piid=self.spec.iid))

    def __on_value_changed(self, params: dict, ctx: Any) -> None:
        _LOGGER.debug('property changed, %s', params)
        self._value = self.spec.value_format(params['value'])
        if not self._pending_write_ha_state_timer:
            self.async_write_ha_state()

    def __on_device_state_changed(
        self, key: str, state: MIoTDeviceState
    ) -> None:
        self._attr_available = state == MIoTDeviceState.ONLINE
        if not self._attr_available:
            self.async_write_ha_state()
            return
        # Refresh value
        self.__request_refresh_prop()

    def __request_refresh_prop(self) -> None:
        if self.spec.readable:
            self.miot_device.miot_client.request_refresh_prop(
                did=self.miot_device.did, siid=self.service.iid,
                piid=self.spec.iid)
        if self._pending_write_ha_state_timer:
            self._pending_write_ha_state_timer.cancel()
        self._pending_write_ha_state_timer = self._main_loop.call_later(
            1, self.__write_ha_state_handler)

    def __write_ha_state_handler(self) -> None:
        self._pending_write_ha_state_timer = None
        self.async_write_ha_state()


class MIoTEventEntity(Entity):
    """MIoT Event Entity."""
    # pylint: disable=unused-argument
    # pylint: disable=inconsistent-quotes
    miot_device: MIoTDevice
    spec: MIoTSpecEvent
    service: MIoTSpecService

    _main_loop: asyncio.AbstractEventLoop
    _value: Any
    _attr_event_types: list[str]
    _arguments_map: dict[int, str]

    def __init__(self, miot_device: MIoTDevice, spec: MIoTSpecEvent) -> None:
        if miot_device is None or spec is None or spec.service is None:
            raise MIoTDeviceError('init error, invalid params')
        self.miot_device = miot_device
        self.spec = spec
        self.service = spec.service
        self._main_loop = miot_device.miot_client.main_loop
        self._value = None
        # Gen entity_id
        self.entity_id = self.miot_device.gen_event_entity_id(
            ha_domain=DOMAIN, spec_name=spec.name,
            siid=spec.service.iid,  eiid=spec.iid)
        # Set entity attr
        self._attr_unique_id = self.entity_id
        self._attr_should_poll = False
        self._attr_has_entity_name = True
        self._attr_name = (
            f'{"* "if self.spec.proprietary else " "}'
            f'{self.service.description_trans} {spec.description_trans}')
        self._attr_available = miot_device.online
        self._attr_event_types = [spec.description_trans]

        self._arguments_map = {}
        for prop in spec.argument:
            self._arguments_map[prop.iid] = prop.description_trans

        _LOGGER.info(
            'new miot event entity, %s, %s, %s, %s, %s',
            self.miot_device.name, self._attr_name, spec.platform,
            spec.device_class, self.entity_id)

    @property
    def device_info(self) -> dict:
        return self.miot_device.device_info

    async def async_added_to_hass(self) -> None:
        # Sub device state changed
        self.miot_device.sub_device_state(
            key=f'event.{ self.service.iid}.{self.spec.iid}',
            handler=self.__on_device_state_changed)
        # Sub value changed
        self.miot_device.sub_event(
            handler=self.__on_event_occurred,
            siid=self.service.iid, eiid=self.spec.iid)

    async def async_will_remove_from_hass(self) -> None:
        self.miot_device.unsub_device_state(
            key=f'event.{ self.service.iid}.{self.spec.iid}')
        self.miot_device.unsub_event(
            siid=self.service.iid, eiid=self.spec.iid)

    @abstractmethod
    def on_event_occurred(
        self, name: str, arguments: list[dict[int, Any]]
    ): ...

    def __on_event_occurred(self, params: dict, ctx: Any) -> None:
        _LOGGER.debug('event occurred, %s',  params)
        trans_arg = {}
        for item in params['arguments']:
            try:
                if 'value' not in item:
                    continue
                if 'piid' in item:
                    trans_arg[self._arguments_map[item['piid']]] = item[
                        'value']
                elif (
                    isinstance(item['value'], list)
                    and len(item['value']) == len(self.spec.argument)
                ):
                    # Dirty fix for cloud multi-arguments
                    trans_arg = {
                        prop.description_trans: item['value'][index]
                        for index, prop in enumerate(self.spec.argument)
                    }
                    break
            except KeyError as error:
                _LOGGER.debug(
                    'on event msg, invalid args, %s, %s, %s',
                    self.entity_id, params, error)
        self.on_event_occurred(
            name=self.spec.description_trans, arguments=trans_arg)
        self.async_write_ha_state()

    def __on_device_state_changed(
        self, key: str, state: MIoTDeviceState
    ) -> None:
        state_new = state == MIoTDeviceState.ONLINE
        if state_new == self._attr_available:
            return
        self._attr_available = state_new
        self.async_write_ha_state()


class MIoTActionEntity(Entity):
    """MIoT Action Entity."""
    # pylint: disable=unused-argument
    # pylint: disable=inconsistent-quotes
    miot_device: MIoTDevice
    spec: MIoTSpecAction
    service: MIoTSpecService
    action_platform: str

    _main_loop: asyncio.AbstractEventLoop
    _in_map: dict[int, MIoTSpecProperty]
    _out_map: dict[int, MIoTSpecProperty]

    def __init__(self, miot_device: MIoTDevice, spec: MIoTSpecAction) -> None:
        if miot_device is None or spec is None or spec.service is None:
            raise MIoTDeviceError('init error, invalid params')
        self.miot_device = miot_device
        self.spec = spec
        self.service = spec.service
        self.action_platform = 'action'
        self._main_loop = miot_device.miot_client.main_loop
        # Gen entity_id
        self.entity_id = self.miot_device.gen_action_entity_id(
            ha_domain=DOMAIN, spec_name=spec.name,
            siid=spec.service.iid, aiid=spec.iid)
        # Set entity attr
        self._attr_unique_id = self.entity_id
        self._attr_should_poll = False
        self._attr_has_entity_name = True
        self._attr_name = (
            f'{"* "if self.spec.proprietary else " "}'
            f'{self.service.description_trans} {spec.description_trans}')
        self._attr_available = miot_device.online

        _LOGGER.debug(
            'new miot action entity, %s, %s, %s, %s, %s',
            self.miot_device.name, self._attr_name, spec.platform,
            spec.device_class, self.entity_id)

    @property
    def device_info(self) -> dict:
        return self.miot_device.device_info

    async def async_added_to_hass(self) -> None:
        self.miot_device.sub_device_state(
            key=f'{self.action_platform}.{ self.service.iid}.{self.spec.iid}',
            handler=self.__on_device_state_changed)

    async def async_will_remove_from_hass(self) -> None:
        self.miot_device.unsub_device_state(
            key=f'{self.action_platform}.{ self.service.iid}.{self.spec.iid}')

    async def action_async(self, in_list: list = None) -> Optional[list]:
        try:
            return await self.miot_device.miot_client.action_async(
                did=self.miot_device.did,
                siid=self.service.iid,
                aiid=self.spec.iid,
                in_list=in_list or [])
        except MIoTClientError as e:
            raise RuntimeError(f'{e}, {self.entity_id}, {self.name}') from e

    def __on_device_state_changed(
        self, key: str, state: MIoTDeviceState
    ) -> None:
        state_new = state == MIoTDeviceState.ONLINE
        if state_new == self._attr_available:
            return
        self._attr_available = state_new
        self.async_write_ha_state()
