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
    DEGREE,
    LIGHT_LUX,
    REVOLUTIONS_PER_MINUTE,
    PERCENTAGE,
    SIGNAL_STRENGTH_DECIBELS,
    UnitOfBloodGlucoseConcentration,
    UnitOfEnergy,
    UnitOfElectricCurrent,
    UnitOfElectricPotential,
    UnitOfFrequency,
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
    UnitOfDataRate
)
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.components.switch import SwitchDeviceClass


# pylint: disable=relative-beyond-top-level
from .specs.specv2entity import (
    SPEC_ACTION_TRANS_MAP,
    SPEC_DEVICE_TRANS_MAP,
    SPEC_EVENT_TRANS_MAP,
    SPEC_PROP_TRANS_MAP,
    SPEC_SERVICE_TRANS_MAP
)
from .common import slugify_name, slugify_did
from .const import DOMAIN
from .miot_client import MIoTClient
from .miot_error import MIoTClientError, MIoTDeviceError
from .miot_mips import MIoTDeviceState
from .miot_spec import (
    MIoTSpecAction,
    MIoTSpecEvent,
    MIoTSpecInstance,
    MIoTSpecProperty,
    MIoTSpecService,
    MIoTSpecValueList,
    MIoTSpecValueRange
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

    _suggested_area: Optional[str]

    _sub_id: int
    _device_state_sub_list: dict[str, dict[
        str, Callable[[str, MIoTDeviceState], None]]]
    _value_sub_list: dict[str, dict[str, Callable[[dict, Any], None]]]

    _entity_list: dict[str, list[MIoTEntityData]]
    _prop_list: dict[str, list[MIoTSpecProperty]]
    _event_list: dict[str, list[MIoTSpecEvent]]
    _action_list: dict[str, list[MIoTSpecAction]]

    def __init__(
        self, miot_client: MIoTClient,
        device_info: dict[str, Any],
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

        self._sub_id = 0
        self._device_state_sub_list = {}
        self._value_sub_list = {}
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
    ) -> int:
        sub_id = self.__gen_sub_id()
        if key in self._device_state_sub_list:
            self._device_state_sub_list[key][str(sub_id)] = handler
        else:
            self._device_state_sub_list[key] = {str(sub_id): handler}
        return sub_id

    def unsub_device_state(self, key: str, sub_id: int) -> None:
        sub_list = self._device_state_sub_list.get(key, None)
        if sub_list:
            sub_list.pop(str(sub_id), None)
        if not sub_list:
            self._device_state_sub_list.pop(key, None)

    def sub_property(
        self, handler: Callable[[dict, Any], None], siid: int, piid: int
    ) -> int:
        key: str = f'p.{siid}.{piid}'

        def _on_prop_changed(params: dict, ctx: Any) -> None:
            for handler in self._value_sub_list[key].values():
                handler(params, ctx)

        sub_id = self.__gen_sub_id()
        if key in self._value_sub_list:
            self._value_sub_list[key][str(sub_id)] = handler
        else:
            self._value_sub_list[key] = {str(sub_id): handler}
            self.miot_client.sub_prop(
                did=self._did, handler=_on_prop_changed, siid=siid, piid=piid)
        return sub_id

    def unsub_property(self, siid: int, piid: int, sub_id: int) -> None:
        key: str = f'p.{siid}.{piid}'

        sub_list = self._value_sub_list.get(key, None)
        if sub_list:
            sub_list.pop(str(sub_id), None)
        if not sub_list:
            self.miot_client.unsub_prop(did=self._did, siid=siid, piid=piid)
            self._value_sub_list.pop(key, None)

    def sub_event(
        self, handler: Callable[[dict, Any], None], siid: int, eiid: int
    ) -> int:
        key: str = f'e.{siid}.{eiid}'

        def _on_event_occurred(params: dict, ctx: Any) -> None:
            for handler in self._value_sub_list[key].values():
                handler(params, ctx)

        sub_id = self.__gen_sub_id()
        if key in self._value_sub_list:
            self._value_sub_list[key][str(sub_id)] = handler
        else:
            self._value_sub_list[key] = {str(sub_id): handler}
            self.miot_client.sub_event(
                did=self._did, handler=_on_event_occurred, siid=siid, eiid=eiid)
        return sub_id

    def unsub_event(self, siid: int, eiid: int, sub_id: int) -> None:
        key: str = f'e.{siid}.{eiid}'

        sub_list = self._value_sub_list.get(key, None)
        if sub_list:
            sub_list.pop(str(sub_id), None)
        if not sub_list:
            self.miot_client.unsub_event(did=self._did, siid=siid, eiid=eiid)
            self._value_sub_list.pop(key, None)

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
        return slugify_did(
            cloud_server=self.miot_client.cloud_server, did=self._did)

    def gen_device_entity_id(self, ha_domain: str) -> str:
        return (
            f'{ha_domain}.{self._model_strs[0][:9]}_{self.did_tag}_'
            f'{self._model_strs[-1][:20]}')

    def gen_service_entity_id(self, ha_domain: str, siid: int,
                              description: str) -> str:
        return (
            f'{ha_domain}.{self._model_strs[0][:9]}_{self.did_tag}_'
            f'{self._model_strs[-1][:20]}_s_{siid}_{description}')

    def gen_prop_entity_id(
        self, ha_domain: str, spec_name: str, siid: int, piid: int
    ) -> str:
        return (
            f'{ha_domain}.{self._model_strs[0][:9]}_{self.did_tag}_'
            f'{self._model_strs[-1][:20]}_{slugify_name(spec_name)}'
            f'_p_{siid}_{piid}')

    def gen_event_entity_id(
        self, ha_domain: str, spec_name: str, siid: int, eiid: int
    ) -> str:
        return (
            f'{ha_domain}.{self._model_strs[0][:9]}_{self.did_tag}_'
            f'{self._model_strs[-1][:20]}_{slugify_name(spec_name)}'
            f'_e_{siid}_{eiid}')

    def gen_action_entity_id(
        self, ha_domain: str, spec_name: str, siid: int, aiid: int
    ) -> str:
        return (
            f'{ha_domain}.{self._model_strs[0][:9]}_{self.did_tag}_'
            f'{self._model_strs[-1][:20]}_{slugify_name(spec_name)}'
            f'_a_{siid}_{aiid}')

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
        if not prop.platform:
            return
        self._prop_list.setdefault(prop.platform, [])
        self._prop_list[prop.platform].append(prop)

    def append_event(self, event: MIoTSpecEvent) -> None:
        if not event.platform:
            return
        self._event_list.setdefault(event.platform, [])
        self._event_list[event.platform].append(event)

    def append_action(self, action: MIoTSpecAction) -> None:
        if not action.platform:
            return
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
        if 'required' not in SPEC_DEVICE_TRANS_MAP[spec_name]:
            return None
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
            required_properties: dict
            optional_properties: dict
            required_actions: set
            optional_actions: set
            # 2. The required service shall have all required properties
            # and actions.
            if service.name in required_services:
                required_properties = SPEC_DEVICE_TRANS_MAP[spec_name][
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
                if not {
                    prop.name for prop in service.properties if prop.access
                }.issuperset(set(required_properties.keys())):
                    return None
                if not {
                    action.name for action in service.actions
                }.issuperset(required_actions):
                    return None
                # 3. The required property in required service shall have all
                # required access mode.
                for prop in service.properties:
                    if prop.name in required_properties:
                        if not set(prop.access).issuperset(
                                required_properties[prop.name]):
                            return None
            # 4. The optional service shall have all required properties
            # and actions.
            elif service.name in optional_services:
                required_properties = SPEC_DEVICE_TRANS_MAP[spec_name][
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
                if not {
                    prop.name for prop in service.properties if prop.access
                }.issuperset(set(required_properties.keys())):
                    continue
                if not {
                    action.name for action in service.actions
                }.issuperset(required_actions):
                    continue
                # 5. The required property in optional service shall have all
                # required access mode.
                for prop in service.properties:
                    if prop.name in required_properties:
                        if not set(prop.access).issuperset(
                                required_properties[prop.name]):
                            continue
            else:
                continue
            # property
            for prop in service.properties:
                if prop.name in set.union(
                        set(required_properties.keys()), optional_properties):
                    if prop.unit:
                        prop.external_unit = self.unit_convert(prop.unit)
                    #     prop.icon = self.icon_convert(prop.unit)
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
        self, miot_service: MIoTSpecService
    ) -> Optional[MIoTEntityData]:
        if (
            miot_service.platform
            or miot_service.name not in SPEC_SERVICE_TRANS_MAP
        ):
            return None
        service_name = miot_service.name
        if isinstance(SPEC_SERVICE_TRANS_MAP[service_name], str):
            service_name = SPEC_SERVICE_TRANS_MAP[service_name]
        if 'required' not in SPEC_SERVICE_TRANS_MAP[service_name]:
            return None
        # Required properties, required access mode
        required_properties: dict = SPEC_SERVICE_TRANS_MAP[service_name][
            'required'].get('properties', {})
        if not {
            prop.name for prop in miot_service.properties if prop.access
        }.issuperset(set(required_properties.keys())):
            return None
        for prop in miot_service.properties:
            if prop.name in required_properties:
                if not set(prop.access).issuperset(
                        required_properties[prop.name]):
                    return None
        # Required actions
        # Required events
        platform = SPEC_SERVICE_TRANS_MAP[service_name]['entity']
        entity_data = MIoTEntityData(platform=platform, spec=miot_service)
        # Optional properties
        optional_properties = SPEC_SERVICE_TRANS_MAP[service_name][
            'optional'].get('properties', set({}))
        for prop in miot_service.properties:
            if prop.name in set.union(
                    set(required_properties.keys()), optional_properties):
                if prop.unit:
                    prop.external_unit = self.unit_convert(prop.unit)
                    # prop.icon = self.icon_convert(prop.unit)
                prop.platform = platform
                entity_data.props.add(prop)
        # Optional actions
        # Optional events
        miot_service.platform = platform
        # entity_category
        if entity_category := SPEC_SERVICE_TRANS_MAP[service_name].get(
            'entity_category', None):
            miot_service.entity_category = entity_category
        return entity_data

    def parse_miot_property_entity(self, miot_prop: MIoTSpecProperty) -> bool:
        if (
            miot_prop.platform
            or miot_prop.name not in SPEC_PROP_TRANS_MAP['properties']
        ):
            return False
        prop_name = miot_prop.name
        if isinstance(SPEC_PROP_TRANS_MAP['properties'][prop_name], str):
            prop_name = SPEC_PROP_TRANS_MAP['properties'][prop_name]
        platform = SPEC_PROP_TRANS_MAP['properties'][prop_name]['entity']
        # Check
        prop_access: set = set({})
        if miot_prop.readable:
            prop_access.add('read')
        if miot_prop.writable:
            prop_access.add('write')
        if prop_access != (SPEC_PROP_TRANS_MAP[
                'entities'][platform]['access']):
            return False
        if miot_prop.format_.__name__ not in SPEC_PROP_TRANS_MAP[
                'entities'][platform]['format']:
            return False
        miot_prop.device_class = SPEC_PROP_TRANS_MAP['properties'][prop_name][
            'device_class']
        # Optional params
        if 'state_class' in SPEC_PROP_TRANS_MAP['properties'][prop_name]:
            miot_prop.state_class = SPEC_PROP_TRANS_MAP['properties'][
                prop_name]['state_class']
        if (
            not miot_prop.external_unit
            and 'unit_of_measurement' in SPEC_PROP_TRANS_MAP['properties'][
                prop_name]
        ):
            # Priority: spec_modify.unit > unit_convert > specv2entity.unit
            miot_prop.external_unit = SPEC_PROP_TRANS_MAP['properties'][
                prop_name]['unit_of_measurement']
        # Priority: default.icon when device_class is set > spec_modify.icon
        #           > icon_convert
        miot_prop.platform = platform
        return True

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
                miot_service=service)
            if service_entity:
                self.append_entity(entity_data=service_entity)
            # STEP 3.1: property conversion
            for prop in service.properties:
                if prop.platform or not prop.access:
                    continue
                if prop.unit:
                    prop.external_unit = self.unit_convert(prop.unit)
                    if not prop.icon:
                        prop.icon = self.icon_convert(prop.unit)
                # Special conversion
                self.parse_miot_property_entity(miot_prop=prop)
                # General conversion
                if not prop.platform:
                    if prop.writable:
                        if prop.format_ == str:
                            prop.platform = 'text'
                        elif prop.format_ == bool:
                            prop.platform = 'switch'
                            prop.device_class = SwitchDeviceClass.SWITCH
                        elif prop.value_list:
                            prop.platform = 'select'
                        elif prop.value_range:
                            prop.platform = 'number'
                        else:
                            # Irregular property will not be transformed.
                            continue
                    elif prop.readable or prop.notifiable:
                        if prop.format_ == bool:
                            prop.platform = 'binary_sensor'
                        else:
                            prop.platform = 'sensor'
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
        """Convert MIoT unit to Home Assistant unit.
        2026/01/06: property unit statistics of the latest released
        MIoT-Spec-V2 for all device models: unit, quantity.
        {
            "no_unit": 148499,
            "percentage": 12074,
            "none": 11857,
            "minutes": 5707,
            "celsius": 5767,
            "seconds": 3062,
            "kelvin": 2511,
            "hours": 1380,
            "days": 615,
            "rgb": 752,         // color
            "L": 379,
            "mg/m3": 335,
            "ppm": 182,
            "watt": 246,
            "arcdegrees": 130,
            "μg/m3": 117,
            "kWh": 149,
            "ms": 108,
            "pascal": 108,
            "lux": 100,
            "V": 59,
            "m": 45,
            "A": 36,
            "mL": 30,
            "arcdegress": 25,
            "mA": 26,
            "bpm": 21,          // realtime-heartrate
            "B/s": 21,
            "weeks": 18,
            "dB": 17,
            "calorie": 18,      // 1 cal = 4.184 J
            "metre": 15,
            "hour": 11,
            "cm": 12,
            "gram": 8,
            "km/h": 8,
            "mV": 9,
            "times": 4,         // exercise-count
            "kCal": 4,
            "mmHg": 4,
            "pcs": 3,
            "meter": 3,
            "kW": 2,
            "KByte/s": 2,
            "毫摩尔每升": 2,      // blood-sugar, cholesterol
            "m3/h": 2,
            "ppb": 2,
            "mv": 2,
            "w": 1,
            "bar": 1,
            "megapascal": 1,
            "kB": 1,
            "mmol/L": 1,        // urea
            "min/km": 1,
            "kilopascal": 1,
            "liter": 1,
            "W": 1
        }
        """
        unit_map = {
            'percentage': PERCENTAGE,
            'weeks': UnitOfTime.WEEKS,
            'days': UnitOfTime.DAYS,
            'hour': UnitOfTime.HOURS,
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
            'kilopascal': UnitOfPressure.KPA,
            'mmHg': UnitOfPressure.MMHG,
            'bar': UnitOfPressure.BAR,
            'L': UnitOfVolume.LITERS,
            'liter': UnitOfVolume.LITERS,
            'mL': UnitOfVolume.MILLILITERS,
            'Hz': UnitOfFrequency.HERTZ,
            'calorie': UnitOfEnergy.CALORIE,
            'kCal': UnitOfEnergy.KILO_CALORIE,
            'km/h': UnitOfSpeed.KILOMETERS_PER_HOUR,
            'm/s': UnitOfSpeed.METERS_PER_SECOND,
            'watt': UnitOfPower.WATT,
            'w': UnitOfPower.WATT,
            'W': UnitOfPower.WATT,
            'kW': UnitOfPower.KILO_WATT,
            'Wh': UnitOfEnergy.WATT_HOUR,
            'kWh': UnitOfEnergy.KILO_WATT_HOUR,
            'A': UnitOfElectricCurrent.AMPERE,
            'mA': UnitOfElectricCurrent.MILLIAMPERE,
            'V': UnitOfElectricPotential.VOLT,
            'mv': UnitOfElectricPotential.MILLIVOLT,
            'mV': UnitOfElectricPotential.MILLIVOLT,
            'cm': UnitOfLength.CENTIMETERS,
            'm': UnitOfLength.METERS,
            'meter': UnitOfLength.METERS,
            'km': UnitOfLength.KILOMETERS,
            'm3/h': UnitOfVolumeFlowRate.CUBIC_METERS_PER_HOUR,
            '毫摩尔每升': UnitOfBloodGlucoseConcentration.MILLIMOLE_PER_LITER,
            'mmol/L': UnitOfBloodGlucoseConcentration.MILLIMOLE_PER_LITER,
            'rpm': REVOLUTIONS_PER_MINUTE,
            'gram': UnitOfMass.GRAMS,
            'kilogram': UnitOfMass.KILOGRAMS,
            'dB': SIGNAL_STRENGTH_DECIBELS,
            'arcdegrees': DEGREE,
            'arcdegress': DEGREE,
            'kB': UnitOfInformation.KILOBYTES,
            'MB': UnitOfInformation.MEGABYTES,
            'GB': UnitOfInformation.GIGABYTES,
            'TB': UnitOfInformation.TERABYTES,
            'B/s': UnitOfDataRate.BYTES_PER_SECOND,
            'KB/s': UnitOfDataRate.KILOBYTES_PER_SECOND,
            'KByte/s': UnitOfDataRate.KILOBYTES_PER_SECOND,
            'MB/s': UnitOfDataRate.MEGABYTES_PER_SECOND,
            'GB/s': UnitOfDataRate.GIGABYTES_PER_SECOND
        }

        # Handle UnitOfConductivity separately since
        # it might not be available in all HA versions
        try:
            # pylint: disable=import-outside-toplevel
            from homeassistant.const import UnitOfConductivity  # type: ignore
            unit_map['μS/cm'] = UnitOfConductivity.MICROSIEMENS_PER_CM
            unit_map['mWh'] = UnitOfEnergy.MILLIWATT_HOUR
        except Exception:  # pylint: disable=broad-except
            unit_map['μS/cm'] = 'μS/cm'
            unit_map['mWh'] = 'mWh'

        return unit_map.get(spec_unit, None)

    def icon_convert(self, spec_unit: str) -> Optional[str]:
        if spec_unit in {'percentage'}:
            return 'mdi:percent'
        if spec_unit in {
            'weeks', 'days', 'hour', 'hours', 'minutes', 'seconds', 'ms', 'μs'
        }:
            return 'mdi:clock'
        if spec_unit in {'celsius'}:
            return 'mdi:temperature-celsius'
        if spec_unit in {'fahrenheit'}:
            return 'mdi:temperature-fahrenheit'
        if spec_unit in {'kelvin'}:
            return 'mdi:temperature-kelvin'
        if spec_unit in {'μg/m3', 'mg/m3', 'ppm', 'ppb'}:
            return 'mdi:blur'
        if spec_unit in {'lux'}:
            return 'mdi:brightness-6'
        if spec_unit in {'pascal', 'kilopascal', 'megapascal', 'mmHg', 'bar'}:
            return 'mdi:gauge'
        if spec_unit in {'watt', 'w', 'W'}:
            return 'mdi:flash-triangle'
        if spec_unit in {'L', 'mL'}:
            return 'mdi:gas-cylinder'
        if spec_unit in {'km/h', 'm/s'}:
            return 'mdi:speedometer'
        if spec_unit in {'kWh'}:
            return 'mdi:transmission-tower'
        if spec_unit in {'A', 'mA'}:
            return 'mdi:current-ac'
        if spec_unit in {'V', 'mv', 'mV'}:
            return 'mdi:current-dc'
        if spec_unit in {'cm', 'm', 'meter', 'km'}:
            return 'mdi:ruler'
        if spec_unit in {'rgb'}:
            return 'mdi:palette'
        if spec_unit in {'m3/h', 'L/s'}:
            return 'mdi:pipe-leak'
        if spec_unit in {'μS/cm'}:
            return 'mdi:resistor-nodes'
        if spec_unit in {'gram', 'kilogram'}:
            return 'mdi:weight'
        if spec_unit in {'dB'}:
            return 'mdi:signal-distance-variant'
        if spec_unit in {'times'}:
            return 'mdi:counter'
        if spec_unit in {'mmol/L'}:
            return 'mdi:dots-hexagon'
        if spec_unit in {'kB', 'MB', 'GB'}:
            return 'mdi:network-pos'
        if spec_unit in {'arcdegress', 'arcdegrees'}:
            return 'mdi:angle-obtuse'
        if spec_unit in {'B/s', 'KB/s', 'MB/s', 'GB/s'}:
            return 'mdi:network'
        if spec_unit in {'calorie', 'kCal'}:
            return 'mdi:food'
        if spec_unit in {'rpm'}:
            return 'mdi:fan-clock'
        return None

    def __gen_sub_id(self) -> int:
        self._sub_id += 1
        return self._sub_id

    def __on_device_state_changed(
        self, did: str, state: MIoTDeviceState, ctx: Any
    ) -> None:
        self._online = state == MIoTDeviceState.ONLINE
        for key, sub_list in self._device_state_sub_list.items():
            for handler in sub_list.values():
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
    _state_sub_id: int
    _value_sub_ids: dict[str, int]

    _event_occurred_handler: Optional[
        Callable[[MIoTSpecEvent, dict], None]]
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
        self._state_sub_id = 0
        self._value_sub_ids = {}
        # Gen entity id
        if isinstance(self.entity_data.spec, MIoTSpecInstance):
            self.entity_id = miot_device.gen_device_entity_id(DOMAIN)
            self._attr_name = f' {self.entity_data.spec.description_trans}'
        elif isinstance(self.entity_data.spec, MIoTSpecService):
            self.entity_id = miot_device.gen_service_entity_id(
                DOMAIN, siid=self.entity_data.spec.iid,
                description=self.entity_data.spec.description)
            self._attr_name = (
                f'{"* "if self.entity_data.spec.proprietary else " "}'
                f'{self.entity_data.spec.description_trans}')
            self._attr_entity_category = entity_data.spec.entity_category
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
    def event_occurred_handler(
        self
    ) -> Optional[Callable[[MIoTSpecEvent, dict], None]]:
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
    def device_info(self) -> Optional[DeviceInfo]:
        return self.miot_device.device_info

    async def async_added_to_hass(self) -> None:
        state_id = 's.0'
        if isinstance(self.entity_data.spec, MIoTSpecService):
            state_id = f's.{self.entity_data.spec.iid}'
        self._state_sub_id = self.miot_device.sub_device_state(
            key=state_id, handler=self.__on_device_state_changed)
        # Sub prop
        for prop in self.entity_data.props:
            if not prop.notifiable and not prop.readable:
                continue
            key = f'p.{prop.service.iid}.{prop.iid}'
            self._value_sub_ids[key] = self.miot_device.sub_property(
                handler=self.__on_properties_changed,
                siid=prop.service.iid, piid=prop.iid)
        # Sub event
        for event in self.entity_data.events:
            key = f'e.{event.service.iid}.{event.iid}'
            self._value_sub_ids[key] = self.miot_device.sub_event(
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
        self.miot_device.unsub_device_state(
            key=state_id, sub_id=self._state_sub_id)
        # Unsub prop
        for prop in self.entity_data.props:
            if not prop.notifiable and not prop.readable:
                continue
            sub_id = self._value_sub_ids.pop(
                f'p.{prop.service.iid}.{prop.iid}', None)
            if sub_id:
                self.miot_device.unsub_property(
                    siid=prop.service.iid, piid=prop.iid, sub_id=sub_id)
        # Unsub event
        for event in self.entity_data.events:
            sub_id = self._value_sub_ids.pop(
                f'e.{event.service.iid}.{event.iid}', None)
            if sub_id:
                self.miot_device.unsub_event(
                    siid=event.service.iid, eiid=event.iid, sub_id=sub_id)

    def get_map_value(
        self, map_: Optional[dict[int, Any]], key: int
    ) -> Any:
        if map_ is None:
            return None
        return map_.get(key, None)

    def get_map_key(
        self, map_: Optional[dict[int, Any]], value: Any
    ) -> Optional[int]:
        if map_ is None:
            return None
        for key, value_ in map_.items():
            if value_ == value:
                return key
        return None

    def get_prop_value(self, prop: Optional[MIoTSpecProperty]) -> Any:
        if not prop:
            _LOGGER.error(
                'get_prop_value error, property is None, %s, %s',
                self._attr_name, self.entity_id)
            return None
        return self._prop_value_map.get(prop, None)

    def set_prop_value(
        self, prop: Optional[MIoTSpecProperty], value: Any
    ) -> None:
        if not prop:
            _LOGGER.error(
                'set_prop_value error, property is None, %s, %s',
                self._attr_name, self.entity_id)
            return
        self._prop_value_map[prop] = value

    async def set_property_async(
        self, prop: Optional[MIoTSpecProperty], value: Any,
        update_value: bool = True, write_ha_state: bool = True
    ) -> bool:
        if not prop:
            raise RuntimeError(
                f'set property failed, property is None, '
                f'{self.entity_id}, {self.name}')
        value = prop.value_format(value)
        value = prop.value_precision(value)
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
        if update_value:
            self._prop_value_map[prop] = value
        if write_ha_state:
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
        value: Any = prop.value_format(
            await self.miot_device.miot_client.get_prop_async(
                did=self.miot_device.did, siid=prop.service.iid, piid=prop.iid))
        value = prop.eval_expr(value)
        result = prop.value_precision(value)
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
            value = prop.eval_expr(value)
            value = prop.value_precision(value)
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
    _value_range: Optional[MIoTSpecValueRange]
    # {Any: Any}
    _value_list: Optional[MIoTSpecValueList]
    _value: Any
    _state_sub_id: int
    _value_sub_id: int

    _pending_write_ha_state_timer: Optional[asyncio.TimerHandle]

    def __init__(self, miot_device: MIoTDevice, spec: MIoTSpecProperty) -> None:
        if miot_device is None or spec is None or spec.service is None:
            raise MIoTDeviceError('init error, invalid params')
        self.miot_device = miot_device
        self.spec = spec
        self.service = spec.service
        self._main_loop = miot_device.miot_client.main_loop
        self._value_range = spec.value_range
        self._value_list = spec.value_list
        self._value = None
        self._state_sub_id = 0
        self._value_sub_id = 0
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
            'new miot property entity, %s, %s, %s, %s, %s',
            self.miot_device.name, self._attr_name, spec.platform,
            spec.device_class, self.entity_id)

    @property
    def device_info(self) -> Optional[DeviceInfo]:
        return self.miot_device.device_info

    async def async_added_to_hass(self) -> None:
        # Sub device state changed
        self._state_sub_id = self.miot_device.sub_device_state(
            key=f'{ self.service.iid}.{self.spec.iid}',
            handler=self.__on_device_state_changed)
        # Sub value changed
        self._value_sub_id = self.miot_device.sub_property(
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
            key=f'{ self.service.iid}.{self.spec.iid}',
            sub_id=self._state_sub_id)
        self.miot_device.unsub_property(
            siid=self.service.iid, piid=self.spec.iid,
            sub_id=self._value_sub_id)

    def get_vlist_description(self, value: Any) -> Optional[str]:
        if not self._value_list:
            return None
        return self._value_list.get_description_by_value(value)

    def get_vlist_value(self, description: str) -> Any:
        if not self._value_list:
            return None
        return self._value_list.get_value_by_description(description)

    async def set_property_async(self, value: Any) -> bool:
        if not self.spec.writable:
            raise RuntimeError(
                f'set property failed, not writable, '
                f'{self.entity_id}, {self.name}')
        value = self.spec.value_format(value)
        value = self.spec.value_precision(value)
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
        value: Any = self.spec.value_format(
            await self.miot_device.miot_client.get_prop_async(
                did=self.miot_device.did, siid=self.spec.service.iid,
                piid=self.spec.iid))
        value = self.spec.eval_expr(value)
        result = self.spec.value_precision(value)
        return result

    def __on_value_changed(self, params: dict, ctx: Any) -> None:
        _LOGGER.debug('property changed, %s', params)
        value: Any = self.spec.value_format(params['value'])
        value = self.spec.eval_expr(value)
        self._value = self.spec.value_precision(value)
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
    _attr_event_types: list[str]
    _arguments_map: dict[int, str]
    _state_sub_id: int
    _value_sub_id: int

    def __init__(self, miot_device: MIoTDevice, spec: MIoTSpecEvent) -> None:
        if miot_device is None or spec is None or spec.service is None:
            raise MIoTDeviceError('init error, invalid params')
        self.miot_device = miot_device
        self.spec = spec
        self.service = spec.service
        self._main_loop = miot_device.miot_client.main_loop
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
        self._state_sub_id = 0
        self._value_sub_id = 0

        _LOGGER.info(
            'new miot event entity, %s, %s, %s, %s, %s',
            self.miot_device.name, self._attr_name, spec.platform,
            spec.device_class, self.entity_id)

    @property
    def device_info(self) -> Optional[DeviceInfo]:
        return self.miot_device.device_info

    async def async_added_to_hass(self) -> None:
        # Sub device state changed
        self._state_sub_id = self.miot_device.sub_device_state(
            key=f'event.{ self.service.iid}.{self.spec.iid}',
            handler=self.__on_device_state_changed)
        # Sub value changed
        self._value_sub_id = self.miot_device.sub_event(
            handler=self.__on_event_occurred,
            siid=self.service.iid, eiid=self.spec.iid)

    async def async_will_remove_from_hass(self) -> None:
        self.miot_device.unsub_device_state(
            key=f'event.{ self.service.iid}.{self.spec.iid}',
            sub_id=self._state_sub_id)
        self.miot_device.unsub_event(
            siid=self.service.iid, eiid=self.spec.iid,
            sub_id=self._value_sub_id)

    @abstractmethod
    def on_event_occurred(
        self, name: str, arguments: dict[str, Any] | None = None
    ) -> None: ...

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

    _main_loop: asyncio.AbstractEventLoop
    _in_map: dict[int, MIoTSpecProperty]
    _out_map: dict[int, MIoTSpecProperty]
    _state_sub_id: int

    def __init__(self, miot_device: MIoTDevice, spec: MIoTSpecAction) -> None:
        if miot_device is None or spec is None or spec.service is None:
            raise MIoTDeviceError('init error, invalid params')
        self.miot_device = miot_device
        self.spec = spec
        self.service = spec.service
        self._main_loop = miot_device.miot_client.main_loop
        self._state_sub_id = 0
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
    def device_info(self) -> Optional[DeviceInfo]:
        return self.miot_device.device_info

    async def async_added_to_hass(self) -> None:
        self._state_sub_id = self.miot_device.sub_device_state(
            key=f'a.{ self.service.iid}.{self.spec.iid}',
            handler=self.__on_device_state_changed)

    async def async_will_remove_from_hass(self) -> None:
        self.miot_device.unsub_device_state(
            key=f'a.{ self.service.iid}.{self.spec.iid}',
            sub_id=self._state_sub_id)

    async def action_async(
        self, in_list: Optional[list] = None
    ) -> Optional[list]:
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
