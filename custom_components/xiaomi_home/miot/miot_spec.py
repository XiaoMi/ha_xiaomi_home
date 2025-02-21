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

MIoT-Spec-V2 parser.
"""
import asyncio
import os
import platform
import time
from typing import Any, Optional, Type, Union
import logging
from slugify import slugify


# pylint: disable=relative-beyond-top-level
from .const import DEFAULT_INTEGRATION_LANGUAGE, SPEC_STD_LIB_EFFECTIVE_TIME
from .common import MIoTHttp, load_yaml_file
from .miot_error import MIoTSpecError
from .miot_storage import MIoTStorage

_LOGGER = logging.getLogger(__name__)


class MIoTSpecValueRange:
    """MIoT SPEC value range class."""
    min_: int
    max_: int
    step: int

    def __init__(self, value_range: Union[dict, list]) -> None:
        if isinstance(value_range, dict):
            self.load(value_range)
        elif isinstance(value_range, list):
            self.from_spec(value_range)
        else:
            raise MIoTSpecError('invalid value range format')

    def load(self, value_range: dict) -> None:
        if (
            'min' not in value_range
            or 'max' not in value_range
            or 'step' not in value_range
        ):
            raise MIoTSpecError('invalid value range')
        self.min_ = value_range['min']
        self.max_ = value_range['max']
        self.step = value_range['step']

    def from_spec(self, value_range: list) -> None:
        if len(value_range) != 3:
            raise MIoTSpecError('invalid value range')
        self.min_ = value_range[0]
        self.max_ = value_range[1]
        self.step = value_range[2]

    def dump(self) -> dict:
        return {
            'min': self.min_,
            'max': self.max_,
            'step': self.step
        }

    def __str__(self) -> str:
        return f'[{self.min_}, {self.max_}, {self.step}'


class MIoTSpecValueListItem:
    """MIoT SPEC value list item class."""
    # NOTICE: bool type without name
    name: str
    # Value
    value: Any
    # Descriptions after multilingual conversion.
    description: str

    def __init__(self, item: dict) -> None:
        self.load(item)

    def load(self, item: dict) -> None:
        if 'value' not in item or 'description' not in item:
            raise MIoTSpecError('invalid value list item, %s')

        self.name = item.get('name', None)
        self.value = item['value']
        self.description = item['description']

    @staticmethod
    def from_spec(item: dict) -> 'MIoTSpecValueListItem':
        if (
            'name' not in item
            or 'value' not in item
            or 'description' not in item
        ):
            raise MIoTSpecError('invalid value list item, %s')
        # Slugify name and convert to lower-case.
        cache = {
            'name': slugify(text=item['name'], separator='_').lower(),
            'value': item['value'],
            'description': item['description']
        }
        return MIoTSpecValueListItem(cache)

    def dump(self) -> dict:
        return {
            'name': self.name,
            'value': self.value,
            'description': self.description
        }

    def __str__(self) -> str:
        return f'{self.name}: {self.value} - {self.description}'


class MIoTSpecValueList:
    """MIoT SPEC value list class."""
    # pylint: disable=inconsistent-quotes
    items: list[MIoTSpecValueListItem]

    def __init__(self, value_list: list[dict]) -> None:
        if not isinstance(value_list, list):
            raise MIoTSpecError('invalid value list format')
        self.items = []
        self.load(value_list)

    @property
    def names(self) -> list[str]:
        return [item.name for item in self.items]

    @property
    def values(self) -> list[Any]:
        return [item.value for item in self.items]

    @property
    def descriptions(self) -> list[str]:
        return [item.description for item in self.items]

    @staticmethod
    def from_spec(value_list: list[dict]) -> 'MIoTSpecValueList':
        result = MIoTSpecValueList([])
        dup_desc: dict[str, int] = {}
        for item in value_list:
            # Handle duplicate descriptions.
            count = 0
            if item['description'] in dup_desc:
                count = dup_desc[item['description']]
            count += 1
            dup_desc[item['description']] = count
            if count > 1:
                item['name'] = f'{item["name"]}_{count}'
                item['description'] = f'{item["description"]}_{count}'

            result.items.append(MIoTSpecValueListItem.from_spec(item))
        return result

    def load(self, value_list: list[dict]) -> None:
        for item in value_list:
            self.items.append(MIoTSpecValueListItem(item))

    def to_map(self) -> dict:
        return {item.value: item.description for item in self.items}

    def get_value_by_description(self, description: str) -> Any:
        for item in self.items:
            if item.description == description:
                return item.value
        return None

    def get_description_by_value(self, value: Any) -> Optional[str]:
        for item in self.items:
            if item.value == value:
                return item.description
        return None

    def dump(self) -> list:
        return [item.dump() for item in self.items]


class _SpecStdLib:
    """MIoT-Spec-V2 standard library."""
    # pylint: disable=inconsistent-quotes
    _lang: str
    _devices: dict[str, dict[str, str]]
    _services: dict[str, dict[str, str]]
    _properties: dict[str, dict[str, str]]
    _events: dict[str, dict[str, str]]
    _actions: dict[str, dict[str, str]]
    _values: dict[str, dict[str, str]]

    def __init__(self, lang: str) -> None:
        self._lang = lang
        self._devices = {}
        self._services = {}
        self._properties = {}
        self._events = {}
        self._actions = {}
        self._values = {}

        self._spec_std_lib = None

    def load(self, std_lib: dict[str, dict[str, dict[str, str]]]) -> None:
        if (
            not isinstance(std_lib, dict)
            or 'devices' not in std_lib
            or 'services' not in std_lib
            or 'properties' not in std_lib
            or 'events' not in std_lib
            or 'actions' not in std_lib
            or 'values' not in std_lib
        ):
            return
        self._devices = std_lib['devices']
        self._services = std_lib['services']
        self._properties = std_lib['properties']
        self._events = std_lib['events']
        self._actions = std_lib['actions']
        self._values = std_lib['values']

    def device_translate(self, key: str) -> Optional[str]:
        if not self._devices or key not in self._devices:
            return None
        if self._lang not in self._devices[key]:
            return self._devices[key].get(
                DEFAULT_INTEGRATION_LANGUAGE, None)
        return self._devices[key][self._lang]

    def service_translate(self, key: str) -> Optional[str]:
        if not self._services or key not in self._services:
            return None
        if self._lang not in self._services[key]:
            return self._services[key].get(
                DEFAULT_INTEGRATION_LANGUAGE, None)
        return self._services[key][self._lang]

    def property_translate(self, key: str) -> Optional[str]:
        if not self._properties or key not in self._properties:
            return None
        if self._lang not in self._properties[key]:
            return self._properties[key].get(
                DEFAULT_INTEGRATION_LANGUAGE, None)
        return self._properties[key][self._lang]

    def event_translate(self, key: str) -> Optional[str]:
        if not self._events or key not in self._events:
            return None
        if self._lang not in self._events[key]:
            return self._events[key].get(
                DEFAULT_INTEGRATION_LANGUAGE, None)
        return self._events[key][self._lang]

    def action_translate(self, key: str) -> Optional[str]:
        if not self._actions or key not in self._actions:
            return None
        if self._lang not in self._actions[key]:
            return self._actions[key].get(
                DEFAULT_INTEGRATION_LANGUAGE, None)
        return self._actions[key][self._lang]

    def value_translate(self, key: str) -> Optional[str]:
        if not self._values or key not in self._values:
            return None
        if self._lang not in self._values[key]:
            return self._values[key].get(
                DEFAULT_INTEGRATION_LANGUAGE, None)
        return self._values[key][self._lang]

    def dump(self) -> dict[str, dict[str, dict[str, str]]]:
        return {
            'devices': self._devices,
            'services': self._services,
            'properties': self._properties,
            'events': self._events,
            'actions': self._actions,
            'values': self._values
        }

    async def refresh_async(self) -> bool:
        std_lib_new = await self.__request_from_cloud_async()
        if std_lib_new:
            self.load(std_lib_new)
            return True
        return False

    async def __request_from_cloud_async(self) -> Optional[dict]:
        std_libs: Optional[dict] = None
        for index in range(3):
            try:
                tasks: list = []
                # Get std lib
                for name in [
                        'device', 'service', 'property', 'event', 'action']:
                    tasks.append(self.__get_template_list(
                        'https://miot-spec.org/miot-spec-v2/template/list/'
                        + name))
                tasks.append(self.__get_property_value())
                # Async request
                results = await asyncio.gather(*tasks)
                if None in results:
                    raise MIoTSpecError('init failed, None in result')
                std_libs = {
                    'devices': results[0],
                    'services': results[1],
                    'properties': results[2],
                    'events': results[3],
                    'actions': results[4],
                    'values': results[5],
                }
                # Get external std lib, Power by LM
                tasks.clear()
                for name in [
                    'device', 'service', 'property', 'event', 'action',
                        'property_value']:
                    tasks.append(MIoTHttp.get_json_async(
                        'https://cdn.cnbj1.fds.api.mi-img.com/res-conf/'
                        f'xiaomi-home/std_ex_{name}.json'))
                results = await asyncio.gather(*tasks)
                if results[0]:
                    for key, value in results[0].items():
                        if key in std_libs['devices']:
                            std_libs['devices'][key].update(value)
                        else:
                            std_libs['devices'][key] = value
                else:
                    _LOGGER.error('get external std lib failed, devices')
                if results[1]:
                    for key, value in results[1].items():
                        if key in std_libs['services']:
                            std_libs['services'][key].update(value)
                        else:
                            std_libs['services'][key] = value
                else:
                    _LOGGER.error('get external std lib failed, services')
                if results[2]:
                    for key, value in results[2].items():
                        if key in std_libs['properties']:
                            std_libs['properties'][key].update(value)
                        else:
                            std_libs['properties'][key] = value
                else:
                    _LOGGER.error('get external std lib failed, properties')
                if results[3]:
                    for key, value in results[3].items():
                        if key in std_libs['events']:
                            std_libs['events'][key].update(value)
                        else:
                            std_libs['events'][key] = value
                else:
                    _LOGGER.error('get external std lib failed, events')
                if results[4]:
                    for key, value in results[4].items():
                        if key in std_libs['actions']:
                            std_libs['actions'][key].update(value)
                        else:
                            std_libs['actions'][key] = value
                else:
                    _LOGGER.error('get external std lib failed, actions')
                if results[5]:
                    for key, value in results[5].items():
                        if key in std_libs['values']:
                            std_libs['values'][key].update(value)
                        else:
                            std_libs['values'][key] = value
                else:
                    _LOGGER.error(
                        'get external std lib failed, values')
                return std_libs
            except Exception as err:  # pylint: disable=broad-exception-caught
                _LOGGER.error(
                    'update spec std lib error, retry, %d, %s', index, err)
        return None

    async def __get_property_value(self) -> dict:
        reply = await MIoTHttp.get_json_async(
            url='https://miot-spec.org/miot-spec-v2'
            '/normalization/list/property_value')
        if reply is None or 'result' not in reply:
            raise MIoTSpecError('get property value failed')
        result = {}
        for item in reply['result']:
            if (
                not isinstance(item, dict)
                or 'normalization' not in item
                or 'description' not in item
                or 'proName' not in item
                or 'urn' not in item
            ):
                continue
            result[
                f'{item["urn"]}|{item["proName"]}|{item["normalization"]}'
            ] = {
                'zh-Hans': item['description'],
                'en': item['normalization']
            }
        return result

    async def __get_template_list(self, url: str) -> dict:
        reply = await MIoTHttp.get_json_async(url=url)
        if reply is None or 'result' not in reply:
            raise MIoTSpecError(f'get service failed, {url}')
        result: dict = {}
        for item in reply['result']:
            if (
                not isinstance(item, dict)
                or 'type' not in item
                or 'description' not in item
            ):
                continue
            if 'zh_cn' in item['description']:
                item['description']['zh-Hans'] = item['description'].pop(
                    'zh_cn')
            if 'zh_hk' in item['description']:
                item['description']['zh-Hant'] = item['description'].pop(
                    'zh_hk')
                item['description'].pop('zh_tw', None)
            elif 'zh_tw' in item['description']:
                item['description']['zh-Hant'] = item['description'].pop(
                    'zh_tw')
            result[item['type']] = item['description']
        return result


class _MIoTSpecBase:
    """MIoT SPEC base class."""
    iid: int
    type_: str
    description: str
    description_trans: str
    proprietary: bool
    need_filter: bool
    name: str
    icon: Optional[str]

    # External params
    platform: Optional[str]
    device_class: Any
    state_class: Any
    external_unit: Any

    spec_id: int

    def __init__(self, spec: dict) -> None:
        self.iid = spec['iid']
        self.type_ = spec['type']
        self.description = spec['description']

        self.description_trans = spec.get('description_trans', None)
        self.proprietary = spec.get('proprietary', False)
        self.need_filter = spec.get('need_filter', False)
        self.name = spec.get('name', 'xiaomi')
        self.icon = spec.get('icon', None)

        self.platform = None
        self.device_class = None
        self.state_class = None
        self.external_unit = None

        self.spec_id = hash(f'{self.type_}.{self.iid}')

    def __hash__(self) -> int:
        return self.spec_id

    def __eq__(self, value) -> bool:
        return self.spec_id == value.spec_id


class MIoTSpecProperty(_MIoTSpecBase):
    """MIoT SPEC property class."""
    unit: Optional[str]
    precision: int
    expr: Optional[str]

    _format_: Type
    _value_range: Optional[MIoTSpecValueRange]
    _value_list: Optional[MIoTSpecValueList]

    _access: list
    _writable: bool
    _readable: bool
    _notifiable: bool

    service: 'MIoTSpecService'

    def __init__(
            self,
            spec: dict,
            service: 'MIoTSpecService',
            format_: str,
            access: list,
            unit: Optional[str] = None,
            value_range: Optional[dict] = None,
            value_list: Optional[list[dict]] = None,
            precision: Optional[int] = None,
            expr: Optional[str] = None
    ) -> None:
        super().__init__(spec=spec)
        self.service = service
        self.format_ = format_
        self.access = access
        self.unit = unit
        self.value_range = value_range
        self.value_list = value_list
        self.precision = precision or 1
        self.expr = expr

        self.spec_id = hash(
            f'p.{self.name}.{self.service.iid}.{self.iid}')

    @property
    def format_(self) -> Type:
        return self._format_

    @format_.setter
    def format_(self, value: str) -> None:
        self._format_ = {
            'string': str,
            'str': str,
            'bool': bool,
            'float': float}.get(
            value, int)

    @property
    def access(self) -> list:
        return self._access

    @access.setter
    def access(self, value: list) -> None:
        self._access = value
        if isinstance(value, list):
            self._writable = 'write' in value
            self._readable = 'read' in value
            self._notifiable = 'notify' in value

    @property
    def writable(self) -> bool:
        return self._writable

    @property
    def readable(self) -> bool:
        return self._readable

    @property
    def notifiable(self):
        return self._notifiable

    @property
    def value_range(self) -> Optional[MIoTSpecValueRange]:
        return self._value_range

    @value_range.setter
    def value_range(self, value: Union[dict, list, None]) -> None:
        """Set value-range, precision."""
        if not value:
            self._value_range = None
            return
        self._value_range = MIoTSpecValueRange(value_range=value)
        if isinstance(value, list):
            self.precision = len(str(value[2]).split(
                '.')[1].rstrip('0')) if '.' in str(value[2]) else 0

    @property
    def value_list(self) -> Optional[MIoTSpecValueList]:
        return self._value_list

    @value_list.setter
    def value_list(
        self, value: Union[list[dict], MIoTSpecValueList, None]
    ) -> None:
        if not value:
            self._value_list = None
            return
        if isinstance(value, list):
            self._value_list = MIoTSpecValueList(value_list=value)
        elif isinstance(value, MIoTSpecValueList):
            self._value_list = value

    def eval_expr(self, src_value: Any) -> Any:
        if not self.expr:
            return src_value
        try:
            # pylint: disable=eval-used
            return eval(self.expr, {'src_value': src_value})
        except Exception as err:  # pylint: disable=broad-exception-caught
            _LOGGER.error(
                'eval expression error, %s, %s, %s, %s',
                self.iid, src_value, self.expr, err)
            return src_value

    def value_format(self, value: Any) -> Any:
        if value is None:
            return None
        if self.format_ == int:
            return int(value)
        if self.format_ == float:
            return round(value, self.precision)
        if self.format_ == bool:
            return bool(value in [True, 1, 'True', 'true', '1'])
        return value

    def dump(self) -> dict:
        return {
            'type': self.type_,
            'name': self.name,
            'iid': self.iid,
            'description': self.description,
            'description_trans': self.description_trans,
            'proprietary': self.proprietary,
            'need_filter': self.need_filter,
            'format': self.format_.__name__,
            'access': self._access,
            'unit': self.unit,
            'value_range': (
                self._value_range.dump() if self._value_range else None),
            'value_list': self._value_list.dump() if self._value_list else None,
            'precision': self.precision,
            'expr': self.expr,
            'icon': self.icon
        }


class MIoTSpecEvent(_MIoTSpecBase):
    """MIoT SPEC event class."""
    argument: list[MIoTSpecProperty]
    service: 'MIoTSpecService'

    def __init__(
        self, spec: dict, service: 'MIoTSpecService',
        argument: Optional[list[MIoTSpecProperty]] = None
    ) -> None:
        super().__init__(spec=spec)
        self.argument = argument or []
        self.service = service

        self.spec_id = hash(
            f'e.{self.name}.{self.service.iid}.{self.iid}')

    def dump(self) -> dict:
        return {
            'type': self.type_,
            'name': self.name,
            'iid': self.iid,
            'description': self.description,
            'description_trans': self.description_trans,
            'proprietary': self.proprietary,
            'argument': [prop.iid for prop in self.argument],
            'need_filter': self.need_filter
        }


class MIoTSpecAction(_MIoTSpecBase):
    """MIoT SPEC action class."""
    in_: list[MIoTSpecProperty]
    out: list[MIoTSpecProperty]
    service: 'MIoTSpecService'

    def __init__(
            self, spec: dict, service: 'MIoTSpecService',
            in_: Optional[list[MIoTSpecProperty]] = None,
            out: Optional[list[MIoTSpecProperty]] = None
    ) -> None:
        super().__init__(spec=spec)
        self.in_ = in_ or []
        self.out = out or []
        self.service = service

        self.spec_id = hash(
            f'a.{self.name}.{self.service.iid}.{self.iid}')

    def dump(self) -> dict:
        return {
            'type': self.type_,
            'name': self.name,
            'iid': self.iid,
            'description': self.description,
            'description_trans': self.description_trans,
            'in': [prop.iid for prop in self.in_],
            'out': [prop.iid for prop in self.out],
            'proprietary': self.proprietary,
            'need_filter': self.need_filter
        }


class MIoTSpecService(_MIoTSpecBase):
    """MIoT SPEC service class."""
    properties: list[MIoTSpecProperty]
    events: list[MIoTSpecEvent]
    actions: list[MIoTSpecAction]

    def __init__(self, spec: dict) -> None:
        super().__init__(spec=spec)
        self.properties = []
        self.events = []
        self.actions = []

    def dump(self) -> dict:
        return {
            'type': self.type_,
            'name': self.name,
            'iid': self.iid,
            'description': self.description,
            'description_trans': self.description_trans,
            'proprietary': self.proprietary,
            'properties': [prop.dump() for prop in self.properties],
            'events': [event.dump() for event in self.events],
            'actions': [action.dump() for action in self.actions],
            'need_filter': self.need_filter
        }


class MIoTSpecInstance:
    """MIoT SPEC instance class."""
    urn: str
    name: str
    # urn_name: str
    description: str
    description_trans: str
    services: list[MIoTSpecService]

    # External params
    platform: str
    device_class: Any
    icon: str

    def __init__(
        self, urn: str, name: str, description: str, description_trans: str
    ) -> None:
        self.urn = urn
        self.name = name
        self.description = description
        self.description_trans = description_trans
        self.services = []

    @staticmethod
    def load(specs: dict) -> 'MIoTSpecInstance':
        instance = MIoTSpecInstance(
            urn=specs['urn'],
            name=specs['name'],
            description=specs['description'],
            description_trans=specs['description_trans'])
        for service in specs['services']:
            spec_service = MIoTSpecService(spec=service)
            for prop in service['properties']:
                spec_prop = MIoTSpecProperty(
                    spec=prop,
                    service=spec_service,
                    format_=prop['format'],
                    access=prop['access'],
                    unit=prop['unit'],
                    value_range=prop['value_range'],
                    value_list=prop['value_list'],
                    precision=prop.get('precision', None),
                    expr=prop.get('expr', None))
                spec_service.properties.append(spec_prop)
            for event in service['events']:
                spec_event = MIoTSpecEvent(
                    spec=event, service=spec_service)
                arg_list: list[MIoTSpecProperty] = []
                for piid in event['argument']:
                    for prop in spec_service.properties:
                        if prop.iid == piid:
                            arg_list.append(prop)
                            break
                spec_event.argument = arg_list
                spec_service.events.append(spec_event)
            for action in service['actions']:
                spec_action = MIoTSpecAction(
                    spec=action, service=spec_service, in_=action['in'])
                in_list: list[MIoTSpecProperty] = []
                for piid in action['in']:
                    for prop in spec_service.properties:
                        if prop.iid == piid:
                            in_list.append(prop)
                            break
                spec_action.in_ = in_list
                out_list: list[MIoTSpecProperty] = []
                for piid in action['out']:
                    for prop in spec_service.properties:
                        if prop.iid == piid:
                            out_list.append(prop)
                            break
                spec_action.out = out_list
                spec_service.actions.append(spec_action)
            instance.services.append(spec_service)
        return instance

    def dump(self) -> dict:
        return {
            'urn': self.urn,
            'name': self.name,
            'description': self.description,
            'description_trans': self.description_trans,
            'services': [service.dump() for service in self.services]
        }


class _MIoTSpecMultiLang:
    """MIoT SPEC multi lang class."""
    # pylint: disable=broad-exception-caught
    _DOMAIN: str = 'miot_specs_multi_lang'
    _lang: str
    _storage: MIoTStorage
    _main_loop: asyncio.AbstractEventLoop

    _custom_cache: dict[str, dict]
    _current_data: Optional[dict[str, str]]

    def __init__(
        self, lang: Optional[str],
        storage: MIoTStorage,
        loop: Optional[asyncio.AbstractEventLoop] = None
    ) -> None:
        self._lang = lang or DEFAULT_INTEGRATION_LANGUAGE
        self._storage = storage
        self._main_loop = loop or asyncio.get_running_loop()

        self._custom_cache = {}
        self._current_data = None

    async def set_spec_async(self, urn: str) -> None:
        if urn in self._custom_cache:
            self._current_data = self._custom_cache[urn]
            return

        trans_cache: dict[str, str] = {}
        trans_cloud: dict = {}
        trans_local: dict = {}
        # Get multi lang from cloud
        try:
            trans_cloud = await self.__get_multi_lang_async(urn)
            if self._lang == 'zh-Hans':
                # Simplified Chinese
                trans_cache = trans_cloud.get('zh_cn', {})
            elif self._lang == 'zh-Hant':
                # Traditional Chinese, zh_hk or zh_tw
                trans_cache = trans_cloud.get('zh_hk', {})
                if not trans_cache:
                    trans_cache = trans_cloud.get('zh_tw', {})
            else:
                trans_cache = trans_cloud.get(self._lang, {})
        except Exception as err:
            trans_cloud = {}
            _LOGGER.info('get multi lang from cloud failed, %s, %s', urn, err)
        # Get multi lang from local
        try:
            trans_local = await self._storage.load_async(
                domain=self._DOMAIN, name=urn, type_=dict)  # type: ignore
            if (
                isinstance(trans_local, dict)
                and self._lang in trans_local
            ):
                trans_cache.update(trans_local[self._lang])
        except Exception as err:
            trans_local = {}
            _LOGGER.info('get multi lang from local failed, %s, %s', urn, err)
        # Default language
        if not trans_cache:
            if trans_cloud and DEFAULT_INTEGRATION_LANGUAGE in trans_cloud:
                trans_cache = trans_cloud[DEFAULT_INTEGRATION_LANGUAGE]
            if trans_local and DEFAULT_INTEGRATION_LANGUAGE in trans_local:
                trans_cache.update(
                    trans_local[DEFAULT_INTEGRATION_LANGUAGE])
        trans_data: dict[str, str] = {}
        for tag, value in trans_cache.items():
            if value is None or value.strip() == '':
                continue
            # The dict key is like:
            # 'service:002:property:001:valuelist:000' or
            # 'service:002:property:001' or 'service:002'
            strs: list = tag.split(':')
            strs_len = len(strs)
            if strs_len == 2:
                trans_data[f's:{int(strs[1])}'] = value
            elif strs_len == 4:
                type_ = 'p' if strs[2] == 'property' else (
                    'a' if strs[2] == 'action' else 'e')
                trans_data[
                    f'{type_}:{int(strs[1])}:{int(strs[3])}'
                ] = value
            elif strs_len == 6:
                trans_data[
                    f'v:{int(strs[1])}:{int(strs[3])}:{int(strs[5])}'
                ] = value

        self._custom_cache[urn] = trans_data
        self._current_data = trans_data

    def translate(self, key: str) -> Optional[str]:
        if not self._current_data:
            return None
        return self._current_data.get(key, None)

    async def __get_multi_lang_async(self, urn: str) -> dict:
        res_trans = await MIoTHttp.get_json_async(
            url='https://miot-spec.org/instance/v2/multiLanguage',
            params={'urn': urn})
        if (
            not isinstance(res_trans, dict)
            or 'data' not in res_trans
            or not isinstance(res_trans['data'], dict)
        ):
            raise MIoTSpecError('invalid translation data')
        return res_trans['data']


class _SpecBoolTranslation:
    """
    Boolean value translation.
    """
    _BOOL_TRANS_FILE = 'specs/bool_trans.yaml'
    _main_loop: asyncio.AbstractEventLoop
    _lang: str
    _data: Optional[dict[str, list]]
    _data_default: Optional[list[dict]]

    def __init__(
        self, lang: str, loop: Optional[asyncio.AbstractEventLoop] = None
    ) -> None:
        self._main_loop = loop or asyncio.get_event_loop()
        self._lang = lang
        self._data = None
        self._data_default = None

    async def init_async(self) -> None:
        if isinstance(self._data, dict):
            return
        data = None
        self._data = {}
        try:
            data = await self._main_loop.run_in_executor(
                None, load_yaml_file,
                os.path.join(
                    os.path.dirname(os.path.abspath(__file__)),
                    self._BOOL_TRANS_FILE))
        except Exception as err:  # pylint: disable=broad-exception-caught
            _LOGGER.error('bool trans, load file error, %s', err)
            return
        # Check if the file is a valid file
        if (
            not isinstance(data, dict)
            or 'data' not in data
            or not isinstance(data['data'], dict)
            or 'translate' not in data
            or not isinstance(data['translate'], dict)
        ):
            _LOGGER.error('bool trans, valid file')
            return

        if 'default' in data['translate']:
            data_default = (
                data['translate']['default'].get(self._lang, None)
                or data['translate']['default'].get(
                    DEFAULT_INTEGRATION_LANGUAGE, None))
            if data_default:
                self._data_default = [
                    {'value': True, 'description': data_default['true']},
                    {'value': False, 'description': data_default['false']}
                ]

        for urn, key in data['data'].items():
            if key not in data['translate']:
                _LOGGER.error('bool trans, unknown key, %s, %s', urn, key)
                continue
            trans_data = (
                data['translate'][key].get(self._lang, None)
                or data['translate'][key].get(
                    DEFAULT_INTEGRATION_LANGUAGE, None))
            if trans_data:
                self._data[urn] = [
                    {'value': True, 'description': trans_data['true']},
                    {'value': False, 'description': trans_data['false']}
                ]

    async def deinit_async(self) -> None:
        self._data = None
        self._data_default = None

    async def translate_async(self, urn: str) -> Optional[list[dict]]:
        """
        MUST call init_async() before calling this method.
        [
            {'value': True, 'description': 'True'},
            {'value': False, 'description': 'False'}
        ]
        """
        if not self._data or urn not in self._data:
            return self._data_default
        return self._data[urn]


class _SpecFilter:
    """
    MIoT-Spec-V2 filter for entity conversion.
    """
    _SPEC_FILTER_FILE = 'specs/spec_filter.yaml'
    _main_loop: asyncio.AbstractEventLoop
    _data: Optional[dict[str, dict[str, set]]]
    _cache: Optional[dict]

    def __init__(self, loop: Optional[asyncio.AbstractEventLoop]) -> None:
        self._main_loop = loop or asyncio.get_event_loop()
        self._data = None
        self._cache = None

    async def init_async(self) -> None:
        if isinstance(self._data, dict):
            return
        filter_data = None
        self._data = {}
        try:
            filter_data = await self._main_loop.run_in_executor(
                None, load_yaml_file,
                os.path.join(
                    os.path.dirname(os.path.abspath(__file__)),
                    self._SPEC_FILTER_FILE))
        except Exception as err:  # pylint: disable=broad-exception-caught
            _LOGGER.error('spec filter, load file error, %s', err)
            return
        if not isinstance(filter_data, dict):
            _LOGGER.error('spec filter, invalid spec filter content')
            return
        for values in list(filter_data.values()):
            if not isinstance(values, dict):
                _LOGGER.error('spec filter, invalid spec filter data')
                return
            for value in values.values():
                if not isinstance(value, list):
                    _LOGGER.error('spec filter, invalid spec filter rules')
                    return

        self._data = filter_data

    async def deinit_async(self) -> None:
        self._cache = None
        self._data = None

    async def set_spec_spec(self, urn_key: str) -> None:
        """MUST call init_async() first."""
        if not self._data:
            return
        self._cache = self._data.get(urn_key, None)

    def filter_service(self, siid: int) -> bool:
        """Filter service by siid.
        MUST call init_async() and set_spec_spec() first."""
        if (
            self._cache
            and 'services' in self._cache
            and (
                str(siid) in self._cache['services']
                or '*' in self._cache['services'])
        ):
            return True

        return False

    def filter_property(self, siid: int, piid: int) -> bool:
        """Filter property by piid.
        MUST call init_async() and set_spec_spec() first."""
        if (
            self._cache
            and 'properties' in self._cache
            and (
                f'{siid}.{piid}' in self._cache['properties']
                or f'{siid}.*' in self._cache['properties'])
        ):
            return True
        return False

    def filter_event(self, siid: int, eiid: int) -> bool:
        """Filter event by eiid.
        MUST call init_async() and set_spec_spec() first."""
        if (
            self._cache
            and 'events' in self._cache
            and (
                f'{siid}.{eiid}' in self._cache['events']
                or f'{siid}.*' in self._cache['events']
            )
        ):
            return True
        return False

    def filter_action(self, siid: int, aiid: int) -> bool:
        """"Filter action by aiid.
        MUST call init_async() and set_spec_spec() first."""
        if (
            self._cache
            and 'actions' in self._cache
            and (
                f'{siid}.{aiid}' in self._cache['actions']
                or f'{siid}.*' in self._cache['actions'])
        ):
            return True
        return False


class _SpecModify:
    """MIoT-Spec-V2 modify for entity conversion."""
    _SPEC_MODIFY_FILE = 'specs/spec_modify.yaml'
    _main_loop: asyncio.AbstractEventLoop
    _data: Optional[dict]
    _selected: Optional[dict]

    def __init__(
        self, loop: Optional[asyncio.AbstractEventLoop] = None
    ) -> None:
        self._main_loop = loop or asyncio.get_running_loop()
        self._data = None

    async def init_async(self) -> None:
        if isinstance(self._data, dict):
            return
        modify_data = None
        self._data = {}
        self._selected = None
        try:
            modify_data = await self._main_loop.run_in_executor(
                None, load_yaml_file,
                os.path.join(
                    os.path.dirname(os.path.abspath(__file__)),
                    self._SPEC_MODIFY_FILE))
        except Exception as err:  # pylint: disable=broad-exception-caught
            _LOGGER.error('spec modify, load file error, %s', err)
            return
        if not isinstance(modify_data, dict):
            _LOGGER.error('spec modify, invalid spec modify content')
            return
        for key, value in modify_data.items():
            if not isinstance(key, str) or not isinstance(value, (dict, str)):
                _LOGGER.error('spec modify, invalid spec modify data')
                return

        self._data = modify_data

    async def deinit_async(self) -> None:
        self._data = None
        self._selected = None

    async def set_spec_async(self, urn: str) -> None:
        if not self._data:
            return
        self._selected = self._data.get(urn, None)
        if isinstance(self._selected, str):
            return await self.set_spec_async(urn=self._selected)

    def get_prop_unit(self, siid: int, piid: int) -> Optional[str]:
        return self.__get_prop_item(siid=siid, piid=piid, key='unit')

    def get_prop_expr(self, siid: int, piid: int) -> Optional[str]:
        return self.__get_prop_item(siid=siid, piid=piid, key='expr')

    def get_prop_icon(self, siid: int, piid: int) -> Optional[str]:
        return self.__get_prop_item(siid=siid, piid=piid, key='icon')

    def get_prop_access(self, siid: int, piid: int) -> Optional[list]:
        access = self.__get_prop_item(siid=siid, piid=piid, key='access')
        if not isinstance(access, list):
            return None
        return access

    def get_prop_value_range(self, siid: int, piid: int) -> Optional[list]:
        value_range = self.__get_prop_item(siid=siid, piid=piid,
                                           key='value-range')
        if not isinstance(value_range, list):
            return None
        return value_range

    def __get_prop_item(self, siid: int, piid: int, key: str) -> Optional[str]:
        if not self._selected:
            return None
        prop = self._selected.get(f'prop.{siid}.{piid}', None)
        if not prop:
            return None
        return prop.get(key, None)


class MIoTSpecParser:
    """MIoT SPEC parser."""
    # pylint: disable=inconsistent-quotes
    VERSION: int = 1
    _DOMAIN: str = 'miot_specs'
    _lang: str
    _storage: MIoTStorage
    _main_loop: asyncio.AbstractEventLoop

    _std_lib: _SpecStdLib
    _multi_lang: _MIoTSpecMultiLang
    _bool_trans: _SpecBoolTranslation
    _spec_filter: _SpecFilter
    _spec_modify: _SpecModify

    _init_done: bool

    def __init__(
        self, lang: Optional[str],
        storage: MIoTStorage,
        loop: Optional[asyncio.AbstractEventLoop] = None
    ) -> None:
        self._lang = lang or DEFAULT_INTEGRATION_LANGUAGE
        self._storage = storage
        self._main_loop = loop or asyncio.get_running_loop()
        self._std_lib = _SpecStdLib(lang=self._lang)
        self._multi_lang = _MIoTSpecMultiLang(
            lang=self._lang, storage=self._storage, loop=self._main_loop)
        self._bool_trans = _SpecBoolTranslation(
            lang=self._lang, loop=self._main_loop)
        self._spec_filter = _SpecFilter(loop=self._main_loop)
        self._spec_modify = _SpecModify(loop=self._main_loop)

        self._init_done = False

    async def init_async(self) -> None:
        if self._init_done is True:
            return
        await self._bool_trans.init_async()
        await self._spec_filter.init_async()
        await self._spec_modify.init_async()
        std_lib_cache = await self._storage.load_async(
            domain=self._DOMAIN, name='spec_std_lib', type_=dict)
        if (
            isinstance(std_lib_cache, dict)
            and 'data' in std_lib_cache
            and 'ts' in std_lib_cache
            and isinstance(std_lib_cache['ts'], int)
            and int(time.time()) - std_lib_cache['ts'] <
                SPEC_STD_LIB_EFFECTIVE_TIME
        ):
            # Use the cache if the update time is less than 14 day
            _LOGGER.debug(
                'use local spec std cache, ts->%s', std_lib_cache['ts'])
            self._std_lib.load(std_lib_cache['data'])
            self._init_done = True
            return
        # Update spec std lib
        if await self._std_lib.refresh_async():
            if not await self._storage.save_async(
                domain=self._DOMAIN, name='spec_std_lib',
                data={
                    'data': self._std_lib.dump(),
                    'ts': int(time.time())
                }
            ):
                _LOGGER.error('save spec std lib failed')
        else:
            if isinstance(std_lib_cache, dict) and 'data' in std_lib_cache:
                self._std_lib.load(std_lib_cache['data'])
                _LOGGER.info('get spec std lib failed, use local cache')
            else:
                _LOGGER.error('load spec std lib failed')
        self._init_done = True

    async def deinit_async(self) -> None:
        self._init_done = False
        # self._std_lib.deinit()
        await self._bool_trans.deinit_async()
        await self._spec_filter.deinit_async()
        await self._spec_modify.deinit_async()

    async def parse(
        self, urn: str, skip_cache: bool = False,
    ) -> Optional[MIoTSpecInstance]:
        """MUST await init first !!!"""
        if not skip_cache:
            cache_result = await self.__cache_get(urn=urn)
            if isinstance(cache_result, dict):
                _LOGGER.debug('get from cache, %s', urn)
                return MIoTSpecInstance.load(specs=cache_result)
        # Retry three times
        for index in range(3):
            try:
                return await self.__parse(urn=urn)
            except Exception as err:  # pylint: disable=broad-exception-caught
                _LOGGER.error(
                    'parse error, retry, %d, %s, %s', index, urn, err)
        return None

    async def refresh_async(self, urn_list: list[str]) -> int:
        """MUST await init first !!!"""
        if not urn_list:
            return False
        if await self._std_lib.refresh_async():
            if not await self._storage.save_async(
                domain=self._DOMAIN, name='spec_std_lib',
                data={
                    'data': self._std_lib.dump(),
                    'ts': int(time.time())
                }
            ):
                _LOGGER.error('save spec std lib failed')
        else:
            raise MIoTSpecError('get spec std lib failed')
        success_count = 0
        for index in range(0, len(urn_list), 5):
            batch = urn_list[index:index+5]
            task_list = [self._main_loop.create_task(
                self.parse(urn=urn, skip_cache=True)) for urn in batch]
            results = await asyncio.gather(*task_list)
            success_count += sum(1 for result in results if result is not None)
        return success_count

    async def __cache_get(self, urn: str) -> Optional[dict]:
        if platform.system() == 'Windows':
            urn = urn.replace(':', '_')
        return await self._storage.load_async(
            domain=self._DOMAIN,
            name=f'{urn}_{self._lang}',
            type_=dict)  # type: ignore

    async def __cache_set(self, urn: str, data: dict) -> bool:
        if platform.system() == 'Windows':
            urn = urn.replace(':', '_')
        return await self._storage.save_async(
            domain=self._DOMAIN, name=f'{urn}_{self._lang}', data=data)

    async def __get_instance(self, urn: str) -> Optional[dict]:
        return await MIoTHttp.get_json_async(
            url='https://miot-spec.org/miot-spec-v2/instance',
            params={'type': urn})

    async def __parse(self, urn: str) -> MIoTSpecInstance:
        _LOGGER.debug('parse urn, %s', urn)
        # Load spec instance
        instance = await self.__get_instance(urn=urn)
        if (
            not isinstance(instance, dict)
            or 'type' not in instance
            or 'description' not in instance
            or 'services' not in instance
        ):
            raise MIoTSpecError(f'invalid urn instance, {urn}')
        urn_strs: list[str] = urn.split(':')
        urn_key: str = ':'.join(urn_strs[:6])
        # Set translation cache
        await self._multi_lang.set_spec_async(urn=urn)
        # Set spec filter
        await self._spec_filter.set_spec_spec(urn_key=urn_key)
        # Set spec modify
        await self._spec_modify.set_spec_async(urn=urn)
        # Parse device type
        spec_instance: MIoTSpecInstance = MIoTSpecInstance(
            urn=urn, name=urn_strs[3],
            description=instance['description'],
            description_trans=(
                self._std_lib.device_translate(key=':'.join(urn_strs[:5]))
                or instance['description']
                or urn_strs[3]))
        # Parse services
        for service in instance.get('services', []):
            if (
                'iid' not in service
                or 'type' not in service
                or 'description' not in service
            ):
                _LOGGER.error('invalid service, %s, %s', urn, service)
                continue
            type_strs: list[str] = service['type'].split(':')
            if type_strs[3] == 'device-information':
                # Ignore device-information service
                continue
            spec_service: MIoTSpecService = MIoTSpecService(spec=service)
            spec_service.name = type_strs[3]
            # Filter spec service
            spec_service.need_filter = self._spec_filter.filter_service(
                siid=service['iid'])
            if type_strs[1] != 'miot-spec-v2':
                spec_service.proprietary = True
            spec_service.description_trans = (
                self._multi_lang.translate(f's:{service["iid"]}')
                or self._std_lib.service_translate(key=':'.join(type_strs[:5]))
                or service['description']
                or spec_service.name
            )
            # Parse service property
            for property_ in service.get('properties', []):
                if (
                    'iid' not in property_
                    or 'type' not in property_
                    or 'description' not in property_
                    or 'format' not in property_
                    or 'access' not in property_
                ):
                    continue
                p_type_strs: list[str] = property_['type'].split(':')
                # Handle special property.unit
                unit = property_.get('unit', None)
                spec_prop: MIoTSpecProperty = MIoTSpecProperty(
                    spec=property_,
                    service=spec_service,
                    format_=property_['format'],
                    access=property_['access'],
                    unit=unit if unit != 'none' else None)
                spec_prop.name = p_type_strs[3]
                # Filter spec property
                spec_prop.need_filter = (
                    spec_service.need_filter
                    or self._spec_filter.filter_property(
                        siid=service['iid'], piid=property_['iid']))
                if p_type_strs[1] != 'miot-spec-v2':
                    spec_prop.proprietary = spec_service.proprietary or True
                spec_prop.description_trans = (
                    self._multi_lang.translate(
                        f'p:{service["iid"]}:{property_["iid"]}')
                    or self._std_lib.property_translate(
                        key=':'.join(p_type_strs[:5]))
                    or property_['description']
                    or spec_prop.name)
                if 'value-range' in property_:
                    spec_prop.value_range = property_['value-range']
                elif 'value-list' in property_:
                    v_list: list[dict] = property_['value-list']
                    for index, v in enumerate(v_list):
                        if v['description'].strip() == '':
                            v['description'] = f'v_{v["value"]}'
                        v['name'] = v['description']
                        v['description'] = (
                            self._multi_lang.translate(
                                f'v:{service["iid"]}:{property_["iid"]}:'
                                f'{index}')
                            or self._std_lib.value_translate(
                                key=f'{type_strs[:5]}|{p_type_strs[3]}|'
                                f'{v["description"]}')
                            or v['name'])
                    spec_prop.value_list = MIoTSpecValueList.from_spec(v_list)
                elif property_['format'] == 'bool':
                    v_tag = ':'.join(p_type_strs[:5])
                    v_descriptions = (
                        await self._bool_trans.translate_async(urn=v_tag))
                    if v_descriptions:
                        # bool without value-list.name
                        spec_prop.value_list = v_descriptions
                # Prop modify
                spec_prop.unit = self._spec_modify.get_prop_unit(
                    siid=service['iid'], piid=property_['iid']
                ) or spec_prop.unit
                spec_prop.expr = self._spec_modify.get_prop_expr(
                    siid=service['iid'], piid=property_['iid'])
                spec_prop.icon = self._spec_modify.get_prop_icon(
                    siid=service['iid'], piid=property_['iid'])
                spec_service.properties.append(spec_prop)
                custom_access = self._spec_modify.get_prop_access(
                    siid=service['iid'], piid=property_['iid'])
                if custom_access:
                    spec_prop.access = custom_access
                custom_range = self._spec_modify.get_prop_value_range(
                    siid=service['iid'], piid=property_['iid'])
                if custom_range:
                    spec_prop.value_range = custom_range
            # Parse service event
            for event in service.get('events', []):
                if (
                    'iid' not in event
                    or 'type' not in event
                    or 'description' not in event
                    or 'arguments' not in event
                ):
                    continue
                e_type_strs: list[str] = event['type'].split(':')
                spec_event: MIoTSpecEvent = MIoTSpecEvent(
                    spec=event, service=spec_service)
                spec_event.name = e_type_strs[3]
                # Filter spec event
                spec_event.need_filter = (
                    spec_service.need_filter
                    or self._spec_filter.filter_event(
                        siid=service['iid'], eiid=event['iid']))
                if e_type_strs[1] != 'miot-spec-v2':
                    spec_event.proprietary = spec_service.proprietary or True
                spec_event.description_trans = (
                    self._multi_lang.translate(
                        f'e:{service["iid"]}:{event["iid"]}')
                    or self._std_lib.event_translate(
                        key=':'.join(e_type_strs[:5]))
                    or event['description']
                    or spec_event.name
                )
                arg_list: list[MIoTSpecProperty] = []
                for piid in event['arguments']:
                    for prop in spec_service.properties:
                        if prop.iid == piid:
                            arg_list.append(prop)
                            break
                spec_event.argument = arg_list
                spec_service.events.append(spec_event)
            # Parse service action
            for action in service.get('actions', []):
                if (
                    'iid' not in action
                    or 'type' not in action
                    or 'description' not in action
                    or 'in' not in action
                ):
                    continue
                a_type_strs: list[str] = action['type'].split(':')
                spec_action: MIoTSpecAction = MIoTSpecAction(
                    spec=action, service=spec_service)
                spec_action.name = a_type_strs[3]
                # Filter spec action
                spec_action.need_filter = (
                    spec_service.need_filter
                    or self._spec_filter.filter_action(
                        siid=service['iid'], aiid=action['iid']))
                if a_type_strs[1] != 'miot-spec-v2':
                    spec_action.proprietary = spec_service.proprietary or True
                spec_action.description_trans = (
                    self._multi_lang.translate(
                        f'a:{service["iid"]}:{action["iid"]}')
                    or self._std_lib.action_translate(
                        key=':'.join(a_type_strs[:5]))
                    or action['description']
                    or spec_action.name
                )
                in_list: list[MIoTSpecProperty] = []
                for piid in action['in']:
                    for prop in spec_service.properties:
                        if prop.iid == piid:
                            in_list.append(prop)
                            break
                spec_action.in_ = in_list
                out_list: list[MIoTSpecProperty] = []
                for piid in action['out']:
                    for prop in spec_service.properties:
                        if prop.iid == piid:
                            out_list.append(prop)
                            break
                spec_action.out = out_list
                spec_service.actions.append(spec_action)
            spec_instance.services.append(spec_service)

        await self.__cache_set(urn=urn, data=spec_instance.dump())
        return spec_instance
