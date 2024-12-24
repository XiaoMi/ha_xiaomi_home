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
import json
import platform
import time
from typing import Any, Optional
from urllib.parse import urlencode
from urllib.request import Request, urlopen
import logging

# pylint: disable=relative-beyond-top-level
from .const import DEFAULT_INTEGRATION_LANGUAGE, SPEC_STD_LIB_EFFECTIVE_TIME
from .miot_error import MIoTSpecError
from .miot_storage import (
    MIoTStorage,
    SpecBoolTranslation,
    SpecFilter,
    SpecMultiLang)

_LOGGER = logging.getLogger(__name__)


class MIoTSpecBase:
    """MIoT SPEC base class."""
    iid: int
    type_: str
    description: str
    description_trans: Optional[str]
    proprietary: bool
    need_filter: bool
    name: Optional[str]

    # External params
    platform: str
    device_class: Any
    state_class: Any
    icon: str
    external_unit: Any

    spec_id: str

    def __init__(self, spec: dict) -> None:
        self.iid = spec['iid']
        self.type_ = spec['type']
        self.description = spec['description']

        self.description_trans = spec.get('description_trans', None)
        self.proprietary = spec.get('proprietary', False)
        self.need_filter = spec.get('need_filter', False)
        self.name = spec.get('name', None)

        self.platform = None
        self.device_class = None
        self.state_class = None
        self.icon = None
        self.external_unit = None

        self.spec_id = hash(f'{self.type_}.{self.iid}')

    def __hash__(self) -> int:
        return self.spec_id

    def __eq__(self, value: object) -> bool:
        return self.spec_id == value.spec_id


class MIoTSpecProperty(MIoTSpecBase):
    """MIoT SPEC property class."""
    format_: str
    precision: int
    unit: str

    value_range: list
    value_list: list[dict]

    _access: list
    _writable: bool
    _readable: bool
    _notifiable: bool

    service: MIoTSpecBase

    def __init__(
            self, spec: dict, service: MIoTSpecBase = None,
            format_: str = None, access: list = None,
            unit: str = None, value_range: list = None,
            value_list: list[dict] = None, precision: int = 0
    ) -> None:
        super().__init__(spec=spec)
        self.service = service
        self.format_ = format_
        self.access = access
        self.unit = unit
        self.value_range = value_range
        self.value_list = value_list
        self.precision = precision

        self.spec_id = hash(
            f'p.{self.name}.{self.service.iid}.{self.iid}')

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

    def value_format(self, value: Any) -> Any:
        if value is None:
            return None
        if self.format_ == 'int':
            return int(value)
        if self.format_ == 'float':
            return round(value, self.precision)
        if self.format_ == 'bool':
            return bool(value in [True, 1, 'true', '1'])
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
            'format': self.format_,
            'access': self._access,
            'unit': self.unit,
            'value_range': self.value_range,
            'value_list': self.value_list,
            'precision': self.precision
        }


class MIoTSpecEvent(MIoTSpecBase):
    """MIoT SPEC event class."""
    argument: list[MIoTSpecProperty]
    service: MIoTSpecBase

    def __init__(
        self, spec: dict, service: MIoTSpecBase = None,
        argument: list[MIoTSpecProperty] = None
    ) -> None:
        super().__init__(spec=spec)
        self.argument = argument
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
            'need_filter': self.need_filter,
            'argument': [prop.iid for prop in self.argument],
        }


class MIoTSpecAction(MIoTSpecBase):
    """MIoT SPEC action class."""
    in_: list[MIoTSpecProperty]
    out: list[MIoTSpecProperty]
    service: MIoTSpecBase

    def __init__(
            self, spec: dict, service: MIoTSpecBase = None,
            in_: list[MIoTSpecProperty] = None,
            out: list[MIoTSpecProperty] = None
    ) -> None:
        super().__init__(spec=spec)
        self.in_ = in_
        self.out = out
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
            'proprietary': self.proprietary,
            'need_filter': self.need_filter,
            'in': [prop.iid for prop in self.in_],
            'out': [prop.iid for prop in self.out]
        }


class MIoTSpecService(MIoTSpecBase):
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
            'need_filter': self.need_filter,
            'events': [event.dump() for event in self.events],
            'actions': [action.dump() for action in self.actions],
        }


# @dataclass
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
        self, urn: str = None, name: str = None,
        description: str = None, description_trans: str = None
    ) -> None:
        self.urn = urn
        self.name = name
        self.description = description
        self.description_trans = description_trans
        self.services = []

    def load(self, specs: dict) -> 'MIoTSpecInstance':
        self.urn = specs['urn']
        self.name = specs['name']
        self.description = specs['description']
        self.description_trans = specs['description_trans']
        self.services = []
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
                    precision=prop.get('precision', 0))
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
            self.services.append(spec_service)
        return self

    def dump(self) -> dict:
        return {
            'urn': self.urn,
            'name': self.name,
            'description': self.description,
            'description_trans': self.description_trans,
            'services': [service.dump() for service in self.services]
        }


class SpecStdLib:
    """MIoT-Spec-V2 standard library."""
    _lang: str
    _spec_std_lib: Optional[dict[str, dict[str, dict[str, str]]]]

    def __init__(self, lang: str) -> None:
        self._lang = lang
        self._spec_std_lib = None

    def init(self, std_lib: dict[str, dict[str, str]]) -> None:
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
        self._spec_std_lib = std_lib

    def deinit(self) -> None:
        self._spec_std_lib = None

    def device_translate(self, key: str) -> Optional[str]:
        if not self._spec_std_lib or key not in self._spec_std_lib['devices']:
            return None
        if self._lang not in self._spec_std_lib['devices'][key]:
            return self._spec_std_lib['devices'][key].get(
                DEFAULT_INTEGRATION_LANGUAGE, None)
        return self._spec_std_lib['devices'][key][self._lang]

    def service_translate(self, key: str) -> Optional[str]:
        if not self._spec_std_lib or key not in self._spec_std_lib['services']:
            return None
        if self._lang not in self._spec_std_lib['services'][key]:
            return self._spec_std_lib['services'][key].get(
                DEFAULT_INTEGRATION_LANGUAGE, None)
        return self._spec_std_lib['services'][key][self._lang]

    def property_translate(self, key: str) -> Optional[str]:
        if (
            not self._spec_std_lib
            or key not in self._spec_std_lib['properties']
        ):
            return None
        if self._lang not in self._spec_std_lib['properties'][key]:
            return self._spec_std_lib['properties'][key].get(
                DEFAULT_INTEGRATION_LANGUAGE, None)
        return self._spec_std_lib['properties'][key][self._lang]

    def event_translate(self, key: str) -> Optional[str]:
        if not self._spec_std_lib or key not in self._spec_std_lib['events']:
            return None
        if self._lang not in self._spec_std_lib['events'][key]:
            return self._spec_std_lib['events'][key].get(
                DEFAULT_INTEGRATION_LANGUAGE, None)
        return self._spec_std_lib['events'][key][self._lang]

    def action_translate(self, key: str) -> Optional[str]:
        if not self._spec_std_lib or key not in self._spec_std_lib['actions']:
            return None
        if self._lang not in self._spec_std_lib['actions'][key]:
            return self._spec_std_lib['actions'][key].get(
                DEFAULT_INTEGRATION_LANGUAGE, None)
        return self._spec_std_lib['actions'][key][self._lang]

    def value_translate(self, key: str) -> Optional[str]:
        if not self._spec_std_lib or key not in self._spec_std_lib['values']:
            return None
        if self._lang not in self._spec_std_lib['values'][key]:
            return self._spec_std_lib['values'][key].get(
                DEFAULT_INTEGRATION_LANGUAGE, None)
        return self._spec_std_lib['values'][key][self._lang]

    def dump(self) -> dict[str, dict[str, str]]:
        return self._spec_std_lib


class MIoTSpecParser:
    """MIoT SPEC parser."""
    # pylint: disable=inconsistent-quotes
    VERSION: int = 1
    DOMAIN: str = 'miot_specs'
    _lang: str
    _storage: MIoTStorage
    _main_loop: asyncio.AbstractEventLoop

    _init_done: bool
    _ram_cache: dict

    _std_lib: SpecStdLib
    _bool_trans: SpecBoolTranslation
    _multi_lang: SpecMultiLang
    _spec_filter: SpecFilter

    def __init__(
        self, lang: str = DEFAULT_INTEGRATION_LANGUAGE,
        storage: MIoTStorage = None,
        loop: Optional[asyncio.AbstractEventLoop] = None
    ) -> None:
        self._lang = lang
        self._storage = storage
        self._main_loop = loop or asyncio.get_running_loop()

        self._init_done = False
        self._ram_cache = {}

        self._std_lib = SpecStdLib(lang=self._lang)
        self._bool_trans = SpecBoolTranslation(
            lang=self._lang, loop=self._main_loop)
        self._multi_lang = SpecMultiLang(lang=self._lang, loop=self._main_loop)
        self._spec_filter = SpecFilter(loop=self._main_loop)

    async def init_async(self) -> None:
        if self._init_done is True:
            return
        await self._bool_trans.init_async()
        await self._multi_lang.init_async()
        await self._spec_filter.init_async()
        std_lib_cache: dict = None
        if self._storage:
            std_lib_cache: dict = await self._storage.load_async(
                domain=self.DOMAIN, name='spec_std_lib', type_=dict)
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
                self._std_lib.init(std_lib_cache['data'])
                self._init_done = True
                return
        # Update spec std lib
        spec_lib_new = await self.__request_spec_std_lib_async()
        if spec_lib_new:
            self._std_lib.init(spec_lib_new)
            if self._storage:
                if not await self._storage.save_async(
                        domain=self.DOMAIN, name='spec_std_lib',
                        data={
                            'data': self._std_lib.dump(),
                            'ts': int(time.time())
                        }
                ):
                    _LOGGER.error('save spec std lib failed')
        else:
            if std_lib_cache:
                self._std_lib.init(std_lib_cache['data'])
                _LOGGER.error('get spec std lib failed, use local cache')
            else:
                _LOGGER.error('get spec std lib failed')
        self._init_done = True

    async def deinit_async(self) -> None:
        self._init_done = False
        self._std_lib.deinit()
        await self._bool_trans.deinit_async()
        await self._multi_lang.deinit_async()
        await self._spec_filter.deinit_async()
        self._ram_cache.clear()

    async def parse(
        self, urn: str, skip_cache: bool = False,
    ) -> MIoTSpecInstance:
        """MUST await init first !!!"""
        if not skip_cache:
            cache_result = await self.__cache_get(urn=urn)
            if isinstance(cache_result, dict):
                _LOGGER.debug('get from cache, %s', urn)
                return MIoTSpecInstance().load(specs=cache_result)
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
        spec_std_new: dict = await self.__request_spec_std_lib_async()
        if spec_std_new:
            self._std_lib.init(spec_std_new)
            if self._storage:
                if not await self._storage.save_async(
                        domain=self.DOMAIN, name='spec_std_lib',
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

    def __http_get(
        self, url: str, params: dict = None, headers: dict = None
    ) -> dict:
        if params:
            encoded_params = urlencode(params)
            full_url = f'{url}?{encoded_params}'
        else:
            full_url = url
        request = Request(full_url, method='GET', headers=headers or {})
        content: bytes = None
        with urlopen(request) as response:
            content = response.read()
        return (
            json.loads(str(content, 'utf-8'))
            if content is not None else None)

    async def __http_get_async(
        self, url: str, params: dict = None, headers: dict = None
    ) -> dict:
        return await self._main_loop.run_in_executor(
            None, self.__http_get, url, params, headers)

    async def __cache_get(self, urn: str) -> Optional[dict]:
        if self._storage is not None:
            if platform.system() == 'Windows':
                urn = urn.replace(':', '_')
            return await self._storage.load_async(
                domain=self.DOMAIN, name=f'{urn}_{self._lang}', type_=dict)
        return self._ram_cache.get(urn, None)

    async def __cache_set(self, urn: str, data: dict) -> bool:
        if self._storage is not None:
            if platform.system() == 'Windows':
                urn = urn.replace(':', '_')
            return await self._storage.save_async(
                domain=self.DOMAIN, name=f'{urn}_{self._lang}', data=data)
        self._ram_cache[urn] = data
        return True

    def __spec_format2dtype(self, format_: str) -> str:
        # 'string'|'bool'|'uint8'|'uint16'|'uint32'|
        # 'int8'|'int16'|'int32'|'int64'|'float'
        return {'string': 'str', 'bool': 'bool', 'float': 'float'}.get(
            format_, 'int')

    async def __request_spec_std_lib_async(self) -> Optional[SpecStdLib]:
        std_libs: dict = None
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
                    tasks.append(self.__http_get_async(
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
        reply = await self.__http_get_async(
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
        reply = await self.__http_get_async(url=url)
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

    async def __get_instance(self, urn: str) -> dict:
        return await self.__http_get_async(
            url='https://miot-spec.org/miot-spec-v2/instance',
            params={'type': urn})

    async def __get_translation(self, urn: str) -> dict:
        return await self.__http_get_async(
            url='https://miot-spec.org/instance/v2/multiLanguage',
            params={'urn': urn})

    async def __parse(self, urn: str) -> MIoTSpecInstance:
        _LOGGER.debug('parse urn, %s', urn)
        # Load spec instance
        instance: dict = await self.__get_instance(urn=urn)
        if (
            not isinstance(instance, dict)
            or 'type' not in instance
            or 'description' not in instance
            or 'services' not in instance
        ):
            raise MIoTSpecError(f'invalid urn instance, {urn}')
        translation: dict = {}
        try:
            # Load multiple language configuration.
            res_trans = await self.__get_translation(urn=urn)
            if (
                not isinstance(res_trans, dict)
                or 'data' not in res_trans
                or not isinstance(res_trans['data'], dict)
            ):
                raise MIoTSpecError('invalid translation data')
            urn_strs: list[str] = urn.split(':')
            urn_key: str = ':'.join(urn_strs[:6])
            trans_data: dict[str, str] = None
            if self._lang == 'zh-Hans':
                # Simplified Chinese
                trans_data = res_trans['data'].get('zh_cn', {})
            elif self._lang == 'zh-Hant':
                # Traditional Chinese, zh_hk or zh_tw
                trans_data = res_trans['data'].get('zh_hk', {})
                if not trans_data:
                    trans_data = res_trans['data'].get('zh_tw', {})
            else:
                trans_data = res_trans['data'].get(self._lang, {})
            # Load local multiple language configuration.
            multi_lang: dict = await self._multi_lang.translate_async(
                urn_key=urn_key)
            if multi_lang:
                trans_data.update(multi_lang)
            if not trans_data:
                trans_data = res_trans['data'].get(
                    DEFAULT_INTEGRATION_LANGUAGE, {})
                if not trans_data:
                    raise MIoTSpecError(
                        f'the language is not supported, {self._lang}')
                else:
                    _LOGGER.error(
                        'the language is not supported, %s, try using the '
                        'default language, %s, %s',
                        self._lang, DEFAULT_INTEGRATION_LANGUAGE, urn)
            for tag, value in trans_data.items():
                if value is None or value.strip() == '':
                    continue
                # The dict key is like:
                # 'service:002:property:001:valuelist:000' or
                # 'service:002:property:001' or 'service:002'
                strs: list = tag.split(':')
                strs_len = len(strs)
                if strs_len == 2:
                    translation[f's:{int(strs[1])}'] = value
                elif strs_len == 4:
                    type_ = 'p' if strs[2] == 'property' else (
                        'a' if strs[2] == 'action' else 'e')
                    translation[
                        f'{type_}:{int(strs[1])}:{int(strs[3])}'
                    ] = value
                elif strs_len == 6:
                    translation[
                        f'v:{int(strs[1])}:{int(strs[3])}:{int(strs[5])}'
                    ] = value
        except MIoTSpecError as e:
            _LOGGER.error('get translation error, %s, %s', urn, e)
        # Spec filter
        self._spec_filter.filter_spec(urn_key=urn_key)
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
                translation.get(f's:{service["iid"]}', None)
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
                spec_prop: MIoTSpecProperty = MIoTSpecProperty(
                    spec=property_,
                    service=spec_service,
                    format_=self.__spec_format2dtype(property_['format']),
                    access=property_['access'],
                    unit=property_.get('unit', None))
                spec_prop.name = p_type_strs[3]
                # Filter spec property
                spec_prop.need_filter = (
                    spec_service.need_filter
                    or self._spec_filter.filter_property(
                        siid=service['iid'], piid=property_['iid']))
                if p_type_strs[1] != 'miot-spec-v2':
                    spec_prop.proprietary = spec_service.proprietary or True
                spec_prop.description_trans = (
                    translation.get(
                        f'p:{service["iid"]}:{property_["iid"]}', None)
                    or self._std_lib.property_translate(
                        key=':'.join(p_type_strs[:5]))
                    or property_['description']
                    or spec_prop.name)
                if 'value-range' in property_:
                    spec_prop.value_range = {
                        'min': property_['value-range'][0],
                        'max': property_['value-range'][1],
                        'step': property_['value-range'][2]
                    }
                    spec_prop.precision = len(str(
                        property_['value-range'][2]).split(
                        '.')[1].rstrip('0')) if '.' in str(
                            property_['value-range'][2]) else 0
                elif 'value-list' in property_:
                    v_list: list[dict] = property_['value-list']
                    for index, v in enumerate(v_list):
                        v['name'] = v['description']
                        v['description'] = (
                            translation.get(
                                f'v:{service["iid"]}:{property_["iid"]}:'
                                f'{index}', None)
                            or self._std_lib.value_translate(
                                key=f'{type_strs[:5]}|{p_type_strs[3]}|'
                                f'{v["description"]}')
                            or v['name']
                        )
                    spec_prop.value_list = v_list
                elif property_['format'] == 'bool':
                    v_tag = ':'.join(p_type_strs[:5])
                    v_descriptions: dict = (
                        await self._bool_trans.translate_async(urn=v_tag))
                    if v_descriptions:
                        spec_prop.value_list = v_descriptions
                spec_service.properties.append(spec_prop)
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
                    translation.get(
                        f'e:{service["iid"]}:{event["iid"]}', None)
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
                    translation.get(
                        f'a:{service["iid"]}:{action["iid"]}', None)
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
