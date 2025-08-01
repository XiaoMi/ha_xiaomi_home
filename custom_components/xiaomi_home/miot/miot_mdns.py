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

MIoT central hub gateway service discovery.
"""
import asyncio
import base64
import binascii
import copy
from enum import Enum
from typing import Callable, Coroutine, Optional
import logging

from zeroconf import (
    DNSQuestionType,
    IPVersion,
    ServiceStateChange,
    Zeroconf)
from zeroconf.asyncio import (
    AsyncServiceInfo,
    AsyncZeroconf,
    AsyncServiceBrowser)

# pylint: disable=relative-beyond-top-level
from .miot_error import MipsServiceError

_LOGGER = logging.getLogger(__name__)

MIPS_MDNS_TYPE = '_miot-central._tcp.local.'
MIPS_MDNS_REQUEST_TIMEOUT_MS = 5000
MIPS_MDNS_UPDATE_INTERVAL_S = 600


class MipsServiceState(Enum):
    ADDED = 1
    REMOVED = 2
    UPDATED = 3


class MipsServiceData:
    """Mips service data."""
    profile: str
    profile_bin: bytes

    name: str
    addresses: list[str]
    port: int
    type: str
    server: str

    did: str
    group_id: str
    role: int
    suite_mqtt: bool

    def __init__(self, service_info: AsyncServiceInfo) -> None:
        if service_info is None:
            raise MipsServiceError('invalid params')
        properties: dict = service_info.decoded_properties
        if not properties:
            raise MipsServiceError('invalid service properties')
        self.profile = properties.get('profile', None)
        if self.profile is None:
            raise MipsServiceError('invalid service profile')
        self.profile_bin = base64.b64decode(self.profile)
        self.name = service_info.name
        self.addresses = service_info.parsed_addresses(
            version=IPVersion.V4Only)
        if not self.addresses:
            raise MipsServiceError('invalid addresses')
        if not service_info.port:
            raise MipsServiceError('invalid port')
        self.port = service_info.port
        self.type = service_info.type
        self.server = service_info.server or ''
        # Parse profile
        self.did = str(int.from_bytes(self.profile_bin[1:9], byteorder='big'))
        self.group_id = binascii.hexlify(
            self.profile_bin[9:17][::-1]).decode('utf-8')
        self.role = int(self.profile_bin[20] >> 4)
        self.suite_mqtt = ((self.profile_bin[22] >> 1) & 0x01) == 0x01

    def valid_service(self) -> bool:
        if self.role != 1:
            return False
        return self.suite_mqtt

    def to_dict(self) -> dict:
        return {
            'name': self.name,
            'addresses': self.addresses,
            'port': self.port,
            'type': self.type,
            'server': self.server,
            'did': self.did,
            'group_id': self.group_id,
            'role': self.role,
            'suite_mqtt': self.suite_mqtt
        }

    def __str__(self) -> str:
        return str(self.to_dict())


class MipsService:
    """MIPS service discovery."""
    _aiozc: AsyncZeroconf
    _main_loop: asyncio.AbstractEventLoop
    _aio_browser: AsyncServiceBrowser
    _services: dict[str, dict]
    # key = (key, group_id)
    _sub_list: dict[tuple[str, str], Callable[[
        str, MipsServiceState, dict], Coroutine]]

    def __init__(
        self, aiozc: AsyncZeroconf,
        loop: Optional[asyncio.AbstractEventLoop] = None
    ) -> None:
        self._aiozc = aiozc
        self._main_loop = loop or asyncio.get_running_loop()

        self._services = {}
        self._sub_list = {}

    async def init_async(self) -> None:
        await self._aiozc.zeroconf.async_wait_for_start()

        self._aio_browser = AsyncServiceBrowser(
            zeroconf=self._aiozc.zeroconf,
            type_=MIPS_MDNS_TYPE,
            handlers=[self.__on_service_state_change],
            question_type=DNSQuestionType.QM)

    async def deinit_async(self) -> None:
        await self._aio_browser.async_cancel()
        self._services = {}
        self._sub_list = {}

    def get_services(self, group_id: Optional[str] = None) -> dict[str, dict]:
        """get mips services.

        Args:
            group_id (str, optional): _description_. Defaults to None.

        Returns: {
            [group_id:str]: {
                "name": str,
                "addresses": list[str],
                "port": number,
                "type": str,
                "server": str,
                "version": int,
                "did": str,
                "group_id": str,
                "role": int,
                "suite_mqtt": bool
            }
        }
        """
        if group_id:
            if group_id not in self._services:
                return {}
            return {group_id: copy.deepcopy(self._services[group_id])}
        return copy.deepcopy(self._services)

    def sub_service_change(
            self, key: str, group_id: str,
            handler: Callable[[str, MipsServiceState, dict], Coroutine]
    ) -> None:
        if key is None or group_id is None or handler is None:
            raise MipsServiceError('invalid params')
        self._sub_list[(key, group_id)] = handler

    def unsub_service_change(self, key: str) -> None:
        if key is None:
            return
        for keys in list(self._sub_list.keys()):
            if key == keys[0]:
                self._sub_list.pop(keys, None)

    def __on_service_state_change(
            self, zeroconf: Zeroconf, service_type: str, name: str,
            state_change: ServiceStateChange
    ) -> None:
        _LOGGER.debug(
            'mdns discovery changed, %s, %s, %s',
            state_change, name, service_type)

        if state_change is ServiceStateChange.Removed:
            for item in list(self._services.values()):
                if item['name'] != name:
                    continue
            # Ignore mdns REMOVED package. Let the connection close by itself.
                # service_data = self._services.pop(item['group_id'], {})
                # self.__call_service_change(
                #     state=MipsServiceState.REMOVED, data=service_data)
                return
        self._main_loop.create_task(
            self.__request_service_info_async(zeroconf, service_type, name))

    async def __request_service_info_async(
            self, zeroconf: Zeroconf, service_type: str, name: str
    ) -> None:
        info = AsyncServiceInfo(service_type, name)
        await info.async_request(
            zeroconf, MIPS_MDNS_REQUEST_TIMEOUT_MS,
            question_type=DNSQuestionType.QU)

        try:
            service_data = MipsServiceData(info)
            if not service_data.valid_service():
                raise MipsServiceError(
                    'no primary role, no support mqtt connection')
            if service_data.group_id in self._services:
                # Update mips service
                buffer_data = self._services[service_data.group_id]
                if (
                    service_data.did != buffer_data['did']
                    or service_data.addresses != buffer_data['addresses']
                    or service_data.port != buffer_data['port']
                ):
                    self._services[service_data.group_id].update(
                        service_data.to_dict())
                    self.__call_service_change(
                        state=MipsServiceState.UPDATED,
                        data=service_data.to_dict())
            else:
                # Add mips service
                self._services[service_data.group_id] = service_data.to_dict()
                self.__call_service_change(
                    state=MipsServiceState.ADDED,
                    data=self._services[service_data.group_id])
        except MipsServiceError as error:
            _LOGGER.error('invalid mips service, %s, %s', error, info)

    def __call_service_change(
        self, state: MipsServiceState, data: dict
    ) -> None:
        _LOGGER.info('call service change, %s, %s', state, data)
        for keys in list(self._sub_list.keys()):
            if keys[1] in [data.get('group_id', None), '*']:
                self._main_loop.create_task(
                    self._sub_list[keys](data['group_id'], state, data))
