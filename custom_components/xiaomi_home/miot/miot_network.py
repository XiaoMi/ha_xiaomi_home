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

MIoT network utilities.
"""
import asyncio
import logging
import platform
import socket
from dataclasses import dataclass
from enum import Enum, auto
import subprocess
from typing import Callable, Coroutine, Optional
import aiohttp
import psutil
import ipaddress

_LOGGER = logging.getLogger(__name__)


class InterfaceStatus(Enum):
    """Interface status."""
    ADD = 0
    UPDATE = auto()
    REMOVE = auto()


@dataclass
class NetworkInfo:
    """Network information."""
    name: str
    ip: str
    netmask: str
    net_seg: str


class MIoTNetwork:
    """MIoT network utilities."""
    _IP_ADDRESS_LIST: list[str] = [
        '1.2.4.8',          # CNNIC sDNS
        '8.8.8.8',          # Google Public DNS
        '9.9.9.9'           # Quad9
    ]
    _URL_ADDRESS_LIST: list[str] = [
        'https://www.bing.com',
        'https://www.google.com',
        'https://www.baidu.com'
    ]
    _REFRESH_INTERVAL = 30
    _DETECT_TIMEOUT = 6

    _main_loop: asyncio.AbstractEventLoop

    _ip_addr_map: dict[str, float]
    _http_addr_map: dict[str, float]
    _http_session: aiohttp.ClientSession

    _refresh_interval: int
    _refresh_task: Optional[asyncio.Task]
    _refresh_timer: Optional[asyncio.TimerHandle]

    _network_status: bool
    _network_info: dict[str, NetworkInfo]

    _sub_list_network_status: dict[str, Callable[[bool], Coroutine]]
    _sub_list_network_info: dict[str, Callable[[
        InterfaceStatus, NetworkInfo], Coroutine]]
    _done_event: asyncio.Event

    def __init__(
        self,
        ip_addr_list: Optional[list[str]] = None,
        url_addr_list: Optional[list[str]] = None,
        refresh_interval: Optional[int] = None,
        loop: Optional[asyncio.AbstractEventLoop] = None
    ) -> None:
        self._main_loop = loop or asyncio.get_running_loop()
        self._ip_addr_map = {
            ip: self._DETECT_TIMEOUT for ip in
            ip_addr_list or self._IP_ADDRESS_LIST}
        self._http_addr_map = {
            url: self._DETECT_TIMEOUT for url in
            url_addr_list or self._URL_ADDRESS_LIST}
        self._http_session = aiohttp.ClientSession()
        self._refresh_interval = refresh_interval or self._REFRESH_INTERVAL

        self._refresh_task = None
        self._refresh_timer = None

        self._network_status = False
        self._network_info = {}

        self._sub_list_network_status = {}
        self._sub_list_network_info = {}

        self._done_event = asyncio.Event()

    async def init_async(self) -> bool:
        self.__refresh_timer_handler()
        # MUST get network info before starting
        return await self._done_event.wait()

    async def deinit_async(self) -> None:
        if self._refresh_task:
            self._refresh_task.cancel()
            self._refresh_task = None
        if self._refresh_timer:
            self._refresh_timer.cancel()
            self._refresh_timer = None
        await self._http_session.close()

        self._network_status = False
        self._network_info.clear()
        self._sub_list_network_status.clear()
        self._sub_list_network_info.clear()
        self._done_event.clear()

    @property
    def network_status(self) -> bool:
        return self._network_status

    @property
    def network_info(self) -> dict[str, NetworkInfo]:
        return self._network_info

    async def update_addr_list_async(
        self,
        ip_addr_list: Optional[list[str]] = None,
        url_addr_list: Optional[list[str]] = None,
    ) -> None:
        new_ip_map: dict = {}
        for ip in ip_addr_list or self._IP_ADDRESS_LIST:
            if ip in self._ip_addr_map:
                new_ip_map[ip] = self._ip_addr_map[ip]
            else:
                new_ip_map[ip] = self._DETECT_TIMEOUT
        self._ip_addr_map = new_ip_map
        new_url_map: dict = {}
        for url in url_addr_list or self._URL_ADDRESS_LIST:
            if url in self._http_addr_map:
                new_url_map[url] = self._http_addr_map[url]
            else:
                new_url_map[url] = self._DETECT_TIMEOUT
        self._http_addr_map = new_url_map

    def sub_network_status(
        self, key: str, handler: Callable[[bool], Coroutine]
    ) -> None:
        self._sub_list_network_status[key] = handler

    def unsub_network_status(self, key: str) -> None:
        self._sub_list_network_status.pop(key, None)

    def sub_network_info(
        self, key: str,
        handler: Callable[[InterfaceStatus, NetworkInfo], Coroutine]
    ) -> None:
        self._sub_list_network_info[key] = handler

    def unsub_network_info(self, key: str) -> None:
        self._sub_list_network_info.pop(key, None)

    async def refresh_async(self) -> None:
        self.__refresh_timer_handler()

    async def get_network_status_async(self) -> bool:
        try:
            ip_addr: str = ''
            ip_ts: float = self._DETECT_TIMEOUT
            for ip, ts in self._ip_addr_map.items():
                if ts < ip_ts:
                    ip_addr = ip
                    ip_ts = ts
            if (
                ip_ts < self._DETECT_TIMEOUT
                and await self.ping_multi_async(ip_list=[ip_addr])
            ):
                return True
            url_addr: str = ''
            url_ts: float = self._DETECT_TIMEOUT
            for http, ts in self._http_addr_map.items():
                if ts < url_ts:
                    url_addr = http
                    url_ts = ts
            if (
                url_ts < self._DETECT_TIMEOUT
                and await self.http_multi_async(url_list=[url_addr])
            ):
                return True
            # Detect all addresses
            results = await asyncio.gather(
                *[self.ping_multi_async(), self.http_multi_async()])
            return any(results)
        except Exception as err:  # pylint: disable=broad-exception-caught
            _LOGGER.error('get network status error, %s', err)
        return False

    async def get_network_info_async(self) -> dict[str, NetworkInfo]:
        return await self._main_loop.run_in_executor(
            None, self.__get_network_info)

    async def ping_multi_async(
        self, ip_list: Optional[list[str]] = None
    ) -> bool:
        addr_list = ip_list or list(self._ip_addr_map.keys())
        tasks = []
        for addr in addr_list:
            tasks.append(self.__ping_async(addr))
        results = await asyncio.gather(*tasks)
        for addr, ts in zip(addr_list, results):
            if addr in self._ip_addr_map:
                self._ip_addr_map[addr] = ts
        return any([ts < self._DETECT_TIMEOUT for ts in results])

    async def http_multi_async(
        self, url_list: Optional[list[str]] = None
    ) -> bool:
        addr_list = url_list or list(self._http_addr_map.keys())
        tasks = []
        for addr in addr_list:
            tasks.append(self.__http_async(url=addr))
        results = await asyncio.gather(*tasks)
        for addr, ts in zip(addr_list, results):
            if addr in self._http_addr_map:
                self._http_addr_map[addr] = ts
        return any([ts < self._DETECT_TIMEOUT for ts in results])

    def __calc_network_address(self, ip: str, netmask: str) -> str:
        return str(ipaddress.IPv4Network(
            f'{ip}/{netmask}', strict=False).network_address)

    async def __ping_async(self, address: Optional[str] = None) -> float:
        start_ts: float = self._main_loop.time()
        try:
            process = await asyncio.create_subprocess_exec(
                *(
                    [
                        'ping', '-n', '1', '-w',
                        str(self._DETECT_TIMEOUT*1000), address]
                    if platform.system().lower() == 'windows' else
                    [
                        'ping', '-c', '1', '-w',
                        str(self._DETECT_TIMEOUT), address]),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            await process.communicate()
            if process.returncode == 0:
                return self._main_loop.time() - start_ts
            return self._DETECT_TIMEOUT
        except Exception as err:  # pylint: disable=broad-exception-caught
            _LOGGER.debug('ping error, %s',err)
            return self._DETECT_TIMEOUT

    async def __http_async(self, url: str) -> float:
        start_ts: float = self._main_loop.time()
        try:
            async with self._http_session.get(
                    url, timeout=self._DETECT_TIMEOUT):
                return self._main_loop.time() - start_ts
        except Exception:  # pylint: disable=broad-exception-caught
            pass
        return self._DETECT_TIMEOUT

    def __get_network_info(self) -> dict[str, NetworkInfo]:
        interfaces = psutil.net_if_addrs()
        results: dict[str, NetworkInfo] = {}
        for name, addresses in interfaces.items():
            # Skip hassio and docker* interface
            if name == 'hassio' or name.startswith('docker'):
                continue
            for address in addresses:
                if (
                    address.family != socket.AF_INET
                    or not address.address
                    or not address.netmask
                ):
                    continue
                # skip lo interface
                if address.address == '127.0.0.1':
                    continue
                results[name] = NetworkInfo(
                    name=name,
                    ip=address.address,
                    netmask=address.netmask,
                    net_seg=self.__calc_network_address(
                        address.address, address.netmask))
        return results

    def __call_network_info_change(
        self, status: InterfaceStatus, info: NetworkInfo
    ) -> None:
        for handler in self._sub_list_network_info.values():
            self._main_loop.create_task(handler(status, info))

    async def __update_status_and_info_async(self) -> None:
        try:
            status: bool = await self.get_network_status_async()
            infos = await self.get_network_info_async()

            if self._network_status != status:
                for handler in self._sub_list_network_status.values():
                    self._main_loop.create_task(handler(status))
                self._network_status = status

            for name in list(self._network_info.keys()):
                info = infos.pop(name, None)
                if info:
                    # Update
                    if (
                        info.ip != self._network_info[name].ip
                        or info.netmask != self._network_info[name].netmask
                    ):
                        self._network_info[name] = info
                        self.__call_network_info_change(
                            InterfaceStatus.UPDATE, info)
                else:
                    # Remove
                    self.__call_network_info_change(
                        InterfaceStatus.REMOVE,
                        self._network_info.pop(name))
            # Add
            for name, info in infos.items():
                self._network_info[name] = info
                self.__call_network_info_change(InterfaceStatus.ADD, info)

            if not self._done_event.is_set():
                self._done_event.set()
        except asyncio.CancelledError:
            _LOGGER.error('update_status_and_info task was cancelled')

    def __refresh_timer_handler(self) -> None:
        if self._refresh_timer:
            self._refresh_timer.cancel()
            self._refresh_timer = None
        if self._refresh_task is None or self._refresh_task.done():
            self._refresh_task = self._main_loop.create_task(
                self.__update_status_and_info_async())
        self._refresh_timer = self._main_loop.call_later(
            self._refresh_interval, self.__refresh_timer_handler)
