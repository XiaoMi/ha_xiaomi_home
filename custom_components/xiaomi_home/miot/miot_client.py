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

MIoT client instance.
"""
from copy import deepcopy
from typing import Any, Callable, Optional, final
import asyncio
import json
import logging
import time
import traceback
from dataclasses import dataclass
from enum import Enum, auto

from homeassistant.core import HomeAssistant
from homeassistant.components import zeroconf

# pylint: disable=relative-beyond-top-level
from .common import MIoTMatcher, slugify_did
from .const import (
    DEFAULT_CTRL_MODE, DEFAULT_INTEGRATION_LANGUAGE, DEFAULT_NICK_NAME, DOMAIN,
    MIHOME_CERT_EXPIRE_MARGIN, NETWORK_REFRESH_INTERVAL,
    OAUTH2_CLIENT_ID, SUPPORT_CENTRAL_GATEWAY_CTRL,
    DEFAULT_COVER_DEAD_ZONE_WIDTH)
from .miot_cloud import MIoTHttpClient, MIoTOauthClient
from .miot_error import MIoTClientError, MIoTErrorCode
from .miot_mips import (
    MIoTDeviceState, MipsCloudClient, MipsDeviceState,
    MipsLocalClient)
from .miot_lan import MIoTLan
from .miot_network import MIoTNetwork
from .miot_storage import MIoTCert, MIoTStorage
from .miot_mdns import MipsService, MipsServiceState
from .miot_i18n import MIoTI18n

_LOGGER = logging.getLogger(__name__)


REFRESH_PROPS_DELAY = 0.2
REFRESH_PROPS_RETRY_DELAY = 3
REFRESH_CLOUD_DEVICES_DELAY = 6
REFRESH_CLOUD_DEVICES_RETRY_DELAY = 60
REFRESH_GATEWAY_DEVICES_DELAY = 3

@dataclass
class MIoTClientSub:
    """MIoT client subscription."""
    topic: Optional[str]
    handler: Callable[[dict, Any], None]
    handler_ctx: Any = None

    def __str__(self) -> str:
        return f'{self.topic}, {id(self.handler)}, {id(self.handler_ctx)}'


class CtrlMode(Enum):
    """MIoT client control mode."""
    AUTO = 0
    CLOUD = auto()

    @staticmethod
    def load(mode: str) -> 'CtrlMode':
        if mode == 'auto':
            return CtrlMode.AUTO
        if mode == 'cloud':
            return CtrlMode.CLOUD
        raise MIoTClientError(f'unknown ctrl mode, {mode}')


class MIoTClient:
    """MIoT client instance."""
    # pylint: disable=unused-argument
    # pylint: disable=broad-exception-caught
    # pylint: disable=inconsistent-quotes
    _main_loop: asyncio.AbstractEventLoop

    _uid: str
    _entry_id: str
    _entry_data: dict
    _cloud_server: str
    _ctrl_mode: CtrlMode
    # MIoT network monitor
    _network: MIoTNetwork
    # MIoT storage client
    _storage: MIoTStorage
    # MIoT mips service
    _mips_service: MipsService
    # MIoT oauth client
    _oauth: MIoTOauthClient
    # MIoT http client
    _http: MIoTHttpClient
    # MIoT i18n client
    _i18n: MIoTI18n
    # MIoT cert client
    _cert: MIoTCert
    # User config, store in the .storage/xiaomi_home
    _user_config: dict

    # Multi local mips client, key=group_id
    _mips_local: dict[str, MipsLocalClient]
    # Cloud mips client
    _mips_cloud: MipsCloudClient
    # MIoT lan client
    _miot_lan: MIoTLan

    # Device list load from local storage, {did: <info>}
    _device_list_cache: dict[str, dict]
    # Device list obtained from cloud, {did: <info>}
    _device_list_cloud: dict[str, dict]
    # Device list obtained from gateway, {did: <info>}
    _device_list_gateway: dict[str, dict]
    # Device list scanned from LAN, {did: <info>}
    _device_list_lan: dict[str, dict]
    # Device list update timestamp
    _device_list_update_ts: int

    _sub_source_list: dict[str, Optional[str]]
    _sub_tree: MIoTMatcher
    _sub_device_state: dict[str, MipsDeviceState]

    _mips_local_state_changed_timers: dict[str, asyncio.TimerHandle]
    _refresh_token_timer: Optional[asyncio.TimerHandle]
    _refresh_cert_timer: Optional[asyncio.TimerHandle]
    _refresh_cloud_devices_timer: Optional[asyncio.TimerHandle]
    # Refresh prop
    _refresh_props_list: dict[str, dict]
    _refresh_props_timer: Optional[asyncio.TimerHandle]
    _refresh_props_retry_count: int

    # Persistence notify handler, params: notify_id, title, message
    _persistence_notify: Callable[[str, Optional[str], Optional[str]], None]
    # Device list changed notify
    _show_devices_changed_notify_timer: Optional[asyncio.TimerHandle]
    # Display devices changed notify
    _display_devs_notify: list[str]
    _display_notify_content_hash: Optional[int]
    # Display binary mode
    _display_binary_text: bool
    _display_binary_bool: bool

    def __init__(
            self,
            entry_id: str,
            entry_data: dict,
            network: MIoTNetwork,
            storage: MIoTStorage,
            mips_service: MipsService,
            miot_lan: MIoTLan,
            loop: Optional[asyncio.AbstractEventLoop] = None) -> None:
        # MUST run in a running event loop
        self._main_loop = loop or asyncio.get_running_loop()
        # Check params
        if not isinstance(entry_data, dict):
            raise MIoTClientError('invalid entry data')
        if 'uid' not in entry_data or 'cloud_server' not in entry_data:
            raise MIoTClientError('invalid entry data content')
        if not isinstance(network, MIoTNetwork):
            raise MIoTClientError('invalid miot network')
        if not isinstance(storage, MIoTStorage):
            raise MIoTClientError('invalid miot storage')
        if not isinstance(mips_service, MipsService):
            raise MIoTClientError('invalid mips service')
        self._entry_id = entry_id
        self._entry_data = entry_data
        self._uid = entry_data['uid']
        self._cloud_server = entry_data['cloud_server']
        self._ctrl_mode = CtrlMode.load(
            entry_data.get('ctrl_mode', DEFAULT_CTRL_MODE))
        self._network = network
        self._storage = storage
        self._mips_service = mips_service
        self._oauth = None
        self._http = None
        self._i18n = None
        self._cert = None
        self._user_config = None

        self._mips_local = {}
        self._mips_cloud = None
        self._miot_lan = miot_lan

        self._device_list_cache = {}
        self._device_list_cloud = {}
        self._device_list_gateway = {}
        self._device_list_lan = {}
        self._device_list_update_ts = 0
        self._sub_source_list = {}
        self._sub_tree = MIoTMatcher()
        self._sub_device_state = {}

        self._mips_local_state_changed_timers = {}
        self._refresh_token_timer = None
        self._refresh_cert_timer = None
        self._refresh_cloud_devices_timer = None

        # Refresh prop
        self._refresh_props_list = {}
        self._refresh_props_timer = None
        self._refresh_props_retry_count = 0

        self._persistence_notify = None
        self._show_devices_changed_notify_timer = None

        self._display_devs_notify = entry_data.get(
            'display_devices_changed_notify', ['add', 'del', 'offline'])
        self._display_notify_content_hash = None
        self._display_binary_text = 'text' in entry_data.get(
            'display_binary_mode', ['text'])
        self._display_binary_bool = 'bool' in entry_data.get(
            'display_binary_mode', ['text'])

    async def init_async(self) -> None:
        # Load user config and check
        self._user_config = await self._storage.load_user_config_async(
            uid=self._uid, cloud_server=self._cloud_server)
        if not self._user_config:
            # Integration need to be add again
            raise MIoTClientError('load_user_config_async error')
        # Hide sensitive info in printing
        p_user_config: dict = deepcopy(self._user_config)
        p_access_token: str = p_user_config['auth_info']['access_token']
        p_refresh_token: str = p_user_config['auth_info']['refresh_token']
        p_mac_key: str = p_user_config['auth_info']['mac_key']
        p_user_config['auth_info'][
            'access_token'] = f"{p_access_token[:5]}***{p_access_token[-5:]}"
        p_user_config['auth_info'][
            'refresh_token'] = f"{p_refresh_token[:5]}***{p_refresh_token[-5:]}"
        p_user_config['auth_info'][
            'mac_key'] = f"{p_mac_key[:5]}***{p_mac_key[-5:]}"
        _LOGGER.debug('user config, %s', json.dumps(p_user_config))
        # MIoT i18n client
        self._i18n = MIoTI18n(
            lang=self._entry_data.get(
                'integration_language', DEFAULT_INTEGRATION_LANGUAGE),
            loop=self._main_loop)
        await self._i18n.init_async()
        # Load cache device list
        await self.__load_cache_device_async()
        # MIoT oauth client instance
        self._oauth = MIoTOauthClient(
            client_id=OAUTH2_CLIENT_ID,
            redirect_url=self._entry_data['oauth_redirect_url'],
            cloud_server=self._cloud_server,
            uuid=self._entry_data["uuid"],
            loop=self._main_loop)
        # MIoT http client instance
        self._http = MIoTHttpClient(
            cloud_server=self._cloud_server,
            client_id=OAUTH2_CLIENT_ID,
            access_token=self._user_config['auth_info']['access_token'],
            loop=self._main_loop)
        # MIoT cert client
        self._cert = MIoTCert(
            storage=self._storage,
            uid=self._uid,
            cloud_server=self.cloud_server)
        # MIoT cloud mips client
        self._mips_cloud = MipsCloudClient(
            uuid=self._entry_data['uuid'],
            cloud_server=self._cloud_server,
            app_id=OAUTH2_CLIENT_ID,
            token=self._user_config['auth_info']['access_token'],
            loop=self._main_loop)
        self._mips_cloud.enable_logger(logger=_LOGGER)
        self._mips_cloud.sub_mips_state(
            key=f'{self._uid}-{self._cloud_server}',
            handler=self.__on_mips_cloud_state_changed)
        # Subscribe network status
        self._network.sub_network_status(
            key=f'{self._uid}-{self._cloud_server}',
            handler=self.__on_network_status_changed)
        await self.__on_network_status_changed(
            status=self._network.network_status)
        # Create multi mips local client instance according to the
        # number of hub gateways
        if self._ctrl_mode == CtrlMode.AUTO:
            # Central hub gateway ctrl
            if self._cloud_server in SUPPORT_CENTRAL_GATEWAY_CTRL:
                for home_id, info in self._entry_data['home_selected'].items():
                    # Create local mips service changed listener
                    self._mips_service.sub_service_change(
                        key=f'{self._uid}-{self._cloud_server}',
                        group_id=info['group_id'],
                        handler=self.__on_mips_service_state_change)
                    service_data = self._mips_service.get_services(
                        group_id=info['group_id']).get(info['group_id'], None)
                    if not service_data:
                        _LOGGER.info(
                            'central mips service not scanned, %s', home_id)
                        continue
                    _LOGGER.info(
                        'central mips service scanned, %s, %s',
                        home_id, service_data)
                    mips = MipsLocalClient(
                        did=self._entry_data['virtual_did'],
                        group_id=info['group_id'],
                        host=service_data['addresses'][0],
                        ca_file=self._cert.ca_file,
                        cert_file=self._cert.cert_file,
                        key_file=self._cert.key_file,
                        port=service_data['port'],
                        home_name=info['home_name'],
                        loop=self._main_loop)
                    self._mips_local[info['group_id']] = mips
                    mips.enable_logger(logger=_LOGGER)
                    mips.on_dev_list_changed = self.__on_gw_device_list_changed
                    mips.sub_mips_state(
                        key=info['group_id'],
                        handler=self.__on_mips_local_state_changed)
                    mips.connect()
            # Lan ctrl
            await self._miot_lan.vote_for_lan_ctrl_async(
                key=f'{self._uid}-{self._cloud_server}', vote=True)
            self._miot_lan.sub_lan_state(
                key=f'{self._uid}-{self._cloud_server}',
                handler=self.__on_miot_lan_state_change)
            if self._miot_lan.init_done:
                await self.__on_miot_lan_state_change(True)
        else:
            self._miot_lan.unsub_lan_state(
                key=f'{self._uid}-{self._cloud_server}')
            if self._miot_lan.init_done:
                self._miot_lan.unsub_device_state(
                    key=f'{self._uid}-{self._cloud_server}')
                self._miot_lan.delete_devices(
                    devices=list(self._device_list_cache.keys()))
            await self._miot_lan.vote_for_lan_ctrl_async(
                key=f'{self._uid}-{self._cloud_server}', vote=False)

        _LOGGER.info('init_async, %s, %s', self._uid, self._cloud_server)

    async def deinit_async(self) -> None:
        self._network.unsub_network_status(
            key=f'{self._uid}-{self._cloud_server}')
        # Cancel refresh props
        if self._refresh_props_timer:
            self._refresh_props_timer.cancel()
            self._refresh_props_timer = None
        self._refresh_props_list.clear()
        self._refresh_props_retry_count = 0
        # Cloud mips
        self._mips_cloud.unsub_mips_state(
            key=f'{self._uid}-{self._cloud_server}')
        self._mips_cloud.deinit()
        # Cancel refresh cloud devices
        if self._refresh_cloud_devices_timer:
            self._refresh_cloud_devices_timer.cancel()
            self._refresh_cloud_devices_timer = None
        if self._ctrl_mode == CtrlMode.AUTO:
            # Central hub gateway mips
            if self._cloud_server in SUPPORT_CENTRAL_GATEWAY_CTRL:
                self._mips_service.unsub_service_change(
                    key=f'{self._uid}-{self._cloud_server}')
                for mips in self._mips_local.values():
                    mips.on_dev_list_changed = None
                    mips.unsub_mips_state(key=mips.group_id)
                    mips.deinit()
                if self._mips_local_state_changed_timers:
                    for timer_item in (
                            self._mips_local_state_changed_timers.values()):
                        timer_item.cancel()
                    self._mips_local_state_changed_timers.clear()
            self._miot_lan.unsub_lan_state(
                key=f'{self._uid}-{self._cloud_server}')
            if self._miot_lan.init_done:
                self._miot_lan.unsub_device_state(
                    key=f'{self._uid}-{self._cloud_server}')
                self._miot_lan.delete_devices(
                    devices=list(self._device_list_cache.keys()))
            await self._miot_lan.vote_for_lan_ctrl_async(
                key=f'{self._uid}-{self._cloud_server}', vote=False)
        # Cancel refresh auth info
        if self._refresh_token_timer:
            self._refresh_token_timer.cancel()
            self._refresh_token_timer = None
        if self._refresh_cert_timer:
            self._refresh_cert_timer.cancel()
            self._refresh_cert_timer = None
        # Cancel device changed notify timer
        if self._show_devices_changed_notify_timer:
            self._show_devices_changed_notify_timer.cancel()
            self._show_devices_changed_notify_timer = None
        await self._oauth.deinit_async()
        await self._http.deinit_async()
        # Remove notify
        self._persistence_notify(
            self.__gen_notify_key('dev_list_changed'), None, None)
        self.__show_client_error_notify(
            message=None, notify_key='oauth_info')
        self.__show_client_error_notify(
            message=None, notify_key='user_cert')
        self.__show_client_error_notify(
            message=None, notify_key='device_cache')
        self.__show_client_error_notify(
            message=None, notify_key='device_cloud')

        _LOGGER.info('deinit_async, %s', self._uid)

    @property
    def main_loop(self) -> asyncio.AbstractEventLoop:
        return self._main_loop

    @property
    def miot_network(self) -> MIoTNetwork:
        return self._network

    @property
    def miot_storage(self) -> MIoTStorage:
        return self._storage

    @property
    def mips_service(self) -> MipsService:
        return self._mips_service

    @property
    def miot_oauth(self) -> MIoTOauthClient:
        return self._oauth

    @property
    def miot_http(self) -> MIoTHttpClient:
        return self._http

    @property
    def miot_i18n(self) -> MIoTI18n:
        return self._i18n

    @property
    def miot_lan(self) -> MIoTLan:
        return self._miot_lan

    @property
    def user_config(self) -> dict:
        return self._user_config

    @property
    def area_name_rule(self) -> Optional[str]:
        return self._entry_data.get('area_name_rule', None)

    @property
    def cloud_server(self) -> str:
        return self._cloud_server

    @property
    def action_debug(self) -> bool:
        return self._entry_data.get('action_debug', False)

    @property
    def hide_non_standard_entities(self) -> bool:
        return self._entry_data.get(
            'hide_non_standard_entities', False)

    @property
    def display_devices_changed_notify(self) -> list[str]:
        return self._display_devs_notify

    @property
    def display_binary_text(self) -> bool:
        return self._display_binary_text

    @property
    def display_binary_bool(self) -> bool:
        return self._display_binary_bool

    @property
    def cover_dead_zone_width(self) -> int:
        return self._entry_data.get('cover_dead_zone_width',
                                    DEFAULT_COVER_DEAD_ZONE_WIDTH)

    @display_devices_changed_notify.setter
    def display_devices_changed_notify(self, value: list[str]) -> None:
        if set(value) == set(self._display_devs_notify):
            return
        self._display_devs_notify = value
        if value:
            self.__request_show_devices_changed_notify()
        else:
            self._persistence_notify(
                self.__gen_notify_key('dev_list_changed'), None, None)

    @property
    def device_list(self) -> dict:
        return self._device_list_cache

    @property
    def persistent_notify(self) -> Callable:
        return self._persistence_notify

    @persistent_notify.setter
    def persistent_notify(self, func) -> None:
        self._persistence_notify = func

    @final
    async def refresh_oauth_info_async(self) -> bool:
        try:
            # Load auth info
            auth_info: Optional[dict] = None
            user_config: dict = await self._storage.load_user_config_async(
                uid=self._uid, cloud_server=self._cloud_server,
                keys=['auth_info'])
            if (
                not user_config
                or (auth_info := user_config.get('auth_info', None)) is None
            ):
                raise MIoTClientError('load_user_config_async error')
            if (
                'expires_ts' not in auth_info
                or 'access_token' not in auth_info
                or 'refresh_token' not in auth_info
            ):
                raise MIoTClientError('invalid auth info')
            # Determine whether to update token
            refresh_time = int(auth_info['expires_ts'] - time.time())
            if refresh_time <= 60:
                valid_auth_info = await self._oauth.refresh_access_token_async(
                    refresh_token=auth_info['refresh_token'])
                auth_info = valid_auth_info
                # Update http token
                self._http.update_http_header(
                    access_token=valid_auth_info['access_token'])
                # Update mips cloud token
                self._mips_cloud.update_access_token(
                    access_token=valid_auth_info['access_token'])
                # Update storage
                if not await self._storage.update_user_config_async(
                        uid=self._uid, cloud_server=self._cloud_server,
                        config={'auth_info': auth_info}):
                    raise MIoTClientError('update_user_config_async error')
                _LOGGER.info(
                    'refresh oauth info, get new access_token, %s',
                    auth_info)
                refresh_time = int(auth_info['expires_ts'] - time.time())
                if refresh_time <= 0:
                    raise MIoTClientError('invalid expires time')
            self.__show_client_error_notify(None, 'oauth_info')
            self.__request_refresh_auth_info(refresh_time)

            _LOGGER.debug(
                'refresh oauth info (%s, %s) after %ds',
                self._uid, self._cloud_server, refresh_time)
            return True
        except Exception as err:
            self.__show_client_error_notify(
                message=self._i18n.translate(
                    'miot.client.invalid_oauth_info'),  # type: ignore
                notify_key='oauth_info')
            _LOGGER.error(
                'refresh oauth info error (%s, %s), %s, %s',
                self._uid, self._cloud_server, err, traceback.format_exc())
        return False

    async def refresh_user_cert_async(self) -> bool:
        try:
            if self._cloud_server not in SUPPORT_CENTRAL_GATEWAY_CTRL:
                return True
            if not await self._cert.verify_ca_cert_async():
                raise MIoTClientError('ca cert is not ready')
            refresh_time = (
                await self._cert.user_cert_remaining_time_async() -
                MIHOME_CERT_EXPIRE_MARGIN)
            if refresh_time <= 60:
                user_key = await self._cert.load_user_key_async()
                if not user_key:
                    user_key = self._cert.gen_user_key()
                    if not await self._cert.update_user_key_async(key=user_key):
                        raise MIoTClientError('update_user_key_async failed')
                csr_str = self._cert.gen_user_csr(
                    user_key=user_key, did=self._entry_data['virtual_did'])
                crt_str = await self.miot_http.get_central_cert_async(csr_str)
                if not await self._cert.update_user_cert_async(cert=crt_str):
                    raise MIoTClientError('update user cert error')
                _LOGGER.info('update_user_cert_async, %s', crt_str)
                # Create cert update task
                refresh_time = (
                    await self._cert.user_cert_remaining_time_async() -
                    MIHOME_CERT_EXPIRE_MARGIN)
                if refresh_time <= 0:
                    raise MIoTClientError('invalid refresh time')
            self.__show_client_error_notify(None, 'user_cert')
            self.__request_refresh_user_cert(refresh_time)

            _LOGGER.debug(
                'refresh user cert (%s, %s) after %ds',
                self._uid, self._cloud_server, refresh_time)
            return True
        except MIoTClientError as error:
            self.__show_client_error_notify(
                message=self._i18n.translate(
                    'miot.client.invalid_cert_info'),  # type: ignore
                notify_key='user_cert')
            _LOGGER.error(
                'refresh user cert error, %s, %s',
                error, traceback.format_exc())
        return False

    async def set_prop_async(
        self, did: str, siid: int, piid: int, value: Any
    ) -> bool:
        if did not in self._device_list_cache:
            raise MIoTClientError(f'did not exist, {did}')
        # Priority local control
        if self._ctrl_mode == CtrlMode.AUTO:
            # Gateway control
            device_gw = self._device_list_gateway.get(did, None)
            if (
                device_gw and device_gw.get('online', False)
                and device_gw.get('specv2_access', False)
                and 'group_id' in device_gw
            ):
                mips = self._mips_local.get(device_gw['group_id'], None)
                if mips is None:
                    _LOGGER.error(
                        'no gateway route, %s, try control through cloud',
                        device_gw)
                else:
                    result = await mips.set_prop_async(
                        did=did, siid=siid, piid=piid, value=value)
                    _LOGGER.debug(
                        'gateway set prop, %s.%d.%d, %s -> %s',
                        did, siid, piid, value, result)
                    rc = (result or {}).get(
                        'code', MIoTErrorCode.CODE_MIPS_INVALID_RESULT.value)
                    if rc in [0, 1]:
                        return True
                    raise MIoTClientError(
                        self.__get_exec_error_with_rc(rc=rc))
            # Lan control
            device_lan = self._device_list_lan.get(did, None)
            if device_lan and device_lan.get('online', False):
                result = await self._miot_lan.set_prop_async(
                    did=did, siid=siid, piid=piid, value=value)
                _LOGGER.debug(
                    'lan set prop, %s.%d.%d, %s -> %s',
                    did, siid, piid, value, result)
                rc = (result or {}).get(
                    'code', MIoTErrorCode.CODE_MIPS_INVALID_RESULT.value)
                if rc in [0, 1]:
                    return True
                raise MIoTClientError(
                    self.__get_exec_error_with_rc(rc=rc))

        # Cloud control
        device_cloud = self._device_list_cloud.get(did, None)
        if device_cloud and device_cloud.get('online', False):
            result = await self._http.set_prop_async(
                params=[
                    {'did': did, 'siid': siid, 'piid': piid, 'value': value}
                ])
            _LOGGER.debug(
                'cloud set prop, %s.%d.%d, %s -> %s',
                did, siid, piid, value, result)
            if result and len(result) == 1:
                rc = result[0].get(
                    'code', MIoTErrorCode.CODE_MIPS_INVALID_RESULT.value)
                if rc in [0, 1]:
                    return True
                if rc in [-704010000, -704042011]:
                    # Device remove or offline
                    _LOGGER.error('device may be removed or offline, %s', did)
                    self._main_loop.create_task(
                        await self.__refresh_cloud_device_with_dids_async(
                            dids=[did]))
                raise MIoTClientError(
                    self.__get_exec_error_with_rc(rc=rc))

        # Show error message
        raise MIoTClientError(
            f'{self._i18n.translate("miot.client.device_exec_error")}, '
            f'{self._i18n.translate("error.common.-10007")}')

    def request_refresh_prop(
        self, did: str, siid: int, piid: int
    ) -> None:
        if did not in self._device_list_cache:
            raise MIoTClientError(f'did not exist, {did}')
        key: str = f'{did}|{siid}|{piid}'
        if key in self._refresh_props_list:
            return
        self._refresh_props_list[key] = {
            'did': did, 'siid': siid, 'piid': piid}
        if self._refresh_props_timer:
            return
        self._refresh_props_timer = self._main_loop.call_later(
            REFRESH_PROPS_DELAY, lambda: self._main_loop.create_task(
                self.__refresh_props_handler()))

    async def get_prop_async(self, did: str, siid: int, piid: int) -> Any:
        if did not in self._device_list_cache:
            raise MIoTClientError(f'did not exist, {did}')

        # NOTICE: Since there are too many request attributes and obtaining
        # them directly from the hub or device will cause device abnormalities,
        # so obtaining the cache from the cloud is the priority here.
        try:
            if self._network.network_status:
                result = await self._http.get_prop_async(
                    did=did, siid=siid, piid=piid)
                if result:
                    return result
        except Exception as err:  # pylint: disable=broad-exception-caught
            # Catch all exceptions
            _LOGGER.error(
                'client get prop from cloud error, %s, %s',
                err, traceback.format_exc())
        if self._ctrl_mode == CtrlMode.AUTO:
            # Central hub gateway
            device_gw = self._device_list_gateway.get(did, None)
            if (
                device_gw and device_gw.get('online', False)
                and device_gw.get('specv2_access', False)
                and 'group_id' in device_gw
            ):
                mips = self._mips_local.get(device_gw['group_id'], None)
                if mips is None:
                    _LOGGER.error('no gw route, %s', device_gw)
                else:
                    return await mips.get_prop_async(
                        did=did, siid=siid, piid=piid)
            # Lan
            device_lan = self._device_list_lan.get(did, None)
            if device_lan and device_lan.get('online', False):
                return await self._miot_lan.get_prop_async(
                    did=did, siid=siid, piid=piid)
        # _LOGGER.error(
        #     'client get prop failed, no-link, %s.%d.%d', did, siid, piid)
        return None

    async def action_async(
        self, did: str, siid: int, aiid: int, in_list: list
    ) -> list:
        if did not in self._device_list_cache:
            raise MIoTClientError(f'did not exist, {did}')

        device_gw = self._device_list_gateway.get(did, None)
        # Priority local control
        if self._ctrl_mode == CtrlMode.AUTO:
            if (
                device_gw and device_gw.get('online', False)
                and device_gw.get('specv2_access', False)
                and 'group_id' in device_gw
            ):
                mips = self._mips_local.get(
                    device_gw['group_id'], None)
                if mips is None:
                    _LOGGER.error('no gw route, %s', device_gw)
                else:
                    result = await mips.action_async(
                        did=did, siid=siid, aiid=aiid, in_list=in_list)
                    rc = (result or {}).get(
                        'code', MIoTErrorCode.CODE_MIPS_INVALID_RESULT.value)
                    if rc in [0, 1]:
                        return result.get('out', [])
                    raise MIoTClientError(
                        self.__get_exec_error_with_rc(rc=rc))
            # Lan control
            device_lan = self._device_list_lan.get(did, None)
            if device_lan and device_lan.get('online', False):
                result = await self._miot_lan.action_async(
                    did=did, siid=siid, aiid=aiid, in_list=in_list)
                _LOGGER.debug(
                    'lan action, %s, %s, %s -> %s', did, siid, aiid, result)
                rc = (result or {}).get(
                    'code', MIoTErrorCode.CODE_MIPS_INVALID_RESULT.value)
                if rc in [0, 1]:
                    return result.get('out', [])
                raise MIoTClientError(
                    self.__get_exec_error_with_rc(rc=rc))
        # Cloud control
        device_cloud = self._device_list_cloud.get(did, None)
        if device_cloud and device_cloud.get('online', False):
            result: dict = await self._http.action_async(
                did=did, siid=siid, aiid=aiid, in_list=in_list)
            if result:
                rc = result.get(
                    'code', MIoTErrorCode.CODE_MIPS_INVALID_RESULT.value)
                if rc in [0, 1]:
                    return result.get('out', [])
                if rc in [-704010000, -704042011]:
                    # Device remove or offline
                    _LOGGER.error('device removed or offline, %s', did)
                    self._main_loop.create_task(
                        await self.__refresh_cloud_device_with_dids_async(
                            dids=[did]))
                raise MIoTClientError(
                    self.__get_exec_error_with_rc(rc=rc))
        # TODO: Show error message
        _LOGGER.error(
            'client action failed, %s.%d.%d', did, siid, aiid)
        return []

    def sub_prop(
        self, did: str, handler: Callable[[dict, Any], None],
        siid: Optional[int] = None, piid: Optional[int] = None,
        handler_ctx: Any = None
    ) -> bool:
        if did not in self._device_list_cache:
            raise MIoTClientError(f'did not exist, {did}')

        topic = (
            f'{did}/p/'
            f'{"#" if siid is None or piid is None else f"{siid}/{piid}"}')
        self._sub_tree[topic] = MIoTClientSub(
            topic=topic, handler=handler, handler_ctx=handler_ctx)
        _LOGGER.debug('client sub prop, %s', topic)
        return True

    def unsub_prop(
        self, did: str, siid: Optional[int] = None, piid: Optional[int] = None
    ) -> bool:
        topic = (
            f'{did}/p/'
            f'{"#" if siid is None or piid is None else f"{siid}/{piid}"}')
        if self._sub_tree.get(topic=topic):
            del self._sub_tree[topic]
        _LOGGER.debug('client unsub prop, %s', topic)
        return True

    def sub_event(
        self, did: str, handler: Callable[[dict, Any], None],
        siid: Optional[int] = None, eiid: Optional[int] = None,
        handler_ctx: Any = None
    ) -> bool:
        if did not in self._device_list_cache:
            raise MIoTClientError(f'did not exist, {did}')
        topic = (
            f'{did}/e/'
            f'{"#" if siid is None or eiid is None else f"{siid}/{eiid}"}')
        self._sub_tree[topic] = MIoTClientSub(
            topic=topic, handler=handler, handler_ctx=handler_ctx)
        _LOGGER.debug('client sub event, %s', topic)
        return True

    def unsub_event(
        self, did: str, siid: Optional[int] = None, eiid: Optional[int] = None
    ) -> bool:
        topic = (
            f'{did}/e/'
            f'{"#" if siid is None or eiid is None else f"{siid}/{eiid}"}')
        if self._sub_tree.get(topic=topic):
            del self._sub_tree[topic]
        _LOGGER.debug('client unsub event, %s', topic)
        return True

    def sub_device_state(
        self, did: str, handler: Callable[[str, MIoTDeviceState, Any], None],
        handler_ctx: Any = None
    ) -> bool:
        """Call callback handler in main loop"""
        if did not in self._device_list_cache:
            raise MIoTClientError(f'did not exist, {did}')
        self._sub_device_state[did] = MipsDeviceState(
            did=did, handler=handler, handler_ctx=handler_ctx)
        _LOGGER.debug('client sub device state, %s', did)
        return True

    def unsub_device_state(self, did: str) -> bool:
        self._sub_device_state.pop(did, None)
        _LOGGER.debug('client unsub device state, %s', did)
        return True

    async def remove_device_async(self, did: str) -> None:
        if did not in self._device_list_cache:
            return
        sub_from = self._sub_source_list.pop(did, None)
        # Unsub
        if sub_from:
            self.__unsub_from(sub_from, did)
        # Storage
        await self._storage.save_async(
            domain='miot_devices',
            name=f'{self._uid}_{self._cloud_server}',
            data=self._device_list_cache)
        # Update notify
        self.__request_show_devices_changed_notify()

    async def remove_device2_async(self, did_tag: str) -> None:
        for did in self._device_list_cache:
            d_tag = slugify_did(cloud_server=self._cloud_server, did=did)
            if did_tag == d_tag:
                await self.remove_device_async(did)
                break

    def __get_exec_error_with_rc(self, rc: int) -> str:
        err_msg: str = self._i18n.translate(
            key=f'error.common.{rc}')  # type: ignore
        if not err_msg:
            err_msg = f'{self._i18n.translate(key="error.common.-10000")}, '
            err_msg += f'code={rc}'
        return (
            f'{self._i18n.translate(key="miot.client.device_exec_error")}, '
            + err_msg)

    @final
    def __gen_notify_key(self, name: str) -> str:
        return f'{DOMAIN}-{self._uid}-{self._cloud_server}-{name}'

    @final
    def __request_refresh_auth_info(self, delay_sec: int) -> None:
        if self._refresh_token_timer:
            self._refresh_token_timer.cancel()
            self._refresh_token_timer = None
        self._refresh_token_timer = self._main_loop.call_later(
            delay_sec, lambda: self._main_loop.create_task(
                self.refresh_oauth_info_async()))

    @final
    def __request_refresh_user_cert(self, delay_sec: int) -> None:
        if self._refresh_cert_timer:
            self._refresh_cert_timer.cancel()
            self._refresh_cert_timer = None
        self._refresh_cert_timer = self._main_loop.call_later(
            delay_sec, lambda: self._main_loop.create_task(
                self.refresh_user_cert_async()))

    @final
    def __unsub_from(self, sub_from: str, did: str) -> None:
        mips: Any = None
        if sub_from == 'cloud':
            mips = self._mips_cloud
        elif sub_from == 'lan':
            mips = self._miot_lan
        elif sub_from in self._mips_local:
            mips = self._mips_local[sub_from]
        if mips is not None:
            try:
                mips.unsub_prop(did=did)
                mips.unsub_event(did=did)
            except RuntimeError as e:
                if 'Event loop is closed' in str(e):
                    # Ignore unsub exception when loop is closed
                    pass
                else:
                    raise

    @final
    def __sub_from(self, sub_from: str, did: str) -> None:
        mips = None
        if sub_from == 'cloud':
            mips = self._mips_cloud
        elif sub_from == 'lan':
            mips = self._miot_lan
        elif sub_from in self._mips_local:
            mips = self._mips_local[sub_from]
        if mips is not None:
            mips.sub_prop(did=did, handler=self.__on_prop_msg)
            mips.sub_event(did=did, handler=self.__on_event_msg)

    @final
    def __update_device_msg_sub(self, did: str) -> None:
        if did not in self._device_list_cache:
            return
        from_old: Optional[str] = self._sub_source_list.get(did, None)
        from_new: Optional[str] = None
        if self._ctrl_mode == CtrlMode.AUTO:
            if (
                did in self._device_list_gateway
                and self._device_list_gateway[did].get('online', False)
                and self._device_list_gateway[did].get('push_available', False)
            ):
                from_new = self._device_list_gateway[did]['group_id']
            elif (
                did in self._device_list_lan
                and self._device_list_lan[did].get('online', False)
                and self._device_list_lan[did].get('push_available', False)
            ):
                from_new = 'lan'

        if (
            from_new is None
            and did in self._device_list_cloud
            and self._device_list_cloud[did].get('online', False)
        ):
            from_new = 'cloud'
        if (from_new == from_old) and (from_new=='cloud' or from_new=='lan'):
            # No need to update
            return
        # Unsub old
        if from_old:
            self.__unsub_from(from_old, did)
        # Sub new
        self.__sub_from(from_new, did)
        self._sub_source_list[did] = from_new
        _LOGGER.info(
            'device sub changed, %s, from %s to %s', did, from_old, from_new)

    @final
    async def __on_network_status_changed(self, status: bool) -> None:
        _LOGGER.info('network status changed, %s', status)
        if status:
            # Check auth_info
            if await self.refresh_oauth_info_async():
                # Connect to mips cloud
                self._mips_cloud.connect()
                # Update device list
                self.__request_refresh_cloud_devices()
            await self.refresh_user_cert_async()
        else:
            self.__request_show_devices_changed_notify(delay_sec=30)
            # Cancel refresh cloud devices
            if self._refresh_cloud_devices_timer:
                self._refresh_cloud_devices_timer.cancel()
                self._refresh_cloud_devices_timer = None
            # Disconnect cloud mips
            self._mips_cloud.disconnect()

    @final
    async def __on_mips_service_state_change(
        self, group_id: str, state: MipsServiceState, data: dict
    ) -> None:
        _LOGGER.info(
            'mips service state changed, %s, %s, %s', group_id, state, data)

        mips = self._mips_local.get(group_id, None)
        if mips:
            # if state == MipsServiceState.REMOVED:
            #     mips.disconnect()
            #     self._mips_local.pop(group_id, None)
            #     return
            if ( # ADDED or UPDATED
                mips.client_id == self._entry_data['virtual_did']
                and mips.host == data['addresses'][0]
                and mips.port == data['port']
            ):
                return
            mips.disconnect()
            self._mips_local.pop(group_id, None)
        home_name: str = ''
        for info in list(self._entry_data['home_selected'].values()):
            if info.get('group_id', None) == group_id:
                home_name = info.get('home_name', '')
        mips = MipsLocalClient(
            did=self._entry_data['virtual_did'],
            group_id=group_id,
            host=data['addresses'][0],
            ca_file=self._cert.ca_file,
            cert_file=self._cert.cert_file,
            key_file=self._cert.key_file,
            port=data['port'],
            home_name=home_name,
            loop=self._main_loop)
        self._mips_local[group_id] = mips
        mips.enable_logger(logger=_LOGGER)
        mips.on_dev_list_changed = self.__on_gw_device_list_changed
        mips.sub_mips_state(
            key=group_id, handler=self.__on_mips_local_state_changed)
        mips.connect()

    @final
    async def __on_mips_cloud_state_changed(
        self, key: str, state: bool
    ) -> None:
        _LOGGER.info('cloud mips state changed, %s, %s', key, state)
        if state:
            # Connect
            self.__request_refresh_cloud_devices(immediately=True)
            # Sub cloud device state
            for did in list(self._device_list_cache.keys()):
                self._mips_cloud.sub_device_state(
                    did=did, handler=self.__on_cloud_device_state_changed)
        else:
            # Disconnect
            for did, info in self._device_list_cloud.items():
                cloud_state_old: Optional[bool] = info.get('online', None)
                if not cloud_state_old:
                    # Cloud state is None or False, no need to update
                    continue
                info['online'] = False
                if did not in self._device_list_cache:
                    continue
                self.__update_device_msg_sub(did=did)
                state_old: Optional[bool] = self._device_list_cache[did].get(
                    'online', None)
                state_new: Optional[bool] = self.__check_device_state(
                    False,
                    self._device_list_gateway.get(
                        did, {}).get('online', False),
                    self._device_list_lan.get(did, {}).get('online', False))
                if state_old == state_new:
                    continue
                self._device_list_cache[did]['online'] = state_new
                sub = self._sub_device_state.get(did, None)
                if sub and sub.handler:
                    sub.handler(did, MIoTDeviceState.OFFLINE, sub.handler_ctx)
            self.__request_show_devices_changed_notify()

    @final
    async def __on_mips_local_state_changed(
        self, group_id: str, state: bool
    ) -> None:
        _LOGGER.info('local mips state changed, %s, %s', group_id, state)
        mips = self._mips_local.get(group_id, None)
        if not mips:
            _LOGGER.info(
                'local mips state changed, mips not exist, %s', group_id)
            # The connection to the central hub gateway is definitely broken.
            self.__show_central_state_changed_notify(False)
            return
        if state:
            # Connected
            self.__request_refresh_gw_devices_by_group_id(group_id=group_id)
        else:
            # Disconnect
            for did, info in self._device_list_gateway.items():
                if info.get('group_id', None) != group_id:
                    # Not belong to this gateway
                    continue
                if not info.get('online', False):
                    # Device offline, no need to update
                    continue
                # Update local device info
                info['online'] = False
                info['push_available'] = False
                if did not in self._device_list_cache:
                    # Device not exist
                    continue
                self.__update_device_msg_sub(did=did)
                state_old: Optional[bool] = self._device_list_cache.get(
                    did, {}).get('online', None)
                state_new: Optional[bool] = self.__check_device_state(
                    self._device_list_cloud.get(did, {}).get('online', None),
                    False,
                    self._device_list_lan.get(did, {}).get('online', False))
                if state_old == state_new:
                    continue
                self._device_list_cache[did]['online'] = state_new
                sub = self._sub_device_state.get(did, None)
                if sub and sub.handler:
                    sub.handler(did, MIoTDeviceState.OFFLINE, sub.handler_ctx)
            self.__request_show_devices_changed_notify()
        self.__show_central_state_changed_notify(state)

    @final
    async def __on_miot_lan_state_change(self, state: bool) -> None:
        _LOGGER.info(
            'miot lan state changed, %s, %s, %s',
            self._uid, self._cloud_server,  state)
        if state:
            # Update device
            self._miot_lan.sub_device_state(
                key=f'{self._uid}-{self._cloud_server}',
                handler=self.__on_lan_device_state_changed)
            for did, info in (
                    await self._miot_lan.get_dev_list_async()).items():
                await self.__on_lan_device_state_changed(
                    did=did, state=info, ctx=None)
            _LOGGER.info('lan device list, %s', self._device_list_lan)
            self._miot_lan.update_devices(devices={
                did: {
                    'token': info['token'],
                    'model': info['model'],
                    'connect_type': info['connect_type']}
                for did, info in self._device_list_cache.items()
                if 'token' in info and 'connect_type' in info
                and info['connect_type'] in [0, 8, 12, 23]
            })
        else:
            for did, info in self._device_list_lan.items():
                if not info.get('online', False):
                    continue
                # Update local device info
                info['online'] = False
                info['push_available'] = False
                self.__update_device_msg_sub(did=did)
                state_old: Optional[bool] = self._device_list_cache.get(
                    did, {}).get('online', None)
                state_new: Optional[bool] = self.__check_device_state(
                    self._device_list_cloud.get(did, {}).get('online', None),
                    self._device_list_gateway.get(
                        did, {}).get('online', False),
                    False)
                if state_old == state_new:
                    continue
                self._device_list_cache[did]['online'] = state_new
                sub = self._sub_device_state.get(did, None)
                if sub and sub.handler:
                    sub.handler(did, MIoTDeviceState.OFFLINE, sub.handler_ctx)
            self._device_list_lan = {}
            self.__request_show_devices_changed_notify()

    @final
    def __on_cloud_device_state_changed(
        self, did: str, state: MIoTDeviceState, ctx: Any
    ) -> None:
        _LOGGER.info('cloud device state changed, %s, %s', did, state)
        cloud_device = self._device_list_cloud.get(did, None)
        if not cloud_device:
            return
        cloud_state_new: bool = state == MIoTDeviceState.ONLINE
        if cloud_device.get('online', False) == cloud_state_new:
            return
        cloud_device['online'] = cloud_state_new
        if did not in self._device_list_cache:
            return
        self.__update_device_msg_sub(did=did)
        state_old: Optional[bool] = self._device_list_cache[did].get(
            'online', None)
        state_new: Optional[bool] = self.__check_device_state(
            cloud_state_new,
            self._device_list_gateway.get(did, {}).get('online', False),
            self._device_list_lan.get(did, {}).get('online', False))
        if state_old == state_new:
            return
        self._device_list_cache[did]['online'] = state_new
        sub = self._sub_device_state.get(did, None)
        if sub and sub.handler:
            sub.handler(
                did, MIoTDeviceState.ONLINE if state_new
                else MIoTDeviceState.OFFLINE, sub.handler_ctx)
        self.__request_show_devices_changed_notify()

    @final
    async def __on_gw_device_list_changed(
        self, mips: MipsLocalClient, did_list: list[str]
    ) -> None:
        _LOGGER.info(
            'gateway devices list changed, %s, %s', mips.group_id, did_list)
        payload: dict = {
            'filter': {
                'did': did_list
            },
            'info': [
                'name', 'model', 'urn',
                'online', 'specV2Access', 'pushAvailable'
            ]
        }
        gw_list = await mips.get_dev_list_async(
            payload=json.dumps(payload))
        if gw_list is None:
            _LOGGER.error('local mips get_dev_list_async failed, %s', did_list)
            return
        await self.__update_devices_from_gw_async(
            gw_list=gw_list, group_id=mips.group_id, filter_dids=[
                did for did in did_list
                if self._device_list_gateway.get(did, {}).get(
                    'group_id', None) == mips.group_id])
        self.__request_show_devices_changed_notify()

    @final
    async def __on_lan_device_state_changed(
        self, did: str, state: dict, ctx: Any
    ) -> None:
        _LOGGER.info('lan device state changed, %s, %s', did, state)
        lan_state_new: bool = state.get('online', False)
        lan_sub_new: bool = state.get('push_available', False)
        self._device_list_lan.setdefault(did, {})
        if (
            lan_state_new == self._device_list_lan[did].get('online', False)
            and lan_sub_new == self._device_list_lan[did].get(
                'push_available', False)
        ):
            return
        self._device_list_lan[did]['online'] = lan_state_new
        self._device_list_lan[did]['push_available'] = lan_sub_new
        if did not in self._device_list_cache:
            return
        self.__update_device_msg_sub(did=did)
        if lan_state_new == self._device_list_cache[did].get('online', False):
            return
        state_old: Optional[bool] = self._device_list_cache[did].get(
            'online', None)
        state_new: Optional[bool] = self.__check_device_state(
            self._device_list_cloud.get(did, {}).get('online', None),
            self._device_list_gateway.get(did, {}).get('online', False),
            lan_state_new)
        if state_old == state_new:
            return
        self._device_list_cache[did]['online'] = state_new
        sub = self._sub_device_state.get(did, None)
        if sub and sub.handler:
            sub.handler(
                did, MIoTDeviceState.ONLINE if state_new
                else MIoTDeviceState.OFFLINE, sub.handler_ctx)
        self.__request_show_devices_changed_notify()

    @final
    def __on_prop_msg(self, params: dict, ctx: Any) -> None:
        """params MUST contain did, siid, piid, value"""
        # BLE device has no online/offline msg
        try:
            subs: list[MIoTClientSub] = list(self._sub_tree.iter_match(
                f'{params["did"]}/p/{params["siid"]}/{params["piid"]}'))
            for sub in subs:
                sub.handler(params, sub.handler_ctx)
        except Exception as err:  # pylint: disable=broad-exception-caught
            _LOGGER.error('on prop msg error, %s, %s', params, err)

    @final
    def __on_event_msg(self, params: dict, ctx: Any) -> None:
        try:
            subs: list[MIoTClientSub] = list(self._sub_tree.iter_match(
                f'{params["did"]}/e/{params["siid"]}/{params["eiid"]}'))
            for sub in subs:
                sub.handler(params, sub.handler_ctx)
        except Exception as err:  # pylint: disable=broad-exception-caught
            _LOGGER.error('on event msg error, %s, %s', params, err)

    @final
    def __check_device_state(
        self, cloud_state: Optional[bool], gw_state: bool, lan_state: bool
    ) -> Optional[bool]:
        if cloud_state is None and not gw_state and not lan_state:
            # Device remove
            return None
        if cloud_state or gw_state or lan_state:
            return True
        return False

    @final
    async def __load_cache_device_async(self) -> None:
        """Load device list from cache."""
        cache_list: Optional[dict[str, dict]] = await self._storage.load_async(
            domain='miot_devices', name=f'{self._uid}_{self._cloud_server}',
            type_=dict)  # type: ignore
        if not cache_list:
            self.__show_client_error_notify(
                message=self._i18n.translate(
                    'miot.client.invalid_device_cache'),  # type: ignore
                notify_key='device_cache')
            raise MIoTClientError('load device list from cache error')
        else:
            self.__show_client_error_notify(
                message=None, notify_key='device_cache')
        # Set default online status = False
        self._device_list_cache = {}
        for did, info in cache_list.items():
            if info.get('online', None):
                self._device_list_cache[did] = {
                    **info, 'online': False}
            else:
                self._device_list_cache[did] = info
        self._device_list_cloud = deepcopy(self._device_list_cache)
        self._device_list_gateway = {
            did: {
                'did': did,
                'name': info.get('name', None),
                'group_id': info.get('group_id', None),
                'online': False,
                'push_available': False}
            for did, info in self._device_list_cache.items()}

    @final
    async def __update_devices_from_cloud_async(
        self, cloud_list: dict[str, dict],
        filter_dids: Optional[list[str]] = None
    ) -> None:
        """Update cloud devices.
        NOTICE: This function will operate the cloud_list
        """
        # MIoT cloud may not publish the online state updating message
        # for the BLE device. Assume that all BLE devices are online.
        # MIoT cloud does not publish the online state updating message for the
        # child device under the proxy gateway (eg, VRF air conditioner
        # controller). Assume that all proxy gateway child devices are online.
        for did, info in cloud_list.items():
            if did.startswith('blt.') or did.startswith('proxy.'):
                info['online'] = True
        for did, info in self._device_list_cache.items():
            if filter_dids and did not in filter_dids:
                continue
            state_old: Optional[bool] = info.get('online', None)
            cloud_state_old: Optional[bool] = self._device_list_cloud.get(
                did, {}).get('online', None)
            cloud_state_new: Optional[bool] = None
            device_new = cloud_list.pop(did, None)
            if device_new:
                cloud_state_new = device_new.get('online', None)
                # Update cache device info
                info.update(
                    {**device_new, 'online': state_old})
                # Update cloud device
                self._device_list_cloud[did] = device_new
            else:
                # Device deleted
                self._device_list_cloud[did]['online'] = None
            if cloud_state_old == cloud_state_new:
                # Cloud online status no change
                continue
            # Update sub from
            self.__update_device_msg_sub(did=did)
            state_new: Optional[bool] = self.__check_device_state(
                cloud_state_new,
                self._device_list_gateway.get(did, {}).get('online', False),
                self._device_list_lan.get(did, {}).get('online', False))
            if state_old == state_new:
                # Online status no change
                continue
            info['online'] = state_new
            # Call device state changed callback
            sub = self._sub_device_state.get(did, None)
            if sub and sub.handler:
                sub.handler(
                    did, MIoTDeviceState.ONLINE if state_new
                    else MIoTDeviceState.OFFLINE, sub.handler_ctx)
        # New devices
        self._device_list_cloud.update(cloud_list)
        # Update storage
        if not await self._storage.save_async(
            domain='miot_devices',
            name=f'{self._uid}_{self._cloud_server}',
            data=self._device_list_cache
        ):
            _LOGGER.error('save device list to cache failed')

    @final
    async def __refresh_cloud_devices_async(self) -> None:
        _LOGGER.debug(
            'refresh cloud devices, %s, %s', self._uid, self._cloud_server)
        if self._refresh_cloud_devices_timer:
            self._refresh_cloud_devices_timer.cancel()
            self._refresh_cloud_devices_timer = None
        try:
            result = await self._http.get_devices_async(
                home_ids=list(self._entry_data.get('home_selected', {}).keys()))
        except Exception as err:  # pylint: disable=broad-exception-caught
            _LOGGER.error('refresh cloud devices failed, %s', err)
            self._refresh_cloud_devices_timer = self._main_loop.call_later(
                REFRESH_CLOUD_DEVICES_RETRY_DELAY,
                lambda: self._main_loop.create_task(
                    self.__refresh_cloud_devices_async()))
            return
        if not result and 'devices' not in result:
            self.__show_client_error_notify(
                message=self._i18n.translate(
                    'miot.client.device_cloud_error'),  # type: ignore
                notify_key='device_cloud')
            return
        else:
            self.__show_client_error_notify(
                message=None, notify_key='device_cloud')
        cloud_list: dict[str, dict] = result['devices']
        await self.__update_devices_from_cloud_async(cloud_list=cloud_list)
        # Update lan device
        if (
            self._ctrl_mode == CtrlMode.AUTO
            and self._miot_lan.init_done
        ):
            self._miot_lan.update_devices(devices={
                did: {
                    'token': info['token'],
                    'model': info['model'],
                    'connect_type': info['connect_type']}
                for did, info in self._device_list_cache.items()
                if 'token' in info and 'connect_type' in info
                and info['connect_type'] in [0, 8, 12, 23]
            })

        self.__request_show_devices_changed_notify()

    @final
    async def __refresh_cloud_device_with_dids_async(
        self, dids: list[str]
    ) -> None:
        _LOGGER.debug('refresh cloud device with dids, %s', dids)
        cloud_list = await self._http.get_devices_with_dids_async(dids=dids)
        if cloud_list is None:
            _LOGGER.error('cloud http get_dev_list_async failed, %s', dids)
            return
        await self.__update_devices_from_cloud_async(
            cloud_list=cloud_list, filter_dids=dids)
        self.__request_show_devices_changed_notify()

    def __request_refresh_cloud_devices(self, immediately=False) -> None:
        _LOGGER.debug(
            'request refresh cloud devices, %s, %s',
            self._uid, self._cloud_server)
        delay_sec : int = 0 if immediately else REFRESH_CLOUD_DEVICES_DELAY
        if self._refresh_cloud_devices_timer:
            self._refresh_cloud_devices_timer.cancel()
        self._refresh_cloud_devices_timer = self._main_loop.call_later(
            delay_sec, lambda: self._main_loop.create_task(
                self.__refresh_cloud_devices_async()))

    @final
    async def __update_devices_from_gw_async(
        self, gw_list: dict[str, dict],
        group_id: Optional[str] = None,
        filter_dids: Optional[list[str]] = None
    ) -> None:
        """Update cloud devices.
        NOTICE: This function will operate the gw_list"""
        _LOGGER.debug('update gw devices, %s, %s', group_id, filter_dids)
        if not gw_list and not filter_dids:
            return
        for did, info in self._device_list_cache.items():
            if did not in filter_dids:
                continue
            device_old = self._device_list_gateway.get(did, None)
            gw_state_old = device_old.get(
                'online', False) if device_old else False
            gw_state_new: bool = False
            device_new = gw_list.pop(did, None)
            if device_new:
                # Update gateway device info
                self._device_list_gateway[did] = {
                    **device_new, 'group_id': group_id}
                gw_state_new = device_new.get('online', False)
            else:
                # Device offline
                if device_old:
                    device_old['online'] = False
            # Update cache group_id
            info['group_id'] = group_id
            if (gw_state_old == gw_state_new) and (not gw_state_new):
                continue
            self.__update_device_msg_sub(did=did)
            state_old: Optional[bool] = info.get('online', None)
            state_new: Optional[bool] = self.__check_device_state(
                self._device_list_cloud.get(did, {}).get('online', None),
                gw_state_new,
                self._device_list_lan.get(did, {}).get('online', False))
            if state_old == state_new:
                continue
            info['online'] = state_new
            sub = self._sub_device_state.get(did, None)
            if sub and sub.handler:
                sub.handler(
                    did, MIoTDeviceState.ONLINE if state_new
                    else MIoTDeviceState.OFFLINE, sub.handler_ctx)
        # New devices or device home info changed
        for did, info in gw_list.items():
            self._device_list_gateway[did] = {**info, 'group_id': group_id}
            if did not in self._device_list_cache:
                continue
            group_id_old: str = self._device_list_cache[did].get(
                'group_id', None)
            self._device_list_cache[did]['group_id'] = group_id
            _LOGGER.info(
                'move device %s from %s to %s', did, group_id_old, group_id)
            self.__update_device_msg_sub(did=did)
            state_old: Optional[bool] = self._device_list_cache[did].get(
                'online', None)
            state_new: Optional[bool] = self.__check_device_state(
                self._device_list_cloud.get(did, {}).get('online', None),
                info.get('online', False),
                self._device_list_lan.get(did, {}).get('online', False))
            if state_old == state_new:
                continue
            self._device_list_cache[did]['online'] = state_new
            sub = self._sub_device_state.get(did, None)
            if sub and sub.handler:
                sub.handler(
                    did, MIoTDeviceState.ONLINE if state_new
                    else MIoTDeviceState.OFFLINE, sub.handler_ctx)

    @final
    async def __refresh_gw_devices_with_group_id_async(
        self, group_id: str
    ) -> None:
        """Refresh gateway devices by group_id"""
        _LOGGER.debug(
            'refresh gw devices with group_id, %s', group_id)
        # Remove timer
        self._mips_local_state_changed_timers.pop(group_id, None)
        mips = self._mips_local.get(group_id, None)
        if not mips:
            _LOGGER.error('mips not exist, %s', group_id)
            return
        if not mips.mips_state:
            _LOGGER.debug('local mips disconnect, skip refresh, %s', group_id)
            return
        payload: dict = {
            'info': [
                'name', 'model', 'urn',
                'online', 'specV2Access', 'pushAvailable'
            ]
        }
        gw_list: dict = await mips.get_dev_list_async(
            payload=json.dumps(payload))
        if gw_list is None:
            _LOGGER.error(
                'refresh gw devices with group_id failed, %s, %s',
                self._uid, group_id)
            # Retry until success
            self.__request_refresh_gw_devices_by_group_id(
                group_id=group_id)
            return
        await self.__update_devices_from_gw_async(
            gw_list=gw_list, group_id=group_id, filter_dids=[
                did for did, info in self._device_list_gateway.items()
                if info.get('group_id', None) == group_id])
        self.__request_show_devices_changed_notify()

    @final
    def __request_refresh_gw_devices_by_group_id(
        self, group_id: str, immediately: bool = False
    ) -> None:
        """Request refresh gateway devices by group_id"""
        refresh_timer = self._mips_local_state_changed_timers.get(
            group_id, None)
        if immediately:
            if refresh_timer:
                self._mips_local_state_changed_timers.pop(group_id, None)
                refresh_timer.cancel()
            self._mips_local_state_changed_timers[group_id] = (
                self._main_loop.call_later(
                    0, lambda: self._main_loop.create_task(
                        self.__refresh_gw_devices_with_group_id_async(
                            group_id=group_id))))
        if refresh_timer:
            return
        self._mips_local_state_changed_timers[group_id] = (
            self._main_loop.call_later(
                REFRESH_GATEWAY_DEVICES_DELAY,
                lambda: self._main_loop.create_task(
                    self.__refresh_gw_devices_with_group_id_async(
                        group_id=group_id))))

    @final
    async def __refresh_props_from_cloud(self, patch_len: int = 150) -> bool:
        if not self._network.network_status:
            return False

        request_list = None
        if len(self._refresh_props_list) < patch_len:
            request_list = self._refresh_props_list
            self._refresh_props_list = {}
        else:
            request_list = {}
            for _ in range(patch_len):
                key, value = self._refresh_props_list.popitem()
                request_list[key] = value
        try:
            results = await self._http.get_props_async(
                params=list(request_list.values()))
            if not results:
                raise MIoTClientError('get_props_async failed')
            for result in results:
                if (
                    'did' not in result
                    or 'siid' not in result
                    or 'piid' not in result
                    or 'value' not in result
                ):
                    continue
                request_list.pop(
                    f'{result["did"]}|{result["siid"]}|{result["piid"]}',
                    None)
                self.__on_prop_msg(params=result, ctx=None)
            if request_list:
                _LOGGER.info(
                    'refresh props failed, cloud, %s',
                    list(request_list.keys()))
                request_list = None
            return True
        except Exception as err:  # pylint:disable=broad-exception-caught
            _LOGGER.error(
                'refresh props error, cloud, %s, %s',
                err, traceback.format_exc())
            # Add failed request back to the list
            self._refresh_props_list.update(request_list)
            return False

    @final
    async def __refresh_props_from_gw(self) -> bool:
        if not self._mips_local or not self._device_list_gateway:
            return False
        request_list = {}
        succeed_once = False
        for key in list(self._refresh_props_list.keys()):
            did = key.split('|')[0]
            if did in request_list:
                # NOTICE: A device only requests once a cycle, continuous
                # acquisition of properties can cause device exceptions.
                continue
            params = self._refresh_props_list.pop(key)
            device_gw = self._device_list_gateway.get(did, None)
            if not device_gw:
                # Device not exist
                continue
            mips_gw = self._mips_local.get(device_gw['group_id'], None)
            if not mips_gw:
                _LOGGER.error('mips gateway not exist, %s', key)
                continue
            request_list[did] = {
                **params,
                'fut': mips_gw.get_prop_async(
                    did=did, siid=params['siid'], piid=params['piid'],
                    timeout_ms=6000)}
        results = await asyncio.gather(
            *[v['fut'] for v in request_list.values()])
        for (did, param), result in zip(request_list.items(), results):
            if result is None:
                # Don't use "not result", it will be skipped when result
                # is 0, false
                continue
            self.__on_prop_msg(
                params={
                    'did': did,
                    'siid': param['siid'],
                    'piid': param['piid'],
                    'value': result},
                ctx=None)
            succeed_once = True
        if succeed_once:
            return True
        _LOGGER.info(
            'refresh props failed, gw, %s', list(request_list.keys()))
        # Add failed request back to the list
        self._refresh_props_list.update(request_list)
        return False

    @final
    async def __refresh_props_from_lan(self) -> bool:
        if not self._miot_lan.init_done or len(self._mips_local) > 0:
            return False
        request_list = {}
        succeed_once = False
        for key in list(self._refresh_props_list.keys()):
            did = key.split('|')[0]
            if did in request_list:
                # NOTICE: A device only requests once a cycle, continuous
                # acquisition of properties can cause device exceptions.
                continue
            params = self._refresh_props_list.pop(key)
            if did not in self._device_list_lan:
                continue
            request_list[did] = {
                **params,
                'fut': self._miot_lan.get_prop_async(
                    did=did, siid=params['siid'], piid=params['piid'],
                    timeout_ms=6000)}
        results = await asyncio.gather(
            *[v['fut'] for v in request_list.values()])
        for (did, param), result in zip(request_list.items(), results):
            if result is None:
                # Don't use "not result", it will be skipped when result
                # is 0, false
                continue
            self.__on_prop_msg(
                params={
                    'did': did,
                    'siid': param['siid'],
                    'piid': param['piid'],
                    'value': result},
                ctx=None)
            succeed_once = True
        if succeed_once:
            return True
        _LOGGER.info(
            'refresh props failed, lan, %s', list(request_list.keys()))
        # Add failed request back to the list
        self._refresh_props_list.update(request_list)
        return False

    @final
    async def __refresh_props_handler(self) -> None:
        if not self._refresh_props_list:
            return
        # Cloud, Central hub gateway, Lan control
        if (
            await self.__refresh_props_from_cloud()
            or await self.__refresh_props_from_gw()
            or await self.__refresh_props_from_lan()
        ):
            self._refresh_props_retry_count = 0
            if self._refresh_props_list:
                self._refresh_props_timer = self._main_loop.call_later(
                    REFRESH_PROPS_DELAY, lambda: self._main_loop.create_task(
                        self.__refresh_props_handler()))
            else:
                self._refresh_props_timer = None
            return

        # Try three times, and if it fails three times, empty the list.
        if self._refresh_props_retry_count >= 3:
            self._refresh_props_list = {}
            self._refresh_props_retry_count = 0
            if self._refresh_props_timer:
                self._refresh_props_timer.cancel()
                self._refresh_props_timer = None
            _LOGGER.info('refresh props failed, retry count exceed')
            return
        self._refresh_props_retry_count += 1
        _LOGGER.info(
            'refresh props failed, retry, %s', self._refresh_props_retry_count)
        self._refresh_props_timer = self._main_loop.call_later(
            REFRESH_PROPS_RETRY_DELAY, lambda: self._main_loop.create_task(
                self.__refresh_props_handler()))

    @final
    def __show_client_error_notify(
        self, message: Optional[str], notify_key: str = ''
    ) -> None:
        if message:

            self._persistence_notify(
                f'{DOMAIN}{self._uid}{self._cloud_server}{notify_key}error',
                self._i18n.translate(
                    key='miot.client.xiaomi_home_error_title'),  # type: ignore
                self._i18n.translate(
                    key='miot.client.xiaomi_home_error',
                    replace={
                        'nick_name': self._entry_data.get(
                            'nick_name', DEFAULT_NICK_NAME),
                        'uid': self._uid,
                        'cloud_server': self._cloud_server,
                        'message': message}))  # type: ignore
        else:
            self._persistence_notify(
                f'{DOMAIN}{self._uid}{self._cloud_server}{notify_key}error',
                None, None)

    @final
    def __show_devices_changed_notify(self) -> None:
        """Show device list changed notify"""
        self._show_devices_changed_notify_timer = None
        if self._persistence_notify is None:
            return

        message_add: str = ''
        count_add: int = 0
        message_del: str = ''
        count_del: int = 0
        message_offline: str = ''
        count_offline: int = 0

        # New devices
        if 'add' in self._display_devs_notify:
            for did, info in {
                    **self._device_list_gateway, **self._device_list_cloud
            }.items():
                if did in self._device_list_cache:
                    continue
                count_add += 1
                message_add += (
                    f'- {info.get("name", "unknown")} ({did}, '
                    f'{info.get("model", "unknown")})\n')
        # Get unavailable and offline devices
        home_name_del: Optional[str] = None
        home_name_offline: Optional[str] = None
        for did, info in self._device_list_cache.items():
            online: Optional[bool] = info.get('online', None)
            home_name_new = info.get('home_name', 'unknown')
            if online:
                # Skip online device
                continue
            if 'del' in self._display_devs_notify and online is None:
                # Device not exist
                if home_name_del != home_name_new:
                    message_del += f'\n[{home_name_new}]\n'
                    home_name_del = home_name_new
                count_del += 1
                message_del += (
                    f'- {info.get("name", "unknown")} ({did}, '
                    f'{info.get("room_name", "unknown")})\n')
                continue
            if 'offline' in self._display_devs_notify:
                # Device offline
                if home_name_offline != home_name_new:
                    message_offline += f'\n[{home_name_new}]\n'
                    home_name_offline = home_name_new
                count_offline += 1
                message_offline += (
                    f'- {info.get("name", "unknown")} ({did}, '
                    f'{info.get("room_name", "unknown")})\n')

        message = ''
        if 'add' in self._display_devs_notify and count_add:
            message += self._i18n.translate(
                key='miot.client.device_list_add',
                replace={
                    'count': count_add,
                    'message': message_add})  # type: ignore
        if 'del' in self._display_devs_notify and count_del:
            message += self._i18n.translate(
                key='miot.client.device_list_del',
                replace={
                    'count': count_del,
                    'message': message_del})  # type: ignore
        if 'offline' in self._display_devs_notify and count_offline:
            message += self._i18n.translate(
                key='miot.client.device_list_offline',
                replace={
                    'count': count_offline,
                    'message': message_offline})  # type: ignore
        if message != '':
            msg_hash = hash(message)
            if msg_hash == self._display_notify_content_hash:
                # Notify content no change, return
                _LOGGER.debug(
                    'device list changed notify content no change, return')
                return
            network_status = self._i18n.translate(
                key='miot.client.network_status_online'
                if self._network.network_status
                else 'miot.client.network_status_offline')
            self._persistence_notify(
                self.__gen_notify_key('dev_list_changed'),
                self._i18n.translate(
                    'miot.client.device_list_changed_title'),  # type: ignore
                self._i18n.translate(
                    key='miot.client.device_list_changed',
                    replace={
                        'nick_name': self._entry_data.get(
                            'nick_name', DEFAULT_NICK_NAME),
                        'uid': self._uid,
                        'cloud_server': self._cloud_server,
                        'network_status': network_status,
                        'message': message}))  # type: ignore
            self._display_notify_content_hash = msg_hash
            _LOGGER.debug(
                'show device list changed notify, add %s, del %s, offline %s',
                count_add, count_del, count_offline)
        else:
            self._persistence_notify(
                self.__gen_notify_key('dev_list_changed'), None, None)

    @final
    def __request_show_devices_changed_notify(
        self, delay_sec: float = 6
    ) -> None:
        if not self._display_devs_notify:
            return
        if not self._mips_cloud and not self._mips_local and not self._miot_lan:
            return
        if self._show_devices_changed_notify_timer:
            self._show_devices_changed_notify_timer.cancel()
        self._show_devices_changed_notify_timer = self._main_loop.call_later(
            delay_sec, self.__show_devices_changed_notify)

    @final
    def __show_central_state_changed_notify(self, connected: bool) -> None:
        conn_status: str = (
            self._i18n.translate('miot.client.central_state_connected')
            if connected else
            self._i18n.translate('miot.client.central_state_disconnected'))
        self._persistence_notify(
            self.__gen_notify_key('central_state_changed'),
            self._i18n.translate('miot.client.central_state_changed_title'),
            self._i18n.translate(key='miot.client.central_state_changed',
                replace={
                    'nick_name': self._entry_data.get(
                                'nick_name', DEFAULT_NICK_NAME),
                    'uid': self._uid,
                    'cloud_server': self._cloud_server,
                    'conn_status': conn_status
                }))

@staticmethod
async def get_miot_instance_async(
    hass: HomeAssistant, entry_id: str, entry_data: Optional[dict] = None,
    persistent_notify: Optional[Callable[[str, str, str], None]] = None
) -> MIoTClient:
    if entry_id is None:
        raise MIoTClientError('invalid entry_id')
    miot_client = hass.data[DOMAIN].get('miot_clients', {}).get(entry_id, None)
    if miot_client:
        _LOGGER.info('instance exist, %s', entry_id)
        return miot_client
    # Create new instance
    if not entry_data:
        raise MIoTClientError('entry data is None')
    # Get running loop
    loop: asyncio.AbstractEventLoop = asyncio.get_running_loop()
    if not loop:
        raise MIoTClientError('loop is None')
    # MIoT storage
    storage: Optional[MIoTStorage] = hass.data[DOMAIN].get(
        'miot_storage', None)
    if not storage:
        storage = MIoTStorage(
            root_path=entry_data['storage_path'], loop=loop)
        hass.data[DOMAIN]['miot_storage'] = storage
        _LOGGER.info('create miot_storage instance')
    global_config: dict = await storage.load_user_config_async(
        uid='global_config', cloud_server='all',
        keys=['network_detect_addr', 'net_interfaces', 'enable_subscribe'])
    # MIoT network
    network_detect_addr: dict = global_config.get('network_detect_addr', {})
    network: Optional[MIoTNetwork] = hass.data[DOMAIN].get(
        'miot_network', None)
    if not network:
        network = MIoTNetwork(
            ip_addr_list=network_detect_addr.get('ip', []),
            url_addr_list=network_detect_addr.get('url', []),
            refresh_interval=NETWORK_REFRESH_INTERVAL,
            loop=loop)
        hass.data[DOMAIN]['miot_network'] = network
        await network.init_async()
        _LOGGER.info('create miot_network instance')
    # MIoT service
    mips_service: Optional[MipsService] = hass.data[DOMAIN].get(
        'mips_service', None)
    if not mips_service:
        aiozc = await zeroconf.async_get_async_instance(hass)
        mips_service = MipsService(aiozc=aiozc, loop=loop)
        hass.data[DOMAIN]['mips_service'] = mips_service
        await mips_service.init_async()
        _LOGGER.info('create mips_service instance')
    # MIoT lan
    miot_lan: Optional[MIoTLan] = hass.data[DOMAIN].get('miot_lan', None)
    if not miot_lan:
        miot_lan = MIoTLan(
            net_ifs=global_config.get('net_interfaces', []),
            network=network,
            mips_service=mips_service,
            enable_subscribe=global_config.get('enable_subscribe', False),
            loop=loop)
        hass.data[DOMAIN]['miot_lan'] = miot_lan
        _LOGGER.info('create miot_lan instance')
    # MIoT client
    miot_client = MIoTClient(
        entry_id=entry_id,
        entry_data=entry_data,
        network=network,
        storage=storage,
        mips_service=mips_service,
        miot_lan=miot_lan,
        loop=loop
    )
    miot_client.persistent_notify = persistent_notify
    hass.data[DOMAIN]['miot_clients'].setdefault(entry_id, miot_client)
    _LOGGER.info('new miot_client instance, %s, %s', entry_id, entry_data)
    await miot_client.init_async()
    return miot_client
