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

Config flow for Xiaomi Home.
"""
import asyncio
import hashlib
import ipaddress
import json
import secrets
import traceback
from typing import Optional, Set, Tuple
from urllib.parse import urlparse
from aiohttp import web
from aiohttp.hdrs import METH_GET
import voluptuous as vol
import logging

from homeassistant import config_entries
from homeassistant.components import zeroconf
from homeassistant.components.zeroconf import HaAsyncZeroconf
from homeassistant.components.webhook import (
    async_register as webhook_async_register,
    async_unregister as webhook_async_unregister,
    async_generate_path as webhook_async_generate_path
)
from homeassistant.core import callback
from homeassistant.data_entry_flow import AbortFlow
from homeassistant.helpers.instance_id import async_get
import homeassistant.helpers.config_validation as cv

from .miot.const import (
    DEFAULT_CLOUD_SERVER,
    DEFAULT_CTRL_MODE,
    DEFAULT_INTEGRATION_LANGUAGE,
    DEFAULT_COVER_DEAD_ZONE_WIDTH,
    MIN_COVER_DEAD_ZONE_WIDTH,
    MAX_COVER_DEAD_ZONE_WIDTH,
    DEFAULT_NICK_NAME,
    DEFAULT_OAUTH2_API_HOST,
    DEFAULT_CLOUD_BROKER_HOST,
    DOMAIN,
    OAUTH2_AUTH_URL,
    OAUTH2_CLIENT_ID,
    CLOUD_SERVERS,
    OAUTH_REDIRECT_URL,
    INTEGRATION_LANGUAGES,
    SUPPORT_CENTRAL_GATEWAY_CTRL,
    NETWORK_REFRESH_INTERVAL,
    MIHOME_CERT_EXPIRE_MARGIN
)
from .miot.miot_cloud import MIoTHttpClient, MIoTOauthClient
from .miot.miot_storage import MIoTStorage, MIoTCert
from .miot.miot_mdns import MipsService
from .miot.web_pages import oauth_redirect_page
from .miot.miot_error import (
    MIoTConfigError, MIoTError, MIoTErrorCode, MIoTOauthError)
from .miot.miot_i18n import MIoTI18n
from .miot.miot_network import MIoTNetwork
from .miot.miot_client import MIoTClient, get_miot_instance_async
from .miot.miot_spec import MIoTSpecParser
from .miot.miot_lan import MIoTLan

_LOGGER = logging.getLogger(__name__)


class XiaomiMihomeConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Xiaomi Home config flow."""
    # pylint: disable=unused-argument, inconsistent-quotes
    VERSION = 1
    MINOR_VERSION = 1
    DEFAULT_AREA_NAME_RULE = 'room'
    _main_loop: asyncio.AbstractEventLoop
    _miot_network: MIoTNetwork
    _mips_service: MipsService
    _miot_storage: MIoTStorage
    _miot_i18n: MIoTI18n
    _miot_oauth: Optional[MIoTOauthClient]
    _miot_http: Optional[MIoTHttpClient]

    _storage_path: str
    _virtual_did: str
    _uid: str
    _uuid: str
    _ctrl_mode: str
    _area_name_rule: str
    _action_debug: bool
    _hide_non_standard_entities: bool
    _display_binary_mode: list[str]
    _display_devices_changed_notify: list[str]

    _cloud_server: str
    _integration_language: str
    _cover_dz_width: int
    _auth_info: dict
    _nick_name: str
    _home_selected: dict
    _devices_filter: dict
    _device_list_sorted: dict
    _oauth_redirect_url_full: str

    # Config cache
    _cc_home_info: dict
    _cc_home_list_show: dict
    _cc_network_detect_addr: str
    _cc_oauth_auth_url: str
    _cc_user_cert_done: bool
    _cc_task_oauth: Optional[asyncio.Task[None]]
    _cc_config_rc: Optional[str]
    _cc_fut_oauth_code: Optional[asyncio.Future]
    _opt_check_network_deps: bool

    def __init__(self) -> None:
        self._main_loop = asyncio.get_running_loop()
        self._cloud_server = DEFAULT_CLOUD_SERVER
        self._integration_language = DEFAULT_INTEGRATION_LANGUAGE
        self._cover_dz_width = DEFAULT_COVER_DEAD_ZONE_WIDTH
        self._storage_path = ''
        self._virtual_did = ''
        self._uid = ''
        self._uuid = ''   # MQTT client id
        self._ctrl_mode = DEFAULT_CTRL_MODE
        self._area_name_rule = self.DEFAULT_AREA_NAME_RULE
        self._action_debug = False
        self._hide_non_standard_entities = False
        self._display_binary_mode = ['bool']
        self._display_devices_changed_notify = ['add', 'del', 'offline']
        self._auth_info = {}
        self._nick_name = DEFAULT_NICK_NAME
        self._home_selected = {}
        self._devices_filter = {}
        self._device_list_sorted = {}
        self._oauth_redirect_url_full = ''
        self._miot_oauth = None
        self._miot_http = None

        self._cc_home_info = {}
        self._cc_home_list_show = {}
        self._cc_network_detect_addr = ''
        self._cc_oauth_auth_url = ''
        self._cc_user_cert_done = False
        self._cc_task_oauth = None
        self._cc_config_rc = None
        self._cc_fut_oauth_code = None
        self._opt_check_network_deps = False

    async def async_step_user(
        self, user_input: Optional[dict] = None
    ):
        self.hass.data.setdefault(DOMAIN, {})
        if not self._virtual_did:
            self._virtual_did = str(secrets.randbits(64))
            self.hass.data[DOMAIN].setdefault(self._virtual_did, {})
        if not self._storage_path:
            self._storage_path = self.hass.config.path('.storage', DOMAIN)
        # MIoT storage
        self._miot_storage = self.hass.data[DOMAIN].get('miot_storage', None)
        if not self._miot_storage:
            self._miot_storage = MIoTStorage(
                root_path=self._storage_path, loop=self._main_loop)
            self.hass.data[DOMAIN]['miot_storage'] = self._miot_storage
            _LOGGER.info(
                'async_step_user, create miot storage, %s', self._storage_path)
        # MIoT network
        network_detect_addr = (await self._miot_storage.load_user_config_async(
            uid='global_config', cloud_server='all',
            keys=['network_detect_addr'])).get('network_detect_addr', {})
        self._cc_network_detect_addr = ','.join(
            network_detect_addr.get('ip', [])
            + network_detect_addr.get('url', []))
        self._miot_network = self.hass.data[DOMAIN].get('miot_network', None)
        if not self._miot_network:
            self._miot_network = MIoTNetwork(
                ip_addr_list=network_detect_addr.get('ip', []),
                url_addr_list=network_detect_addr.get('url', []),
                refresh_interval=NETWORK_REFRESH_INTERVAL,
                loop=self._main_loop)
            self.hass.data[DOMAIN]['miot_network'] = self._miot_network
            await self._miot_network.init_async()
            _LOGGER.info('async_step_user, create miot network')
        # MIPS service
        self._mips_service = self.hass.data[DOMAIN].get('mips_service', None)
        if not self._mips_service:
            aiozc: HaAsyncZeroconf = await zeroconf.async_get_async_instance(
                self.hass)
            self._mips_service = MipsService(aiozc=aiozc, loop=self._main_loop)
            self.hass.data[DOMAIN]['mips_service'] = self._mips_service
            await self._mips_service.init_async()
            _LOGGER.info('async_step_user, create mips service')

        return await self.async_step_eula(user_input)

    async def async_step_eula(
        self, user_input: Optional[dict] = None
    ):
        if user_input:
            if user_input.get('eula', None) is True:
                return await self.async_step_auth_config()
            return await self.__show_eula_form('eula_not_agree')
        return await self.__show_eula_form('')

    async def __show_eula_form(self, reason: str):
        return self.async_show_form(
            step_id='eula',
            data_schema=vol.Schema({
                vol.Required('eula', default=False): bool,  # type: ignore
            }),
            last_step=False,
            errors={'base': reason},
        )

    async def async_step_auth_config(
        self, user_input: Optional[dict] = None
    ):
        if user_input:
            self._cloud_server = user_input.get(
                'cloud_server', self._cloud_server)
            # Gen instance uuid
            ha_uuid = await async_get(self.hass)
            if not ha_uuid:
                raise AbortFlow(reason='ha_uuid_get_failed')
            self._uuid = hashlib.sha256(
                f'{ha_uuid}.{self._virtual_did}.{self._cloud_server}'.encode(
                    'utf-8')).hexdigest()[:32]
            self._integration_language = user_input.get(
                'integration_language', DEFAULT_INTEGRATION_LANGUAGE)
            self._miot_i18n = MIoTI18n(
                lang=self._integration_language, loop=self._main_loop)
            await self._miot_i18n.init_async()
            webhook_path = webhook_async_generate_path(
                webhook_id=self._virtual_did)
            self._oauth_redirect_url_full = (
                f'{user_input.get("oauth_redirect_url")}{webhook_path}')

            if user_input.get('network_detect_config', False):
                return await self.async_step_network_detect_config()
            return await self.async_step_oauth(user_input)
        return await self.__show_auth_config_form('')

    async def __show_auth_config_form(self, reason: str):
        # Generate default language from HomeAssistant config (not user config)
        default_language: str = self.hass.config.language
        if default_language not in INTEGRATION_LANGUAGES:
            if default_language.split('-', 1)[0] not in INTEGRATION_LANGUAGES:
                default_language = DEFAULT_INTEGRATION_LANGUAGE
            else:
                default_language = default_language.split('-', 1)[0]
        return self.async_show_form(
            step_id='auth_config',
            data_schema=vol.Schema({
                vol.Required(
                    'cloud_server',
                    default=self._cloud_server  # type: ignore
                ):  vol.In(CLOUD_SERVERS),
                vol.Required(
                    'integration_language',
                    default=default_language  # type: ignore
                ):   vol.In(INTEGRATION_LANGUAGES),
                vol.Required(
                    'oauth_redirect_url',
                    default=OAUTH_REDIRECT_URL  # type: ignore
                ): vol.In([OAUTH_REDIRECT_URL]),
                vol.Required(
                    'network_detect_config',
                    default=False  # type: ignore
                ): bool,
            }),
            errors={'base': reason},
            last_step=False,
        )

    async def async_step_network_detect_config(
        self, user_input: Optional[dict] = None
    ):
        if not user_input:
            return await self.__show_network_detect_config_form(reason='')
        self._cc_network_detect_addr = user_input.get(
            'network_detect_addr', self._cc_network_detect_addr)

        ip_list, url_list, invalid_list = _handle_network_detect_addr(
            addr_str=self._cc_network_detect_addr)
        if invalid_list:
            return await self.__show_network_detect_config_form(
                reason='invalid_network_addr')
        if ip_list or url_list:
            if ip_list and not await self._miot_network.ping_multi_async(
                    ip_list=ip_list):
                return await self.__show_network_detect_config_form(
                    reason='invalid_ip_addr')
            if url_list and not await self._miot_network.http_multi_async(
                    url_list=url_list):
                return await self.__show_network_detect_config_form(
                    reason='invalid_http_addr')
        else:
            if not await self._miot_network.get_network_status_async():
                return await self.__show_network_detect_config_form(
                    reason='invalid_default_addr')
        network_detect_addr: dict = {'ip': ip_list, 'url': url_list}
        # Save
        if await self._miot_storage.update_user_config_async(
            uid='global_config', cloud_server='all', config={
                'network_detect_addr': network_detect_addr}):
            _LOGGER.info(
                'update network_detect_addr, %s', network_detect_addr)
        await self._miot_network.update_addr_list_async(
            ip_addr_list=ip_list, url_addr_list=url_list)
        # Check network deps
        self._opt_check_network_deps = user_input.get(
            'check_network_deps', self._opt_check_network_deps)
        if self._opt_check_network_deps:
            # OAuth2
            if not await self._miot_network.http_multi_async(
                    url_list=[OAUTH2_AUTH_URL]):
                return await self.__show_network_detect_config_form(
                    reason='unreachable_oauth2_host')
            # HTTP API
            http_host = (
                DEFAULT_OAUTH2_API_HOST
                if self._cloud_server == DEFAULT_CLOUD_SERVER
                else f'{self._cloud_server}.{DEFAULT_OAUTH2_API_HOST}')
            if not await self._miot_network.http_multi_async(
                    url_list=[
                        f'https://{http_host}/app/v2/ha/oauth/get_token']):
                return await self.__show_network_detect_config_form(
                    reason='unreachable_http_host')
            # SPEC API
            if not await self._miot_network.http_multi_async(
                    url_list=[
                        'https://miot-spec.org/miot-spec-v2/template/list/'
                        'device']):
                return await self.__show_network_detect_config_form(
                    reason='unreachable_spec_host')
            # MQTT Broker
            # pylint: disable=import-outside-toplevel
            try:
                from paho.mqtt import client
                mqtt_client = client.Client(
                    client_id=f'ha.{self._uid}',
                    protocol=client.MQTTv5)  # type: ignore
                if mqtt_client.connect(
                    host=f'{self._cloud_server}-{DEFAULT_CLOUD_BROKER_HOST}',
                    port=8883) != 0:
                    raise RuntimeError('mqtt connect error')
                mqtt_client.disconnect()
            except Exception as err:  # pylint: disable=broad-exception-caught
                _LOGGER.error('try connect mqtt broker error, %s', err)
                return await self.__show_network_detect_config_form(
                    reason='unreachable_mqtt_broker')

        return await self.async_step_oauth()

    async def __show_network_detect_config_form(self, reason: str):
        if not self._cc_network_detect_addr:
            addr_list: dict = (await self._miot_storage.load_user_config_async(
                'global_config', 'all', ['network_detect_addr'])).get(
                    'network_detect_addr', {})
            self._cc_network_detect_addr = ','.join(
                addr_list.get('ip', [])+addr_list.get('url', []))
        return self.async_show_form(
            step_id='network_detect_config',
            data_schema=vol.Schema({
                vol.Optional(
                    'network_detect_addr',
                    default=self._cc_network_detect_addr  # type: ignore
                ): str,
                vol.Optional(
                    'check_network_deps',
                    default=self._opt_check_network_deps  # type: ignore
                ): bool,
            }),
            errors={'base': reason},
            description_placeholders={
                'broker_host':
                    f'{self._cloud_server}-{DEFAULT_CLOUD_BROKER_HOST}:8883',
                'http_host': (
                    DEFAULT_OAUTH2_API_HOST
                    if self._cloud_server == DEFAULT_CLOUD_SERVER
                    else f'{self._cloud_server}.{DEFAULT_OAUTH2_API_HOST}')},
            last_step=False
        )

    async def async_step_oauth(
        self, user_input: Optional[dict] = None
    ):
        # 1: Init miot_oauth, generate auth url
        try:
            if not self._miot_oauth:
                _LOGGER.info(
                    'async_step_oauth, redirect_url: %s',
                    self._oauth_redirect_url_full)
                miot_oauth = MIoTOauthClient(
                    client_id=OAUTH2_CLIENT_ID,
                    redirect_url=self._oauth_redirect_url_full,
                    cloud_server=self._cloud_server,
                    uuid=self._uuid,
                    loop=self._main_loop)
                self._cc_oauth_auth_url = miot_oauth.gen_auth_url(
                    redirect_url=self._oauth_redirect_url_full)
                self.hass.data[DOMAIN][self._virtual_did]['oauth_state'] = (
                    miot_oauth.state)
                self.hass.data[DOMAIN][self._virtual_did]['i18n'] = (
                    self._miot_i18n)
                _LOGGER.info(
                    'async_step_oauth, oauth_url: %s', self._cc_oauth_auth_url)
                webhook_async_unregister(
                    self.hass, webhook_id=self._virtual_did)
                webhook_async_register(
                    self.hass,
                    domain=DOMAIN,
                    name='oauth redirect url webhook',
                    webhook_id=self._virtual_did,
                    handler=_handle_oauth_webhook,
                    allowed_methods=(METH_GET,),
                )
                self._cc_fut_oauth_code = self.hass.data[DOMAIN][
                    self._virtual_did].get('fut_oauth_code', None)
                if not self._cc_fut_oauth_code:
                    self._cc_fut_oauth_code = self._main_loop.create_future()
                    self.hass.data[DOMAIN][self._virtual_did][
                        'fut_oauth_code'] = self._cc_fut_oauth_code
                _LOGGER.info(
                    'async_step_oauth, webhook.async_register: %s',
                    self._virtual_did)
                self._miot_oauth = miot_oauth
        except Exception as err:  # pylint: disable=broad-exception-caught
            _LOGGER.error(
                'async_step_oauth, %s, %s', err, traceback.format_exc())
            return self.async_show_progress_done(next_step_id='oauth_error')

        # 2: show OAuth2 loading page
        if self._cc_task_oauth is None:
            self._cc_task_oauth = self.hass.async_create_task(
                self.__check_oauth_async())
        if self._cc_task_oauth.done():
            if (error := self._cc_task_oauth.exception()):
                _LOGGER.error('task_oauth exception, %s', error)
                self._cc_config_rc = str(error)
                return self.async_show_progress_done(next_step_id='oauth_error')
            if self._miot_oauth:
                await self._miot_oauth.deinit_async()
                self._miot_oauth = None
            return self.async_show_progress_done(next_step_id='homes_select')
        # pylint: disable=unexpected-keyword-arg
        return self.async_show_progress(
            step_id='oauth',
            progress_action='oauth',
            description_placeholders={
                'link_left':
                    f'<a href="{self._cc_oauth_auth_url}" target="_blank">',
                'link_right': '</a>'
            },
            progress_task=self._cc_task_oauth,  # type: ignore
        )

    async def __check_oauth_async(self) -> None:
        # TASK 1: Get oauth code
        if not self._cc_fut_oauth_code:
            raise MIoTConfigError('oauth_code_fut_error')
        oauth_code: Optional[str] = await self._cc_fut_oauth_code
        if not oauth_code:
            raise MIoTConfigError('oauth_code_error')
        # TASK 2: Get access_token and user_info from miot_oauth
        if not self._auth_info:
            try:
                if not self._miot_oauth:
                    raise MIoTConfigError('oauth_client_error')
                auth_info = await self._miot_oauth.get_access_token_async(
                    code=oauth_code)
                if not self._miot_http:
                    self._miot_http = MIoTHttpClient(
                        cloud_server=self._cloud_server,
                        client_id=OAUTH2_CLIENT_ID,
                        access_token=auth_info['access_token'])
                else:
                    self._miot_http.update_http_header(
                        cloud_server=self._cloud_server,
                        client_id=OAUTH2_CLIENT_ID,
                        access_token=auth_info['access_token'])
                self._auth_info = auth_info
                try:
                    self._nick_name = (
                        await self._miot_http.get_user_info_async() or {}
                    ).get('miliaoNick', self._nick_name)
                except (MIoTOauthError, json.JSONDecodeError):
                    self._nick_name = DEFAULT_NICK_NAME
                    _LOGGER.error('get nick name failed')
            except Exception as err:
                _LOGGER.error(
                    'get_access_token, %s, %s', err, traceback.format_exc())
                raise MIoTConfigError('get_token_error') from err

        # TASK 3: Get home info
        try:
            if not self._miot_http:
                raise MIoTConfigError('http_client_error')
            self._cc_home_info = (
                await self._miot_http.get_devices_async())
            _LOGGER.info('get_homeinfos response: %s', self._cc_home_info)
            self._uid = self._cc_home_info['uid']
            if self._uid == self._nick_name:
                self._nick_name = DEFAULT_NICK_NAME
            # Save auth_info
            if not (await self._miot_storage.update_user_config_async(
                    uid=self._uid, cloud_server=self._cloud_server, config={
                        'auth_info': self._auth_info
                    })):
                raise MIoTError('miot_storage.update_user_config_async error')
        except Exception as err:
            _LOGGER.error(
                'get_homeinfos error, %s, %s', err, traceback.format_exc())
            raise MIoTConfigError('get_homeinfo_error') from err

        # TASK 4: Abort if unique_id configured
        # Each MiHome account can only configure one instance
        await self.async_set_unique_id(f'{self._cloud_server}{self._uid}')
        self._abort_if_unique_id_configured()

        # TASK 5: Query mdns info
        mips_list = None
        if self._cloud_server in SUPPORT_CENTRAL_GATEWAY_CTRL:
            try:
                mips_list = self._mips_service.get_services()
            except Exception as err:
                _LOGGER.error(
                    'async_update_services error, %s, %s',
                    err, traceback.format_exc())
                raise MIoTConfigError('mdns_discovery_error') from err

        # TASK 6: Generate devices filter
        home_list = {}
        tip_devices = self._miot_i18n.translate(key='config.other.devices')
        # home list
        for device_source in ['home_list','share_home_list',
                              'separated_shared_list']:
            if device_source not in self._cc_home_info['homes']:
                continue
            for home_id, home_info in self._cc_home_info[
                    'homes'][device_source].items():
                # i18n
                tip_central = ''
                group_id = home_info.get('group_id', None)
                dev_list = {
                    device['did']: device
                    for device in list(self._cc_home_info['devices'].values())
                    if device.get('home_id', None) == home_id}
                if (
                    mips_list
                    and group_id in mips_list
                    and mips_list[group_id].get('did', None) in dev_list
                ):
                    # i18n
                    tip_central = self._miot_i18n.translate(
                        key='config.other.found_central_gateway')
                    home_info['central_did'] = mips_list[group_id].get(
                        'did', None)
                home_list[home_id] = (
                    f'{home_info["home_name"]} '
                    f'[ {len(dev_list)} {tip_devices} {tip_central} ]')

        self._cc_home_list_show = dict(sorted(home_list.items()))

        # TASK 7: Get user's MiHome certificate
        if self._cloud_server in SUPPORT_CENTRAL_GATEWAY_CTRL:
            miot_cert = MIoTCert(
                storage=self._miot_storage,
                uid=self._uid, cloud_server=self._cloud_server)
            if not self._cc_user_cert_done:
                try:
                    if await miot_cert.user_cert_remaining_time_async(
                            did=self._virtual_did) < MIHOME_CERT_EXPIRE_MARGIN:
                        user_key = await miot_cert.load_user_key_async()
                        if user_key is None:
                            user_key = miot_cert.gen_user_key()
                            if not await miot_cert.update_user_key_async(
                                    key=user_key):
                                raise MIoTError('update_user_key_async failed')
                        csr_str = miot_cert.gen_user_csr(
                            user_key=user_key, did=self._virtual_did)
                        crt_str = await self._miot_http.get_central_cert_async(
                            csr_str)
                        if not crt_str:
                            raise MIoTError('get_central_cert_async failed')
                        if not await miot_cert.update_user_cert_async(
                                cert=crt_str):
                            raise MIoTError('update_user_cert_async failed')
                        self._cc_user_cert_done = True
                        _LOGGER.info(
                            'get mihome cert success, %s, %s',
                            self._uid, self._virtual_did)
                except Exception as err:
                    _LOGGER.error(
                        'get user cert error, %s, %s',
                        err, traceback.format_exc())
                    raise MIoTConfigError('get_cert_error') from err

        # Auth success, unregister oauth webhook
        webhook_async_unregister(self.hass, webhook_id=self._virtual_did)
        if self._miot_http:
            await self._miot_http.deinit_async()
            self._miot_http = None
        _LOGGER.info(
            '__check_oauth_async, webhook.async_unregister: %s',
            self._virtual_did)

    # Show setup error message
    async def async_step_oauth_error(self, user_input=None):
        if self._cc_config_rc is None:
            return await self.async_step_oauth()
        if self._cc_config_rc.startswith('Flow aborted: '):
            raise AbortFlow(
                reason=self._cc_config_rc.replace('Flow aborted: ', ''))
        error_reason = self._cc_config_rc
        self._cc_config_rc = None
        return self.async_show_form(
            step_id='oauth_error',
            data_schema=vol.Schema({}),
            last_step=False,
            errors={'base': error_reason},
        )

    async def async_step_homes_select(
        self, user_input: Optional[dict] = None
    ):
        _LOGGER.debug('async_step_homes_select')
        try:
            if not user_input:
                return await self.__show_homes_select_form('')

            home_selected: list = user_input.get('home_infos', [])
            if not home_selected:
                return await self.__show_homes_select_form(
                    'no_family_selected')
            for device_source in ['home_list','share_home_list',
                                  'separated_shared_list']:
                if device_source not in self._cc_home_info['homes']:
                    continue
                for home_id, home_info in self._cc_home_info[
                        'homes'][device_source].items():
                    if home_id in home_selected:
                        self._home_selected[home_id] = home_info
            self._area_name_rule = user_input.get(
                'area_name_rule', self._area_name_rule)
            # Storage device list
            devices_list: dict[str, dict] = {
                did: dev_info
                for did, dev_info in self._cc_home_info['devices'].items()
                if dev_info['home_id'] in home_selected}
            if not devices_list:
                return await self.__show_homes_select_form('no_devices')
            self._device_list_sorted = dict(sorted(
                devices_list.items(), key=lambda item:
                    item[1].get('home_id', '')+item[1].get('room_id', '')))

            if not await self._miot_storage.save_async(
                    domain='miot_devices',
                    name=f'{self._uid}_{self._cloud_server}',
                    data=self._device_list_sorted):
                _LOGGER.error(
                    'save devices async failed, %s, %s',
                    self._uid, self._cloud_server)
                return await self.__show_homes_select_form(
                    'devices_storage_failed')
            if user_input.get('advanced_options', False):
                return await self.async_step_advanced_options()
            return await self.config_flow_done()
        except Exception as err:
            _LOGGER.error(
                'async_step_homes_select, %s, %s',
                err, traceback.format_exc())
            raise AbortFlow(
                reason='config_flow_error',
                description_placeholders={
                    'error': f'config_flow error, {err}'}
            ) from err

    async def __show_homes_select_form(self, reason: str):
        return self.async_show_form(
            step_id='homes_select',
            data_schema=vol.Schema({
                vol.Required('home_infos'): cv.multi_select(
                    self._cc_home_list_show),
                vol.Required(
                    'area_name_rule',
                    default=self._area_name_rule  # type: ignore
                ): vol.In(self._miot_i18n.translate(
                    key='config.room_name_rule')),
                vol.Required(
                    'advanced_options', default=False  # type: ignore
                ): bool,
            }),
            errors={'base': reason},
            description_placeholders={
                'nick_name': self._nick_name,
            },
            last_step=False,
        )

    async def async_step_advanced_options(
        self, user_input: Optional[dict] = None
    ):
        if user_input:
            self._ctrl_mode = user_input.get('ctrl_mode', self._ctrl_mode)
            self._action_debug = user_input.get(
                'action_debug', self._action_debug)
            self._hide_non_standard_entities = user_input.get(
                'hide_non_standard_entities', self._hide_non_standard_entities)
            self._display_binary_mode = user_input.get(
                'display_binary_mode', self._display_binary_mode)
            self._display_devices_changed_notify = user_input.get(
                'display_devices_changed_notify',
                self._display_devices_changed_notify)
            # Device filter
            if user_input.get('devices_filter', False):
                return await self.async_step_devices_filter()
            return await self.config_flow_done()
        return self.async_show_form(
            step_id='advanced_options',
            data_schema=vol.Schema({
                vol.Required(
                    'devices_filter', default=False): bool,  # type: ignore
                vol.Required(
                    'ctrl_mode', default=self._ctrl_mode  # type: ignore
                ): vol.In(self._miot_i18n.translate(key='config.control_mode')),
                vol.Required(
                    'action_debug', default=self._action_debug  # type: ignore
                ): bool,
                vol.Required(
                    'hide_non_standard_entities',
                    default=self._hide_non_standard_entities  # type: ignore
                ): bool,
                vol.Required(
                    'display_binary_mode',
                    default=self._display_binary_mode  # type: ignore
                ): cv.multi_select(
                    self._miot_i18n.translate(
                        key='config.binary_mode')),  # type: ignore
                vol.Required(
                    'display_devices_changed_notify',
                    default=self._display_devices_changed_notify  # type: ignore
                ): cv.multi_select(
                    self._miot_i18n.translate(
                        key='config.device_state')),  # type: ignore
            }),
            last_step=False,
        )

    async def async_step_devices_filter(
        self, user_input: Optional[dict] = None
    ):
        if user_input:
            # Room filter
            include_items: dict = {}
            exclude_items: dict = {}
            room_list_in: list = user_input.get('room_list', [])
            if room_list_in:
                if user_input.get(
                        'room_filter_mode', 'exclude') == 'include':
                    include_items['room_id'] = room_list_in
                else:
                    exclude_items['room_id'] = room_list_in
            # Connect Type filter
            type_list_in: list = user_input.get('type_list', [])
            if type_list_in:
                if user_input.get(
                        'type_filter_mode', 'exclude') == 'include':
                    include_items['connect_type'] = type_list_in
                else:
                    exclude_items['connect_type'] = type_list_in
            # Model filter
            model_list_in: list = user_input.get('model_list', [])
            if model_list_in:
                if user_input.get(
                        'model_filter_mode', 'exclude') == 'include':
                    include_items['model'] = model_list_in
                else:
                    exclude_items['model'] = model_list_in
            # Device filter
            device_list_in: list = user_input.get('device_list', [])
            if device_list_in:
                if user_input.get(
                        'devices_filter_mode', 'exclude') == 'include':
                    include_items['did'] = device_list_in
                else:
                    exclude_items['did'] = device_list_in
            device_filter_list = _handle_devices_filter(
                devices=self._device_list_sorted,
                logic_or=(user_input.get('statistics_logic', 'or') == 'or'),
                item_in=include_items, item_ex=exclude_items)
            if not device_filter_list:
                return await self.__show_devices_filter_form(
                    reason='no_filter_devices')
            self._device_list_sorted = dict(sorted(
                device_filter_list.items(), key=lambda item:
                    item[1].get('home_id', '')+item[1].get('room_id', '')))
            # Save devices
            if not await self._miot_storage.save_async(
                    domain='miot_devices',
                    name=f'{self._uid}_{self._cloud_server}',
                    data=self._device_list_sorted):
                _LOGGER.error(
                    'save devices async failed, %s, %s',
                    self._uid, self._cloud_server)
                raise AbortFlow(
                    reason='storage_error', description_placeholders={
                        'error': 'save user devices error'})
            self._devices_filter = {
                'room_list': {
                    'items': room_list_in,
                    'mode': user_input.get('room_filter_mode', 'exclude')},
                'type_list': {
                    'items': type_list_in,
                    'mode': user_input.get('type_filter_mode', 'exclude')},
                'model_list': {
                    'items': model_list_in,
                    'mode': user_input.get('model_filter_mode', 'exclude')},
                'device_list': {
                    'items': device_list_in,
                    'mode': user_input.get('devices_filter_mode', 'exclude')},
                'statistics_logic': user_input.get('statistics_logic', 'or'),
            }
            return await self.config_flow_done()
        return await self.__show_devices_filter_form(reason='')

    async def __show_devices_filter_form(self, reason: str):
        tip_devices: str = self._miot_i18n.translate(
            key='config.other.devices')  # type: ignore
        tip_without_room: str = self._miot_i18n.translate(
            key='config.other.without_room')  # type: ignore
        trans_statistics_logic: dict = self._miot_i18n.translate(
            key='config.statistics_logic')  # type: ignore
        trans_filter_mode: dict = self._miot_i18n.translate(
            key='config.filter_mode')  # type: ignore
        trans_connect_type: dict = self._miot_i18n.translate(
            key='config.connect_type')  # type: ignore

        room_device_count: dict = {}
        model_device_count: dict = {}
        connect_type_count: dict = {}
        device_list: dict = {}
        for did, info in self._device_list_sorted.items():
            device_list[did] = (
                f'[ {info["home_name"]} {info["room_name"]} ] ' +
                f'{info["name"]}, {did}')
            room_device_count.setdefault(info['room_id'], 0)
            room_device_count[info['room_id']] += 1
            model_device_count.setdefault(info['model'], 0)
            model_device_count[info['model']] += 1
            connect_type_count.setdefault(str(info['connect_type']), 0)
            connect_type_count[str(info['connect_type'])] += 1
        model_list: dict = {}
        for model, count in model_device_count.items():
            model_list[model] = f'{model} [ {count} {tip_devices} ]'
        type_list: dict = {
            k: f'{trans_connect_type.get(k, f"Connect Type ({k})")} '
            f'[ {v} {tip_devices} ]'
            for k, v in connect_type_count.items()}
        room_list: dict = {}
        for home_id, home_info in self._home_selected.items():
            for room_id, room_name in home_info['room_info'].items():
                if room_id not in room_device_count:
                    continue
                room_list[room_id] = (
                    f'{home_info["home_name"]} {room_name}'
                    f' [ {room_device_count[room_id]}{tip_devices} ]')
            if home_id in room_device_count:
                room_list[home_id] = (
                    f'{home_info["home_name"]} {tip_without_room}'
                    f' [ {room_device_count[home_id]}{tip_devices} ]')
        return self.async_show_form(
            step_id='devices_filter',
            data_schema=vol.Schema({
                vol.Required(
                    'room_filter_mode', default='exclude'  # type: ignore
                ): vol.In(trans_filter_mode),
                vol.Optional('room_list'): cv.multi_select(room_list),
                vol.Required(
                    'type_filter_mode', default='exclude'  # type: ignore
                ): vol.In(trans_filter_mode),
                vol.Optional('type_list'): cv.multi_select(type_list),
                vol.Required(
                    'model_filter_mode', default='exclude'  # type: ignore
                ): vol.In(trans_filter_mode),
                vol.Optional('model_list'): cv.multi_select(dict(sorted(
                    model_list.items(), key=lambda item: item[0]))),
                vol.Required(
                    'devices_filter_mode', default='exclude'  # type: ignore
                ): vol.In(trans_filter_mode),
                vol.Optional('device_list'): cv.multi_select(dict(sorted(
                    device_list.items(), key=lambda device: device[1]))),
                vol.Required(
                    'statistics_logic', default='or'  # type: ignore
                ): vol.In(trans_statistics_logic),
            }),
            errors={'base': reason},
            last_step=False
        )

    async def config_flow_done(self):
        return self.async_create_entry(
            title=(
                f'{self._nick_name}: {self._uid} '
                f'[{CLOUD_SERVERS[self._cloud_server]}]'),
            data={
                'virtual_did': self._virtual_did,
                'uuid': self._uuid,
                'integration_language': self._integration_language,
                'storage_path': self._storage_path,
                'uid': self._uid,
                'nick_name': self._nick_name,
                'cloud_server': self._cloud_server,
                'oauth_redirect_url': self._oauth_redirect_url_full,
                'ctrl_mode': self._ctrl_mode,
                'home_selected': self._home_selected,
                'devices_filter': self._devices_filter,
                'area_name_rule': self._area_name_rule,
                'action_debug': self._action_debug,
                'hide_non_standard_entities':
                    self._hide_non_standard_entities,
                'cover_dead_zone_width': self._cover_dz_width,
                'display_binary_mode': self._display_binary_mode,
                'display_devices_changed_notify':
                    self._display_devices_changed_notify
            })

    @ staticmethod
    @ callback
    def async_get_options_flow(
            config_entry: config_entries.ConfigEntry,
    ) -> config_entries.OptionsFlow:
        return OptionsFlowHandler(config_entry)


class OptionsFlowHandler(config_entries.OptionsFlow):
    """Xiaomi MiHome options flow."""
    # pylint: disable=unused-argument
    # pylint: disable=inconsistent-quotes
    _config_entry: config_entries.ConfigEntry
    _main_loop: asyncio.AbstractEventLoop
    _miot_client: MIoTClient

    _miot_network: MIoTNetwork
    _miot_storage: MIoTStorage
    _mips_service: MipsService
    _miot_oauth: MIoTOauthClient
    _miot_http: MIoTHttpClient
    _miot_i18n: MIoTI18n
    _miot_lan: MIoTLan

    _entry_data: dict
    _virtual_did: str
    _uid: str
    _storage_path: str
    _cloud_server: str

    _integration_language: str
    _ctrl_mode: str
    _nick_name: str
    _home_selected_list: list
    _devices_filter: dict
    _action_debug: bool
    _hide_non_standard_entities: bool
    _display_binary_mode: list[str]
    _display_devs_notify: list[str]
    _cover_dz_width: int

    _oauth_redirect_url_full: str
    _auth_info: dict
    _home_selected: dict
    _device_list_sorted: dict
    _devices_add: list[str]
    _devices_remove: list[str]

    # Config options
    _lang_new: str
    _nick_name_new: Optional[str]
    _action_debug_new: bool
    _hide_non_standard_entities_new: bool
    _display_binary_mode_new: list[str]
    _update_user_info: bool
    _update_devices: bool
    _update_trans_rules: bool
    _opt_lan_ctrl_cfg: bool
    _opt_network_detect_cfg: bool
    _opt_check_network_deps: bool
    _cover_width_new: int

    _trans_rules_count: int
    _trans_rules_count_success: int

    _need_reload: bool

    # Config cache
    _cc_home_info: dict
    _cc_home_list_show: dict
    _cc_oauth_auth_url: Optional[str]
    _cc_task_oauth: Optional[asyncio.Task[None]]
    _cc_config_rc: Optional[str]
    _cc_fut_oauth_code: Optional[asyncio.Future]
    _cc_devices_local: dict
    _cc_network_detect_addr: str

    def __init__(self, config_entry: config_entries.ConfigEntry):
        self._config_entry = config_entry
        self._main_loop = asyncio.get_event_loop()

        self._entry_data = dict(config_entry.data)
        self._virtual_did = self._entry_data['virtual_did']
        self._uid = self._entry_data['uid']
        self._storage_path = self._entry_data['storage_path']
        self._cloud_server = self._entry_data['cloud_server']
        self._ctrl_mode = self._entry_data.get('ctrl_mode', DEFAULT_CTRL_MODE)
        self._integration_language = self._entry_data.get(
            'integration_language', DEFAULT_INTEGRATION_LANGUAGE)
        self._cover_dz_width = self._entry_data.get(
            'cover_dead_zone_width', DEFAULT_COVER_DEAD_ZONE_WIDTH)
        self._nick_name = self._entry_data.get('nick_name', DEFAULT_NICK_NAME)
        self._action_debug = self._entry_data.get('action_debug', False)
        self._hide_non_standard_entities = self._entry_data.get(
            'hide_non_standard_entities', False)
        self._display_binary_mode = self._entry_data.get(
            'display_binary_mode', ['text'])
        self._display_devs_notify = self._entry_data.get(
            'display_devices_changed_notify', ['add', 'del', 'offline'])
        self._home_selected_list = list(
            self._entry_data['home_selected'].keys())
        self._devices_filter = self._entry_data.get('devices_filter', {})

        self._oauth_redirect_url_full = ''
        self._auth_info = {}
        self._home_selected = {}
        self._device_list_sorted = {}

        self._devices_add = []
        self._devices_remove = []

        self._lang_new = self._integration_language
        self._nick_name_new = None
        self._action_debug_new = False
        self._hide_non_standard_entities_new = False
        self._display_binary_mode_new = []
        self._cover_width_new = self._cover_dz_width
        self._update_user_info = False
        self._update_devices = False
        self._update_trans_rules = False
        self._opt_lan_ctrl_cfg = False
        self._opt_network_detect_cfg = False
        self._opt_check_network_deps = False
        self._trans_rules_count = 0
        self._trans_rules_count_success = 0

        self._need_reload = False

        self._cc_home_info = {}
        self._cc_home_list_show = {}
        self._cc_oauth_auth_url = None
        self._cc_task_oauth = None
        self._cc_config_rc = None
        self._cc_fut_oauth_code = None
        self._cc_devices_local = {}
        self._cc_network_detect_addr = ''

        _LOGGER.info(
            'options init, %s, %s, %s, %s', config_entry.entry_id,
            config_entry.unique_id, config_entry.data, config_entry.options)

    async def async_step_init(self, user_input=None):
        self.hass.data.setdefault(DOMAIN, {})
        self.hass.data[DOMAIN].setdefault(self._virtual_did, {})
        try:
            # MIoT client
            self._miot_client = await get_miot_instance_async(
                hass=self.hass, entry_id=self._config_entry.entry_id)
            if not self._miot_client:
                raise MIoTConfigError('invalid miot client')
            # MIoT network
            self._miot_network = self._miot_client.miot_network
            if not self._miot_network:
                raise MIoTConfigError('invalid miot network')
            # MIoT storage
            self._miot_storage = self._miot_client.miot_storage
            if not self._miot_storage:
                raise MIoTConfigError('invalid miot storage')
            # Mips service
            self._mips_service = self._miot_client.mips_service
            if not self._mips_service:
                raise MIoTConfigError('invalid mips service')
            # MIoT oauth
            self._miot_oauth = self._miot_client.miot_oauth
            if not self._miot_oauth:
                raise MIoTConfigError('invalid miot oauth')
            # MIoT http
            self._miot_http = self._miot_client.miot_http
            if not self._miot_http:
                raise MIoTConfigError('invalid miot http')
            self._miot_i18n = self._miot_client.miot_i18n
            if not self._miot_i18n:
                raise MIoTConfigError('invalid miot i18n')
            self._miot_lan = self._miot_client.miot_lan
            if not self._miot_lan:
                raise MIoTConfigError('invalid miot lan')
            # Check token
            if not await self._miot_client.refresh_oauth_info_async():
                # Check network
                if not await self._miot_network.get_network_status_async():
                    raise AbortFlow(
                        reason='network_connect_error',
                        description_placeholders={})
                self._need_reload = True
                return await self.async_step_auth_config()
            return await self.async_step_config_options()
        except MIoTConfigError as err:
            raise AbortFlow(
                reason='options_flow_error',
                description_placeholders={'error': str(err)}
            ) from err
        except AbortFlow as err:
            raise err
        except Exception as err:
            _LOGGER.error(
                'async_step_init error, %s, %s',
                err, traceback.format_exc())
            raise AbortFlow(
                reason='re_add',
                description_placeholders={'error': str(err)},
            ) from err

    async def async_step_auth_config(self, user_input=None):
        if user_input:
            webhook_path = webhook_async_generate_path(
                webhook_id=self._virtual_did)
            self._oauth_redirect_url_full = (
                f'{user_input.get("oauth_redirect_url")}{webhook_path}')
            return await self.async_step_oauth(user_input)
        return self.async_show_form(
            step_id='auth_config',
            data_schema=vol.Schema({
                vol.Required(
                    'oauth_redirect_url',
                    default=OAUTH_REDIRECT_URL  # type: ignore
                ): vol.In([OAUTH_REDIRECT_URL]),
            }),
            description_placeholders={
                'cloud_server': CLOUD_SERVERS[self._cloud_server],
            },
            last_step=False,
        )

    async def async_step_oauth(self, user_input=None):
        try:
            if self._cc_task_oauth is None:
                self._cc_oauth_auth_url = self._miot_oauth.gen_auth_url(
                    redirect_url=self._oauth_redirect_url_full)
                self.hass.data[DOMAIN][self._virtual_did]['oauth_state'] = (
                    self._miot_oauth.state)
                self.hass.data[DOMAIN][self._virtual_did]['i18n'] = (
                    self._miot_i18n)
                _LOGGER.info(
                    'async_step_oauth, oauth_url: %s', self._cc_oauth_auth_url)
                webhook_async_unregister(
                    self.hass, webhook_id=self._virtual_did)
                webhook_async_register(
                    self.hass,
                    domain=DOMAIN,
                    name='oauth redirect url webhook',
                    webhook_id=self._virtual_did,
                    handler=_handle_oauth_webhook,
                    allowed_methods=(METH_GET,),
                )
                self._cc_fut_oauth_code = self.hass.data[DOMAIN][
                    self._virtual_did].get('fut_oauth_code', None)
                if self._cc_fut_oauth_code is None:
                    self._cc_fut_oauth_code = self._main_loop.create_future()
                    self.hass.data[DOMAIN][self._virtual_did][
                        'fut_oauth_code'] = self._cc_fut_oauth_code
                self._cc_task_oauth = self.hass.async_create_task(
                    self.__check_oauth_async())
                _LOGGER.info(
                    'async_step_oauth, webhook.async_register: %s',
                    self._virtual_did)

            if self._cc_task_oauth.done():
                if (error := self._cc_task_oauth.exception()):
                    _LOGGER.error('task_oauth exception, %s', error)
                    self._cc_config_rc = str(error)
                    self._cc_task_oauth = None
                    return self.async_show_progress_done(
                        next_step_id='oauth_error')
                return self.async_show_progress_done(
                    next_step_id='config_options')
        except Exception as err:  # pylint: disable=broad-exception-caught
            _LOGGER.error(
                'async_step_oauth error, %s, %s',
                err, traceback.format_exc())
            self._cc_config_rc = str(err)
            return self.async_show_progress_done(next_step_id='oauth_error')
        # pylint: disable=unexpected-keyword-arg
        return self.async_show_progress(
            step_id='oauth',
            progress_action='oauth',
            description_placeholders={
                'link_left':
                    f'<a href="{self._cc_oauth_auth_url}" target="_blank">',
                'link_right': '</a>'
            },
            progress_task=self._cc_task_oauth,  # type: ignore
        )

    async def __check_oauth_async(self) -> None:
        # Get oauth code
        if not self._cc_fut_oauth_code:
            raise MIoTConfigError('oauth_code_fut_error')
        oauth_code: str = await self._cc_fut_oauth_code
        if not oauth_code:
            raise MIoTConfigError('oauth_code_error')
        _LOGGER.debug('options flow __check_oauth_async, %s', oauth_code)
        # Get access_token and user_info from miot_oauth
        if not self._auth_info:
            auth_info: dict = {}
            try:
                auth_info = await self._miot_oauth.get_access_token_async(
                    code=oauth_code)
            except Exception as err:
                _LOGGER.error(
                    'get_access_token, %s, %s', err, traceback.format_exc())
                raise MIoTConfigError('get_token_error') from err
            # Check uid
            m_http: MIoTHttpClient = MIoTHttpClient(
                cloud_server=self._cloud_server,
                client_id=OAUTH2_CLIENT_ID,
                access_token=auth_info['access_token'],
                loop=self._main_loop)
            if await m_http.get_uid_async() != self._uid:
                raise AbortFlow('inconsistent_account')
            del m_http
            self._miot_http.update_http_header(
                access_token=auth_info['access_token'])
            if not await self._miot_storage.update_user_config_async(
                    uid=self._uid,
                    cloud_server=self._cloud_server,
                    config={'auth_info': auth_info}):
                raise AbortFlow('storage_error')
            self._auth_info = auth_info

        # Auth success, unregister oauth webhook
        webhook_async_unregister(self.hass, webhook_id=self._virtual_did)
        _LOGGER.info(
            '__check_oauth_async, webhook.async_unregister: %s',
            self._virtual_did)

    # Show setup error message
    async def async_step_oauth_error(self, user_input=None):
        if self._cc_config_rc is None:
            return await self.async_step_oauth()
        if self._cc_config_rc.startswith('Flow aborted: '):
            raise AbortFlow(
                reason=self._cc_config_rc.replace('Flow aborted: ', ''))
        error_reason = self._cc_config_rc
        self._cc_config_rc = None
        return self.async_show_form(
            step_id='oauth_error',
            data_schema=vol.Schema({}),
            last_step=False,
            errors={'base': error_reason},
        )

    async def async_step_config_options(self, user_input=None):
        if not user_input:
            return self.async_show_form(
                step_id='config_options',
                data_schema=vol.Schema({
                    # Integration configure
                    vol.Required(
                        'integration_language',
                        default=self._integration_language  # type: ignore
                    ): vol.In(INTEGRATION_LANGUAGES),
                    vol.Required(
                        'update_user_info',
                        default=self._update_user_info  # type: ignore
                    ): bool,
                    vol.Required(
                        'network_detect_config',
                        default=self._opt_network_detect_cfg  # type: ignore
                    ): bool,
                    # Device info configure
                    vol.Required(
                        'update_devices',
                        default=self._update_devices  # type: ignore
                    ): bool,
                    vol.Required(
                        'display_devices_changed_notify',
                        default=self._display_devs_notify  # type: ignore
                    ): cv.multi_select(
                        self._miot_i18n.translate(
                            'config.device_state')),  # type: ignore
                    vol.Required(
                        'update_lan_ctrl_config',
                        default=self._opt_lan_ctrl_cfg  # type: ignore
                    ): bool,
                    # Entity info configure
                    vol.Required(
                        'action_debug',
                        default=self._action_debug  # type: ignore
                    ): bool,
                    vol.Required(
                        'hide_non_standard_entities',
                        default=self._hide_non_standard_entities  # type: ignore
                    ): bool,
                    vol.Required(
                        'display_binary_mode',
                        default=self._display_binary_mode  # type: ignore
                    ): cv.multi_select(
                        self._miot_i18n.translate(
                            'config.binary_mode')),  # type: ignore
                    vol.Optional(
                        'cover_dead_zone_width',
                        default=self._cover_dz_width  # type: ignore
                    ): vol.All(vol.Coerce(int), vol.Range(
                        min=MIN_COVER_DEAD_ZONE_WIDTH,
                        max=MAX_COVER_DEAD_ZONE_WIDTH)),
                    vol.Required(
                        'update_trans_rules',
                        default=self._update_trans_rules  # type: ignore
                    ): bool,
                }),
                errors={},
                description_placeholders={
                    'nick_name': self._nick_name,
                    'uid': self._uid,
                    'cloud_server': CLOUD_SERVERS[self._cloud_server],
                    'instance_id': f'ha.{self._entry_data["uuid"]}'
                },
                last_step=False,
            )
        # Check network
        if not await self._miot_network.get_network_status_async():
            raise AbortFlow(
                reason='network_connect_error', description_placeholders={})
        self._lang_new = user_input.get(
            'integration_language', self._integration_language)
        self._update_user_info = user_input.get(
            'update_user_info', self._update_user_info)
        self._update_devices = user_input.get(
            'update_devices', self._update_devices)
        self._action_debug_new = user_input.get(
            'action_debug', self._action_debug)
        self._hide_non_standard_entities_new = user_input.get(
            'hide_non_standard_entities', self._hide_non_standard_entities)
        self._display_binary_mode_new = user_input.get(
            'display_binary_mode', self._display_binary_mode)
        self._display_devs_notify = user_input.get(
            'display_devices_changed_notify', self._display_devs_notify)
        self._update_trans_rules = user_input.get(
            'update_trans_rules', self._update_trans_rules)
        self._opt_lan_ctrl_cfg = user_input.get(
            'update_lan_ctrl_config', self._opt_lan_ctrl_cfg)
        self._opt_network_detect_cfg = user_input.get(
            'network_detect_config', self._opt_network_detect_cfg)
        self._cover_width_new = user_input.get(
            'cover_dead_zone_width', self._cover_dz_width)

        return await self.async_step_update_user_info()

    async def async_step_update_user_info(self, user_input=None):
        if not self._update_user_info:
            return await self.async_step_homes_select()
        if not user_input:
            nick_name_new = (
                await self._miot_http.get_user_info_async() or {}).get(
                    'miliaoNick', DEFAULT_NICK_NAME)
            return self.async_show_form(
                step_id='update_user_info',
                data_schema=vol.Schema({
                    vol.Required('nick_name', default=nick_name_new): str
                }),
                description_placeholders={
                    'nick_name': self._nick_name
                },
                last_step=False
            )

        self._nick_name_new = user_input.get('nick_name')
        return await self.async_step_homes_select()

    async def async_step_homes_select(
        self, user_input: Optional[dict] = None
    ):
        if not self._update_devices:
            return await self.async_step_update_trans_rules()
        if not user_input:
            # Query mdns info
            try:
                mips_list = self._mips_service.get_services()
            except Exception as err:
                _LOGGER.error(
                    'async_update_services error, %s, %s',
                    err, traceback.format_exc())
                raise MIoTConfigError('mdns_discovery_error') from err

            # Get home info
            try:
                self._cc_home_info = (
                    await self._miot_http.get_devices_async())
            except Exception as err:
                _LOGGER.error(
                    'get_homeinfos error, %s, %s', err, traceback.format_exc())
                raise MIoTConfigError('get_homeinfo_error') from err
            # Generate devices filter
            home_list = {}
            tip_devices = self._miot_i18n.translate(key='config.other.devices')
            # home list
            for device_source in ['home_list','share_home_list',
                                  'separated_shared_list']:
                if device_source not in self._cc_home_info['homes']:
                    continue
                for home_id, home_info in self._cc_home_info[
                        'homes'][device_source].items():
                    # i18n
                    tip_central = ''
                    group_id = home_info.get('group_id', None)
                    did_list = {
                        device['did']: device for device in list(
                            self._cc_home_info['devices'].values())
                        if device.get('home_id', None) == home_id}
                    if (
                        group_id in mips_list
                        and mips_list[group_id].get('did', None) in did_list
                    ):
                        # i18n
                        tip_central = self._miot_i18n.translate(
                            key='config.other.found_central_gateway')
                        home_info['central_did'] = mips_list[group_id].get(
                            'did', None)
                    home_list[home_id] = (
                        f'{home_info["home_name"]} '
                        f'[ {len(did_list)} {tip_devices} {tip_central} ]')
            # Remove deleted item
            self._home_selected_list = [
                home_id for home_id in self._home_selected_list
                if home_id in home_list]
            self._cc_home_list_show = dict(sorted(home_list.items()))
            # Get local devices
            self._cc_devices_local = (
                await self._miot_storage.load_async(
                    domain='miot_devices',
                    name=f'{self._uid}_{self._cloud_server}',
                    type_=dict)) or {}  # type: ignore

            return await self.__show_homes_select_form('')

        self._home_selected_list = user_input.get('home_infos', [])
        if not self._home_selected_list:
            return await self.__show_homes_select_form('no_family_selected')
        self._ctrl_mode = user_input.get('ctrl_mode', self._ctrl_mode)
        self._home_selected = {}
        for device_source in ['home_list','share_home_list',
                              'separated_shared_list']:
            if device_source not in self._cc_home_info['homes']:
                continue
            for home_id, home_info in self._cc_home_info[
                    'homes'][device_source].items():
                if home_id in self._home_selected_list:
                    self._home_selected[home_id] = home_info
        # Get device list
        device_list: dict = {
            did: dev_info
            for did, dev_info in self._cc_home_info['devices'].items()
            if dev_info['home_id'] in self._home_selected_list}
        if not device_list:
            return await self.__show_homes_select_form('no_devices')
        self._device_list_sorted = dict(sorted(
            device_list.items(), key=lambda item:
                item[1].get('home_id', '')+item[1].get('room_id', '')))

        if user_input.get('devices_filter', False):
            return await self.async_step_devices_filter()
        return await self.update_devices_done_async()

    async def __show_homes_select_form(self, reason: str):
        devices_local_count: str = str(len(self._cc_devices_local))
        return self.async_show_form(
            step_id='homes_select',
            data_schema=vol.Schema({
                vol.Required(
                    'home_infos',
                    default=self._home_selected_list  # type: ignore
                ): cv.multi_select(self._cc_home_list_show),
                vol.Required(
                    'devices_filter', default=False  # type: ignore
                ): bool,
                vol.Required(
                    'ctrl_mode', default=self._ctrl_mode  # type: ignore
                ): vol.In(self._miot_i18n.translate(key='config.control_mode')),
            }),
            errors={'base': reason},
            description_placeholders={
                'local_count': devices_local_count
            },
            last_step=False
        )

    async def async_step_devices_filter(
        self, user_input: Optional[dict] = None
    ):
        if user_input:
            # Room filter
            include_items: dict = {}
            exclude_items: dict = {}
            room_list_in: list = user_input.get('room_list', [])
            room_filter_mode: str = user_input.get(
                'room_filter_mode', 'exclude')
            if room_list_in:
                if room_filter_mode == 'include':
                    include_items['room_id'] = room_list_in
                else:
                    exclude_items['room_id'] = room_list_in
            # Connect Type filter
            type_list_in: list = user_input.get('type_list', [])
            type_filter_mode: str = user_input.get(
                'type_filter_mode', 'exclude')
            if type_list_in:
                if type_filter_mode == 'include':
                    include_items['connect_type'] = type_list_in
                else:
                    exclude_items['connect_type'] = type_list_in
            # Model filter
            model_list_in: list = user_input.get('model_list', [])
            model_filter_mode: str = user_input.get(
                'model_filter_mode', 'exclude')
            if model_list_in:
                if model_filter_mode == 'include':
                    include_items['model'] = model_list_in
                else:
                    exclude_items['model'] = model_list_in
            # Device filter
            device_list_in: list = user_input.get('device_list', [])
            device_filter_mode: str = user_input.get(
                'devices_filter_mode', 'exclude')
            if device_list_in:
                if device_filter_mode == 'include':
                    include_items['did'] = device_list_in
                else:
                    exclude_items['did'] = device_list_in
            statistics_logic: str = user_input.get('statistics_logic', 'or')
            device_filter_list = _handle_devices_filter(
                devices=self._device_list_sorted,
                logic_or=(statistics_logic == 'or'),
                item_in=include_items, item_ex=exclude_items)
            if not device_filter_list:
                return await self.__show_devices_filter_form(
                    reason='no_filter_devices')
            self._device_list_sorted = dict(sorted(
                device_filter_list.items(), key=lambda item:
                    item[1].get('home_id', '')+item[1].get('room_id', '')))
            self._devices_filter = {
                'room_list': {
                    'items': room_list_in, 'mode': room_filter_mode},
                'type_list': {
                    'items': type_list_in, 'mode': type_filter_mode},
                'model_list': {
                    'items': model_list_in, 'mode': model_filter_mode},
                'device_list': {
                    'items': device_list_in, 'mode': device_filter_mode},
                'statistics_logic': statistics_logic}
            return await self.update_devices_done_async()
        return await self.__show_devices_filter_form(reason='')

    async def __show_devices_filter_form(self, reason: str):
        tip_devices: str = self._miot_i18n.translate(
            key='config.other.devices')  # type: ignore
        tip_without_room: str = self._miot_i18n.translate(
            key='config.other.without_room')  # type: ignore
        trans_statistics_logic: dict = self._miot_i18n.translate(
            key='config.statistics_logic')  # type: ignore
        trans_filter_mode: dict = self._miot_i18n.translate(
            key='config.filter_mode')  # type: ignore
        trans_connect_type: dict = self._miot_i18n.translate(
            key='config.connect_type')  # type: ignore

        room_device_count: dict = {}
        model_device_count: dict = {}
        connect_type_count: dict = {}
        device_list: dict = {}
        for did, info in self._device_list_sorted.items():
            device_list[did] = (
                f'[ {info["home_name"]} {info["room_name"]} ] ' +
                f'{info["name"]}, {did}')
            room_device_count.setdefault(info['room_id'], 0)
            room_device_count[info['room_id']] += 1
            model_device_count.setdefault(info['model'], 0)
            model_device_count[info['model']] += 1
            connect_type_count.setdefault(str(info['connect_type']), 0)
            connect_type_count[str(info['connect_type'])] += 1
        model_list: dict = {}
        for model, count in model_device_count.items():
            model_list[model] = f'{model} [ {count} {tip_devices} ]'
        type_list: dict = {
            k: f'{trans_connect_type.get(k, f"Connect Type ({k})")} '
            f'[ {v} {tip_devices} ]'
            for k, v in connect_type_count.items()}
        room_list: dict = {}
        for home_id, home_info in self._home_selected.items():
            for room_id, room_name in home_info['room_info'].items():
                if room_id not in room_device_count:
                    continue
                room_list[room_id] = (
                    f'{home_info["home_name"]} {room_name}'
                    f' [ {room_device_count[room_id]}{tip_devices} ]')
            if home_id in room_device_count:
                room_list[home_id] = (
                    f'{home_info["home_name"]} {tip_without_room}'
                    f' [ {room_device_count[home_id]}{tip_devices} ]')
        return self.async_show_form(
            step_id='devices_filter',
            data_schema=vol.Schema({
                vol.Required(
                    'room_filter_mode', default=self._devices_filter.get(
                        'room_list', {}).get('mode', 'exclude')  # type: ignore
                ): vol.In(trans_filter_mode),
                vol.Optional('room_list', default=[
                    room_id for room_id in self._devices_filter.get(
                        'room_list', {}).get('items', [])
                    if room_id in room_list]  # type: ignore
                ): cv.multi_select(room_list),
                vol.Required(
                    'type_filter_mode', default=self._devices_filter.get(
                        'type_list', {}).get('mode', 'exclude')  # type: ignore
                ): vol.In(trans_filter_mode),
                vol.Optional('type_list', default=[
                    type_ for type_ in self._devices_filter.get(
                        'type_list', {}).get('items', [])
                    if type_ in type_list]  # type: ignore
                ): cv.multi_select(type_list),
                vol.Required(
                    'model_filter_mode',
                    default=self._devices_filter.get('model_list', {}).get(
                        'mode', 'exclude')  # type: ignore
                ): vol.In(trans_filter_mode),
                vol.Optional('model_list', default=[
                    model for model in self._devices_filter.get(
                        'model_list', {}).get('items', [])
                    if model in model_list]  # type: ignore
                ): cv.multi_select(dict(sorted(
                    model_list.items(), key=lambda item: item[0]))),
                vol.Required(
                    'devices_filter_mode', default=self._devices_filter.get(
                        'device_list', {}).get(
                            'mode', 'exclude')  # type: ignore
                ):  vol.In(trans_filter_mode),
                vol.Optional('device_list', default=[
                    did for did in self._devices_filter.get(
                        'device_list', {}).get('items', [])
                    if did in device_list]  # type: ignore
                ): cv.multi_select(dict(sorted(
                    device_list.items(), key=lambda device: device[1]))),
                vol.Required(
                    'statistics_logic', default=self._devices_filter.get(
                        'statistics_logic', 'or')
                ): vol.In(trans_statistics_logic),
            }),
            errors={'base': reason},
            last_step=False
        )

    async def update_devices_done_async(self):
        # Statistics devices changed
        self._devices_add = []
        self._devices_remove = []

        self._devices_add = [
            did for did in list(self._device_list_sorted.keys())
            if did not in self._cc_devices_local]
        self._devices_remove = [
            did for did in self._cc_devices_local.keys()
            if did not in self._device_list_sorted]
        _LOGGER.debug(
            'devices update, add->%s, remove->%s',
            self._devices_add, self._devices_remove)
        return await self.async_step_update_trans_rules()

    async def async_step_update_trans_rules(self, user_input=None):
        if not self._update_trans_rules:
            return await self.async_step_update_lan_ctrl_config()
        urn_list: list[str] = list({
            info['urn']
            for info in list(self._miot_client.device_list.values())
            if 'urn' in info})
        self._trans_rules_count = len(urn_list)
        if not user_input:
            return self.async_show_form(
                step_id='update_trans_rules',
                data_schema=vol.Schema({
                    vol.Required(
                        'confirm', default=False  # type: ignore
                    ): bool
                }),
                description_placeholders={
                    'urn_count': str(self._trans_rules_count),
                },
                last_step=False
            )
        if user_input.get('confirm', False):
            # Update trans rules
            if urn_list:
                spec_parser: MIoTSpecParser = MIoTSpecParser(
                    lang=self._lang_new, storage=self._miot_storage)
                await spec_parser.init_async()
                self._trans_rules_count_success = (
                    await spec_parser.refresh_async(urn_list=urn_list))
                await spec_parser.deinit_async()
        else:
            # SKIP update trans rules
            self._update_trans_rules = False

        return await self.async_step_update_lan_ctrl_config()

    async def async_step_update_lan_ctrl_config(self, user_input=None):
        if not self._opt_lan_ctrl_cfg:
            return await self.async_step_network_detect_config()
        if not user_input:
            notice_net_dup: str = ''
            lan_ctrl_config = await self._miot_storage.load_user_config_async(
                'global_config', 'all', ['net_interfaces', 'enable_subscribe'])
            selected_if = lan_ctrl_config.get('net_interfaces', [])
            enable_subscribe = lan_ctrl_config.get('enable_subscribe', False)
            net_unavailable = self._miot_i18n.translate(
                key='config.lan_ctrl_config.net_unavailable')
            net_if = {
                if_name: f'{if_name}: {net_unavailable}'
                for if_name in selected_if}
            net_info = await self._miot_network.get_network_info_async()
            net_segs = set()
            for if_name, info in net_info.items():
                net_if[if_name] = (
                    f'{if_name} ({info.ip}/{info.netmask})')
                net_segs.add(info.net_seg)
            if len(net_segs) != len(net_info):
                notice_net_dup: str = self._miot_i18n.translate(
                    key='config.lan_ctrl_config.notice_net_dup')  # type: ignore
            return self.async_show_form(
                step_id='update_lan_ctrl_config',
                data_schema=vol.Schema({
                    vol.Required(
                        'net_interfaces', default=selected_if
                    ): cv.multi_select(net_if),
                    vol.Required(
                        'enable_subscribe', default=enable_subscribe): bool
                }),
                description_placeholders={
                    'notice_net_dup': notice_net_dup,
                },
                last_step=False
            )

        selected_if_new: list = user_input.get('net_interfaces', [])
        enable_subscribe_new: bool = user_input.get('enable_subscribe', False)
        lan_ctrl_config = await self._miot_storage.load_user_config_async(
            'global_config', 'all', ['net_interfaces', 'enable_subscribe'])
        selected_if = lan_ctrl_config.get('net_interfaces', [])
        enable_subscribe = lan_ctrl_config.get('enable_subscribe', False)
        if (
            set(selected_if_new) != set(selected_if)
            or enable_subscribe_new != enable_subscribe
        ):
            if not await self._miot_storage.update_user_config_async(
                    'global_config', 'all', {
                        'net_interfaces': selected_if_new,
                        'enable_subscribe': enable_subscribe_new}
            ):
                raise AbortFlow(
                    reason='storage_error',
                    description_placeholders={
                        'error': 'Update net config error'})
            await self._miot_lan.update_net_ifs_async(net_ifs=selected_if_new)
            await self._miot_lan.update_subscribe_option(
                enable_subscribe=enable_subscribe_new)

        return await self.async_step_network_detect_config()

    async def async_step_network_detect_config(
        self, user_input: Optional[dict] = None
    ):
        if not self._opt_network_detect_cfg:
            return await self.async_step_config_confirm()
        if not user_input:
            return await self.__show_network_detect_config_form(reason='')
        self._cc_network_detect_addr = user_input.get(
            'network_detect_addr', self._cc_network_detect_addr)

        ip_list, url_list, invalid_list = _handle_network_detect_addr(
            addr_str=self._cc_network_detect_addr)
        if invalid_list:
            return await self.__show_network_detect_config_form(
                reason='invalid_network_addr')
        if ip_list or url_list:
            if ip_list and not await self._miot_network.ping_multi_async(
                    ip_list=ip_list):
                return await self.__show_network_detect_config_form(
                    reason='invalid_ip_addr')
            if url_list and not await self._miot_network.http_multi_async(
                    url_list=url_list):
                return await self.__show_network_detect_config_form(
                    reason='invalid_http_addr')
        else:
            if not await self._miot_network.get_network_status_async():
                return await self.__show_network_detect_config_form(
                    reason='invalid_default_addr')
        network_detect_addr: dict = {'ip': ip_list, 'url': url_list}
        # Save
        if await self._miot_storage.update_user_config_async(
            uid='global_config', cloud_server='all', config={
                'network_detect_addr': network_detect_addr}):
            _LOGGER.info(
                'update network_detect_addr, %s', network_detect_addr)
        await self._miot_network.update_addr_list_async(
            ip_addr_list=ip_list, url_addr_list=url_list)
        # Check network deps
        self._opt_check_network_deps = user_input.get(
            'check_network_deps', False)
        if self._opt_check_network_deps:
            # OAuth2
            if not await self._miot_network.http_multi_async(
                    url_list=[OAUTH2_AUTH_URL]):
                return await self.__show_network_detect_config_form(
                    reason='unreachable_oauth2_host')
            # HTTP API
            http_host = (
                DEFAULT_OAUTH2_API_HOST
                if self._cloud_server == DEFAULT_CLOUD_SERVER
                else f'{self._cloud_server}.{DEFAULT_OAUTH2_API_HOST}')
            if not await self._miot_network.http_multi_async(
                    url_list=[
                        f'https://{http_host}/app/v2/ha/oauth/get_token']):
                return await self.__show_network_detect_config_form(
                    reason='unreachable_http_host')
            # SPEC API
            if not await self._miot_network.http_multi_async(
                    url_list=[
                        'https://miot-spec.org/miot-spec-v2/template/list/'
                        'device']):
                return await self.__show_network_detect_config_form(
                    reason='unreachable_spec_host')
            # MQTT Broker
            # pylint: disable=import-outside-toplevel
            try:
                from paho.mqtt import client
                mqtt_client = client.Client(
                    client_id=f'ha.{self._uid}',
                    protocol=client.MQTTv5)  # type: ignore
                if mqtt_client.connect(
                    host=f'{self._cloud_server}-{DEFAULT_CLOUD_BROKER_HOST}',
                    port=8883) != 0:
                    raise RuntimeError('mqtt connect error')
                mqtt_client.disconnect()
            except Exception as err:  # pylint: disable=broad-exception-caught
                _LOGGER.error('try connect mqtt broker error, %s', err)
                return await self.__show_network_detect_config_form(
                    reason='unreachable_mqtt_broker')

        return await self.async_step_config_confirm()

    async def __show_network_detect_config_form(self, reason: str):
        if not self._cc_network_detect_addr:
            addr_list: dict = (await self._miot_storage.load_user_config_async(
                'global_config', 'all', ['network_detect_addr'])).get(
                    'network_detect_addr', {})
            self._cc_network_detect_addr = ','.join(
                addr_list.get('ip', [])+addr_list.get('url', []))
        return self.async_show_form(
            step_id='network_detect_config',
            data_schema=vol.Schema({
                vol.Optional(
                    'network_detect_addr',
                    default=self._cc_network_detect_addr  # type: ignore
                ): str,
                vol.Optional(
                    'check_network_deps',
                    default=self._opt_check_network_deps  # type: ignore
                ): bool,
            }),
            errors={'base': reason},
            description_placeholders={
                'broker_host':
                    f'{self._cloud_server}-{DEFAULT_CLOUD_BROKER_HOST}:8883',
                'http_host': (
                    DEFAULT_OAUTH2_API_HOST
                    if self._cloud_server == DEFAULT_CLOUD_SERVER
                    else f'{self._cloud_server}.{DEFAULT_OAUTH2_API_HOST}')},
            last_step=False
        )

    async def async_step_config_confirm(self, user_input=None):
        if not user_input or not user_input.get('confirm', False):
            enable_text = self._miot_i18n.translate(
                key='config.option_status.enable')
            disable_text = self._miot_i18n.translate(
                key='config.option_status.disable')
            trans_devs_display: dict = self._miot_i18n.translate(
                key='config.device_state')  # type: ignore
            return self.async_show_form(
                step_id='config_confirm',
                data_schema=vol.Schema({
                    vol.Required(
                        'confirm', default=False): bool  # type: ignore
                }),
                description_placeholders={
                    'nick_name': self._nick_name,
                    'lang_new': INTEGRATION_LANGUAGES[self._lang_new],
                    'nick_name_new': self._nick_name_new,
                    'cover_width_new': self._cover_width_new,
                    'devices_add': len(self._devices_add),
                    'devices_remove': len(self._devices_remove),
                    'trans_rules_count': self._trans_rules_count,
                    'trans_rules_count_success':
                        self._trans_rules_count_success,
                    'action_debug': (
                        enable_text if self._action_debug_new
                        else disable_text),
                    'hide_non_standard_entities': (
                        enable_text if self._hide_non_standard_entities_new
                        else disable_text),
                    'display_devices_changed_notify': (' '.join(
                        trans_devs_display[key]
                        for key in self._display_devs_notify
                        if key in trans_devs_display)
                        if self._display_devs_notify
                        else self._miot_i18n.translate(
                            key='config.other.no_display'))
                },  # type: ignore
                errors={'base': 'not_confirm'} if user_input else {},
                last_step=True
            )

        if self._lang_new != self._integration_language:
            self._entry_data['integration_language'] = self._lang_new
            self._need_reload = True
        if self._cover_width_new != self._cover_dz_width:
            self._entry_data['cover_dead_zone_width'] = self._cover_width_new
            self._need_reload = True
        if self._update_user_info:
            self._entry_data['nick_name'] = self._nick_name_new
        if self._update_devices:
            self._entry_data['ctrl_mode'] = self._ctrl_mode
            self._entry_data['home_selected'] = self._home_selected
            self._entry_data['devices_filter'] = self._devices_filter
            if not await self._miot_storage.save_async(
                    domain='miot_devices',
                    name=f'{self._uid}_{self._cloud_server}',
                    data=self._device_list_sorted):
                _LOGGER.error(
                    'save devices async failed, %s, %s',
                    self._uid, self._cloud_server)
                raise AbortFlow(
                    reason='storage_error', description_placeholders={
                        'error': 'save user devices error'})
            self._need_reload = True
        if self._update_trans_rules:
            self._need_reload = True
        if self._action_debug_new != self._action_debug:
            self._entry_data['action_debug'] = self._action_debug_new
            self._need_reload = True
        if (
            self._hide_non_standard_entities_new !=
            self._hide_non_standard_entities
        ):
            self._entry_data['hide_non_standard_entities'] = (
                self._hide_non_standard_entities_new)
            self._need_reload = True
        if set(self._display_binary_mode) != set(self._display_binary_mode_new):
            self._entry_data['display_binary_mode'] = (
                self._display_binary_mode_new)
            self._need_reload = True
        # Update display_devices_changed_notify
        self._entry_data['display_devices_changed_notify'] = (
            self._display_devs_notify)
        self._miot_client.display_devices_changed_notify = (
            self._display_devs_notify)
        if (
                self._devices_remove
                and not await self._miot_storage.update_user_config_async(
                    uid=self._uid,
                    cloud_server=self._cloud_server,
                    config={'devices_remove': self._devices_remove})
        ):
            raise AbortFlow(
                reason='storage_error',
                description_placeholders={'error': 'Update user config error'})
        entry_title = (
            f'{self._nick_name_new or self._nick_name}: '
            f'{self._uid} [{CLOUD_SERVERS[self._cloud_server]}]')
        # Update entry config
        self.hass.config_entries.async_update_entry(
            self._config_entry, title=entry_title, data=self._entry_data)
        # Reload later
        if self._need_reload:
            self._main_loop.call_later(
                0, lambda: self._main_loop.create_task(
                    self.hass.config_entries.async_reload(
                        entry_id=self._config_entry.entry_id)))
        return self.async_create_entry(title='', data={})


async def _handle_oauth_webhook(hass, webhook_id, request):
    """Webhook to handle oauth2 callback."""
    # pylint: disable=inconsistent-quotes
    i18n: MIoTI18n = hass.data[DOMAIN][webhook_id].get('i18n', None)
    try:
        data = dict(request.query)
        if data.get('code', None) is None or data.get('state', None) is None:
            raise MIoTConfigError(
                'invalid oauth code or state',
                MIoTErrorCode.CODE_CONFIG_INVALID_INPUT)

        if data['state'] != hass.data[DOMAIN][webhook_id]['oauth_state']:
            raise MIoTConfigError(
                f'inconsistent state, '
                f'{hass.data[DOMAIN][webhook_id]["oauth_state"]}!='
                f'{data["state"]}', MIoTErrorCode.CODE_CONFIG_INVALID_STATE)

        fut_oauth_code: asyncio.Future = hass.data[DOMAIN][webhook_id].pop(
            'fut_oauth_code', None)
        fut_oauth_code.set_result(data['code'])
        _LOGGER.info('webhook code: %s', data['code'])

        success_trans: dict = {}
        if i18n:
            success_trans = i18n.translate(
                'oauth2.success') or {}  # type: ignore
        # Delete
        del hass.data[DOMAIN][webhook_id]['oauth_state']
        del hass.data[DOMAIN][webhook_id]['i18n']
        return web.Response(
            body=await oauth_redirect_page(
                title=success_trans.get('title', 'Success'),
                content=success_trans.get(
                    'content', (
                        'Please close this page and return to the account '
                        'authentication page to click NEXT')),
                button=success_trans.get('button', 'Close Page'),
                success=True,
            ), content_type='text/html')

    except Exception as err:  # pylint: disable=broad-exception-caught
        fail_trans: dict = {}
        err_msg: str = str(err)
        if i18n:
            if isinstance(err, MIoTConfigError):
                err_msg = i18n.translate(
                    f'oauth2.error_msg.{err.code.value}'
                ) or err.message  # type: ignore
            fail_trans = i18n.translate('oauth2.fail') or {}  # type: ignore
        return web.Response(
            body=await oauth_redirect_page(
                title=fail_trans.get('title', 'Authentication Failed'),
                content=str(fail_trans.get('content', (
                    '{error_msg}, Please close this page and return to the '
                    'account authentication page to click the authentication '
                    'link again.'))).replace('{error_msg}', err_msg),
                button=fail_trans.get('button', 'Close Page'),
                success=False),
            content_type='text/html')


def _handle_devices_filter(
    devices: dict, logic_or: bool, item_in: dict, item_ex: dict
) -> dict:
    """Private method to filter devices."""
    include_set: Set = set([])
    if not item_in:
        include_set = set(devices.keys())
    else:
        filter_item: list[set] = []
        for key, value in item_in.items():
            filter_item.append(set([
                did for did, info in devices.items()
                if str(info[key]) in value]))
        include_set = (
            set.union(*filter_item)
            if logic_or else set.intersection(*filter_item))
    if not include_set:
        return {}
    if item_ex:
        filter_item: list[set] = []
        for key, value in item_ex.items():
            filter_item.append(set([
                did for did, info in devices.items()
                if str(info[key]) in value]))
        exclude_set: Set = (
            set.union(*filter_item)
            if logic_or else set.intersection(*filter_item))
        if exclude_set:
            include_set = include_set-exclude_set
    if not include_set:
        return {}
    return {
        did: info for did, info in devices.items() if did in include_set}


def _handle_network_detect_addr(
    addr_str: str
) -> Tuple[list[str], list[str], list[str]]:
    ip_list: list[str] = []
    url_list: list[str] = []
    invalid_list: list[str] = []
    if addr_str:
        for addr in addr_str.split(','):
            addr = addr.strip()
            if not addr:
                continue
            # pylint: disable=broad-exception-caught
            try:
                ipaddress.ip_address(addr)
                ip_list.append(addr)
                continue
            except Exception:
                pass
            try:
                result = urlparse(addr)
                if (
                    result.netloc
                    and result.scheme.startswith('http')
                ):
                    url_list.append(addr)
                    continue
            except Exception:
                pass
            invalid_list.append(addr)
    return ip_list, url_list, invalid_list
