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

MIoT Pub/Sub client.
"""
import asyncio
import json
import logging
import random
import re
import ssl
import struct
import threading
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum, auto
from typing import Any, Callable, Optional, final, Coroutine

from paho.mqtt.client import (
    MQTT_ERR_SUCCESS,
    MQTT_ERR_NO_CONN,
    MQTT_ERR_UNKNOWN,
    Client,
    MQTTv5,
    MQTTMessage)

# pylint: disable=relative-beyond-top-level
from .common import MIoTMatcher
from .const import (
    UNSUPPORTED_MODELS,
    MIHOME_MQTT_KEEPALIVE,
    DEFAULT_CLOUD_BROKER_HOST
)
from .miot_error import MIoTErrorCode, MIoTMipsError

_LOGGER = logging.getLogger(__name__)


class _MipsMsgTypeOptions(Enum):
    """MIoT Pub/Sub message type."""
    ID = 0
    RET_TOPIC = auto()
    PAYLOAD = auto()
    FROM = auto()
    MAX = auto()


class _MipsMessage:
    """MIoT Pub/Sub message."""
    mid: int = 0
    msg_from: Optional[str] = None
    ret_topic: Optional[str] = None
    payload: Optional[str] = None

    @staticmethod
    def unpack(data: bytes) -> '_MipsMessage':
        mips_msg = _MipsMessage()
        data_len = len(data)
        data_start = 0
        data_end = 0
        while data_start < data_len:
            data_end = data_start+5
            unpack_len, unpack_type = struct.unpack(
                '<IB', data[data_start:data_end])
            unpack_data = data[data_end:data_end+unpack_len]
            #  string end with \x00
            match unpack_type:
                case _MipsMsgTypeOptions.ID.value:
                    mips_msg.mid = int.from_bytes(
                        unpack_data, byteorder='little')
                case _MipsMsgTypeOptions.RET_TOPIC.value:
                    mips_msg.ret_topic = str(
                        unpack_data.strip(b'\x00'), 'utf-8')
                case _MipsMsgTypeOptions.PAYLOAD.value:
                    mips_msg.payload = str(unpack_data.strip(b'\x00'), 'utf-8')
                case _MipsMsgTypeOptions.FROM.value:
                    mips_msg.msg_from = str(
                        unpack_data.strip(b'\x00'), 'utf-8')
                case _:
                    pass
            data_start = data_end+unpack_len
        return mips_msg

    @staticmethod
    def pack(
        mid: int,
        payload: str,
        msg_from: Optional[str] = None,
        ret_topic: Optional[str] = None
    ) -> bytes:
        if mid is None or payload is None:
            raise MIoTMipsError('invalid mid or payload')
        pack_msg: bytes = b''
        # mid
        pack_msg += struct.pack('<IBI', 4, _MipsMsgTypeOptions.ID.value, mid)
        # msg_from
        if msg_from:
            pack_len = len(msg_from)
            pack_msg += struct.pack(
                f'<IB{pack_len}sx', pack_len+1,
                _MipsMsgTypeOptions.FROM.value, msg_from.encode('utf-8'))
        # ret_topic
        if ret_topic:
            pack_len = len(ret_topic)
            pack_msg += struct.pack(
                f'<IB{pack_len}sx', pack_len+1,
                _MipsMsgTypeOptions.RET_TOPIC.value, ret_topic.encode('utf-8'))
        # payload
        pack_len = len(payload)
        pack_msg += struct.pack(
            f'<IB{pack_len}sx', pack_len+1,
            _MipsMsgTypeOptions.PAYLOAD.value, payload.encode('utf-8'))
        return pack_msg

    def __str__(self) -> str:
        return f'{self.mid}, {self.msg_from}, {self.ret_topic}, {self.payload}'


@dataclass
class _MipsRequest:
    """MIoT Pub/Sub request."""
    mid: int
    on_reply: Callable[[str, Any], None]
    on_reply_ctx: Any
    timer: Optional[asyncio.TimerHandle]


@dataclass
class _MipsBroadcast:
    """MIoT Pub/Sub broadcast."""
    topic: str
    """
    param 1: msg topic
    param 2: msg payload
    param 3: handle_ctx
    """
    handler: Callable[[str, str, Any], None]
    handler_ctx: Any

    def __str__(self) -> str:
        return f'{self.topic}, {id(self.handler)}, {id(self.handler_ctx)}'


@dataclass
class _MipsState:
    """MIoT Pub/Sub state."""
    key: str
    """
    str: key
    bool: mips connect state
    """
    handler: Callable[[str, bool], Coroutine]


class MIoTDeviceState(Enum):
    """MIoT device state define."""
    DISABLE = 0
    OFFLINE = auto()
    ONLINE = auto()


@dataclass
class MipsDeviceState:
    """MIoT Pub/Sub device state."""
    did: Optional[str] = None
    """handler
    str: did
    MIoTDeviceState: online/offline/disable
    Any: ctx
    """
    handler: Optional[Callable[[str, MIoTDeviceState, Any], None]] = None
    handler_ctx: Any = None


class _MipsClient(ABC):
    """MIoT Pub/Sub client."""
    # pylint: disable=unused-argument
    MQTT_INTERVAL_S = 1
    MIPS_QOS: int = 2
    UINT32_MAX: int = 0xFFFFFFFF
    MIPS_RECONNECT_INTERVAL_MIN: float = 10
    MIPS_RECONNECT_INTERVAL_MAX: float = 600
    MIPS_SUB_PATCH: int = 300
    MIPS_SUB_INTERVAL: float = 1
    main_loop: asyncio.AbstractEventLoop
    _logger: Optional[logging.Logger]
    _client_id: str
    _host: str
    _port: int
    _username: Optional[str]
    _password: Optional[str]
    _ca_file: Optional[str]
    _cert_file: Optional[str]
    _key_file: Optional[str]

    _mqtt_logger: Optional[logging.Logger]
    _mqtt: Optional[Client]
    _mqtt_fd: int
    _mqtt_timer: Optional[asyncio.TimerHandle]
    _mqtt_state: bool

    _event_connect: asyncio.Event
    _event_disconnect: asyncio.Event
    _internal_loop: asyncio.AbstractEventLoop
    _mips_thread: Optional[threading.Thread]
    _mips_reconnect_tag: bool
    _mips_reconnect_interval: float
    _mips_reconnect_timer: Optional[asyncio.TimerHandle]
    _mips_state_sub_map: dict[str, _MipsState]
    _mips_state_sub_map_lock: threading.Lock
    _mips_sub_pending_map: dict[str, int]
    _mips_sub_pending_timer: Optional[asyncio.TimerHandle]

    def __init__(
            self,
            client_id: str,
            host: str,
            port: int,
            username: Optional[str] = None,
            password: Optional[str] = None,
            ca_file: Optional[str] = None,
            cert_file: Optional[str] = None,
            key_file: Optional[str] = None,
            loop: Optional[asyncio.AbstractEventLoop] = None
    ) -> None:
        # MUST run with running loop
        self.main_loop = loop or asyncio.get_running_loop()
        self._logger = None
        self._client_id = client_id
        self._host = host
        self._port = port
        self._username = username
        self._password = password
        self._ca_file = ca_file
        self._cert_file = cert_file
        self._key_file = key_file

        self._mqtt_logger = None
        self._mqtt_fd = -1
        self._mqtt_timer = None
        self._mqtt_state = False
        self._mqtt = None

        # Mips init
        self._event_connect = asyncio.Event()
        self._event_disconnect = asyncio.Event()
        self._mips_thread = None
        self._mips_reconnect_tag = False
        self._mips_reconnect_interval = 0
        self._mips_reconnect_timer = None
        self._mips_state_sub_map = {}
        self._mips_state_sub_map_lock = threading.Lock()
        self._mips_sub_pending_map = {}
        self._mips_sub_pending_timer = None
        # DO NOT start the thread yet. Do that on connect

    @property
    def client_id(self) -> str:
        return self._client_id

    @property
    def host(self) -> str:
        return self._host

    @property
    def port(self) -> int:
        return self._port

    @final
    @property
    def mips_state(self) -> bool:
        """mips connect state.

        Returns:
            bool: True: connected, False: disconnected
        """
        if self._mqtt:
            return self._mqtt.is_connected()
        return False

    def connect(self, thread_name: Optional[str] = None) -> None:
        """mips connect."""
        # Start mips thread
        if self._mips_thread:
            return
        self._internal_loop = asyncio.new_event_loop()
        self._mips_thread = threading.Thread(target=self.__mips_loop_thread)
        self._mips_thread.daemon = True
        self._mips_thread.name = (
            self._client_id if thread_name is None else thread_name)
        self._mips_thread.start()

    async def connect_async(self) -> None:
        """mips connect async."""
        self.connect()
        await self._event_connect.wait()

    def disconnect(self) -> None:
        """mips disconnect."""
        if not self._mips_thread:
            return
        self._internal_loop.call_soon_threadsafe(self.__mips_disconnect)
        self._mips_thread.join()
        self._mips_thread = None
        self._internal_loop.close()

    async def disconnect_async(self) -> None:
        """mips disconnect async."""
        self.disconnect()
        await self._event_disconnect.wait()

    @final
    def deinit(self) -> None:
        self.disconnect()

        self._logger = None
        self._username = None
        self._password = None
        self._ca_file = None
        self._cert_file = None
        self._key_file = None
        self._mqtt_logger = None
        with self._mips_state_sub_map_lock:
            self._mips_state_sub_map.clear()
        self._mips_sub_pending_map.clear()
        self._mips_sub_pending_timer = None

    @final
    async def deinit_async(self) -> None:
        await self.disconnect_async()

        self._logger = None
        self._username = None
        self._password = None
        self._ca_file = None
        self._cert_file = None
        self._key_file = None
        self._mqtt_logger = None
        with self._mips_state_sub_map_lock:
            self._mips_state_sub_map.clear()
        self._mips_sub_pending_map.clear()
        self._mips_sub_pending_timer = None

    def update_mqtt_password(self, password: str) -> None:
        self._password = password
        if self._mqtt:
            self._mqtt.username_pw_set(
                username=self._username, password=self._password)

    def log_debug(self, msg, *args, **kwargs) -> None:
        if self._logger:
            self._logger.debug(f'{self._client_id}, '+msg, *args, **kwargs)

    def log_info(self, msg, *args, **kwargs) -> None:
        if self._logger:
            self._logger.info(f'{self._client_id}, '+msg, *args, **kwargs)

    def log_error(self, msg, *args, **kwargs) -> None:
        if self._logger:
            self._logger.error(f'{self._client_id}, '+msg, *args, **kwargs)

    def enable_logger(self, logger: Optional[logging.Logger] = None) -> None:
        self._logger = logger

    def enable_mqtt_logger(
        self, logger: Optional[logging.Logger] = None
    ) -> None:
        self._mqtt_logger = logger
        if self._mqtt:
            if logger:
                self._mqtt.enable_logger(logger=logger)
            else:
                self._mqtt.disable_logger()

    @final
    def sub_mips_state(
        self, key: str, handler: Callable[[str, bool], Coroutine]
    ) -> bool:
        """Subscribe mips state.
        NOTICE: callback to main loop thread
        This will be called before the client is connected.
        So use mutex instead of IPC.
        """
        if isinstance(key, str) is False or handler is None:
            raise MIoTMipsError('invalid params')
        state = _MipsState(key=key, handler=handler)
        with self._mips_state_sub_map_lock:
            self._mips_state_sub_map[key] = state
        self.log_debug(f'mips register mips state, {key}')
        return True

    @final
    def unsub_mips_state(self, key: str) -> bool:
        """Unsubscribe mips state."""
        if isinstance(key, str) is False:
            raise MIoTMipsError('invalid params')
        with self._mips_state_sub_map_lock:
            del self._mips_state_sub_map[key]
        self.log_debug(f'mips unregister mips state, {key}')
        return True

    @abstractmethod
    def sub_prop(
        self,
        did: str,
        handler: Callable[[dict, Any], None],
        siid: Optional[int] = None,
        piid: Optional[int] = None,
        handler_ctx: Any = None
    ) -> bool: ...

    @abstractmethod
    def unsub_prop(
        self,
        did: str,
        siid: Optional[int] = None,
        piid: Optional[int] = None
    ) -> bool: ...

    @abstractmethod
    def sub_event(
        self,
        did: str,
        handler: Callable[[dict, Any], None],
        siid: Optional[int] = None,
        eiid: Optional[int] = None,
        handler_ctx: Any = None
    ) -> bool: ...

    @abstractmethod
    def unsub_event(
        self,
        did: str,
        siid: Optional[int] = None,
        eiid: Optional[int] = None
    ) -> bool: ...

    @abstractmethod
    async def get_dev_list_async(
        self,
        payload: Optional[str] = None,
        timeout_ms: int = 10000
    ) -> dict[str, dict]: ...

    @abstractmethod
    async def get_prop_async(
        self, did: str, siid: int, piid: int, timeout_ms: int = 10000
    ) -> Any: ...

    @abstractmethod
    async def set_prop_async(
        self, did: str, siid: int, piid: int, value: Any,
        timeout_ms: int = 10000
    ) -> dict: ...

    @abstractmethod
    async def action_async(
        self, did: str, siid: int, aiid: int, in_list: list,
        timeout_ms: int = 10000
    ) -> dict: ...

    @abstractmethod
    def _on_mips_message(self, topic: str, payload: bytes) -> None: ...

    @abstractmethod
    def _on_mips_connect(self, rc: int, props: dict) -> None: ...

    @abstractmethod
    def _on_mips_disconnect(self, rc: int, props: dict) -> None: ...

    @final
    def _mips_sub_internal(self, topic: str) -> None:
        """mips subscribe.
        NOTICE: Internal function, only mips threads are allowed to call
        """
        self.__thread_check()
        if not self._mqtt or not self._mqtt.is_connected():
            self.log_error(f'mips sub when not connected, {topic}')
            return

        if topic not in self._mips_sub_pending_map:
            self._mips_sub_pending_map[topic] = 0
        if not self._mips_sub_pending_timer:
            self._mips_sub_pending_timer = self._internal_loop.call_later(
                0.01, self.__mips_sub_internal_pending_handler, topic)

    @final
    def _mips_unsub_internal(self, topic: str) -> None:
        """mips unsubscribe.
        NOTICE: Internal function, only mips threads are allowed to call
        """
        self.__thread_check()
        if not self._mqtt or not self._mqtt.is_connected():
            self.log_debug(f'mips unsub when not connected, {topic}')
            return
        try:
            result, mid = self._mqtt.unsubscribe(topic=topic)
            if (result == MQTT_ERR_SUCCESS) or (result == MQTT_ERR_NO_CONN):
                self.log_debug(
                    f'mips unsub internal success, {result}, {mid}, {topic}')
                return
            self.log_error(
                f'mips unsub internal error, {result}, {mid}, {topic}')
        except Exception as err:  # pylint: disable=broad-exception-caught
            # Catch all exception
            self.log_error(f'mips unsub internal error, {topic}, {err}')

    @final
    def _mips_publish_internal(
        self, topic: str, payload: str | bytes,
        wait_for_publish: bool = False, timeout_ms: int = 10000
    ) -> bool:
        """mips publish message.
        NOTICE: Internal function, only mips threads are allowed to call

        """
        self.__thread_check()
        if not self._mqtt or not self._mqtt.is_connected():
            return False
        try:
            handle = self._mqtt.publish(
                topic=topic, payload=payload, qos=self.MIPS_QOS)
            # self.log_debug(f'_mips_publish_internal, {topic}, {payload}')
            if wait_for_publish is True:
                handle.wait_for_publish(timeout_ms/1000.0)
            return True
        except Exception as err:  # pylint: disable=broad-exception-caught
            # Catch other exception
            self.log_error(f'mips publish internal error, {err}')
        return False

    def __thread_check(self) -> None:
        if threading.current_thread() is not self._mips_thread:
            raise MIoTMipsError('illegal call')

    def __mqtt_read_handler(self) -> None:
        self.__mqtt_loop_handler()

    def __mqtt_write_handler(self) -> None:
        self._internal_loop.remove_writer(self._mqtt_fd)
        self.__mqtt_loop_handler()

    def __mqtt_timer_handler(self) -> None:
        self.__mqtt_loop_handler()
        if self._mqtt:
            self._mqtt_timer = self._internal_loop.call_later(
                self.MQTT_INTERVAL_S, self.__mqtt_timer_handler)

    def __mqtt_loop_handler(self) -> None:
        try:
            # If the main loop is closed, stop the internal loop immediately
            if self.main_loop.is_closed():
                self.log_debug(
                    'The main loop is closed, stop the internal loop.')
                if not self._internal_loop.is_closed():
                    self._internal_loop.stop()
                return
            if self._mqtt:
                self._mqtt.loop_read()
            if self._mqtt:
                self._mqtt.loop_write()
            if self._mqtt:
                self._mqtt.loop_misc()
            if self._mqtt and self._mqtt.want_write():
                self._internal_loop.add_writer(
                    self._mqtt_fd, self.__mqtt_write_handler)
        except Exception as err:  # pylint: disable=broad-exception-caught
            # Catch all exception
            self.log_error(f'__mqtt_loop_handler, {err}')
            raise err

    def __mips_loop_thread(self) -> None:
        self.log_info('mips_loop_thread start')
        # mqtt init for API_VERSION2,
        # callback_api_version=CallbackAPIVersion.VERSION2,
        self._mqtt = Client(client_id=self._client_id, protocol=MQTTv5)
        self._mqtt.enable_logger(logger=self._mqtt_logger)
        # Set mqtt config
        if self._username:
            self._mqtt.username_pw_set(
                username=self._username, password=self._password)
        if (
            self._ca_file
            and self._cert_file
            and self._key_file
        ):
            self._mqtt.tls_set(
                tls_version=ssl.PROTOCOL_TLS_CLIENT,
                ca_certs=self._ca_file,
                certfile=self._cert_file,
                keyfile=self._key_file)
        else:
            self._mqtt.tls_set(tls_version=ssl.PROTOCOL_TLS_CLIENT)
        self._mqtt.tls_insecure_set(True)
        self._mqtt.on_connect = self.__on_connect
        self._mqtt.on_connect_fail = self.__on_connect_failed
        self._mqtt.on_disconnect = self.__on_disconnect
        self._mqtt.on_message = self.__on_message
        # Connect to mips
        self.__mips_start_connect_tries()
        # Run event loop
        self._internal_loop.run_forever()
        self.log_info('mips_loop_thread exit!')

    def __on_connect(self, client, user_data, flags, rc, props) -> None:
        if not self._mqtt:
            _LOGGER.error('__on_connect, but mqtt is None')
            return
        if not self._mqtt.is_connected():
            _LOGGER.error('__on_connect, but mqtt is disconnected')
            return
        self.log_info(f'mips connect, {flags}, {rc}, {props}')
        self.__reset_reconnect_time()
        self._mqtt_state = True
        self._internal_loop.call_soon(
            self._on_mips_connect, rc, props)
        with self._mips_state_sub_map_lock:
            for item in self._mips_state_sub_map.values():
                if item.handler is None:
                    continue
                self.main_loop.call_soon_threadsafe(
                    self.main_loop.create_task,
                    item.handler(item.key, True))
        # Resolve future
        self.main_loop.call_soon_threadsafe(
            self._event_connect.set)
        self.main_loop.call_soon_threadsafe(
            self._event_disconnect.clear)

    def __on_connect_failed(self, client: Client, user_data: Any) -> None:
        self.log_error('mips connect failed')
        # Try to reconnect
        self.__mips_try_reconnect()

    def __on_disconnect(self,  client, user_data, rc, props) -> None:
        if self._mqtt_state:
            (self.log_info if rc == 0 else self.log_error)(
                f'mips disconnect, {rc}, {props}')
            self._mqtt_state = False
            if self._mqtt_timer:
                self._mqtt_timer.cancel()
                self._mqtt_timer = None
            if self._mqtt_fd != -1:
                self._internal_loop.remove_reader(self._mqtt_fd)
                self._internal_loop.remove_writer(self._mqtt_fd)
                self._mqtt_fd = -1
            # Clear retry sub
            if self._mips_sub_pending_timer:
                self._mips_sub_pending_timer.cancel()
                self._mips_sub_pending_timer = None
            self._mips_sub_pending_map = {}
            self._internal_loop.call_soon(
                self._on_mips_disconnect, rc, props)
            # Call state sub handler
            with self._mips_state_sub_map_lock:
                for item in self._mips_state_sub_map.values():
                    if item.handler is None:
                        continue
                    self.main_loop.call_soon_threadsafe(
                        self.main_loop.create_task,
                        item.handler(item.key, False))

        # Try to reconnect
        self.__mips_try_reconnect()
        # Set event
        self.main_loop.call_soon_threadsafe(
            self._event_disconnect.set)
        self.main_loop.call_soon_threadsafe(
            self._event_connect.clear)

    def __on_message(
        self,
        client: Client,
        user_data: Any,
        msg: MQTTMessage
    ) -> None:
        self._on_mips_message(topic=msg.topic, payload=msg.payload)

    def __mips_sub_internal_pending_handler(self, ctx: Any) -> None:
        if not self._mqtt or not self._mqtt.is_connected():
            _LOGGER.error(
                'mips sub internal pending, but mqtt is None or disconnected')
            return
        subbed_count = 1
        for topic in list(self._mips_sub_pending_map.keys()):
            if subbed_count > self.MIPS_SUB_PATCH:
                break
            count = self._mips_sub_pending_map[topic]
            if count > 3:
                self._mips_sub_pending_map.pop(topic)
                self.log_error(f'retry mips sub internal error, {topic}')
                continue
            subbed_count += 1
            result = mid = None
            try:
                result, mid = self._mqtt.subscribe(topic, qos=self.MIPS_QOS)
                if result == MQTT_ERR_SUCCESS:
                    self._mips_sub_pending_map.pop(topic)
                    self.log_debug(f'mips sub internal success, {topic}')
                    continue
            except Exception as err:  # pylint: disable=broad-exception-caught
                # Catch all exception
                self.log_error(f'mips sub internal error, {topic}. {err}')
            self._mips_sub_pending_map[topic] = count+1
            self.log_error(
                f'retry mips sub internal, {count}, {topic}, {result}, {mid}')

        if len(self._mips_sub_pending_map):
            self._mips_sub_pending_timer = self._internal_loop.call_later(
                self.MIPS_SUB_INTERVAL,
                self.__mips_sub_internal_pending_handler, None)
        else:
            self._mips_sub_pending_timer = None

    def __mips_connect(self) -> None:
        if not self._mqtt:
            _LOGGER.error('__mips_connect, but mqtt is None')
            return
        result = MQTT_ERR_UNKNOWN
        if self._mips_reconnect_timer:
            self._mips_reconnect_timer.cancel()
            self._mips_reconnect_timer = None
        try:
            # Try clean mqtt fd before mqtt connect
            if self._mqtt_timer:
                self._mqtt_timer.cancel()
                self._mqtt_timer = None
            if self._mqtt_fd != -1:
                self._internal_loop.remove_reader(self._mqtt_fd)
                self._internal_loop.remove_writer(self._mqtt_fd)
                self._mqtt_fd = -1
            result = self._mqtt.connect(
                host=self._host, port=self._port,
                clean_start=True, keepalive=MIHOME_MQTT_KEEPALIVE)
            self.log_info(f'__mips_connect success, {result}')
        except (TimeoutError, OSError) as error:
            self.log_error('__mips_connect, connect error, %s', error)

        if result == MQTT_ERR_SUCCESS:
            socket = self._mqtt.socket()
            if socket is None:
                self.log_error(
                    '__mips_connect, connect success, but socket is None')
                self.__mips_try_reconnect()
                return
            self._mqtt_fd = socket.fileno()
            self.log_debug(f'__mips_connect, _mqtt_fd, {self._mqtt_fd}')
            self._internal_loop.add_reader(
                self._mqtt_fd, self.__mqtt_read_handler)
            if self._mqtt.want_write():
                self._internal_loop.add_writer(
                    self._mqtt_fd, self.__mqtt_write_handler)
            self._mqtt_timer = self._internal_loop.call_later(
                self.MQTT_INTERVAL_S, self.__mqtt_timer_handler)
        else:
            self.log_error(f'__mips_connect error result, {result}')
            self.__mips_try_reconnect()

    def __mips_try_reconnect(self, immediately: bool = False) -> None:
        if self._mips_reconnect_timer:
            self._mips_reconnect_timer.cancel()
            self._mips_reconnect_timer = None
        if not self._mips_reconnect_tag:
            return
        interval: float = 0
        if not immediately:
            interval = self.__get_next_reconnect_time()
            self.log_error(
                'mips try reconnect after %ss', interval)
        self._mips_reconnect_timer = self._internal_loop.call_later(
            interval, self.__mips_connect)

    def __mips_start_connect_tries(self) -> None:
        self._mips_reconnect_tag = True
        self.__mips_try_reconnect(immediately=True)

    def __mips_disconnect(self) -> None:
        self._mips_reconnect_tag = False
        if self._mips_reconnect_timer:
            self._mips_reconnect_timer.cancel()
            self._mips_reconnect_timer = None
        if self._mqtt_timer:
            self._mqtt_timer.cancel()
            self._mqtt_timer = None
        if self._mqtt_fd != -1:
            self._internal_loop.remove_reader(self._mqtt_fd)
            self._internal_loop.remove_writer(self._mqtt_fd)
            self._mqtt_fd = -1
        # Clear retry sub
        if self._mips_sub_pending_timer:
            self._mips_sub_pending_timer.cancel()
            self._mips_sub_pending_timer = None
        self._mips_sub_pending_map = {}
        if self._mqtt:
            self._mqtt.disconnect()
            self._mqtt = None
        self._internal_loop.stop()

    def __get_next_reconnect_time(self) -> float:
        if self._mips_reconnect_interval < self.MIPS_RECONNECT_INTERVAL_MIN:
            self._mips_reconnect_interval = self.MIPS_RECONNECT_INTERVAL_MIN
        else:
            self._mips_reconnect_interval = min(
                self._mips_reconnect_interval*2,
                self.MIPS_RECONNECT_INTERVAL_MAX)
        return self._mips_reconnect_interval

    def __reset_reconnect_time(self) -> None:
        self._mips_reconnect_interval = 0


class MipsCloudClient(_MipsClient):
    """MIoT Pub/Sub Cloud Client."""
    # pylint: disable=unused-argument
    # pylint: disable=inconsistent-quotes
    _msg_matcher: MIoTMatcher

    def __init__(
            self, uuid: str, cloud_server: str, app_id: str,
            token: str, port: int = 8883,
            loop: Optional[asyncio.AbstractEventLoop] = None
    ) -> None:
        self._msg_matcher = MIoTMatcher()
        super().__init__(
            client_id=f'ha.{uuid}',
            host=f'{cloud_server}-{DEFAULT_CLOUD_BROKER_HOST}',
            port=port, username=app_id, password=token, loop=loop)

    @final
    def disconnect(self) -> None:
        super().disconnect()
        self._msg_matcher = MIoTMatcher()

    def update_access_token(self, access_token: str) -> bool:
        if not isinstance(access_token, str):
            raise MIoTMipsError('invalid token')
        self.update_mqtt_password(password=access_token)
        return True

    @final
    def sub_prop(
        self,
        did: str,
        handler: Callable[[dict, Any], None],
        siid: Optional[int] = None,
        piid: Optional[int] = None,
        handler_ctx: Any = None
    ) -> bool:
        if not isinstance(did, str) or handler is None:
            raise MIoTMipsError('invalid params')

        topic: str = (
            f'device/{did}/up/properties_changed/'
            f'{"#" if siid is None or piid is None else f"{siid}/{piid}"}')

        def on_prop_msg(topic: str, payload: str, ctx: Any) -> None:
            try:
                msg: dict = json.loads(payload)
            except json.JSONDecodeError:
                self.log_error(
                    f'on_prop_msg, invalid msg, {topic}, {payload}')
                return
            if (
                not isinstance(msg.get('params', None), dict)
                or 'siid' not in msg['params']
                or 'piid' not in msg['params']
                or 'value' not in msg['params']
            ):
                self.log_error(
                    f'on_prop_msg, invalid msg, {topic}, {payload}')
                return
            if handler:
                self.log_debug('on properties_changed, %s', payload)
                handler(msg['params'], ctx)
        return self.__reg_broadcast_external(
            topic=topic, handler=on_prop_msg, handler_ctx=handler_ctx)

    @final
    def unsub_prop(
        self,
        did: str,
        siid: Optional[int] = None,
        piid: Optional[int] = None
    ) -> bool:
        if not isinstance(did, str):
            raise MIoTMipsError('invalid params')
        topic: str = (
            f'device/{did}/up/properties_changed/'
            f'{"#" if siid is None or piid is None else f"{siid}/{piid}"}')
        return self.__unreg_broadcast_external(topic=topic)

    @final
    def sub_event(
        self,
        did: str,
        handler: Callable[[dict, Any], None],
        siid: Optional[int] = None,
        eiid: Optional[int] = None,
        handler_ctx: Any = None
    ) -> bool:
        if not isinstance(did, str) or handler is None:
            raise MIoTMipsError('invalid params')
        # Spelling error: event_occured
        topic: str = (
            f'device/{did}/up/event_occured/'
            f'{"#" if siid is None or eiid is None else f"{siid}/{eiid}"}')

        def on_event_msg(topic: str, payload: str, ctx: Any) -> None:
            try:
                msg: dict = json.loads(payload)
            except json.JSONDecodeError:
                self.log_error(
                    f'on_event_msg, invalid msg, {topic}, {payload}')
                return
            if (
                not isinstance(msg.get('params', None), dict)
                or 'siid' not in msg['params']
                or 'eiid' not in msg['params']
                or 'arguments' not in msg['params']
            ):
                self.log_error(
                    f'on_event_msg, invalid msg, {topic}, {payload}')
                return
            if handler:
                self.log_debug('on on_event_msg, %s', payload)
                msg['params']['from'] = 'cloud'
                handler(msg['params'], ctx)
        return self.__reg_broadcast_external(
            topic=topic, handler=on_event_msg, handler_ctx=handler_ctx)

    @final
    def unsub_event(
        self,
        did: str,
        siid: Optional[int] = None,
        eiid: Optional[int] = None
    ) -> bool:
        if not isinstance(did, str):
            raise MIoTMipsError('invalid params')
        # Spelling error: event_occured
        topic: str = (
            f'device/{did}/up/event_occured/'
            f'{"#" if siid is None or eiid is None else f"{siid}/{eiid}"}')
        return self.__unreg_broadcast_external(topic=topic)

    @final
    def sub_device_state(
        self, did: str, handler: Callable[[str, MIoTDeviceState, Any], None],
        handler_ctx: Any = None
    ) -> bool:
        """subscribe online state."""
        if not isinstance(did, str) or handler is None:
            raise MIoTMipsError('invalid params')
        topic: str = f'device/{did}/state/#'

        def on_state_msg(topic: str, payload: str, ctx: Any) -> None:
            msg: dict = json.loads(payload)
            # {"device_id":"xxxx","device_name":"米家智能插座3   ","event":"online",
            # "model": "cuco.plug.v3","timestamp":1709001070828,"uid":xxxx}
            if msg is None or 'device_id' not in msg or 'event' not in msg:
                self.log_error(f'on_state_msg, recv unknown msg, {payload}')
                return
            if msg['device_id'] != did:
                self.log_error(
                    f'on_state_msg, err msg, {did}!={msg["device_id"]}')
                return
            if handler:
                self.log_debug('cloud, device state changed, %s', payload)
                handler(
                    did, MIoTDeviceState.ONLINE if msg['event'] == 'online'
                    else MIoTDeviceState.OFFLINE, ctx)

        if did.startswith('blt.') or did.startswith('proxy.'):
        # MIoT cloud may not publish BLE device or proxy gateway child device
        # online/offline state message.
        # Do not subscribe BLE device or proxy gateway child device
        # online/offline state.
            return True
        return self.__reg_broadcast_external(
            topic=topic, handler=on_state_msg, handler_ctx=handler_ctx)

    @final
    def unsub_device_state(self, did: str) -> bool:
        if not isinstance(did, str):
            raise MIoTMipsError('invalid params')
        topic: str = f'device/{did}/state/#'
        return self.__unreg_broadcast_external(topic=topic)

    async def get_dev_list_async(
        self, payload: Optional[str] = None, timeout_ms: int = 10000
    ) -> dict[str, dict]:
        raise NotImplementedError('please call in http client')

    async def get_prop_async(
        self, did: str, siid: int, piid: int,  timeout_ms: int = 10000
    ) -> Any:
        raise NotImplementedError('please call in http client')

    async def set_prop_async(
        self, did: str, siid: int, piid: int, value: Any,
        timeout_ms: int = 10000
    ) -> dict:
        raise NotImplementedError('please call in http client')

    async def action_async(
        self, did: str, siid: int, aiid: int, in_list: list,
        timeout_ms: int = 10000
    ) -> dict:
        raise NotImplementedError('please call in http client')

    def __reg_broadcast_external(
        self, topic: str, handler: Callable[[str, str, Any], None],
        handler_ctx: Any = None
    ) -> bool:
        self._internal_loop.call_soon_threadsafe(
            self.__reg_broadcast, topic, handler, handler_ctx)
        return True

    def __unreg_broadcast_external(self, topic: str) -> bool:
        self._internal_loop.call_soon_threadsafe(
            self.__unreg_broadcast, topic)
        return True

    def __reg_broadcast(
        self, topic: str, handler: Callable[[str, str, Any], None],
        handler_ctx: Any = None
    ) -> None:
        if not self._msg_matcher.get(topic=topic):
            sub_bc: _MipsBroadcast = _MipsBroadcast(
                topic=topic, handler=handler,
                handler_ctx=handler_ctx)
            self._msg_matcher[topic] = sub_bc
            self._mips_sub_internal(topic=topic)
        else:
            self.log_debug(f'mips cloud re-reg broadcast, {topic}')

    def __unreg_broadcast(self, topic: str) -> None:
        if self._msg_matcher.get(topic=topic):
            del self._msg_matcher[topic]
            self._mips_unsub_internal(topic=topic)

    def _on_mips_connect(self, rc: int, props: dict) -> None:
        """sub topic."""
        for topic, _ in list(
                self._msg_matcher.iter_all_nodes()):
            self._mips_sub_internal(topic=topic)

    def _on_mips_disconnect(self, rc: int, props: dict) -> None:
        """unsub topic."""
        pass

    def _on_mips_message(self, topic: str, payload: bytes) -> None:
        """
        NOTICE thread safe, this function will be called at the **mips** thread
        """
        # broadcast
        bc_list: list[_MipsBroadcast] = list(
            self._msg_matcher.iter_match(topic))
        if not bc_list:
            return
        # The message from the cloud is not packed.
        payload_str: str = payload.decode('utf-8')
        # self.log_debug(f"on broadcast, {topic}, {payload}")
        for item in bc_list or []:
            if item.handler is None:
                continue
            # NOTICE: call threadsafe
            self.main_loop.call_soon_threadsafe(
                item.handler, topic, payload_str, item.handler_ctx)


class MipsLocalClient(_MipsClient):
    """MIoT Pub/Sub Local Client."""
    # pylint: disable=unused-argument
    # pylint: disable=inconsistent-quotes
    MIPS_RECONNECT_INTERVAL_MIN: float = 6
    MIPS_RECONNECT_INTERVAL_MAX: float = 60
    MIPS_SUB_PATCH: int = 1000
    MIPS_SUB_INTERVAL: float = 0.1
    _did: str
    _group_id: str
    _home_name: str
    _mips_seed_id: int
    _reply_topic: str
    _dev_list_change_topic: str
    _request_map: dict[str, _MipsRequest]
    _msg_matcher: MIoTMatcher
    _get_prop_queue: dict[str, list]
    _get_prop_timer: Optional[asyncio.TimerHandle]
    _on_dev_list_changed: Optional[Callable[[Any, list[str]], Coroutine]]

    def __init__(
        self, did: str, host: str, group_id: str,
        ca_file: str, cert_file: str, key_file: str,
        port: int = 8883, home_name: str = '',
        loop: Optional[asyncio.AbstractEventLoop] = None
    ) -> None:
        self._did = did
        self._group_id = group_id
        self._home_name = home_name
        self._mips_seed_id = random.randint(0, self.UINT32_MAX)
        self._reply_topic = f'{did}/reply'
        self._dev_list_change_topic = f'{did}/appMsg/devListChange'
        self._request_map = {}
        self._msg_matcher = MIoTMatcher()
        self._get_prop_queue = {}
        self._get_prop_timer = None
        self._on_dev_list_changed = None

        super().__init__(
            client_id=did, host=host, port=port,
            ca_file=ca_file, cert_file=cert_file, key_file=key_file, loop=loop)

    @property
    def group_id(self) -> str:
        return self._group_id

    def log_debug(self, msg, *args, **kwargs) -> None:
        if self._logger:
            self._logger.debug(f'{self._home_name}, '+msg, *args, **kwargs)

    def log_info(self, msg, *args, **kwargs) -> None:
        if self._logger:
            self._logger.info(f'{self._home_name}, '+msg, *args, **kwargs)

    def log_error(self, msg, *args, **kwargs) -> None:
        if self._logger:
            self._logger.error(f'{self._home_name}, '+msg, *args, **kwargs)

    @final
    def connect(self, thread_name: Optional[str] = None) -> None:
        # MIPS local thread name use group_id
        super().connect(self._group_id)

    @final
    def disconnect(self) -> None:
        super().disconnect()
        self._request_map = {}
        self._msg_matcher = MIoTMatcher()

    @final
    def sub_prop(
        self,
        did: str,
        handler: Callable[[dict, Any], None],
        siid: Optional[int] = None,
        piid: Optional[int] = None,
        handler_ctx: Any = None
    ) -> bool:
        topic: str = (
            f'appMsg/notify/iot/{did}/property/'
            f'{"#" if siid is None or piid is None else f"{siid}.{piid}"}')

        def on_prop_msg(topic: str, payload: str, ctx: Any):
            msg: dict = json.loads(payload)
            if (
                msg is None
                or 'did' not in msg
                or 'siid' not in msg
                or 'piid' not in msg
                or 'value' not in msg
            ):
                self.log_info('unknown prop msg, %s', payload)
                return
            if handler:
                self.log_debug('local, on properties_changed, %s', payload)
                handler(msg, ctx)
        return self.__reg_broadcast_external(
            topic=topic, handler=on_prop_msg, handler_ctx=handler_ctx)

    @final
    def unsub_prop(
        self,
        did: str,
        siid: Optional[int] = None,
        piid: Optional[int] = None
    ) -> bool:
        topic: str = (
            f'appMsg/notify/iot/{did}/property/'
            f'{"#" if siid is None or piid is None else f"{siid}.{piid}"}')
        return self.__unreg_broadcast_external(topic=topic)

    @final
    def sub_event(
        self,
        did: str,
        handler: Callable[[dict, Any], None],
        siid: Optional[int] = None,
        eiid: Optional[int] = None,
        handler_ctx: Any = None
    ) -> bool:
        topic: str = (
            f'appMsg/notify/iot/{did}/event/'
            f'{"#" if siid is None or eiid is None else f"{siid}.{eiid}"}')

        def on_event_msg(topic: str, payload: str, ctx: Any):
            msg: dict = json.loads(payload)
            if (
                msg is None
                or 'did' not in msg
                or 'siid' not in msg
                or 'eiid' not in msg
                # or 'arguments' not in msg
            ):
                self.log_info('unknown event msg, %s', payload)
                return
            if 'arguments' not in msg:
                self.log_info('wrong event msg, %s', payload)
                msg['arguments'] = []
            if handler:
                self.log_debug('local, on event_occurred, %s', payload)
                handler(msg, ctx)
        return self.__reg_broadcast_external(
            topic=topic, handler=on_event_msg, handler_ctx=handler_ctx)

    @final
    def unsub_event(
        self,
        did: str,
        siid: Optional[int] = None,
        eiid: Optional[int] = None
    ) -> bool:
        topic: str = (
            f'appMsg/notify/iot/{did}/event/'
            f'{"#" if siid is None or eiid is None else f"{siid}.{eiid}"}')
        return self.__unreg_broadcast_external(topic=topic)

    @final
    async def get_prop_safe_async(
        self, did: str, siid: int, piid: int, timeout_ms: int = 10000
    ) -> Any:
        self._get_prop_queue.setdefault(did, [])
        fut: asyncio.Future = self.main_loop.create_future()
        self._get_prop_queue[did].append({
            'param': json.dumps({
                'did': did,
                'siid': siid,
                'piid': piid
            }),
            'fut': fut,
            'timeout_ms': timeout_ms
        })
        if self._get_prop_timer is None:
            self._get_prop_timer = self.main_loop.call_later(
                0.1,
                self.main_loop.create_task,
                self.__get_prop_timer_handle())
        return await fut

    @final
    async def get_prop_async(
        self, did: str, siid: int, piid: int, timeout_ms: int = 10000
    ) -> Any:
        result_obj = await self.__request_async(
            topic='proxy/get',
            payload=json.dumps({
                'did': did,
                'siid': siid,
                'piid': piid
            }),
            timeout_ms=timeout_ms)
        if not isinstance(result_obj, dict) or 'value' not in result_obj:
            return None
        return result_obj['value']

    @final
    async def set_prop_async(
        self, did: str, siid: int, piid: int, value: Any,
        timeout_ms: int = 10000
    ) -> dict:
        payload_obj: dict = {
            'did': did,
            'rpc': {
                'id': self.__gen_mips_id,
                'method': 'set_properties',
                'params': [{
                    'did': did,
                    'siid': siid,
                    'piid': piid,
                    'value': value
                }]
            }
        }
        result_obj = await self.__request_async(
            topic='proxy/rpcReq',
            payload=json.dumps(payload_obj),
            timeout_ms=timeout_ms)
        if result_obj:
            if (
                'result' in result_obj
                and len(result_obj['result']) == 1
                and 'did' in result_obj['result'][0]
                and result_obj['result'][0]['did'] == did
                and 'code' in result_obj['result'][0]
            ):
                return result_obj['result'][0]
            if 'error' in result_obj:
                return result_obj['error']
        return {
            'code': MIoTErrorCode.CODE_INTERNAL_ERROR.value,
            'message': 'Invalid result'}

    @final
    async def action_async(
        self, did: str, siid: int, aiid: int, in_list: list,
        timeout_ms: int = 10000
    ) -> dict:
        payload_obj: dict = {
            'did': did,
            'rpc': {
                'id': self.__gen_mips_id,
                'method': 'action',
                'params': {
                    'did': did,
                    'siid': siid,
                    'aiid': aiid,
                    'in': in_list
                }
            }
        }
        result_obj = await self.__request_async(
            topic='proxy/rpcReq', payload=json.dumps(payload_obj),
            timeout_ms=timeout_ms)
        if result_obj:
            if 'result' in result_obj and 'code' in result_obj['result']:
                return result_obj['result']
            if 'error' in result_obj:
                return result_obj['error']
        return {
            'code': MIoTErrorCode.CODE_INTERNAL_ERROR.value,
            'message': 'Invalid result'}

    @final
    async def get_dev_list_async(
        self, payload: Optional[str] = None, timeout_ms: int = 10000
    ) -> dict[str, dict]:
        result_obj = await self.__request_async(
            topic='proxy/getDevList', payload=payload or '{}',
            timeout_ms=timeout_ms)
        if not result_obj or 'devList' not in result_obj:
            raise MIoTMipsError('invalid result')
        device_list = {}
        for did, info in result_obj['devList'].items():
            name: str = info.get('name', None)
            urn: str = info.get('urn', None)
            model: str = info.get('model', None)
            if name is None or urn is None or model is None:
                self.log_error(f'invalid device info, {did}, {info}')
                continue
            if model in UNSUPPORTED_MODELS:
                self.log_info(f'unsupported model, {model}, {did}')
                continue
            device_list[did] = {
                'did': did,
                'online': info.get('online', False),
                'specv2_access': info.get('specV2Access', False),
                'push_available': info.get('pushAvailable', False)
            }
        return device_list

    @final
    async def get_action_group_list_async(
        self, timeout_ms: int = 10000
    ) -> list[str]:
        result_obj = await self.__request_async(
            topic='proxy/getMijiaActionGroupList',
            payload='{}',
            timeout_ms=timeout_ms)
        if not result_obj or 'result' not in result_obj:
            raise MIoTMipsError('invalid result')
        return result_obj['result']

    @final
    async def exec_action_group_list_async(
        self, ag_id: str, timeout_ms: int = 10000
    ) -> dict:
        result_obj = await self.__request_async(
            topic='proxy/execMijiaActionGroup',
            payload=f'{{"id":"{ag_id}"}}',
            timeout_ms=timeout_ms)
        if result_obj:
            if 'result' in result_obj:
                return result_obj['result']
            if 'error' in result_obj:
                return result_obj['error']
        return {
            'code': MIoTErrorCode.CODE_MIPS_INVALID_RESULT.value,
            'message': 'invalid result'}

    @final
    @property
    def on_dev_list_changed(
        self
    ) -> Optional[Callable[[Any, list[str]], Coroutine]]:
        return self._on_dev_list_changed

    @final
    @on_dev_list_changed.setter
    def on_dev_list_changed(
        self, func: Optional[Callable[[Any, list[str]], Coroutine]]
    ) -> None:
        """run in main loop."""
        self._on_dev_list_changed = func

    def __request(
            self, topic: str, payload: str,
            on_reply: Callable[[str, Any], None],
            on_reply_ctx: Any = None, timeout_ms: int = 10000
    ) -> None:
        req = _MipsRequest(
            mid=self.__gen_mips_id,
            on_reply=on_reply,
            on_reply_ctx=on_reply_ctx,
            timer=None)
        pub_topic: str = f'master/{topic}'
        result = self.__mips_publish(
            topic=pub_topic, payload=payload, mid=req.mid,
            ret_topic=self._reply_topic)
        self.log_debug(
            f'mips local call api, {result}, {req.mid}, {pub_topic}, '
            f'{payload}')

        def on_request_timeout(req: _MipsRequest):
            self.log_error(
                f'on mips request timeout, {req.mid}, {pub_topic}'
                f', {payload}')
            self._request_map.pop(str(req.mid), None)
            req.on_reply(
                '{"error":{"code":-10006, "message":"timeout"}}',
                req.on_reply_ctx)
        req.timer = self._internal_loop.call_later(
            timeout_ms/1000, on_request_timeout, req)
        self._request_map[str(req.mid)] = req

    def __reg_broadcast(
        self, topic: str, handler: Callable[[str, str, Any], None],
        handler_ctx: Any
    ) -> None:
        sub_topic: str = f'{self._did}/{topic}'
        if not self._msg_matcher.get(sub_topic):
            sub_bc: _MipsBroadcast = _MipsBroadcast(
                topic=sub_topic, handler=handler,
                handler_ctx=handler_ctx)
            self._msg_matcher[sub_topic] = sub_bc
            self._mips_sub_internal(topic=f'master/{topic}')
        else:
            self.log_debug(f'mips re-reg broadcast, {sub_topic}')

    def __unreg_broadcast(self, topic) -> None:
        # Central hub gateway needs to add prefix
        unsub_topic: str = f'{self._did}/{topic}'
        if self._msg_matcher.get(unsub_topic):
            del self._msg_matcher[unsub_topic]
            self._mips_unsub_internal(
                topic=re.sub(f'^{self._did}', 'master', unsub_topic))

    @final
    def _on_mips_connect(self, rc: int, props: dict) -> None:
        self.log_debug('__on_mips_connect_handler')
        # Sub did/#, include reply topic
        self._mips_sub_internal(f'{self._did}/#')
        # Sub device list change
        self._mips_sub_internal('master/appMsg/devListChange')
        # Do not need to subscribe api topics, for they are covered by did/#
        # Sub api topic.
        # Sub broadcast topic
        for topic, _ in list(self._msg_matcher.iter_all_nodes()):
            self._mips_sub_internal(
                topic=re.sub(f'^{self._did}', 'master', topic))

    @final
    def _on_mips_disconnect(self, rc: int, props: dict) -> None:
        pass

    @final
    def _on_mips_message(self, topic: str, payload: bytes) -> None:
        mips_msg: _MipsMessage = _MipsMessage.unpack(payload)
        # self.log_debug(
        #     f"mips local client, on_message, {topic} -> {mips_msg}")
        # Reply
        if topic == self._reply_topic:
            self.log_debug(f'on request reply, {mips_msg}')
            req: Optional[_MipsRequest] = self._request_map.pop(
                str(mips_msg.mid), None)
            if req:
                # Cancel timer
                if req.timer:
                    req.timer.cancel()
                if req.on_reply:
                    self.main_loop.call_soon_threadsafe(
                        req.on_reply, mips_msg.payload or '{}',
                        req.on_reply_ctx)
            return
        # Broadcast
        bc_list: list[_MipsBroadcast] = list(self._msg_matcher.iter_match(
            topic=topic))
        if bc_list:
            self.log_debug(f'on broadcast, {topic}, {mips_msg}')
            for item in bc_list or []:
                if item.handler is None:
                    continue
                self.main_loop.call_soon_threadsafe(
                    item.handler, topic[topic.find('/')+1:],
                    mips_msg.payload or '{}', item.handler_ctx)
            return
        # Device list change
        if topic == self._dev_list_change_topic:
            if mips_msg.payload is None:
                self.log_error('devListChange msg is None')
                return
            payload_obj: dict = json.loads(mips_msg.payload)
            dev_list = payload_obj.get('devList', None)
            if not isinstance(dev_list, list) or not dev_list:
                _LOGGER.error(
                    'unknown devListChange msg, %s', mips_msg.payload)
                return
            if self._on_dev_list_changed:
                self.main_loop.call_soon_threadsafe(
                    self.main_loop.create_task,
                    self._on_dev_list_changed(self, dev_list))
            return

        self.log_debug(
            f'mips local client, recv unknown msg, {topic} -> {mips_msg}')

    @property
    def __gen_mips_id(self) -> int:
        mips_id: int = self._mips_seed_id
        self._mips_seed_id = int((self._mips_seed_id+1) % self.UINT32_MAX)
        return mips_id

    def __mips_publish(
        self,
        topic: str,
        payload: str,
        mid: Optional[int] = None,
        ret_topic: Optional[str] = None,
        wait_for_publish: bool = False,
        timeout_ms: int = 10000
    ) -> bool:
        mips_msg: bytes = _MipsMessage.pack(
            mid=mid or self.__gen_mips_id, payload=payload,
            msg_from='local', ret_topic=ret_topic)
        return self._mips_publish_internal(
            topic=topic.strip(), payload=mips_msg,
            wait_for_publish=wait_for_publish, timeout_ms=timeout_ms)

    def __request_external(
            self, topic: str, payload: str,
            on_reply: Callable[[str, Any], None],
            on_reply_ctx: Any = None, timeout_ms: int = 10000
    ) -> bool:
        if topic is None or payload is None or on_reply is None:
            raise MIoTMipsError('invalid params')
        self._internal_loop.call_soon_threadsafe(
            self.__request, topic, payload, on_reply, on_reply_ctx, timeout_ms)
        return True

    def __reg_broadcast_external(
        self, topic: str, handler: Callable[[str, str, Any], None],
        handler_ctx: Any
    ) -> bool:
        self._internal_loop.call_soon_threadsafe(
            self.__reg_broadcast,
            topic, handler, handler_ctx)
        return True

    def __unreg_broadcast_external(self, topic) -> bool:
        self._internal_loop.call_soon_threadsafe(
            self.__unreg_broadcast, topic)
        return True

    @final
    async def __request_async(
        self, topic: str, payload: str, timeout_ms: int = 10000
    ) -> dict:
        fut_handler: asyncio.Future = self.main_loop.create_future()

        def on_msg_reply(payload: str, ctx: Any):
            fut: asyncio.Future = ctx
            if fut:
                self.main_loop.call_soon_threadsafe(fut.set_result, payload)
        if not self.__request_external(
                topic=topic,
                payload=payload,
                on_reply=on_msg_reply,
                on_reply_ctx=fut_handler,
                timeout_ms=timeout_ms):
            # Request error
            fut_handler.set_result('internal request error')

        result = await fut_handler
        try:
            return json.loads(result)
        except json.JSONDecodeError:
            return {
                'code': MIoTErrorCode.CODE_MIPS_INVALID_RESULT.value,
                'message': f'Error: {result}'}

    async def __get_prop_timer_handle(self) -> None:
        for did in list(self._get_prop_queue.keys()):
            item = self._get_prop_queue[did].pop()
            _LOGGER.debug('get prop, %s, %s', did, item)
            result_obj = await self.__request_async(
                topic='proxy/get',
                payload=item['param'],
                timeout_ms=item['timeout_ms'])
            if result_obj is None or 'value' not in result_obj:
                item['fut'].set_result(None)
            else:
                item['fut'].set_result(result_obj['value'])

            if not self._get_prop_queue[did]:
                self._get_prop_queue.pop(did, None)

        if self._get_prop_queue:
            self._get_prop_timer = self.main_loop.call_later(
                0.1, lambda: self.main_loop.create_task(
                    self.__get_prop_timer_handle()))
        else:
            self._get_prop_timer = None
