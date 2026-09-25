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

Remote entities for the Xiaomi universal infrared remote.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Any, Iterable, Optional

from homeassistant.components import persistent_notification
from homeassistant.components.remote import (
    ATTR_ALTERNATIVE,
    ATTR_COMMAND_TYPE,
    ATTR_DELAY_SECS,
    ATTR_DEVICE,
    ATTR_NUM_REPEATS,
    ATTR_TIMEOUT,
    RemoteEntity,
    RemoteEntityFeature,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import ATTR_COMMAND
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.storage import Store

from .miot.const import DOMAIN
from .miot.ir_code import (
    LEARN_SLOT,
    IrCodeBook,
    ensure_miio_ok,
    ir_code_from_read,
)
from .miot.miot_device import MIoTDevice, MIoTEntityData, MIoTServiceEntity
from .miot.miot_error import MIoTClientError

_LOGGER = logging.getLogger(__name__)

_LEARN_TIMEOUT = 30
_NOTIFY_TITLE = 'Xiaomi Home'


async def async_setup_entry(
    hass: HomeAssistant,
    config_entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up a config entry."""
    device_list: list[MIoTDevice] = hass.data[DOMAIN]['devices'][
        config_entry.entry_id]
    new_entities = []
    for miot_device in device_list:
        for data in miot_device.entity_list.get('remote', []):
            new_entities.append(XiaomiRemote(
                miot_device=miot_device, entity_data=data))
    if new_entities:
        async_add_entities(new_entities)


class XiaomiRemote(MIoTServiceEntity, RemoteEntity):
    """Broadlink-style remote for chuangmi.ir.v2."""

    def __init__(
        self, miot_device: MIoTDevice, entity_data: MIoTEntityData
    ) -> None:
        """Initialize the remote."""
        super().__init__(miot_device=miot_device, entity_data=entity_data)
        self._attr_name = None
        self._attr_is_on = True
        self._attr_assumed_state = True
        self._attr_supported_features = (
            RemoteEntityFeature.LEARN_COMMAND
            | RemoteEntityFeature.DELETE_COMMAND)
        self._book = IrCodeBook()
        self._lock = asyncio.Lock()
        self._storage_loaded = False
        self._code_store: Optional[Store] = None
        self._flag_store: Optional[Store] = None

    async def async_added_to_hass(self) -> None:
        """Load learned codes when the entity is added."""
        await super().async_added_to_hass()
        did = self.miot_device.did
        self._code_store = Store(
            self.hass, 1, f'xiaomi_home_remote_{did}_codes')
        self._flag_store = Store(
            self.hass, 1, f'xiaomi_home_remote_{did}_flags')
        await self._async_load_storage()

    async def async_turn_on(self, **kwargs: Any) -> None:
        """Allow the entity to send commands.

        This does not power the infrared blaster. It matches the
        Broadlink remote entity, which blocks send while turned off.
        """
        self._attr_is_on = True
        self.async_write_ha_state()

    async def async_turn_off(self, **kwargs: Any) -> None:
        """Block further send and learn calls."""
        self._attr_is_on = False
        self.async_write_ha_state()

    async def async_send_command(
        self, command: Iterable[str], **kwargs: Any
    ) -> None:
        """Send stored commands, b64 codes, or Pronto hex."""
        if not self._attr_is_on:
            _LOGGER.warning(
                'remote.send_command canceled: %s is turned off',
                self.entity_id)
            return
        if not self._storage_loaded:
            await self._async_load_storage()
        if isinstance(command, str):
            commands = [command]
        else:
            commands = list(command)
        device = kwargs.get(ATTR_DEVICE)
        repeats = kwargs.get(ATTR_NUM_REPEATS, 1)
        delay = kwargs.get(ATTR_DELAY_SECS, 0.4)
        try:
            resolved = [
                self._book.resolve(device, item) for item in commands]
        except ValueError as err:
            raise HomeAssistantError(str(err)) from err
        async with self._lock:
            started = False
            for _ in range(repeats):
                for code, freq in resolved:
                    if started and delay:
                        await asyncio.sleep(delay)
                    started = True
                    await self._play(code, freq)
        await self._async_save_flags()

    async def async_learn_command(self, **kwargs: Any) -> None:
        """Learn IR commands into local storage."""
        if kwargs.get(ATTR_COMMAND_TYPE, 'ir') == 'rf':
            raise HomeAssistantError(
                f'{self.entity_id} does not support learning RF commands')
        if not self._attr_is_on:
            _LOGGER.warning(
                'remote.learn_command canceled: %s is turned off',
                self.entity_id)
            return
        device = kwargs.get(ATTR_DEVICE)
        commands = kwargs.get(ATTR_COMMAND) or []
        if isinstance(commands, str):
            commands = [commands]
        if not device or not commands:
            raise HomeAssistantError('device and command are required')
        if not self._storage_loaded:
            await self._async_load_storage()
        alternative = bool(kwargs.get(ATTR_ALTERNATIVE, False))
        timeout = kwargs.get(ATTR_TIMEOUT) or _LEARN_TIMEOUT
        async with self._lock:
            for command in commands:
                try:
                    first = await self._learn_one(device, command, timeout)
                    if alternative:
                        second = await self._learn_one(
                            device, command, timeout)
                        self._book.set_command(
                            device, command, [first, second])
                    else:
                        self._book.set_command(device, command, first)
                    await self._async_save_codes()
                except (HomeAssistantError, TimeoutError, ValueError) as err:
                    _LOGGER.error(
                        'Failed to learn %s: %s', command, err)
                    raise HomeAssistantError(
                        f'Failed to learn {command}: {err}') from err

    async def async_delete_command(self, **kwargs: Any) -> None:
        """Delete stored commands."""
        device = kwargs.get(ATTR_DEVICE)
        commands = kwargs.get(ATTR_COMMAND) or []
        if isinstance(commands, str):
            commands = [commands]
        if not device or not commands:
            raise HomeAssistantError('device and command are required')
        if not self._storage_loaded:
            await self._async_load_storage()
        try:
            self._book.delete(device, list(commands))
        except ValueError as err:
            raise HomeAssistantError(str(err)) from err
        await self._async_save_codes()
        await self._async_save_flags()

    async def _learn_one(
        self, device: str, command: str, timeout: float
    ) -> str:
        notification_id = f'xiaomi_home_ir_{self.unique_id}'
        persistent_notification.async_create(
            self.hass,
            (
                f'Press the button on the original remote for '
                f'{device} / {command}.'
            ),
            title=_NOTIFY_TITLE,
            notification_id=notification_id)
        try:
            ensure_miio_ok(await self._call(
                'miIO.ir_learn', {'key': LEARN_SLOT}))
            deadline = asyncio.get_running_loop().time() + timeout
            while asyncio.get_running_loop().time() < deadline:
                await asyncio.sleep(1)
                code = ir_code_from_read(await self._call(
                    'miIO.ir_read', {'key': LEARN_SLOT}))
                if code:
                    return code
            raise TimeoutError('learn timeout')
        finally:
            persistent_notification.async_dismiss(
                self.hass, notification_id)

    async def _play(self, code: str, freq: int) -> None:
        ensure_miio_ok(await self._call(
            'miIO.ir_play', {'freq': freq, 'code': code}))

    async def _call(self, method: str, params: dict) -> dict:
        try:
            return await self.miot_device.miot_client.call_miio_async(
                did=self.miot_device.did, method=method, params=params)
        except MIoTClientError as err:
            raise HomeAssistantError(str(err)) from err

    async def _async_load_storage(self) -> None:
        codes = await self._code_store.async_load()
        toggles = await self._flag_store.async_load()
        self._book = IrCodeBook.load(
            codes if isinstance(codes, dict) else {},
            toggles if isinstance(toggles, dict) else {})
        self._storage_loaded = True

    async def _async_save_codes(self) -> None:
        await self._code_store.async_save(self._book.dump())

    async def _async_save_flags(self) -> None:
        await self._flag_store.async_save(self._book.dump_toggles())
