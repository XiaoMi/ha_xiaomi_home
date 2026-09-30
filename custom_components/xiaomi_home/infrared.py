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

Infrared emitter for the Xiaomi universal remote.
"""
from __future__ import annotations

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.entity import EntityCategory
from homeassistant.helpers.entity_platform import AddEntitiesCallback

try:
    from homeassistant.components.infrared import InfraredEmitterEntity
except ImportError:  # Home Assistant before the infrared entity existed
    InfraredEmitterEntity = None

from .miot.const import DOMAIN
from .miot.ir_code import DEFAULT_FREQUENCY, ensure_miio_ok, timings_to_chuangmi
from .miot.miot_device import MIoTDevice, MIoTEntityData, MIoTServiceEntity
from .miot.miot_error import MIoTClientError


async def async_setup_entry(
    hass: HomeAssistant,
    config_entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up a config entry."""
    if InfraredEmitterEntity is None:
        return
    device_list: list[MIoTDevice] = hass.data[DOMAIN]['devices'][
        config_entry.entry_id]
    new_entities = []
    for miot_device in device_list:
        for data in miot_device.entity_list.get('infrared', []):
            new_entities.append(XiaomiInfrared(
                miot_device=miot_device, entity_data=data))
    if new_entities:
        async_add_entities(new_entities)


if InfraredEmitterEntity is not None:

    class XiaomiInfrared(MIoTServiceEntity, InfraredEmitterEntity):
        """chuangmi.ir.v2 emitter for Settings > Infrared."""

        _attr_entity_category = EntityCategory.DIAGNOSTIC

        def __init__(
            self, miot_device: MIoTDevice, entity_data: MIoTEntityData
        ) -> None:
            """Initialize the emitter."""
            super().__init__(
                miot_device=miot_device, entity_data=entity_data)
            # The remote entity already uses the device unique id.
            self._attr_unique_id = f'{self._attr_unique_id}_emitter'
            self._attr_name = None

        async def async_send_command(self, command) -> None:
            """Send one Home Assistant infrared command."""
            freq = getattr(command, 'modulation', None) or DEFAULT_FREQUENCY
            try:
                code, freq = timings_to_chuangmi(
                    command.get_raw_timings(), freq)
            except ValueError as err:
                raise HomeAssistantError(str(err)) from err
            try:
                ensure_miio_ok(
                    await self.miot_device.miot_client.call_miio_async(
                        did=self.miot_device.did,
                        method='miIO.ir_play',
                        params={'freq': freq, 'code': code}))
            except MIoTClientError as err:
                raise HomeAssistantError(str(err)) from err
