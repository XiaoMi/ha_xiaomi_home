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

Select entities for Xiaomi Home.
"""
from __future__ import annotations
from typing import Optional

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.components.select import SelectEntity
from homeassistant.helpers.entity import EntityCategory
from homeassistant.helpers.restore_state import RestoreEntity

from .miot.const import DOMAIN
from .miot.miot_device import MIoTDevice, MIoTPropertyEntity
from .miot.miot_spec import MIoTSpecProperty


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
        for prop in miot_device.prop_list.get('select', []):
            new_entities.append(Select(miot_device=miot_device, spec=prop))

    if new_entities:
        async_add_entities(new_entities)

    # create select for light
    new_light_select_entities = []
    for miot_device in device_list:
        # Add it to all devices with light entities, because some bathroom heaters and clothes drying racks also have lights.
        # if "device:light" in miot_device.spec_instance.urn:
        if miot_device.entity_list.get("light", []):
            device_id = list(miot_device.device_info.get("identifiers"))[0][1]
            new_light_select_entities.append(
                LightCommandSendMode(hass=hass, device_id=device_id))
    if new_light_select_entities:
        async_add_entities(new_light_select_entities)

class Select(MIoTPropertyEntity, SelectEntity):
    """Select entities for Xiaomi Home."""

    def __init__(self, miot_device: MIoTDevice, spec: MIoTSpecProperty) -> None:
        """Initialize the Select."""
        super().__init__(miot_device=miot_device, spec=spec)
        if self._value_list:
            self._attr_options = self._value_list.descriptions

    async def async_select_option(self, option: str) -> None:
        """Change the selected option."""
        await self.set_property_async(
            value=self.get_vlist_value(description=option))

    @property
    def current_option(self) -> Optional[str]:
        """Return the current selected option."""
        return self.get_vlist_description(value=self._value)


class LightCommandSendMode(SelectEntity, RestoreEntity):
    """To control whether to turn on the light, you need to send the light-on command first and
    then send other color temperatures and brightness or send them all at the same time.
    The default is to send one by one."""

    def __init__(self, hass: HomeAssistant, device_id: str):
        super().__init__()
        self.hass = hass
        self._device_id = device_id
        self._attr_name = "Command Send Mode"
        self.entity_id = f"select.light_{device_id}_command_send_mode"
        self._attr_unique_id = self.entity_id
        self._attr_options = [
            "Send One by One", "Send Turn On First", "Send Together"
        ]
        self._attr_device_info = {"identifiers": {(DOMAIN, device_id)}}
        self._attr_current_option = self._attr_options[0]
        self._attr_entity_category = EntityCategory.CONFIG

    async def async_select_option(self, option: str):
        if option in self._attr_options:
            self._attr_current_option = option
            self.async_write_ha_state()

    async def async_added_to_hass(self):
        await super().async_added_to_hass()
        if (last_state := await self.async_get_last_state()
           ) and last_state.state in self._attr_options:
            self._attr_current_option = last_state.state

    @property
    def current_option(self):
        return self._attr_current_option
