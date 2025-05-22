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

Humidifier entities for Xiaomi Home.
"""
from __future__ import annotations
import logging
from typing import Any, Optional

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.components.humidifier import (HumidifierEntity,
                                                 HumidifierDeviceClass,
                                                 HumidifierEntityFeature,
                                                 HumidifierAction)

from .miot.miot_spec import MIoTSpecProperty
from .miot.miot_device import MIoTDevice, MIoTEntityData, MIoTServiceEntity
from .miot.const import DOMAIN

_LOGGER = logging.getLogger(__name__)


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
        for data in miot_device.entity_list.get('humidifier', []):
            data.device_class = HumidifierDeviceClass.HUMIDIFIER
            new_entities.append(
                Humidifier(miot_device=miot_device, entity_data=data))
        for data in miot_device.entity_list.get('dehumidifier', []):
            data.device_class = HumidifierDeviceClass.DEHUMIDIFIER
            new_entities.append(
                Humidifier(miot_device=miot_device, entity_data=data))

    if new_entities:
        async_add_entities(new_entities)


class Humidifier(MIoTServiceEntity, HumidifierEntity):
    """Humidifier entities for Xiaomi Home."""
    # pylint: disable=unused-argument
    _prop_on: Optional[MIoTSpecProperty]
    _prop_mode: Optional[MIoTSpecProperty]
    _prop_target_humidity: Optional[MIoTSpecProperty]
    _prop_humidity: Optional[MIoTSpecProperty]

    _mode_map: dict[Any, Any]

    def __init__(self, miot_device: MIoTDevice,
                 entity_data: MIoTEntityData) -> None:
        """Initialize the Humidifier."""
        super().__init__(miot_device=miot_device, entity_data=entity_data)
        self._attr_device_class = entity_data.device_class
        self._attr_supported_features = HumidifierEntityFeature(0)
        self._prop_on = None
        self._prop_mode = None
        self._prop_target_humidity = None
        self._prop_humidity = None
        self._mode_map = None

        # properties
        for prop in entity_data.props:
            # on
            if prop.name == 'on':
                self._prop_on = prop
            # target-humidity
            elif prop.name == 'target-humidity':
                if not prop.value_range:
                    _LOGGER.error(
                        'invalid target-humidity value_range format, %s',
                        self.entity_id)
                    continue
                self._attr_min_humidity = prop.value_range.min_
                self._attr_max_humidity = prop.value_range.max_
                self._prop_target_humidity = prop
            # mode
            elif prop.name == 'mode':
                if not prop.value_list:
                    _LOGGER.error('mode value_list is None, %s', self.entity_id)
                    continue
                self._mode_map = prop.value_list.to_map()
                self._attr_available_modes = list(self._mode_map.values())
                self._attr_supported_features |= HumidifierEntityFeature.MODES
                self._prop_mode = prop
            # relative-humidity
            elif prop.name == 'relative-humidity':
                self._prop_humidity = prop

    async def async_turn_on(self, **kwargs):
        """Turn the humidifier on."""
        await self.set_property_async(prop=self._prop_on, value=True)

    async def async_turn_off(self, **kwargs):
        """Turn the humidifier off."""
        await self.set_property_async(prop=self._prop_on, value=False)

    async def async_set_humidity(self, humidity: int) -> None:
        """Set new target humidity."""
        if self._prop_target_humidity is None:
            return
        await self.set_property_async(prop=self._prop_target_humidity,
                                      value=humidity)

    async def async_set_mode(self, mode: str) -> None:
        """Set new target preset mode."""
        await self.set_property_async(prop=self._prop_mode,
                                      value=self.get_map_key(
                                          map_=self._mode_map, value=mode))

    @property
    def is_on(self) -> Optional[bool]:
        """Return if the humidifier is on."""
        return self.get_prop_value(prop=self._prop_on)

    @property
    def action(self) -> Optional[HumidifierAction]:
        """Return the current status of the device."""
        if not self.is_on:
            return HumidifierAction.OFF
        if self._attr_device_class == HumidifierDeviceClass.HUMIDIFIER:
            return HumidifierAction.HUMIDIFYING
        return HumidifierAction.DRYING

    @property
    def current_humidity(self) -> Optional[int]:
        """Return the current humidity."""
        return (self.get_prop_value(
            prop=self._prop_humidity) if self._prop_humidity else None)

    @property
    def target_humidity(self) -> Optional[int]:
        """Return the target humidity."""
        return (self.get_prop_value(prop=self._prop_target_humidity)
                if self._prop_target_humidity else None)

    @property
    def mode(self) -> Optional[str]:
        """Return the current preset mode."""
        return self.get_map_value(map_=self._mode_map,
                                  key=self.get_prop_value(prop=self._prop_mode))
