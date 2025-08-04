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

Water heater entities for Xiaomi Home.
"""
from __future__ import annotations
import logging
from typing import Any, Optional

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.components.water_heater import (STATE_ON, STATE_OFF,
                                                   ATTR_TEMPERATURE,
                                                   WaterHeaterEntity,
                                                   WaterHeaterEntityFeature)

from .miot.const import DOMAIN
from .miot.miot_device import MIoTDevice, MIoTEntityData, MIoTServiceEntity
from .miot.miot_spec import MIoTSpecProperty

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
        for data in miot_device.entity_list.get('water_heater', []):
            new_entities.append(
                WaterHeater(miot_device=miot_device, entity_data=data))

    if new_entities:
        async_add_entities(new_entities)


class WaterHeater(MIoTServiceEntity, WaterHeaterEntity):
    """Water heater entities for Xiaomi Home."""
    _prop_on: Optional[MIoTSpecProperty]
    _prop_temp: Optional[MIoTSpecProperty]
    _prop_target_temp: Optional[MIoTSpecProperty]
    _prop_mode: Optional[MIoTSpecProperty]

    _mode_map: Optional[dict[Any, Any]]

    def __init__(self, miot_device: MIoTDevice,
                 entity_data: MIoTEntityData) -> None:
        """Initialize the Water heater."""
        super().__init__(miot_device=miot_device, entity_data=entity_data)
        self._attr_temperature_unit = None
        self._attr_supported_features = WaterHeaterEntityFeature(0)
        self._prop_on = None
        self._prop_temp = None
        self._prop_target_temp = None
        self._prop_mode = None
        self._mode_map = None

        # properties
        for prop in entity_data.props:
            # on
            if prop.name == 'on':
                self._attr_supported_features |= WaterHeaterEntityFeature.ON_OFF
                self._prop_on = prop
            # temperature
            if prop.name == 'temperature':
                if not prop.value_range:
                    _LOGGER.error('invalid temperature value_range format, %s',
                                  self.entity_id)
                    continue
                if prop.external_unit:
                    self._attr_temperature_unit = prop.external_unit
                self._prop_temp = prop
            # target-temperature
            if prop.name == 'target-temperature':
                if not prop.value_range:
                    _LOGGER.error(
                        'invalid target-temperature value_range format, %s',
                        self.entity_id)
                    continue
                self._attr_min_temp = prop.value_range.min_
                self._attr_max_temp = prop.value_range.max_
                self._attr_target_temperature_step = prop.value_range.step
                if self._attr_temperature_unit is None and prop.external_unit:
                    self._attr_temperature_unit = prop.external_unit
                self._attr_supported_features |= (
                    WaterHeaterEntityFeature.TARGET_TEMPERATURE)
                self._prop_target_temp = prop
            # mode
            if prop.name == 'mode':
                if not prop.value_list:
                    _LOGGER.error('mode value_list is None, %s', self.entity_id)
                    continue
                self._mode_map = prop.value_list.to_map()
                self._attr_operation_list = list(self._mode_map.values())
                self._prop_mode = prop
        if not self._attr_operation_list:
            self._attr_operation_list = [STATE_ON]
        self._attr_operation_list.append(STATE_OFF)
        self._attr_supported_features |= WaterHeaterEntityFeature.OPERATION_MODE

    async def async_turn_on(self) -> None:
        """Turn the water heater on."""
        await self.set_property_async(prop=self._prop_on, value=True)

    async def async_turn_off(self) -> None:
        """Turn the water heater off."""
        await self.set_property_async(prop=self._prop_on, value=False)

    async def async_set_temperature(self, **kwargs: Any) -> None:
        """Set the target temperature."""
        await self.set_property_async(prop=self._prop_target_temp,
                                      value=kwargs[ATTR_TEMPERATURE])

    async def async_set_operation_mode(self, operation_mode: str) -> None:
        """Set the operation mode of the water heater."""
        if operation_mode == STATE_OFF:
            await self.set_property_async(prop=self._prop_on, value=False)
            return
        if operation_mode == STATE_ON:
            await self.set_property_async(prop=self._prop_on, value=True)
            return
        if self.get_prop_value(prop=self._prop_on) is not True:
            await self.set_property_async(prop=self._prop_on,
                                          value=True,
                                          write_ha_state=False)
        await self.set_property_async(prop=self._prop_mode,
                                      value=self.get_map_key(
                                          map_=self._mode_map,
                                          value=operation_mode))

    @property
    def current_temperature(self) -> Optional[float]:
        """The current temperature."""
        return (None if self._prop_temp is None else self.get_prop_value(
            prop=self._prop_temp))

    @property
    def target_temperature(self) -> Optional[float]:
        """The target temperature."""
        return (None if self._prop_target_temp is None else self.get_prop_value(
            prop=self._prop_target_temp))

    @property
    def current_operation(self) -> Optional[str]:
        """The current mode."""
        if self.get_prop_value(prop=self._prop_on) is False:
            return STATE_OFF
        if not self._prop_mode and self.get_prop_value(prop=self._prop_on):
            return STATE_ON
        return (None if self._prop_mode is None else self.get_map_value(
            map_=self._mode_map, key=self.get_prop_value(prop=self._prop_mode)))
