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

Fan entities for Xiaomi Home.
"""
from __future__ import annotations
from typing import Any, Optional
import logging

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.components.fan import FanEntity, FanEntityFeature
from homeassistant.util.percentage import (
    percentage_to_ranged_value,
    ranged_value_to_percentage,
    ordered_list_item_to_percentage,
    percentage_to_ordered_list_item
)

from .miot.miot_spec import MIoTSpecProperty
from .miot.const import DOMAIN
from .miot.miot_device import MIoTDevice, MIoTEntityData, MIoTServiceEntity

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
        for data in miot_device.entity_list.get('fan', []):
            new_entities.append(Fan(miot_device=miot_device, entity_data=data))

    if new_entities:
        async_add_entities(new_entities)


class Fan(MIoTServiceEntity, FanEntity):
    """Fan entities for Xiaomi Home."""
    # pylint: disable=unused-argument
    _prop_on: Optional[MIoTSpecProperty]
    _prop_fan_level: Optional[MIoTSpecProperty]
    _prop_mode: Optional[MIoTSpecProperty]
    _prop_horizontal_swing: Optional[MIoTSpecProperty]
    _prop_wind_reverse: Optional[MIoTSpecProperty]
    _prop_wind_reverse_forward: Any
    _prop_wind_reverse_reverse: Any

    _speed_min: int
    _speed_max: int
    _speed_step: int
    _speed_names: Optional[list]
    _speed_name_map: Optional[dict[int, str]]
    _mode_list: Optional[dict[Any, Any]]

    def __init__(
        self, miot_device: MIoTDevice, entity_data: MIoTEntityData
    ) -> None:
        """Initialize the Fan."""
        super().__init__(miot_device=miot_device,  entity_data=entity_data)
        self._attr_preset_modes = []
        self._attr_current_direction = None
        self._attr_supported_features = FanEntityFeature(0)

        self._prop_on = None
        self._prop_fan_level = None
        self._prop_mode = None
        self._prop_horizontal_swing = None
        self._prop_wind_reverse = None
        self._prop_wind_reverse_forward = None
        self._prop_wind_reverse_reverse = None
        self._speed_min = 65535
        self._speed_max = 0
        self._speed_step = 1
        self._speed_names = []
        self._speed_name_map = {}

        self._mode_list = None

        # properties
        for prop in entity_data.props:
            if prop.name == 'on':
                self._attr_supported_features |= FanEntityFeature.TURN_ON
                self._attr_supported_features |= FanEntityFeature.TURN_OFF
                self._prop_on = prop
            elif prop.name == 'fan-level':
                if isinstance(prop.value_range, dict):
                    # Fan level with value-range
                    self._speed_min = prop.value_range['min']
                    self._speed_max = prop.value_range['max']
                    self._speed_step = prop.value_range['step']
                    self._attr_speed_count = int((
                        self._speed_max - self._speed_min)/self._speed_step)+1
                    self._attr_supported_features |= FanEntityFeature.SET_SPEED
                    self._prop_fan_level = prop
                elif (
                    self._prop_fan_level is None
                    and isinstance(prop.value_list, list)
                    and prop.value_list
                ):
                    # Fan level with value-list
                    # Fan level with value-range is prior to fan level with
                    # value-list when a fan has both fan level properties.
                    self._speed_name_map = {
                        item['value']: item['description']
                        for item in prop.value_list}
                    self._speed_names = list(self._speed_name_map.values())
                    self._attr_speed_count = len(prop.value_list)
                    self._attr_supported_features |= FanEntityFeature.SET_SPEED
                    self._prop_fan_level = prop
            elif prop.name == 'mode':
                if (
                    not isinstance(prop.value_list, list)
                    or not prop.value_list
                ):
                    _LOGGER.error(
                        'mode value_list is None, %s', self.entity_id)
                    continue
                self._mode_list = {
                    item['value']: item['description']
                    for item in prop.value_list}
                self._attr_preset_modes = list(self._mode_list.values())
                self._attr_supported_features |= FanEntityFeature.PRESET_MODE
                self._prop_mode = prop
            elif prop.name == 'horizontal-swing':
                self._attr_supported_features |= FanEntityFeature.OSCILLATE
                self._prop_horizontal_swing = prop
            elif prop.name == 'wind-reverse':
                if prop.format_ == 'bool':
                    self._prop_wind_reverse_forward = False
                    self._prop_wind_reverse_reverse = True
                elif (
                    isinstance(prop.value_list, list)
                    and prop.value_list
                ):
                    for item in prop.value_list:
                        if item['name'].lower() in {'foreward'}:
                            self._prop_wind_reverse_forward = item['value']
                        elif item['name'].lower() in {
                                'reversal', 'reverse'}:
                            self._prop_wind_reverse_reverse = item['value']
                if (
                    self._prop_wind_reverse_forward is None
                    or self._prop_wind_reverse_reverse is None
                ):
                    # NOTICE: Value may be 0 or False
                    _LOGGER.info(
                        'invalid wind-reverse, %s', self.entity_id)
                    continue
                self._attr_supported_features |= FanEntityFeature.DIRECTION
                self._prop_wind_reverse = prop

    def __get_mode_description(self, key: int) -> Optional[str]:
        if self._mode_list is None:
            return None
        return self._mode_list.get(key, None)

    def __get_mode_value(self, description: str) -> Optional[int]:
        if self._mode_list is None:
            return None
        for key, value in self._mode_list.items():
            if value == description:
                return key
        return None

    async def async_turn_on(
        self, percentage: int = None, preset_mode: str = None, **kwargs: Any
    ) -> None:
        """Turn the fan on.

        Shall set the percentage or the preset_mode attr to complying
        if applicable.
        """
        # on
        await self.set_property_async(prop=self._prop_on, value=True)
        # percentage
        if percentage:
            if self._speed_names:
                speed = percentage_to_ordered_list_item(
                    self._speed_names, percentage)
                speed_value = self.get_map_value(
                    map_=self._speed_name_map, description=speed)
                await self.set_property_async(
                    prop=self._prop_fan_level, value=speed_value)
            else:
                await self.set_property_async(
                    prop=self._prop_fan_level,
                    value=int(percentage_to_ranged_value(
                        low_high_range=(self._speed_min, self._speed_max),
                        percentage=percentage)))
        # preset_mode
        if preset_mode:
            await self.set_property_async(
                self._prop_mode,
                value=self.__get_mode_value(description=preset_mode))

    async def async_turn_off(self, **kwargs: Any) -> None:
        """Turn the fan off."""
        await self.set_property_async(prop=self._prop_on, value=False)

    async def async_toggle(self, **kwargs: Any) -> None:
        """Toggle the fan."""
        await self.set_property_async(prop=self._prop_on, value=not self.is_on)

    async def async_set_percentage(self, percentage: int) -> None:
        """Set the percentage of the fan speed."""
        if percentage > 0:
            if self._speed_names:
                speed = percentage_to_ordered_list_item(
                    self._speed_names, percentage)
                speed_value = self.get_map_value(
                    map_=self._speed_name_map, description=speed)
                await self.set_property_async(
                    prop=self._prop_fan_level, value=speed_value)
            else:
                await self.set_property_async(
                    prop=self._prop_fan_level,
                    value=int(percentage_to_ranged_value(
                        low_high_range=(self._speed_min, self._speed_max),
                        percentage=percentage)))
            if not self.is_on:
                # If the fan is off, turn it on.
                await self.set_property_async(prop=self._prop_on, value=True)
        else:
            await self.set_property_async(prop=self._prop_on, value=False)

    async def async_set_preset_mode(self, preset_mode: str) -> None:
        """Set the preset mode."""
        await self.set_property_async(
            self._prop_mode,
            value=self.__get_mode_value(description=preset_mode))

    async def async_set_direction(self, direction: str) -> None:
        """Set the direction of the fan."""
        if not self._prop_wind_reverse:
            return
        await self.set_property_async(
            prop=self._prop_wind_reverse,
            value=(
                self._prop_wind_reverse_reverse
                if self.current_direction == 'reverse'
                else self._prop_wind_reverse_forward))

    async def async_oscillate(self, oscillating: bool) -> None:
        """Oscillate the fan."""
        await self.set_property_async(
            prop=self._prop_horizontal_swing, value=oscillating)

    @property
    def is_on(self) -> Optional[bool]:
        """Return if the fan is on. """
        return self.get_prop_value(
            prop=self._prop_on) if self._prop_on else None

    @property
    def preset_mode(self) -> Optional[str]:
        """Return the current preset mode,
        e.g., auto, smart, eco, favorite."""
        return (
            self.__get_mode_description(
                key=self.get_prop_value(prop=self._prop_mode))
            if self._prop_mode else None)

    @property
    def current_direction(self) -> Optional[str]:
        """Return the current direction of the fan."""
        if not self._prop_wind_reverse:
            return None
        return 'reverse' if self.get_prop_value(
            prop=self._prop_wind_reverse
        ) == self._prop_wind_reverse_reverse else 'forward'

    @property
    def percentage(self) -> Optional[int]:
        """Return the current percentage of the fan speed."""
        fan_level = self.get_prop_value(prop=self._prop_fan_level)
        if fan_level is None:
            return None
        if self._speed_names:
            return ordered_list_item_to_percentage(
                self._speed_names, self._speed_name_map[fan_level])
        else:
            return ranged_value_to_percentage(
                low_high_range=(self._speed_min, self._speed_max),
                value=fan_level)

    @property
    def oscillating(self) -> Optional[bool]:
        """Return if the fan is oscillating."""
        return (
            self.get_prop_value(
                prop=self._prop_horizontal_swing)
            if self._prop_horizontal_swing else None)
