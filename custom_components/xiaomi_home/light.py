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

Light entities for Xiaomi Home.
"""
from __future__ import annotations
import logging
from typing import Any, Optional

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.components.light import (
    ATTR_BRIGHTNESS,
    ATTR_COLOR_TEMP_KELVIN,
    ATTR_RGB_COLOR,
    ATTR_EFFECT,
    LightEntity,
    LightEntityFeature,
    ColorMode
)
from homeassistant.util.color import (
    value_to_brightness,
    brightness_to_value
)

from .miot.miot_spec import MIoTSpecProperty
from .miot.miot_device import MIoTDevice, MIoTEntityData,  MIoTServiceEntity
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
        for data in miot_device.entity_list.get('light', []):
            new_entities.append(
                Light(miot_device=miot_device, entity_data=data))

    if new_entities:
        async_add_entities(new_entities)


class Light(MIoTServiceEntity, LightEntity):
    """Light entities for Xiaomi Home."""
    # pylint: disable=unused-argument
    _VALUE_RANGE_MODE_COUNT_MAX = 30
    _prop_on: Optional[MIoTSpecProperty]
    _prop_brightness: Optional[MIoTSpecProperty]
    _prop_color_temp: Optional[MIoTSpecProperty]
    _prop_color: Optional[MIoTSpecProperty]
    _prop_mode: Optional[MIoTSpecProperty]

    _brightness_scale: Optional[tuple[int, int]]
    _mode_map: Optional[dict[Any, Any]]

    def __init__(
        self, miot_device: MIoTDevice,  entity_data: MIoTEntityData
    ) -> None:
        """Initialize the Light."""
        super().__init__(miot_device=miot_device,  entity_data=entity_data)
        self._attr_color_mode = None
        self._attr_supported_color_modes = set()
        self._attr_supported_features = LightEntityFeature(0)
        if miot_device.did.startswith('group.'):
            self._attr_icon = 'mdi:lightbulb-group'

        self._prop_on = None
        self._prop_brightness = None
        self._prop_color_temp = None
        self._prop_color = None
        self._prop_mode = None
        self._brightness_scale = None
        self._mode_map = None

        # properties
        for prop in entity_data.props:
            # on
            if prop.name == 'on':
                self._prop_on = prop
            # brightness
            if prop.name == 'brightness':
                if prop.value_range:
                    self._brightness_scale = (
                        prop.value_range.min_, prop.value_range.max_)
                    self._prop_brightness = prop
                elif (
                    self._mode_map is None
                    and prop.value_list
                ):
                    # For value-list brightness
                    self._mode_map = prop.value_list.to_map()
                    self._attr_effect_list = list(self._mode_map.values())
                    self._attr_supported_features |= LightEntityFeature.EFFECT
                    self._prop_mode = prop
                else:
                    _LOGGER.info(
                        'invalid brightness format, %s', self.entity_id)
                    continue
            # color-temperature
            if prop.name == 'color-temperature':
                if not prop.value_range:
                    _LOGGER.info(
                        'invalid color-temperature value_range format, %s',
                        self.entity_id)
                    continue
                self._attr_min_color_temp_kelvin = prop.value_range.min_
                self._attr_max_color_temp_kelvin = prop.value_range.max_
                self._attr_supported_color_modes.add(ColorMode.COLOR_TEMP)
                self._attr_color_mode = ColorMode.COLOR_TEMP
                self._prop_color_temp = prop
            # color
            if prop.name == 'color':
                self._attr_supported_color_modes.add(ColorMode.RGB)
                self._attr_color_mode = ColorMode.RGB
                self._prop_color = prop
            # mode
            if prop.name == 'mode':
                mode_list = None
                if prop.value_list:
                    mode_list = prop.value_list.to_map()
                elif prop.value_range:
                    mode_list = {}
                    if (
                        int((
                            prop.value_range.max_
                            - prop.value_range.min_
                        ) / prop.value_range.step)
                        > self._VALUE_RANGE_MODE_COUNT_MAX
                    ):
                        _LOGGER.error(
                            'too many mode values, %s, %s, %s',
                            self.entity_id, prop.name, prop.value_range)
                    else:
                        for value in range(
                                prop.value_range.min_,
                                prop.value_range.max_,
                                prop.value_range.step):
                            mode_list[value] = f'mode {value}'
                if mode_list:
                    self._mode_map = mode_list
                    self._attr_effect_list = list(self._mode_map.values())
                    self._attr_supported_features |= LightEntityFeature.EFFECT
                    self._prop_mode = prop
                else:
                    _LOGGER.info('invalid mode format, %s', self.entity_id)
                    continue

        if not self._attr_supported_color_modes:
            if self._prop_brightness:
                self._attr_supported_color_modes.add(ColorMode.BRIGHTNESS)
                self._attr_color_mode = ColorMode.BRIGHTNESS
            elif self._prop_on:
                self._attr_supported_color_modes.add(ColorMode.ONOFF)
                self._attr_color_mode = ColorMode.ONOFF

    @property
    def is_on(self) -> Optional[bool]:
        """Return if the light is on."""
        value_on = self.get_prop_value(prop=self._prop_on)
        # Dirty logic for lumi.gateway.mgl03 indicator light
        if isinstance(value_on, int):
            value_on = value_on == 1
        return value_on

    @property
    def brightness(self) -> Optional[int]:
        """Return the brightness."""
        brightness_value = self.get_prop_value(prop=self._prop_brightness)
        if brightness_value is None:
            return None
        return value_to_brightness(self._brightness_scale, brightness_value)

    @property
    def color_temp_kelvin(self) -> Optional[int]:
        """Return the color temperature."""
        return self.get_prop_value(prop=self._prop_color_temp)

    @property
    def rgb_color(self) -> Optional[tuple[int, int, int]]:
        """Return the rgb color value."""
        rgb = self.get_prop_value(prop=self._prop_color)
        if rgb is None:
            return None
        r = (rgb >> 16) & 0xFF
        g = (rgb >> 8) & 0xFF
        b = rgb & 0xFF
        return r, g, b

    @property
    def effect(self) -> Optional[str]:
        """Return the current mode."""
        return self.get_map_value(
            map_=self._mode_map,
            key=self.get_prop_value(prop=self._prop_mode))

    async def async_turn_on(self, **kwargs) -> None:
        """Turn the light on.

        Shall set attributes in kwargs if applicable.
        """
        # on
        # Dirty logic for lumi.gateway.mgl03 indicator light
        if self._prop_on:
            value_on = True if self._prop_on.format_ == bool else 1
            await self.set_property_async(
                prop=self._prop_on, value=value_on)
        # brightness
        if ATTR_BRIGHTNESS in kwargs:
            brightness = brightness_to_value(
                self._brightness_scale, kwargs[ATTR_BRIGHTNESS])
            await self.set_property_async(
                prop=self._prop_brightness, value=brightness,
                write_ha_state=False)
        # color-temperature
        if ATTR_COLOR_TEMP_KELVIN in kwargs:
            await self.set_property_async(
                prop=self._prop_color_temp,
                value=kwargs[ATTR_COLOR_TEMP_KELVIN],
                write_ha_state=False)
            self._attr_color_mode = ColorMode.COLOR_TEMP
        # rgb color
        if ATTR_RGB_COLOR in kwargs:
            r = kwargs[ATTR_RGB_COLOR][0]
            g = kwargs[ATTR_RGB_COLOR][1]
            b = kwargs[ATTR_RGB_COLOR][2]
            rgb = (r << 16) | (g << 8) | b
            await self.set_property_async(
                prop=self._prop_color, value=rgb,
                write_ha_state=False)
            self._attr_color_mode = ColorMode.RGB
        # mode
        if ATTR_EFFECT in kwargs:
            await self.set_property_async(
                prop=self._prop_mode,
                value=self.get_map_key(
                    map_=self._mode_map, value=kwargs[ATTR_EFFECT]),
                write_ha_state=False)
        self.async_write_ha_state()

    async def async_turn_off(self, **kwargs) -> None:
        """Turn the light off."""
        if not self._prop_on:
            return
        # Dirty logic for lumi.gateway.mgl03 indicator light
        value_on = False if self._prop_on.format_ == bool else 0
        await self.set_property_async(prop=self._prop_on, value=value_on)
