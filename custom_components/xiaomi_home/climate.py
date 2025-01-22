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

Climate entities for Xiaomi Home.
"""
from __future__ import annotations
import logging
from typing import Any, Optional

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.components.climate import (
    SWING_ON,
    SWING_OFF,
    SWING_BOTH,
    SWING_VERTICAL,
    SWING_HORIZONTAL,
    ATTR_TEMPERATURE,
    HVACMode,
    ClimateEntity,
    ClimateEntityFeature
)

from .miot.const import DOMAIN
from .miot.miot_device import MIoTDevice, MIoTServiceEntity, MIoTEntityData
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
        for data in miot_device.entity_list.get('air-conditioner', []):
            new_entities.append(
                AirConditioner(miot_device=miot_device, entity_data=data))
        for data in miot_device.entity_list.get('heater', []):
            new_entities.append(
                Heater(miot_device=miot_device, entity_data=data))

    if new_entities:
        async_add_entities(new_entities)


class AirConditioner(MIoTServiceEntity, ClimateEntity):
    """Air conditioner entities for Xiaomi Home."""
    # service: air-conditioner
    _prop_on: Optional[MIoTSpecProperty]
    _prop_mode: Optional[MIoTSpecProperty]
    _prop_target_temp: Optional[MIoTSpecProperty]
    _prop_target_humi: Optional[MIoTSpecProperty]
    # service: fan-control
    _prop_fan_on: Optional[MIoTSpecProperty]
    _prop_fan_level: Optional[MIoTSpecProperty]
    _prop_horizontal_swing: Optional[MIoTSpecProperty]
    _prop_vertical_swing: Optional[MIoTSpecProperty]
    # service: environment
    _prop_env_temp: Optional[MIoTSpecProperty]
    _prop_env_humi: Optional[MIoTSpecProperty]
    # service: air-condition-outlet-matching
    _prop_ac_state: Optional[MIoTSpecProperty]
    _value_ac_state: Optional[dict[str, int]]

    _hvac_mode_map: Optional[dict[int, HVACMode]]
    _fan_mode_map: Optional[dict[int, str]]

    def __init__(
        self, miot_device: MIoTDevice, entity_data: MIoTEntityData
    ) -> None:
        """Initialize the Air conditioner."""
        super().__init__(miot_device=miot_device, entity_data=entity_data)
        self._attr_icon = 'mdi:air-conditioner'
        self._attr_supported_features = ClimateEntityFeature(0)
        self._attr_swing_mode = None
        self._attr_swing_modes = []

        self._prop_on = None
        self._prop_mode = None
        self._prop_target_temp = None
        self._prop_target_humi = None
        self._prop_fan_on = None
        self._prop_fan_level = None
        self._prop_horizontal_swing = None
        self._prop_vertical_swing = None
        self._prop_env_temp = None
        self._prop_env_humi = None
        self._prop_ac_state = None
        self._value_ac_state = None
        self._hvac_mode_map = None
        self._fan_mode_map = None

        # properties
        for prop in entity_data.props:
            if prop.name == 'on':
                if prop.service.name == 'air-conditioner':
                    self._attr_supported_features |= (
                        ClimateEntityFeature.TURN_ON)
                    self._attr_supported_features |= (
                        ClimateEntityFeature.TURN_OFF)
                    self._prop_on = prop
                elif prop.service.name == 'fan-control':
                    self._attr_swing_modes.append(SWING_ON)
                    self._prop_fan_on = prop
                else:
                    _LOGGER.error(
                        'unknown on property, %s', self.entity_id)
            elif prop.name == 'mode':
                if not prop.value_list:
                    _LOGGER.error(
                        'invalid mode value_list, %s', self.entity_id)
                    continue
                self._hvac_mode_map = {}
                for item in prop.value_list.items:
                    if item.name in {'off', 'idle'}:
                        self._hvac_mode_map[item.value] = HVACMode.OFF
                    elif item.name in {'auto'}:
                        self._hvac_mode_map[item.value] = HVACMode.AUTO
                    elif item.name in {'cool'}:
                        self._hvac_mode_map[item.value] = HVACMode.COOL
                    elif item.name in {'heat'}:
                        self._hvac_mode_map[item.value] = HVACMode.HEAT
                    elif item.name in {'dry'}:
                        self._hvac_mode_map[item.value] = HVACMode.DRY
                    elif item.name in {'fan'}:
                        self._hvac_mode_map[item.value] = HVACMode.FAN_ONLY
                self._attr_hvac_modes = list(self._hvac_mode_map.values())
                self._prop_mode = prop
            elif prop.name == 'target-temperature':
                if not prop.value_range:
                    _LOGGER.error(
                        'invalid target-temperature value_range format, %s',
                        self.entity_id)
                    continue
                self._attr_min_temp = prop.value_range.min_
                self._attr_max_temp = prop.value_range.max_
                self._attr_target_temperature_step = prop.value_range.step
                self._attr_temperature_unit = prop.external_unit
                self._attr_supported_features |= (
                    ClimateEntityFeature.TARGET_TEMPERATURE)
                self._prop_target_temp = prop
            elif prop.name == 'target-humidity':
                if not prop.value_range:
                    _LOGGER.error(
                        'invalid target-humidity value_range format, %s',
                        self.entity_id)
                    continue
                self._attr_min_humidity = prop.value_range.min_
                self._attr_max_humidity = prop.value_range.max_
                self._attr_supported_features |= (
                    ClimateEntityFeature.TARGET_HUMIDITY)
                self._prop_target_humi = prop
            elif prop.name == 'fan-level':
                if not prop.value_list:
                    _LOGGER.error(
                        'invalid fan-level value_list, %s', self.entity_id)
                    continue
                self._fan_mode_map = prop.value_list.to_map()
                self._attr_fan_modes = list(self._fan_mode_map.values())
                self._attr_supported_features |= ClimateEntityFeature.FAN_MODE
                self._prop_fan_level = prop
            elif prop.name == 'horizontal-swing':
                self._attr_swing_modes.append(SWING_HORIZONTAL)
                self._prop_horizontal_swing = prop
            elif prop.name == 'vertical-swing':
                self._attr_swing_modes.append(SWING_VERTICAL)
                self._prop_vertical_swing = prop
            elif prop.name == 'temperature':
                self._prop_env_temp = prop
            elif prop.name == 'relative-humidity':
                self._prop_env_humi = prop

            elif prop.name == 'ac-state':
                self._prop_ac_state = prop
                self._value_ac_state = {}
                self.sub_prop_changed(
                    prop=prop, handler=self.__ac_state_changed)

        # hvac modes
        if HVACMode.OFF not in self._attr_hvac_modes:
            self._attr_hvac_modes.append(HVACMode.OFF)
        # swing modes
        if (
            SWING_HORIZONTAL in self._attr_swing_modes
            and SWING_VERTICAL in self._attr_swing_modes
        ):
            self._attr_swing_modes.append(SWING_BOTH)
        if self._attr_swing_modes:
            self._attr_swing_modes.insert(0, SWING_OFF)
            self._attr_supported_features |= ClimateEntityFeature.SWING_MODE

    async def async_turn_on(self) -> None:
        """Turn the entity on."""
        await self.set_property_async(prop=self._prop_on, value=True)

    async def async_turn_off(self) -> None:
        """Turn the entity off."""
        await self.set_property_async(prop=self._prop_on, value=False)

    async def async_set_hvac_mode(self, hvac_mode: HVACMode) -> None:
        """Set new target hvac mode."""
        # set air-conditioner off
        if hvac_mode == HVACMode.OFF:
            if not await self.set_property_async(
                    prop=self._prop_on, value=False):
                raise RuntimeError(
                    f'set climate prop.on failed, {hvac_mode}, '
                    f'{self.entity_id}')
            return
        # set air-conditioner on
        if self.get_prop_value(prop=self._prop_on) is False:
            await self.set_property_async(
                prop=self._prop_on, value=True, write_ha_state=False)
        # set mode
        mode_value = self.get_map_key(
            map_=self._hvac_mode_map, value=hvac_mode)
        if (
            not mode_value or
            not await self.set_property_async(
                prop=self._prop_mode, value=mode_value)
        ):
            raise RuntimeError(
                f'set climate prop.mode failed, {hvac_mode}, {self.entity_id}')

    async def async_set_temperature(self, **kwargs):
        """Set new target temperature."""
        if ATTR_TEMPERATURE in kwargs:
            temp = kwargs[ATTR_TEMPERATURE]
            if temp > self.max_temp:
                temp = self.max_temp
            elif temp < self.min_temp:
                temp = self.min_temp

            await self.set_property_async(
                prop=self._prop_target_temp, value=temp)

    async def async_set_humidity(self, humidity):
        """Set new target humidity."""
        if humidity > self.max_humidity:
            humidity = self.max_humidity
        elif humidity < self.min_humidity:
            humidity = self.min_humidity
        await self.set_property_async(
            prop=self._prop_target_humi, value=humidity)

    async def async_set_swing_mode(self, swing_mode):
        """Set new target swing operation."""
        if swing_mode == SWING_BOTH:
            await self.set_property_async(
                prop=self._prop_horizontal_swing, value=True,
                write_ha_state=False)
            await self.set_property_async(
                prop=self._prop_vertical_swing, value=True)
        elif swing_mode == SWING_HORIZONTAL:
            await self.set_property_async(
                prop=self._prop_horizontal_swing, value=True)
        elif swing_mode == SWING_VERTICAL:
            await self.set_property_async(
                prop=self._prop_vertical_swing, value=True)
        elif swing_mode == SWING_ON:
            await self.set_property_async(
                prop=self._prop_fan_on, value=True)
        elif swing_mode == SWING_OFF:
            if self._prop_fan_on:
                await self.set_property_async(
                    prop=self._prop_fan_on, value=False,
                    write_ha_state=False)
            if self._prop_horizontal_swing:
                await self.set_property_async(
                    prop=self._prop_horizontal_swing, value=False,
                    write_ha_state=False)
            if self._prop_vertical_swing:
                await self.set_property_async(
                    prop=self._prop_vertical_swing, value=False,
                    write_ha_state=False)
            self.async_write_ha_state()
        else:
            raise RuntimeError(
                f'unknown swing_mode, {swing_mode}, {self.entity_id}')

    async def async_set_fan_mode(self, fan_mode):
        """Set new target fan mode."""
        mode_value = self.get_map_key(
            map_=self._fan_mode_map, value=fan_mode)
        if mode_value is None or not await self.set_property_async(
                prop=self._prop_fan_level, value=mode_value):
            raise RuntimeError(
                f'set climate prop.fan_mode failed, {fan_mode}, '
                f'{self.entity_id}')

    @property
    def target_temperature(self) -> Optional[float]:
        """Return the target temperature."""
        return self.get_prop_value(
            prop=self._prop_target_temp) if self._prop_target_temp else None

    @property
    def target_humidity(self) -> Optional[int]:
        """Return the target humidity."""
        return self.get_prop_value(
            prop=self._prop_target_humi) if self._prop_target_humi else None

    @property
    def current_temperature(self) -> Optional[float]:
        """Return the current temperature."""
        return self.get_prop_value(
            prop=self._prop_env_temp) if self._prop_env_temp else None

    @property
    def current_humidity(self) -> Optional[int]:
        """Return the current humidity."""
        return self.get_prop_value(
            prop=self._prop_env_humi) if self._prop_env_humi else None

    @property
    def hvac_mode(self) -> Optional[HVACMode]:
        """Return the hvac mode. e.g., heat, cool mode."""
        if self.get_prop_value(prop=self._prop_on) is False:
            return HVACMode.OFF
        return self.get_map_value(
            map_=self._hvac_mode_map,
            key=self.get_prop_value(prop=self._prop_mode))

    @property
    def fan_mode(self) -> Optional[str]:
        """Return the fan mode.

        Requires ClimateEntityFeature.FAN_MODE.
        """
        return self.get_map_value(
            map_=self._fan_mode_map,
            key=self.get_prop_value(prop=self._prop_fan_level))

    @property
    def swing_mode(self) -> Optional[str]:
        """Return the swing mode.

        Requires ClimateEntityFeature.SWING_MODE.
        """
        horizontal = (
            self.get_prop_value(prop=self._prop_horizontal_swing))
        vertical = (
            self.get_prop_value(prop=self._prop_vertical_swing))
        if horizontal and vertical:
            return SWING_BOTH
        if horizontal:
            return SWING_HORIZONTAL
        if vertical:
            return SWING_VERTICAL
        if self._prop_fan_on:
            if self.get_prop_value(prop=self._prop_fan_on):
                return SWING_ON
            else:
                return SWING_OFF
        return None

    def __ac_state_changed(self, prop: MIoTSpecProperty, value: Any) -> None:
        del prop
        if not isinstance(value, str):
            _LOGGER.error(
                'ac_status value format error, %s', value)
            return
        v_ac_state = {}
        v_split = value.split('_')
        for item in v_split:
            if len(item) < 2:
                _LOGGER.error('ac_status value error, %s', item)
                continue
            try:
                v_ac_state[item[0]] = int(item[1:])
            except ValueError:
                _LOGGER.error('ac_status value error, %s', item)
        # P: status. 0: on, 1: off
        if 'P' in v_ac_state and self._prop_on:
            self.set_prop_value(prop=self._prop_on,
                                value=v_ac_state['P'] == 0)
        # M: model. 0: cool, 1: heat, 2: auto, 3: fan, 4: dry
        if 'M' in v_ac_state and self._prop_mode:
            mode: Optional[HVACMode] = {
                0: HVACMode.COOL,
                1: HVACMode.HEAT,
                2: HVACMode.AUTO,
                3: HVACMode.FAN_ONLY,
                4: HVACMode.DRY
            }.get(v_ac_state['M'], None)
            if mode:
                self.set_prop_value(
                    prop=self._prop_mode, value=self.get_map_key(
                        map_=self._hvac_mode_map, value=mode))
        # T: target temperature
        if 'T' in v_ac_state and self._prop_target_temp:
            self.set_prop_value(prop=self._prop_target_temp,
                                value=v_ac_state['T'])
        # S: fan level. 0: auto, 1: low, 2: media, 3: high
        if 'S' in v_ac_state and self._prop_fan_level:
            self.set_prop_value(prop=self._prop_fan_level,
                                value=v_ac_state['S'])
        # D: swing mode. 0: on, 1: off
        if (
            'D' in v_ac_state
            and self._attr_swing_modes
            and len(self._attr_swing_modes) == 2
        ):
            if (
                SWING_HORIZONTAL in self._attr_swing_modes
                and self._prop_horizontal_swing
            ):
                self.set_prop_value(
                    prop=self._prop_horizontal_swing,
                    value=v_ac_state['D'] == 0)
            elif (
                SWING_VERTICAL in self._attr_swing_modes
                and self._prop_vertical_swing
            ):
                self.set_prop_value(
                    prop=self._prop_vertical_swing,
                    value=v_ac_state['D'] == 0)
        if self._value_ac_state:
            self._value_ac_state.update(v_ac_state)
            _LOGGER.debug(
                'ac_state update, %s', self._value_ac_state)


class Heater(MIoTServiceEntity, ClimateEntity):
    """Heater entities for Xiaomi Home."""
    # service: heater
    _prop_on: Optional[MIoTSpecProperty]
    _prop_mode: Optional[MIoTSpecProperty]
    _prop_target_temp: Optional[MIoTSpecProperty]
    _prop_heat_level: Optional[MIoTSpecProperty]
    # service: environment
    _prop_env_temp: Optional[MIoTSpecProperty]
    _prop_env_humi: Optional[MIoTSpecProperty]

    _heat_level_map: Optional[dict[int, str]]

    def __init__(
        self, miot_device: MIoTDevice, entity_data: MIoTEntityData
    ) -> None:
        """Initialize the Heater."""
        super().__init__(miot_device=miot_device, entity_data=entity_data)
        self._attr_icon = 'mdi:air-conditioner'
        self._attr_supported_features = ClimateEntityFeature(0)
        self._attr_preset_modes = []

        self._prop_on = None
        self._prop_mode = None
        self._prop_target_temp = None
        self._prop_heat_level = None
        self._prop_env_temp = None
        self._prop_env_humi = None
        self._heat_level_map = None

        # properties
        for prop in entity_data.props:
            if prop.name == 'on':
                self._attr_supported_features |= (
                    ClimateEntityFeature.TURN_ON)
                self._attr_supported_features |= (
                    ClimateEntityFeature.TURN_OFF)
                self._prop_on = prop
            elif prop.name == 'target-temperature':
                if not prop.value_range:
                    _LOGGER.error(
                        'invalid target-temperature value_range format, %s',
                        self.entity_id)
                    continue
                self._attr_min_temp = prop.value_range.min_
                self._attr_max_temp = prop.value_range.max_
                self._attr_target_temperature_step = prop.value_range.step
                self._attr_temperature_unit = prop.external_unit
                self._attr_supported_features |= (
                    ClimateEntityFeature.TARGET_TEMPERATURE)
                self._prop_target_temp = prop
            elif prop.name == 'heat-level':
                if not prop.value_list:
                    _LOGGER.error(
                        'invalid heat-level value_list, %s', self.entity_id)
                    continue
                self._heat_level_map = prop.value_list.to_map()
                self._attr_preset_modes = list(self._heat_level_map.values())
                self._attr_supported_features |= (
                    ClimateEntityFeature.PRESET_MODE)
                self._prop_heat_level = prop
            elif prop.name == 'temperature':
                self._prop_env_temp = prop
            elif prop.name == 'relative-humidity':
                self._prop_env_humi = prop

        # hvac modes
        self._attr_hvac_modes = [HVACMode.HEAT, HVACMode.OFF]

    async def async_turn_on(self) -> None:
        """Turn the entity on."""
        await self.set_property_async(prop=self._prop_on, value=True)

    async def async_turn_off(self) -> None:
        """Turn the entity off."""
        await self.set_property_async(prop=self._prop_on, value=False)

    async def async_set_hvac_mode(self, hvac_mode: HVACMode) -> None:
        """Set new target hvac mode."""
        await self.set_property_async(
            prop=self._prop_on, value=False
            if hvac_mode == HVACMode.OFF else True)

    async def async_set_temperature(self, **kwargs):
        """Set new target temperature."""
        if ATTR_TEMPERATURE in kwargs:
            temp = kwargs[ATTR_TEMPERATURE]
            if temp > self.max_temp:
                temp = self.max_temp
            elif temp < self.min_temp:
                temp = self.min_temp

            await self.set_property_async(
                prop=self._prop_target_temp, value=temp)

    async def async_set_preset_mode(self, preset_mode: str) -> None:
        """Set the preset mode."""
        await self.set_property_async(
            self._prop_heat_level,
            value=self.get_map_key(
                map_=self._heat_level_map, value=preset_mode))

    @property
    def target_temperature(self) -> Optional[float]:
        """Return the target temperature."""
        return self.get_prop_value(
            prop=self._prop_target_temp) if self._prop_target_temp else None

    @property
    def current_temperature(self) -> Optional[float]:
        """Return the current temperature."""
        return self.get_prop_value(
            prop=self._prop_env_temp) if self._prop_env_temp else None

    @property
    def current_humidity(self) -> Optional[int]:
        """Return the current humidity."""
        return self.get_prop_value(
            prop=self._prop_env_humi) if self._prop_env_humi else None

    @property
    def hvac_mode(self) -> Optional[HVACMode]:
        """Return the hvac mode."""
        return (
            HVACMode.HEAT if self.get_prop_value(prop=self._prop_on)
            else HVACMode.OFF)

    @property
    def preset_mode(self) -> Optional[str]:
        return (
            self.get_map_value(
                map_=self._heat_level_map,
                key=self.get_prop_value(prop=self._prop_heat_level))
            if self._prop_heat_level else None)
