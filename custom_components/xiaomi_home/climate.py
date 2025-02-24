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
    FAN_ON, FAN_OFF, SWING_OFF, SWING_BOTH, SWING_VERTICAL, SWING_HORIZONTAL,
    ATTR_TEMPERATURE, HVACMode, ClimateEntity, ClimateEntityFeature)

from .miot.const import DOMAIN
from .miot.miot_device import MIoTDevice, MIoTServiceEntity, MIoTEntityData
from .miot.miot_spec import MIoTSpecProperty

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(hass: HomeAssistant, config_entry: ConfigEntry,
                            async_add_entities: AddEntitiesCallback) -> None:
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
        for data in miot_device.entity_list.get('bath-heater', []):
            new_entities.append(
                PtcBathHeater(miot_device=miot_device, entity_data=data))
        for data in miot_device.entity_list.get('thermostat', []):
            new_entities.append(
                Thermostat(miot_device=miot_device, entity_data=data))
        for data in miot_device.entity_list.get('electric-blanket', []):
            new_entities.append(
                ElectricBlanket(miot_device=miot_device, entity_data=data))

    if new_entities:
        async_add_entities(new_entities)


class FeatureOnOff(MIoTServiceEntity, ClimateEntity):
    """TURN_ON and TURN_OFF feature of the climate entity."""
    _prop_on: Optional[MIoTSpecProperty]

    def __init__(self, miot_device: MIoTDevice,
                 entity_data: MIoTEntityData) -> None:
        """Initialize the feature class."""
        self._prop_on = None

        super().__init__(miot_device=miot_device, entity_data=entity_data)
        # properties
        for prop in entity_data.props:
            if prop.name == 'on':
                if (
                        # The "on" property of the "fan-control" service is not
                        # the on/off feature of the entity.
                        prop.service.name == 'air-conditioner' or
                        prop.service.name == 'heater' or
                        prop.service.name == 'thermostat' or
                        prop.service.name == 'electric-blanket'):
                    self._attr_supported_features |= (
                        ClimateEntityFeature.TURN_ON)
                    self._attr_supported_features |= (
                        ClimateEntityFeature.TURN_OFF)
                    self._prop_on = prop

    async def async_turn_on(self) -> None:
        """Turn on."""
        await self.set_property_async(prop=self._prop_on, value=True)

    async def async_turn_off(self) -> None:
        """Turn off."""
        await self.set_property_async(prop=self._prop_on, value=False)


class FeatureTargetTemperature(MIoTServiceEntity, ClimateEntity):
    """TARGET_TEMPERATURE feature of the climate entity."""
    _prop_target_temp: Optional[MIoTSpecProperty]

    def __init__(self, miot_device: MIoTDevice,
                 entity_data: MIoTEntityData) -> None:
        """Initialize the feature class."""
        self._prop_target_temp = None

        super().__init__(miot_device=miot_device, entity_data=entity_data)
        # properties
        for prop in entity_data.props:
            if prop.name == 'target-temperature':
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

    async def async_set_temperature(self, **kwargs):
        """Set the target temperature."""
        if ATTR_TEMPERATURE in kwargs:
            temp = kwargs[ATTR_TEMPERATURE]
            if temp > self._attr_max_temp:
                temp = self._attr_max_temp
            elif temp < self._attr_min_temp:
                temp = self._attr_min_temp

            await self.set_property_async(prop=self._prop_target_temp,
                                          value=temp)

    @property
    def target_temperature(self) -> Optional[float]:
        """The current target temperature."""
        return (self.get_prop_value(
            prop=self._prop_target_temp) if self._prop_target_temp else None)


class FeaturePresetMode(MIoTServiceEntity, ClimateEntity):
    """PRESET_MODE feature of the climate entity."""
    _prop_mode: Optional[MIoTSpecProperty]
    _mode_map: Optional[dict[int, str]]

    def __init__(self, miot_device: MIoTDevice,
                 entity_data: MIoTEntityData) -> None:
        """Initialize the feature class."""
        self._prop_mode = None
        self._mode_map = None

        super().__init__(miot_device=miot_device, entity_data=entity_data)

    def _init_preset_modes(self, service_name: str, prop_name: str) -> None:
        """Initialize the preset modes."""
        for prop in self.entity_data.props:
            if prop.name == prop_name and prop.service.name == service_name:
                if not prop.value_list:
                    _LOGGER.error('invalid %s %s value_list, %s',service_name,
                                  prop_name, self.entity_id)
                    continue
                self._mode_map = prop.value_list.to_map()
                self._attr_preset_modes = prop.value_list.descriptions
                self._attr_supported_features |= (
                    ClimateEntityFeature.PRESET_MODE)
                self._prop_mode = prop

    async def async_set_preset_mode(self, preset_mode: str) -> None:
        """Set the preset mode."""
        await self.set_property_async(self._prop_mode,
                                      value=self.get_map_key(
                                          map_=self._mode_map,
                                          value=preset_mode))

    @property
    def preset_mode(self) -> Optional[str]:
        """The current preset mode."""
        return (self.get_map_value(
            map_=self._mode_map, key=self.get_prop_value(
                prop=self._prop_mode)) if self._prop_mode else None)


class FeatureFanMode(MIoTServiceEntity, ClimateEntity):
    """FAN_MODE feature of the climate entity."""
    _prop_fan_on: Optional[MIoTSpecProperty]
    _prop_fan_level: Optional[MIoTSpecProperty]
    _fan_mode_map: Optional[dict[int, str]]

    def __init__(self, miot_device: MIoTDevice,
                 entity_data: MIoTEntityData) -> None:
        """Initialize the feature class."""
        self._prop_fan_on = None
        self._prop_fan_level = None
        self._fan_mode_map = None

        super().__init__(miot_device=miot_device, entity_data=entity_data)
        # properties
        for prop in entity_data.props:
            if prop.name == 'fan-level' and prop.service.name == 'fan-control':
                if not prop.value_list:
                    _LOGGER.error('invalid fan-level value_list, %s',
                                  self.entity_id)
                    continue
                self._fan_mode_map = prop.value_list.to_map()
                self._attr_fan_modes = prop.value_list.descriptions
                self._attr_supported_features |= ClimateEntityFeature.FAN_MODE
                self._prop_fan_level = prop
            elif prop.name == 'on' and prop.service.name == 'fan-control':
                self._prop_fan_on = prop
                self._attr_supported_features |= ClimateEntityFeature.FAN_MODE

        if self._prop_fan_on:
            if self._attr_fan_modes is None:
                self._attr_fan_modes = [FAN_ON, FAN_OFF]
            else:
                self._attr_fan_modes.append(FAN_OFF)

    async def async_set_fan_mode(self, fan_mode):
        """Set the target fan mode."""
        if fan_mode == FAN_OFF:
            await self.set_property_async(prop=self._prop_fan_on, value=False)
            return
        if fan_mode == FAN_ON:
            await self.set_property_async(prop=self._prop_fan_on, value=True)
            return
        mode_value = self.get_map_key(map_=self._fan_mode_map, value=fan_mode)
        if mode_value is None or not await self.set_property_async(
                prop=self._prop_fan_level, value=mode_value):
            raise RuntimeError(f'set climate prop.fan_mode failed, {fan_mode}, '
                               f'{self.entity_id}')

    @property
    def fan_mode(self) -> Optional[str]:
        """The current fan mode."""
        if self._prop_fan_level is None and self._prop_fan_on is None:
            return None
        if self._prop_fan_level is None and self._prop_fan_on:
            return (FAN_ON if self.get_prop_value(
                prop=self._prop_fan_on) else FAN_OFF)
        return self.get_map_value(
            map_=self._fan_mode_map,
            key=self.get_prop_value(prop=self._prop_fan_level))


class FeatureSwingMode(MIoTServiceEntity, ClimateEntity):
    """SWING_MODE feature of the climate entity."""
    _prop_horizontal_swing: Optional[MIoTSpecProperty]
    _prop_vertical_swing: Optional[MIoTSpecProperty]

    def __init__(self, miot_device: MIoTDevice,
                 entity_data: MIoTEntityData) -> None:
        """Initialize the feature class."""
        self._prop_horizontal_swing = None
        self._prop_vertical_swing = None

        super().__init__(miot_device=miot_device, entity_data=entity_data)
        # properties
        swing_modes = []
        for prop in entity_data.props:
            if prop.name == 'horizontal-swing':
                swing_modes.append(SWING_HORIZONTAL)
                self._prop_horizontal_swing = prop
            elif prop.name == 'vertical-swing':
                swing_modes.append(SWING_VERTICAL)
                self._prop_vertical_swing = prop
        # swing modes
        if SWING_HORIZONTAL in swing_modes and SWING_VERTICAL in swing_modes:
            swing_modes.append(SWING_BOTH)
        if swing_modes:
            swing_modes.insert(0, SWING_OFF)
            self._attr_supported_features |= ClimateEntityFeature.SWING_MODE
            self._attr_swing_modes = swing_modes

    async def async_set_swing_mode(self, swing_mode):
        """Set the target swing operation."""
        if swing_mode == SWING_BOTH:
            await self.set_property_async(prop=self._prop_horizontal_swing,
                                          value=True)
            await self.set_property_async(prop=self._prop_vertical_swing,
                                          value=True)
        elif swing_mode == SWING_HORIZONTAL:
            await self.set_property_async(prop=self._prop_horizontal_swing,
                                          value=True)
        elif swing_mode == SWING_VERTICAL:
            await self.set_property_async(prop=self._prop_vertical_swing,
                                          value=True)
        elif swing_mode == SWING_OFF:
            if self._prop_horizontal_swing:
                await self.set_property_async(prop=self._prop_horizontal_swing,
                                              value=False)
            if self._prop_vertical_swing:
                await self.set_property_async(prop=self._prop_vertical_swing,
                                              value=False)
        else:
            raise RuntimeError(
                f'unknown swing_mode, {swing_mode}, {self.entity_id}')

    @property
    def swing_mode(self) -> Optional[str]:
        """The current swing mode of the fan."""
        if (self._prop_horizontal_swing is None and
                self._prop_vertical_swing is None):
            return None
        horizontal: bool = (self.get_prop_value(
            prop=self._prop_horizontal_swing)
                            if self._prop_horizontal_swing else False)
        vertical: bool = (self.get_prop_value(prop=self._prop_vertical_swing)
                          if self._prop_vertical_swing else False)
        if horizontal and vertical:
            return SWING_BOTH
        elif horizontal:
            return SWING_HORIZONTAL
        elif vertical:
            return SWING_VERTICAL
        else:
            return SWING_OFF


class FeatureTemperature(MIoTServiceEntity, ClimateEntity):
    """Temperature of the climate entity."""
    _prop_env_temperature: Optional[MIoTSpecProperty]

    def __init__(self, miot_device: MIoTDevice,
                 entity_data: MIoTEntityData) -> None:
        """Initialize the feature class."""
        self._prop_env_temperature = None

        super().__init__(miot_device=miot_device, entity_data=entity_data)
        # properties
        for prop in entity_data.props:
            if prop.name == 'temperature':
                self._prop_env_temperature = prop

    @property
    def current_temperature(self) -> Optional[float]:
        """The current environment temperature."""
        return (self.get_prop_value(prop=self._prop_env_temperature)
                if self._prop_env_temperature else None)


class FeatureHumidity(MIoTServiceEntity, ClimateEntity):
    """Humidity of the climate entity."""
    _prop_env_humidity: Optional[MIoTSpecProperty]

    def __init__(self, miot_device: MIoTDevice,
                 entity_data: MIoTEntityData) -> None:
        """Initialize the feature class."""
        self._prop_env_humidity = None

        super().__init__(miot_device=miot_device, entity_data=entity_data)
        # properties
        for prop in entity_data.props:
            if prop.name == 'relative-humidity':
                self._prop_env_humidity = prop

    @property
    def current_humidity(self) -> Optional[float]:
        """The current environment humidity."""
        return (self.get_prop_value(
            prop=self._prop_env_humidity) if self._prop_env_humidity else None)


class FeatureTargetHumidity(MIoTServiceEntity, ClimateEntity):
    """TARGET_HUMIDITY feature of the climate entity."""
    _prop_target_humidity: Optional[MIoTSpecProperty]

    def __init__(self, miot_device: MIoTDevice,
                 entity_data: MIoTEntityData) -> None:
        """Initialize the feature class."""
        self._prop_target_humidity = None

        super().__init__(miot_device=miot_device, entity_data=entity_data)
        # properties
        for prop in entity_data.props:
            if prop.name == 'target-humidity':
                if not prop.value_range:
                    _LOGGER.error(
                        'invalid target-humidity value_range format, %s',
                        self.entity_id)
                    continue
                self._attr_min_humidity = prop.value_range.min_
                self._attr_max_humidity = prop.value_range.max_
                self._attr_supported_features |= (
                    ClimateEntityFeature.TARGET_HUMIDITY)
                self._prop_target_humidity = prop

    async def async_set_humidity(self, humidity):
        """Set the target humidity."""
        if humidity > self._attr_max_humidity:
            humidity = self._attr_max_humidity
        elif humidity < self._attr_min_humidity:
            humidity = self._attr_min_humidity
        await self.set_property_async(prop=self._prop_target_humidity,
                                      value=humidity)

    @property
    def target_humidity(self) -> Optional[int]:
        """The current target humidity."""
        return (self.get_prop_value(prop=self._prop_target_humidity)
                if self._prop_target_humidity else None)


class Heater(FeatureOnOff, FeatureTargetTemperature, FeatureTemperature,
             FeatureHumidity, FeaturePresetMode):
    """Heater"""

    def __init__(self, miot_device: MIoTDevice,
                 entity_data: MIoTEntityData) -> None:
        """Initialize the heater."""
        super().__init__(miot_device=miot_device, entity_data=entity_data)

        self._attr_icon = 'mdi:radiator'
        # hvac modes
        self._attr_hvac_modes = [HVACMode.HEAT, HVACMode.OFF]
        # preset modes
        self._init_preset_modes('heater', 'heat-level')

    async def async_set_hvac_mode(self, hvac_mode: HVACMode) -> None:
        """Set the target hvac mode."""
        await self.set_property_async(
            prop=self._prop_on,
            value=False if hvac_mode == HVACMode.OFF else True)

    @property
    def hvac_mode(self) -> Optional[HVACMode]:
        """The current hvac mode."""
        return (HVACMode.HEAT if self.get_prop_value(
            prop=self._prop_on) else HVACMode.OFF)


class AirConditioner(FeatureOnOff, FeatureTargetTemperature,
                     FeatureTargetHumidity, FeatureTemperature, FeatureHumidity,
                     FeatureFanMode, FeatureSwingMode):
    """Air conditioner"""
    _prop_mode: Optional[MIoTSpecProperty]
    _hvac_mode_map: Optional[dict[int, HVACMode]]
    _prop_ac_state: Optional[MIoTSpecProperty]
    _value_ac_state: Optional[dict[str, int]]

    def __init__(self, miot_device: MIoTDevice,
                 entity_data: MIoTEntityData) -> None:
        """Initialize the air conditioner."""
        self._prop_mode = None
        self._hvac_mode_map = None
        self._prop_ac_state = None
        self._value_ac_state = None

        super().__init__(miot_device=miot_device, entity_data=entity_data)
        self._attr_icon = 'mdi:air-conditioner'
        # hvac modes
        self._attr_hvac_modes = None
        for prop in entity_data.props:
            if prop.name == 'mode':
                if not prop.value_list:
                    _LOGGER.error('invalid mode value_list, %s', self.entity_id)
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
            elif prop.name == 'ac-state':
                self._prop_ac_state = prop
                self._value_ac_state = {}
                self.sub_prop_changed(prop=prop,
                                      handler=self.__ac_state_changed)

        if self._attr_hvac_modes is None:
            self._attr_hvac_modes = [HVACMode.OFF]
        elif HVACMode.OFF not in self._attr_hvac_modes:
            self._attr_hvac_modes.append(HVACMode.OFF)

    async def async_set_hvac_mode(self, hvac_mode: HVACMode) -> None:
        """Set the target hvac mode."""
        # set the device off
        if hvac_mode == HVACMode.OFF:
            if not await self.set_property_async(prop=self._prop_on,
                                                 value=False):
                raise RuntimeError(f'set climate prop.on failed, {hvac_mode}, '
                                   f'{self.entity_id}')
            return
        # set the device on
        if self.get_prop_value(prop=self._prop_on) is False:
            await self.set_property_async(prop=self._prop_on,
                                          value=True,
                                          write_ha_state=False)
        # set mode
        if self._prop_mode is None:
            return
        mode_value = self.get_map_key(map_=self._hvac_mode_map, value=hvac_mode)
        if mode_value is None or not await self.set_property_async(
                prop=self._prop_mode, value=mode_value):
            raise RuntimeError(
                f'set climate prop.mode failed, {hvac_mode}, {self.entity_id}')

    @property
    def hvac_mode(self) -> Optional[HVACMode]:
        """The current hvac mode."""
        if self.get_prop_value(prop=self._prop_on) is False:
            return HVACMode.OFF
        return (self.get_map_value(map_=self._hvac_mode_map,
                                   key=self.get_prop_value(
                                       prop=self._prop_mode))
                if self._prop_mode else None)

    def __ac_state_changed(self, prop: MIoTSpecProperty, value: Any) -> None:
        del prop
        if not isinstance(value, str):
            _LOGGER.error('ac_status value format error, %s', value)
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
            self.set_prop_value(prop=self._prop_on, value=v_ac_state['P'] == 0)
        # M: model. 0: cool, 1: heat, 2: auto, 3: fan, 4: dry
        if 'M' in v_ac_state and self._prop_mode:
            mode: Optional[HVACMode] = {
                0: HVACMode.COOL,
                1: HVACMode.HEAT,
                2: HVACMode.AUTO,
                3: HVACMode.FAN_ONLY,
                4: HVACMode.DRY,
            }.get(v_ac_state['M'], None)
            if mode:
                self.set_prop_value(prop=self._prop_mode,
                                    value=self.get_map_key(
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
        if ('D' in v_ac_state and self._attr_swing_modes and
                len(self._attr_swing_modes) == 2):
            if (SWING_HORIZONTAL in self._attr_swing_modes and
                    self._prop_horizontal_swing):
                self.set_prop_value(prop=self._prop_horizontal_swing,
                                    value=v_ac_state['D'] == 0)
            elif (SWING_VERTICAL in self._attr_swing_modes and
                  self._prop_vertical_swing):
                self.set_prop_value(prop=self._prop_vertical_swing,
                                    value=v_ac_state['D'] == 0)

        self._value_ac_state.update(v_ac_state)
        _LOGGER.debug('ac_state update, %s', self._value_ac_state)


class PtcBathHeater(FeatureTargetTemperature, FeatureTemperature,
                    FeatureFanMode, FeatureSwingMode):
    """Ptc bath heater"""
    _prop_mode: Optional[MIoTSpecProperty]
    _hvac_mode_map: Optional[dict[int, HVACMode]]

    def __init__(self, miot_device: MIoTDevice,
                 entity_data: MIoTEntityData) -> None:
        """Initialize the ptc bath heater."""
        self._prop_mode = None
        self._hvac_mode_map = None

        super().__init__(miot_device=miot_device, entity_data=entity_data)
        self._attr_icon = 'mdi:hvac'
        # hvac modes
        for prop in entity_data.props:
            if prop.name == 'mode':
                if not prop.value_list:
                    _LOGGER.error('invalid mode value_list, %s', self.entity_id)
                    continue
                self._hvac_mode_map = {}
                for item in prop.value_list.items:
                    if item.name in {'off', 'idle'
                                    } and (HVACMode.OFF not in list(
                                        self._hvac_mode_map.values())):
                        self._hvac_mode_map[item.value] = HVACMode.OFF
                    elif item.name in {'auto'}:
                        self._hvac_mode_map[item.value] = HVACMode.AUTO
                    elif item.name in {'ventilate'}:
                        self._hvac_mode_map[item.value] = HVACMode.COOL
                    elif item.name in {'heat', 'quick_heat'
                                      } and (HVACMode.HEAT not in list(
                                          self._hvac_mode_map.values())):
                        self._hvac_mode_map[item.value] = HVACMode.HEAT
                    elif item.name in {'defog'}:
                        self._hvac_mode_map[item.value] = HVACMode.HEAT_COOL
                    elif item.name in {'dry'}:
                        self._hvac_mode_map[item.value] = HVACMode.DRY
                    elif item.name in {'fan'}:
                        self._hvac_mode_map[item.value] = HVACMode.FAN_ONLY
                self._attr_hvac_modes = list(self._hvac_mode_map.values())
                self._prop_mode = prop

    async def async_set_hvac_mode(self, hvac_mode: HVACMode) -> None:
        """Set the target hvac mode."""
        if self._prop_mode is None:
            return
        mode_value = self.get_map_key(map_=self._hvac_mode_map, value=hvac_mode)
        if mode_value is None or not await self.set_property_async(
                prop=self._prop_mode, value=mode_value):
            raise RuntimeError(
                f'set climate prop.mode failed, {hvac_mode}, {self.entity_id}')

    @property
    def hvac_mode(self) -> Optional[HVACMode]:
        """The current hvac mode."""
        return (self.get_map_value(map_=self._hvac_mode_map,
                                   key=self.get_prop_value(
                                       prop=self._prop_mode))
                if self._prop_mode else None)


class Thermostat(FeatureOnOff, FeatureTargetTemperature, FeatureTemperature,
                 FeatureHumidity, FeatureFanMode):
    """Thermostat"""
    _prop_mode: Optional[MIoTSpecProperty]
    _hvac_mode_map: Optional[dict[int, HVACMode]]

    def __init__(self, miot_device: MIoTDevice,
                 entity_data: MIoTEntityData) -> None:
        """Initialize the thermostat."""
        self._prop_mode = None
        self._hvac_mode_map = None

        super().__init__(miot_device=miot_device, entity_data=entity_data)
        self._attr_icon = 'mdi:thermostat'
        # hvac modes
        self._attr_hvac_modes = None
        for prop in entity_data.props:
            if prop.name == 'mode':
                if not prop.value_list:
                    _LOGGER.error('invalid mode value_list, %s', self.entity_id)
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

        if self._attr_hvac_modes is None:
            self._attr_hvac_modes = [HVACMode.OFF, HVACMode.AUTO]
        elif HVACMode.OFF not in self._attr_hvac_modes:
            self._attr_hvac_modes.insert(0, HVACMode.OFF)

    async def async_set_hvac_mode(self, hvac_mode: HVACMode) -> None:
        """Set the target hvac mode."""
        # set the device off
        if hvac_mode == HVACMode.OFF:
            if not await self.set_property_async(prop=self._prop_on,
                                                 value=False):
                raise RuntimeError(f'set climate prop.on failed, {hvac_mode}, '
                                   f'{self.entity_id}')
            return
        # set the device on
        elif self.get_prop_value(prop=self._prop_on) is False:
            await self.set_property_async(prop=self._prop_on, value=True)
        # set mode
        if self._prop_mode is None:
            return
        mode_value = self.get_map_key(map_=self._hvac_mode_map, value=hvac_mode)
        if mode_value is None or not await self.set_property_async(
                prop=self._prop_mode, value=mode_value):
            raise RuntimeError(
                f'set climate prop.mode failed, {hvac_mode}, {self.entity_id}')

    @property
    def hvac_mode(self) -> Optional[HVACMode]:
        """The current hvac mode."""
        if self.get_prop_value(prop=self._prop_on) is False:
            return HVACMode.OFF
        return (self.get_map_value(map_=self._hvac_mode_map,
                                   key=self.get_prop_value(
                                       prop=self._prop_mode))
                if self._prop_mode else None)


class ElectricBlanket(FeatureOnOff, FeatureTargetTemperature,
                      FeatureTemperature, FeaturePresetMode):
    """Electric blanket"""

    def __init__(self, miot_device: MIoTDevice,
                 entity_data: MIoTEntityData) -> None:
        """Initialize the electric blanket."""
        super().__init__(miot_device=miot_device, entity_data=entity_data)

        self._attr_icon = 'mdi:rug'
        # hvac modes
        self._attr_hvac_modes = [HVACMode.HEAT, HVACMode.OFF]
        # preset modes
        self._init_preset_modes('electric-blanket', 'mode')

    async def async_set_hvac_mode(self, hvac_mode: HVACMode) -> None:
        """Set the target hvac mode."""
        await self.set_property_async(
            prop=self._prop_on,
            value=False if hvac_mode == HVACMode.OFF else True)

    @property
    def hvac_mode(self) -> Optional[HVACMode]:
        """The current hvac mode."""
        return (HVACMode.HEAT if self.get_prop_value(
            prop=self._prop_on) else HVACMode.OFF)
