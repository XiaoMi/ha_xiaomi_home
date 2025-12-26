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

Vacuum entities for Xiaomi Home.
"""
from __future__ import annotations
from typing import Any, Optional
import re
import logging

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.components.vacuum import (StateVacuumEntity,
                                             VacuumEntityFeature)

from .miot.const import DOMAIN
from .miot.miot_device import MIoTDevice, MIoTServiceEntity, MIoTEntityData
from .miot.miot_spec import (MIoTSpecAction, MIoTSpecProperty)

try:  # VacuumActivity is introduced in HA core 2025.1.0
    from homeassistant.components.vacuum import VacuumActivity
    HA_CORE_HAS_ACTIVITY = True
except ImportError:
    HA_CORE_HAS_ACTIVITY = False

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    config_entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    device_list: list[MIoTDevice] = hass.data[DOMAIN]['devices'][
        config_entry.entry_id]
    new_entities = []
    for miot_device in device_list:
        for data in miot_device.entity_list.get('vacuum', []):
            new_entities.append(
                Vacuum(miot_device=miot_device, entity_data=data))
    if new_entities:
        async_add_entities(new_entities)


class Vacuum(MIoTServiceEntity, StateVacuumEntity):
    """Vacuum entities for Xiaomi Home."""
    # pylint: disable=unused-argument
    _prop_status: Optional[MIoTSpecProperty]
    _prop_fan_level: Optional[MIoTSpecProperty]
    _prop_status_cleaning: Optional[list[int]]
    _prop_status_docked: Optional[list[int]]
    _prop_status_paused: Optional[list[int]]
    _prop_status_returning: Optional[list[int]]
    _prop_status_error: Optional[list[int]]

    _action_start_sweep: Optional[MIoTSpecAction]
    _action_stop_sweeping: Optional[MIoTSpecAction]
    _action_pause_sweeping: Optional[MIoTSpecAction]
    _action_continue_sweep: Optional[MIoTSpecAction]
    _action_stop_and_gocharge: Optional[MIoTSpecAction]
    _action_identify: Optional[MIoTSpecAction]

    _status_map: Optional[dict[int, str]]
    _fan_level_map: Optional[dict[int, str]]

    _device_name: str

    def __init__(self, miot_device: MIoTDevice,
                 entity_data: MIoTEntityData) -> None:
        super().__init__(miot_device=miot_device, entity_data=entity_data)
        self._device_name = miot_device.name
        self._attr_supported_features = VacuumEntityFeature(0)

        self._prop_status = None
        self._prop_fan_level = None
        self._prop_status_cleaning = []
        self._prop_status_docked = []
        self._prop_status_paused = []
        self._prop_status_returning = []
        self._prop_status_error = []
        self._action_start_sweep = None
        self._action_stop_sweeping = None
        self._action_pause_sweeping = None
        self._action_continue_sweep = None
        self._action_stop_and_gocharge = None
        self._action_identify = None
        self._status_map = None
        self._fan_level_map = None

        # properties
        for prop in entity_data.props:
            if prop.name == 'status':
                if not prop.value_list:
                    _LOGGER.error('invalid status value_list, %s',
                                  self.entity_id)
                    continue
                self._status_map = prop.value_list.to_map()
                self._attr_supported_features |= VacuumEntityFeature.STATE
                self._prop_status = prop
                for item in prop.value_list.items:
                    item_str: str = item.name
                    item_name: str = re.sub(r'[^a-z]', '', item_str)
                    if item_name in {
                            'charging', 'charged', 'chargingcompleted',
                            'fullcharge', 'fullpower', 'findchargerpause',
                            'drying', 'washing', 'wash', 'inthewash',
                            'inthedry', 'stationworking', 'dustcollecting',
                            'upgrade', 'upgrading', 'updating'
                    }:
                        self._prop_status_docked.append(item.value)
                    elif item_name in {'paused', 'pause'}:
                        self._prop_status_paused.append(item.value)
                    elif item_name in {
                            'gocharging', 'cleancompletegocharging',
                            'findchargewash', 'backtowashmop', 'gowash',
                            'gowashing', 'summon'
                    }:
                        self._prop_status_returning.append(item.value)
                    elif item_name in {
                            'error', 'breakcharging', 'gochargebreak'
                    }:
                        self._prop_status_error.append(item.value)
                    elif (item_name.find('sweeping') != -1) or (
                            item_name.find('mopping') != -1) or (item_name in {
                                'cleaning', 'remoteclean', 'continuesweep',
                                'busy', 'building', 'buildingmap', 'mapping'
                            }):
                        self._prop_status_cleaning.append(item.value)
            elif prop.name == 'fan-level':
                if not prop.value_list:
                    _LOGGER.error('invalid fan-level value_list, %s',
                                  self.entity_id)
                    continue
                self._fan_level_map = prop.value_list.to_map()
                self._attr_fan_speed_list = list(self._fan_level_map.values())
                self._attr_supported_features |= VacuumEntityFeature.FAN_SPEED
                self._prop_fan_level = prop
        # action
        for action in entity_data.actions:
            if action.name == 'start-sweep':
                self._attr_supported_features |= VacuumEntityFeature.START
                self._action_start_sweep = action
            elif action.name == 'stop-sweeping':
                self._attr_supported_features |= VacuumEntityFeature.STOP
                self._action_stop_sweeping = action
            elif action.name == 'pause-sweeping':
                self._attr_supported_features |= VacuumEntityFeature.PAUSE
                self._action_pause_sweeping = action
            elif action.name == 'continue-sweep':
                self._action_continue_sweep = action
            elif action.name == 'stop-and-gocharge':
                self._attr_supported_features |= VacuumEntityFeature.RETURN_HOME
                self._action_stop_and_gocharge = action
            elif action.name == 'identify':
                self._attr_supported_features |= VacuumEntityFeature.LOCATE
                self._action_identify = action

        # Use start-charge from battery service as fallback
        # if stop-and-gocharge is not available
        if self._action_stop_and_gocharge is None:
            for action in entity_data.actions:
                if action.name == 'start-charge':
                    self._attr_supported_features |= (
                        VacuumEntityFeature.RETURN_HOME)
                    self._action_stop_and_gocharge = action
                    break

    async def async_start(self) -> None:
        """Start or resume the cleaning task."""
        if self._prop_status is not None:
            status = self.get_prop_value(prop=self._prop_status)
            if (status in self._prop_status_paused
               ) and self._action_continue_sweep:
                await self.action_async(action=self._action_continue_sweep)
                return
        await self.action_async(action=self._action_start_sweep)

    async def async_stop(self, **kwargs: Any) -> None:
        """Stop the vacuum cleaner, do not return to base."""
        await self.action_async(action=self._action_stop_sweeping)

    async def async_pause(self) -> None:
        """Pause the cleaning task."""
        await self.action_async(action=self._action_pause_sweeping)

    async def async_return_to_base(self, **kwargs: Any) -> None:
        """Set the vacuum cleaner to return to the dock."""
        await self.action_async(action=self._action_stop_and_gocharge)

    async def async_locate(self, **kwargs: Any) -> None:
        """Locate the vacuum cleaner."""
        await self.action_async(action=self._action_identify)

    async def async_set_fan_speed(self, fan_speed: str, **kwargs: Any) -> None:
        """Set fan speed."""
        fan_level_value = self.get_map_key(map_=self._fan_level_map,
                                           value=fan_speed)
        await self.set_property_async(prop=self._prop_fan_level,
                                      value=fan_level_value)

    @property
    def name(self) -> Optional[str]:
        """Name of the vacuum entity."""
        return self._device_name

    @property
    def fan_speed(self) -> Optional[str]:
        """The current fan speed of the vacuum cleaner."""
        return self.get_map_value(
            map_=self._fan_level_map,
            key=self.get_prop_value(prop=self._prop_fan_level))

    if HA_CORE_HAS_ACTIVITY:

        @property
        def activity(self) -> Optional[str]:
            """The current vacuum activity.
        To fix the HA warning below:
            Detected that custom integration 'xiaomi_home' is setting state
            directly.Entity XXX(<class 'custom_components.xiaomi_home.vacuum
            .Vacuum'>)should implement the 'activity' property and return
            its state using the VacuumActivity enum.This will stop working in
            Home Assistant 2026.1.

        Refer to
        https://developers.home-assistant.io/blog/2024/12/08/new-vacuum-state-property

        There are only 6 states in VacuumActivity enum. To be compatible with
        more constants, try get matching VacuumActivity enum first, return state
        string as before if there is no match. In Home Assistant 2026.1, every
        state should map to a VacuumActivity enum.
            """
            status = self.get_prop_value(prop=self._prop_status)
            if status is None:
                return None
            if status in self._prop_status_cleaning:
                return VacuumActivity.CLEANING
            if status in self._prop_status_docked:
                return VacuumActivity.DOCKED
            if status in self._prop_status_paused:
                return VacuumActivity.PAUSED
            if status in self._prop_status_returning:
                return VacuumActivity.RETURNING
            if status in self._prop_status_error:
                return VacuumActivity.ERROR
            return VacuumActivity.IDLE

    else:

        @property
        def state(self) -> Optional[str]:
            """The current state of the vacuum."""
            status = self.get_prop_value(prop=self._prop_status)
            return None if (status is None) else self.get_map_value(
                map_=self._status_map, key=status)
