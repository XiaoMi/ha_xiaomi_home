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
import json
import logging

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.components.vacuum import StateVacuumEntity
from homeassistant.components.vacuum.const import VacuumEntityFeature

from .miot.const import DOMAIN
from .miot.miot_device import MIoTDevice, MIoTServiceEntity, MIoTEntityData
from .miot.miot_spec import (MIoTSpecAction, MIoTSpecProperty)

try:  # VacuumActivity is introduced in HA core 2025.1.0
    from homeassistant.components.vacuum.const import VacuumActivity
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
    _prop_sweep_type: Optional[MIoTSpecProperty]
    _prop_water_level: Optional[MIoTSpecProperty]
    _prop_sweep_count: Optional[MIoTSpecProperty]
    _prop_room_id: Optional[MIoTSpecProperty]
    _prop_zone_id: Optional[MIoTSpecProperty]

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
    _action_start_room_sweep: Optional[MIoTSpecAction]
    _action_start_zone_sweep: Optional[MIoTSpecAction]

    _status_map: Optional[dict[int, str]]
    _fan_level_map: Optional[dict[int, str]]
    _sweep_type_map: Optional[dict[int, str]]
    _water_level_map: Optional[dict[int, str]]
    _sweep_count_map: Optional[dict[int, str]]

    _device_name: str

    def __init__(self, miot_device: MIoTDevice,
                 entity_data: MIoTEntityData) -> None:
        super().__init__(miot_device=miot_device, entity_data=entity_data)
        self._device_name = miot_device.name
        self._attr_supported_features = VacuumEntityFeature.SEND_COMMAND

        self._prop_status = None
        self._prop_fan_level = None
        self._prop_sweep_type = None
        self._prop_water_level = None
        self._prop_sweep_count = None
        self._prop_room_id = None
        self._prop_zone_id = None

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
        self._action_start_room_sweep = None
        self._action_start_zone_sweep = None

        self._status_map = None
        self._fan_level_map = None
        self._sweep_type_map = None
        self._water_level_map = None
        self._sweep_count_map = None

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
            elif prop.name == 'sweep-type':
                if prop.value_list:
                    self._sweep_type_map = prop.value_list.to_map()
                self._prop_sweep_type = prop
            elif prop.name == 'water-level':
                if prop.value_list:
                    self._water_level_map = prop.value_list.to_map()
                self._prop_water_level = prop
            elif prop.name == 'sweep-count':
                if prop.value_list:
                    self._sweep_count_map = prop.value_list.to_map()
                self._prop_sweep_count = prop
            elif prop.name in {'room-id', 'vacuum-room-ids'}:
                self._prop_room_id = prop
            elif prop.name in {'zone-id', 'zone-ids'}:
                self._prop_zone_id = prop

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
            elif action.name in {'start-room-sweep', 'start-vacuum-room-sweep'}:
                self._action_start_room_sweep = action
            elif action.name == 'start-zone-sweep':
                self._action_start_zone_sweep = action

        # Use start-charge from battery service as fallback
        # if stop-and-gocharge is not available
        if self._action_stop_and_gocharge is None:
            for action in entity_data.actions:
                if action.name == 'start-charge':
                    self._attr_supported_features |= (
                        VacuumEntityFeature.RETURN_HOME)
                    self._action_stop_and_gocharge = action
                    break

        # If start-sweep is not available but start-sweep-mop is, use it
        if self._action_start_sweep is None:
            for action in entity_data.actions:
                if action.name in {
                    'start-sweep-mop', 'start-sweep-and-mop',
                    'start-mop', 'start-sweep-before-mop'
                }:
                    self._attr_supported_features |= VacuumEntityFeature.START
                    self._action_start_sweep = action
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

    async def async_send_command(
        self,
        command: str,
        params: Optional[dict] = None,
        **kwargs: Any,
    ) -> None:
        """Send a raw MIoT command to the vacuum.

        Supported commands:
          app_segment_clean params: room_ids (list[str|int])
          app_zoned_clean params: zone_ids (list[str|int])

        Common params:
          fan_level (int)
          water_level (int)
          sweep_type (int)
          sweep_count (int)
        """
        _LOGGER.debug(f"received async_send_command: command={command}, params={params}")

        if type(params) is dict:
            fan_level = params.get('fan_level')
            water_level = params.get('water_level')
            sweep_type = params.get('sweep_type')
            sweep_count = params.get('sweep_count')

            if fan_level is not None and self._prop_fan_level is not None:
                await self.set_property_async(
                    prop=self._prop_fan_level, value=int(fan_level))
            if water_level is not None and self._prop_water_level is not None:
                await self.set_property_async(
                    prop=self._prop_water_level, value=int(water_level))
            if sweep_type is not None and self._prop_sweep_type is not None:
                await self.set_property_async(
                    prop=self._prop_sweep_type, value=int(sweep_type))
            if sweep_count is not None and self._prop_sweep_count is not None:
                await self.set_property_async(
                    prop=self._prop_sweep_count, value=int(sweep_count))

        if command == 'app_segment_clean':
            action = (
                self._action_start_room_sweep or self._action_start_zone_sweep)
            if action is None:
                _LOGGER.error(
                    'send_command clean_room: no room/zone sweep action '
                    'available for %s', self.entity_id)
                return
            if type(params) is dict:
                room_ids = params['room_ids']
            else:
                room_ids = params
            ids_json = json.dumps(
                [int(r) if str(r).isdigit() else str(r)
                 for r in room_ids] if room_ids else [])
            if action.in_:
                piid = action.in_[0].iid
            elif self._prop_room_id:
                piid = self._prop_room_id.iid
            else:
                piid = 5
            await self.action_async(
                action=action, in_list=[{'piid': piid, 'value': ids_json}])

        elif command == 'app_zoned_clean':
            if self._action_start_zone_sweep is None:
                _LOGGER.error(
                    'send_command app_zoned_clean: start-zone-sweep action '
                    'not available for %s', self.entity_id)
                return
            if type(params) is dict:
                zone_ids = params['zone_ids']
            else:
                zone_ids = params
            ids_json = json.dumps(
                [int(r) if str(r).isdigit() else str(r)
                 for r in zone_ids] if zone_ids else [])
            if self._action_start_zone_sweep.in_:
                piid = self._action_start_zone_sweep.in_[0].iid
            elif self._prop_zone_id:
                piid = self._prop_zone_id.iid
            else:
                piid = 6
            await self.action_async(
                action=self._action_start_zone_sweep,
                in_list=[{'piid': piid, 'value': ids_json}])

        else:
            _LOGGER.error(
                'send_command: unknown command "%s" for %s',
                command, self.entity_id)

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
