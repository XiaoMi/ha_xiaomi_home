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
import logging

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.components.vacuum import (
    StateVacuumEntity,
    VacuumEntityFeature
)

from .miot.const import DOMAIN
from .miot.miot_device import MIoTDevice, MIoTServiceEntity, MIoTEntityData
from .miot.miot_spec import (
    MIoTSpecAction,
    MIoTSpecProperty)

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
    _prop_battery_level: Optional[MIoTSpecProperty]

    _action_start_sweep: Optional[MIoTSpecAction]
    _action_stop_sweeping: Optional[MIoTSpecAction]
    _action_pause_sweeping: Optional[MIoTSpecAction]
    _action_continue_sweep: Optional[MIoTSpecAction]
    _action_stop_and_gocharge: Optional[MIoTSpecAction]
    _action_identify: Optional[MIoTSpecAction]

    _status_map: Optional[dict[int, str]]
    _fan_level_map: Optional[dict[int, str]]

    def __init__(
        self, miot_device: MIoTDevice, entity_data: MIoTEntityData
    ) -> None:
        super().__init__(miot_device=miot_device, entity_data=entity_data)
        self._attr_supported_features = VacuumEntityFeature(0)

        self._prop_status = None
        self._prop_fan_level = None
        self._prop_battery_level = None
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
                    _LOGGER.error(
                        'invalid status value_list, %s', self.entity_id)
                    continue
                self._status_map = prop.value_list.to_map()
                self._prop_status = prop
            elif prop.name == 'fan-level':
                if not prop.value_list:
                    _LOGGER.error(
                        'invalid fan-level value_list, %s', self.entity_id)
                    continue
                self._fan_level_map = prop.value_list.to_map()
                self._attr_fan_speed_list = list(self._fan_level_map.values())
                self._attr_supported_features |= VacuumEntityFeature.FAN_SPEED
                self._prop_fan_level = prop

            elif prop.name == 'battery-level':
                self._attr_supported_features |= VacuumEntityFeature.BATTERY
                self._prop_battery_level = prop
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

    async def async_start(self) -> None:
        """Start or resume the cleaning task."""
        if self.state.lower() in ['paused', '暂停中']:
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

    async def async_clean_spot(self, **kwargs: Any) -> None:
        """Perform a spot clean-up."""

    async def async_locate(self, **kwargs: Any) -> None:
        """Locate the vacuum cleaner."""
        await self.action_async(action=self._action_identify)

    async def async_set_fan_speed(self, fan_speed: str, **kwargs: Any) -> None:
        """Set fan speed."""

    @property
    def state(self) -> Optional[str]:
        """Return the current state of the vacuum cleaner."""
        return self.get_map_value(
            map_=self._status_map,
            key=self.get_prop_value(prop=self._prop_status))

    @property
    def battery_level(self) -> Optional[int]:
        """Return the current battery level of the vacuum cleaner."""
        return self.get_prop_value(prop=self._prop_battery_level)

    @property
    def fan_speed(self) -> Optional[str]:
        """Return the current fan speed of the vacuum cleaner."""
        return self.get_map_value(
            map_=self._fan_level_map,
            key=self.get_prop_value(prop=self._prop_fan_level))
