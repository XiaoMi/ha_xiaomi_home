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

Cover entities for Xiaomi Home.
"""
from __future__ import annotations
import logging
from typing import Optional

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.components.cover import (ATTR_POSITION, CoverEntity,
                                            CoverEntityFeature,
                                            CoverDeviceClass)

from .miot.miot_spec import MIoTSpecProperty
from .miot.miot_device import MIoTDevice, MIoTEntityData, MIoTServiceEntity
from .miot.const import DOMAIN

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(hass: HomeAssistant, config_entry: ConfigEntry,
                            async_add_entities: AddEntitiesCallback) -> None:
    """Set up a config entry."""
    device_list: list[MIoTDevice] = hass.data[DOMAIN]['devices'][
        config_entry.entry_id]

    new_entities = []
    for miot_device in device_list:
        for data in miot_device.entity_list.get('cover', []):
            if data.spec.name == 'curtain':
                data.spec.device_class = CoverDeviceClass.CURTAIN
            elif data.spec.name == 'window-opener':
                data.spec.device_class = CoverDeviceClass.WINDOW
            elif data.spec.name == 'motor-controller':
                data.spec.device_class = CoverDeviceClass.SHUTTER
            elif data.spec.name == 'airer':
                data.spec.device_class = CoverDeviceClass.BLIND
            new_entities.append(Cover(miot_device=miot_device,
                                      entity_data=data))

    if new_entities:
        async_add_entities(new_entities)


class Cover(MIoTServiceEntity, CoverEntity):
    """Cover entities for Xiaomi Home."""
    # pylint: disable=unused-argument
    _prop_motor_control: Optional[MIoTSpecProperty]
    _prop_motor_value_open: Optional[int]
    _prop_motor_value_close: Optional[int]
    _prop_motor_value_pause: Optional[int]
    _prop_status: Optional[MIoTSpecProperty]
    _prop_status_opening: Optional[list[int]]
    _prop_status_closing: Optional[list[int]]
    _prop_status_stop: Optional[list[int]]
    _prop_status_closed: Optional[list[int]]
    _prop_current_position: Optional[MIoTSpecProperty]
    _prop_target_position: Optional[MIoTSpecProperty]
    _prop_position_value_range: Optional[int]

    def __init__(self, miot_device: MIoTDevice,
                 entity_data: MIoTEntityData) -> None:
        """Initialize the Cover."""
        super().__init__(miot_device=miot_device, entity_data=entity_data)
        self._attr_device_class = entity_data.spec.device_class
        self._attr_supported_color_modes = set()
        self._attr_supported_features = CoverEntityFeature(0)

        self._prop_motor_control = None
        self._prop_motor_value_open = None
        self._prop_motor_value_close = None
        self._prop_motor_value_pause = None
        self._prop_status = None
        self._prop_status_opening = []
        self._prop_status_closing = []
        self._prop_status_stop = []
        self._prop_status_closed = []
        self._prop_current_position = None
        self._prop_target_position = None
        self._prop_position_value_range = None

        # properties
        for prop in entity_data.props:
            if prop.name == 'motor-control':
                if not prop.value_list:
                    _LOGGER.error('motor-control value_list is None, %s',
                                  self.entity_id)
                    continue
                for item in prop.value_list.items:
                    if item.name in {'open', 'up'}:
                        self._attr_supported_features |= (
                            CoverEntityFeature.OPEN)
                        self._prop_motor_value_open = item.value
                    elif item.name in {'close', 'down'}:
                        self._attr_supported_features |= (
                            CoverEntityFeature.CLOSE)
                        self._prop_motor_value_close = item.value
                    elif item.name in {'pause', 'stop'}:
                        self._attr_supported_features |= (
                            CoverEntityFeature.STOP)
                        self._prop_motor_value_pause = item.value
                self._prop_motor_control = prop
            elif prop.name == 'status':
                if not prop.value_list:
                    _LOGGER.error('status value_list is None, %s',
                                  self.entity_id)
                    continue
                for item in prop.value_list.items:
                    if item.name in {'opening', 'open', 'up'}:
                        self._prop_status_opening.append(item.value)
                    elif item.name in {'closing', 'close', 'down'}:
                        self._prop_status_closing.append(item.value)
                    elif item.name in {'stop', 'stopped', 'pause'}:
                        self._prop_status_stop.append(item.value)
                    elif item.name in {'closed'}:
                        self._prop_status_closed.append(item.value)
                self._prop_status = prop
            elif prop.name == 'current-position':
                if not prop.value_range:
                    _LOGGER.error(
                        'invalid current-position value_range format, %s',
                        self.entity_id)
                    continue
                self._prop_position_value_range = (prop.value_range.max_ -
                                                   prop.value_range.min_)
                self._prop_current_position = prop
            elif prop.name == 'target-position':
                if not prop.value_range:
                    _LOGGER.error(
                        'invalid target-position value_range format, %s',
                        self.entity_id)
                    continue
                self._prop_position_value_range = (prop.value_range.max_ -
                                                   prop.value_range.min_)
                self._attr_supported_features |= CoverEntityFeature.SET_POSITION
                self._prop_target_position = prop

    async def async_open_cover(self, **kwargs) -> None:
        """Open the cover."""
        await self.set_property_async(self._prop_motor_control,
                                      self._prop_motor_value_open)

    async def async_close_cover(self, **kwargs) -> None:
        """Close the cover."""
        await self.set_property_async(self._prop_motor_control,
                                      self._prop_motor_value_close)

    async def async_stop_cover(self, **kwargs) -> None:
        """Stop the cover."""
        await self.set_property_async(self._prop_motor_control,
                                      self._prop_motor_value_pause)

    async def async_set_cover_position(self, **kwargs) -> None:
        """Set the position of the cover."""
        pos = kwargs.get(ATTR_POSITION, None)
        if pos is None:
            return None
        pos = round(pos * self._prop_position_value_range / 100)
        await self.set_property_async(prop=self._prop_target_position,
                                      value=pos)

    @property
    def current_cover_position(self) -> Optional[int]:
        """Return the current position.

        0: the cover is closed, 100: the cover is fully opened, None: unknown.
        """
        if self._prop_current_position is None:
            # Assume that the current position is the same as the target
            # position when the current position is not defined in the device's
            # MIoT-Spec-V2.
            return None if (self._prop_target_position
                            is None) else self.get_prop_value(
                                prop=self._prop_target_position)
        pos = self.get_prop_value(prop=self._prop_current_position)
        return None if pos is None else round(pos * 100 /
                                              self._prop_position_value_range)

    @property
    def is_opening(self) -> Optional[bool]:
        """Return if the cover is opening."""
        if self._prop_status and self._prop_status_opening:
            return (self.get_prop_value(prop=self._prop_status)
                    in self._prop_status_opening)
        # The status is prior to the numerical relationship of the current
        # position and the target position when determining whether the cover
        # is opening.
        if (self._prop_target_position and
                self.current_cover_position is not None):
            return (self.current_cover_position
                    < self.get_prop_value(prop=self._prop_target_position))
        return None

    @property
    def is_closing(self) -> Optional[bool]:
        """Return if the cover is closing."""
        if self._prop_status and self._prop_status_closing:
            return (self.get_prop_value(prop=self._prop_status)
                    in self._prop_status_closing)
        # The status is prior to the numerical relationship of the current
        # position and the target position when determining whether the cover
        # is closing.
        if (self._prop_target_position and
                self.current_cover_position is not None):
            return (self.current_cover_position
                    > self.get_prop_value(prop=self._prop_target_position))
        return None

    @property
    def is_closed(self) -> Optional[bool]:
        """Return if the cover is closed."""
        if self.current_cover_position is not None:
            return self.current_cover_position == 0
        # The current position is prior to the status when determining
        # whether the cover is closed.
        if self._prop_status and self._prop_status_closed:
            return (self.get_prop_value(prop=self._prop_status)
                    in self._prop_status_closed)
        return None
