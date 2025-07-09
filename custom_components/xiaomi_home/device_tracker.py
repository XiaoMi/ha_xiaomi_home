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

Device tracker entities for Xiaomi Home.
"""
from __future__ import annotations
from typing import Optional

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.components.device_tracker import TrackerEntity

from .miot.const import DOMAIN
from .miot.miot_device import MIoTDevice, MIoTServiceEntity, MIoTEntityData
from .miot.miot_spec import MIoTSpecProperty


async def async_setup_entry(
    hass: HomeAssistant,
    config_entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    device_list: list[MIoTDevice] = hass.data[DOMAIN]['devices'][
        config_entry.entry_id]
    new_entities = []
    for miot_device in device_list:
        for data in miot_device.entity_list.get('device_tracker', []):
            new_entities.append(
                DeviceTracker(miot_device=miot_device, entity_data=data))
    if new_entities:
        async_add_entities(new_entities)


class DeviceTracker(MIoTServiceEntity, TrackerEntity):
    """Tracker entities for Xiaomi Home."""
    _prop_battery_level: Optional[MIoTSpecProperty]
    _prop_latitude: Optional[MIoTSpecProperty]
    _prop_longitude: Optional[MIoTSpecProperty]
    _prop_area_id: Optional[MIoTSpecProperty]

    def __init__(self, miot_device: MIoTDevice,
                 entity_data: MIoTEntityData) -> None:
        super().__init__(miot_device=miot_device, entity_data=entity_data)
        self._prop_battery_level = None
        self._prop_latitude = None
        self._prop_longitude = None
        self._prop_area_id = None

        # properties
        for prop in entity_data.props:
            if prop.name == 'battery-level':
                self._prop_battery_level = prop
            elif prop.name == 'latitude':
                self._prop_latitude = prop
            elif prop.name == 'longitude':
                self._prop_longitude = prop
            elif prop.name == 'area-id':
                self._prop_area_id = prop

    @property
    def battery_level(self) -> Optional[int]:
        """The battery level of the device."""
        return None if (self._prop_battery_level
                        is None) else self.get_prop_value(
                            prop=self._prop_battery_level)

    @property
    def latitude(self) -> Optional[float]:
        """The latitude coordinate of the device."""
        return None if self._prop_latitude is None else self.get_prop_value(
            prop=self._prop_latitude)

    @property
    def longitude(self) -> Optional[float]:
        """The longitude coordinate of the device."""
        return None if self._prop_longitude is None else self.get_prop_value(
            prop=self._prop_longitude)

    @property
    def location_name(self) -> Optional[str]:
        """The location name of the device."""
        return None if self._prop_area_id is None else self.get_prop_value(
            prop=self._prop_area_id)
