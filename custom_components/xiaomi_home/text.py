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

Text entities for Xiaomi Home.
"""
from __future__ import annotations
import logging
from typing import Any, Optional

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.components.text import TextEntity
from homeassistant.util import yaml
from homeassistant.exceptions import HomeAssistantError

from .miot.const import DOMAIN
from .miot.miot_spec import MIoTSpecAction, MIoTSpecProperty
from .miot.miot_device import MIoTActionEntity, MIoTDevice, MIoTPropertyEntity

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
        for prop in miot_device.prop_list.get('text', []):
            new_entities.append(Text(miot_device=miot_device, spec=prop))

        if miot_device.miot_client.action_debug:
            for action in miot_device.action_list.get('notify', []):
                new_entities.append(ActionText(
                    miot_device=miot_device, spec=action))

    if new_entities:
        async_add_entities(new_entities)


class Text(MIoTPropertyEntity, TextEntity):
    """Text entities for Xiaomi Home."""

    def __init__(self, miot_device: MIoTDevice, spec: MIoTSpecProperty) -> None:
        """Initialize the Text."""
        super().__init__(miot_device=miot_device, spec=spec)

    @property
    def native_value(self) -> Optional[str]:
        """Return the current text value."""
        if isinstance(self._value, str):
            return self._value[:255]
        return self._value

    async def async_set_value(self, value: str) -> None:
        """Set the text value."""
        await self.set_property_async(value=value)


class ActionText(MIoTActionEntity, TextEntity):
    """Text entities for Xiaomi Home."""

    def __init__(self, miot_device: MIoTDevice, spec: MIoTSpecAction) -> None:
        super().__init__(miot_device=miot_device, spec=spec)
        self._attr_extra_state_attributes = {}
        self._attr_native_value = ''
        action_in: str = ', '.join([
            f'{prop.description_trans}({prop.format_.__name__})'
            for prop in self.spec.in_])
        self._attr_extra_state_attributes['action params'] = f'[{action_in}]'

    async def async_set_value(self, value: str) -> None:
        if not value:
            return
        in_list: Any = None
        try:
            in_list = yaml.parse_yaml(content=value)
        except HomeAssistantError as e:
            _LOGGER.error(
                'action exec failed, %s(%s), invalid action params format, %s',
                self.name, self.entity_id, value)
            raise ValueError(
                f'action exec failed, {self.name}({self.entity_id}), '
                f'invalid action params format, {value}') from e
        if len(self.spec.in_) == 1 and not isinstance(in_list, list):
            in_list = [in_list]
        if not isinstance(in_list, list) or len(in_list) != len(self.spec.in_):
            _LOGGER.error(
                'action exec failed, %s(%s), invalid action params, %s',
                self.name, self.entity_id, value)
            raise ValueError(
                f'action exec failed, {self.name}({self.entity_id}), '
                f'invalid action params, {value}')
        in_value: list[dict] = []
        for index, prop in enumerate(self.spec.in_):
            if prop.format_ == str:
                if isinstance(in_list[index], (bool, int, float, str)):
                    in_value.append(
                        {'piid': prop.iid, 'value': str(in_list[index])})
                    continue
            elif prop.format_ == bool:
                if isinstance(in_list[index], (bool, int)):
                    # yes, no, on, off, true, false and other bool types
                    # will also be parsed as 0 and 1 of int.
                    in_value.append(
                        {'piid': prop.iid, 'value': bool(in_list[index])})
                    continue
            elif prop.format_ == float:
                if isinstance(in_list[index], (int, float)):
                    in_value.append(
                        {'piid': prop.iid, 'value': in_list[index]})
                    continue
            elif prop.format_ == int:
                if isinstance(in_list[index], int):
                    in_value.append(
                        {'piid': prop.iid, 'value': in_list[index]})
                    continue
            # Invalid params type, raise error.
            _LOGGER.error(
                'action exec failed, %s(%s), invalid params item, '
                'which item(%s) in the list must be %s, %s type was %s, %s',
                self.name, self.entity_id, prop.description_trans,
                prop.format_, in_list[index], type(
                    in_list[index]).__name__, value)
            raise ValueError(
                f'action exec failed, {self.name}({self.entity_id}), '
                f'invalid params item, which item({prop.description_trans}) '
                f'in the list must be {prop.format_}, {in_list[index]} type '
                f'was {type(in_list[index]).__name__}, {value}')

        self._attr_native_value = value
        if await self.action_async(in_list=in_value):
            self.async_write_ha_state()
