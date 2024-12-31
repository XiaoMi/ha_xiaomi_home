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

Notify entities for Xiaomi Home.
"""
from __future__ import annotations
import logging
from typing import Optional

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.components.notify import NotifyEntity
from homeassistant.util import yaml
from homeassistant.exceptions import HomeAssistantError

from .miot.miot_spec import MIoTSpecAction
from .miot.miot_device import MIoTDevice, MIoTActionEntity
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
        for action in miot_device.action_list.get('notify', []):
            new_entities.append(Notify(miot_device=miot_device, spec=action))

    if new_entities:
        async_add_entities(new_entities)


class Notify(MIoTActionEntity, NotifyEntity):
    """Notify entities for Xiaomi Home."""

    def __init__(self, miot_device: MIoTDevice, spec: MIoTSpecAction) -> None:
        """Initialize the Notify."""
        super().__init__(miot_device=miot_device, spec=spec)
        self._attr_extra_state_attributes = {}
        action_in: str = ', '.join([
            f'{prop.description_trans}({prop.format_})'
            for prop in self.spec.in_])
        self._attr_extra_state_attributes['action params'] = f'[{action_in}]'

    async def async_send_message(
        self, message: str, title: Optional[str] = None
    ) -> None:
        """Send a message."""
        del title
        if not message:
            _LOGGER.error(
                'action exec failed, %s(%s), empty action params',
                self.name, self.entity_id)
            return
        try:
            in_list: list = yaml.parse_yaml(message)
        except HomeAssistantError:
            _LOGGER.error(
                'action exec failed, %s(%s), invalid action params format, %s',
                self.name, self.entity_id, message)
            return

        if not isinstance(in_list, list):
            in_list = [in_list]

        if not isinstance(in_list, list) or len(in_list) != len(self.spec.in_):
            _LOGGER.error(
                'action exec failed, %s(%s), invalid action params, %s',
                self.name, self.entity_id, message)
            return

        in_value: list[dict] = []
        for index, prop in enumerate(self.spec.in_):
            if type(in_list[index]).__name__ != prop.format_:
                _LOGGER.error(
                    'action exec failed, %s(%s), invalid params item, '
                    'which item(%s) in the list must be %s, %s',
                    self.name, self.entity_id, prop.description_trans,
                    prop.format_, message)
                return
            in_value.append({'piid': prop.iid, 'value': in_list[index]})
        return await self.action_async(in_list=in_value)
