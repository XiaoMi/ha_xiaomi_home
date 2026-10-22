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

Scene entities for Xiaomi Home.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Any

from homeassistant.components.scene import Scene
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers import device_registry, entity_registry
from homeassistant.helpers.device_registry import DeviceEntryType, DeviceInfo
from homeassistant.helpers.entity_platform import (
    AddEntitiesCallback, async_get_current_platform)

from .miot.common import slugify_name
from .miot.const import DOMAIN, INTEGRATION_VERSION
from .miot.miot_client import MIoTClient, MIoTManualScene
from .miot.miot_error import MIoTClientError

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant, config_entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback
) -> None:
    """Set up manual scenes using the entry's existing client."""
    # pylint: disable=unused-argument
    client: MIoTClient = hass.data[DOMAIN]['miot_clients'][
        config_entry.entry_id]
    _prepare_scene_registry(hass, config_entry, client)
    if not config_entry.data.get('enable_manual_scenes', False):
        return

    await client.load_manual_scenes_async(cache_only=True)
    platform = async_get_current_platform()
    entities: dict[str, ManualScene] = {}
    sync_task = None
    unloaded = False

    async def sync_scenes() -> None:
        scenes = client.manual_scenes
        for key in list(entities):
            if key not in scenes:
                entity = entities.pop(key)
                if entity.entity_id in platform.entities:
                    await platform.async_remove_entity(entity.entity_id)
        registry = entity_registry.async_get(hass)
        occupied = set(registry.entities) | set(hass.states.async_entity_ids())
        added = []
        for key, scene in sorted(scenes.items()):
            if key in entities:
                continue
            entity = ManualScene(client, key, scene, config_entry)
            existing = registry.async_get_entity_id(
                'scene', DOMAIN, entity.unique_id)
            if existing:
                if registry.async_get(existing).config_entry_id != (
                        config_entry.entry_id):
                    raise HomeAssistantError('Scene identity belongs elsewhere')
                entity.entity_id = existing
            else:
                base = entity.entity_id
                if base in occupied:
                    base = f'{base}_{key[:12]}'
                entity.entity_id = base
                suffix = 2
                while entity.entity_id in occupied:
                    entity.entity_id = f'{base}_{suffix}'
                    suffix += 1
            occupied.add(entity.entity_id)
            entities[key] = entity
            added.append(entity)
        if added:
            # Reconcile later metadata only after registration has finished.
            await platform.async_add_entities(added)

    @callback
    def schedule_sync() -> None:
        nonlocal sync_task
        if unloaded or set(entities) == set(client.manual_scenes):
            return
        if sync_task is None or sync_task.done():
            sync_task = hass.async_create_task(sync_scenes())
            sync_task.add_done_callback(sync_done)

    @callback
    def sync_done(completed: asyncio.Task) -> None:
        if completed.cancelled():
            return
        if completed.exception() is not None:
            _LOGGER.error('Manual scene entity synchronization failed')
        else:
            schedule_sync()

    async def cancel_sync() -> None:
        nonlocal unloaded
        unloaded = True
        client.unsub_manual_scene_state('platform')
        if sync_task:
            sync_task.cancel()
            await asyncio.gather(sync_task, return_exceptions=True)

    client.sub_manual_scene_state('platform', schedule_sync)
    config_entry.async_on_unload(cancel_sync)
    sync_task = hass.async_create_task(sync_scenes())
    sync_task.add_done_callback(sync_done)
    await sync_task


@callback
def _prepare_scene_registry(
    hass: HomeAssistant, entry: ConfigEntry, client: MIoTClient
) -> None:
    """Replace development scene buttons within this entry."""
    devices = device_registry.async_get(hass)
    matches = [device for device in
               device_registry.async_entries_for_config_entry(
                   devices, entry.entry_id)
               if any((DOMAIN, identifier) in device.identifiers
                      for identifier in client.manual_scene_device_ids)]
    if len(matches) > 1:
        raise HomeAssistantError('Conflicting manual scene service devices')
    if matches:
        device = matches[0]
        identifiers = device.identifiers - {
            (DOMAIN, identifier)
            for identifier in client.manual_scene_device_ids}
        devices.async_update_device(
            device.id, new_identifiers=identifiers | {
                (DOMAIN, client.manual_scene_device_id)},
            entry_type=DeviceEntryType.SERVICE)
    registry = entity_registry.async_get(hass)
    for entity in entity_registry.async_entries_for_config_entry(
            registry, entry.entry_id):
        if (entity.domain == 'button' and entity.platform == DOMAIN
                and entity.unique_id.startswith(
                    f'{DOMAIN}.manual_scene.')):
            registry.async_remove(entity.entity_id)


class ManualScene(Scene):
    """A manual scene activated through the client's current route."""
    _attr_should_poll = False
    _attr_has_entity_name = True

    def __init__(
        self, client: MIoTClient, key: str, scene: MIoTManualScene,
        config_entry: ConfigEntry
    ) -> None:
        self._client = client
        self._scene_key = key
        self._attr_unique_id = f'{DOMAIN}.manual_scene.{key}'
        home = config_entry.data['home_selected'][scene.home_id]
        home_name = home.get('home_name') or scene.home_id
        home_slug = slugify_name(home_name) or 'home'
        scene_slug = slugify_name(scene.scene_id) or 'scene'
        self.entity_id = ('scene.xiaomi_home_scenes_manual_controls'
                          f'{home_slug}_{scene_slug}')
        self._attr_name = scene.scene_name
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, client.manual_scene_device_id)},
            translation_key='manual_scenes',
            manufacturer='Xiaomi', model='xiaomi_home.scenes.manual_controls',
            sw_version=INTEGRATION_VERSION,
            configuration_url=(
                'homeassistant://config/integrations/integration/xiaomi_home'),
            entry_type=DeviceEntryType.SERVICE)

    @property
    def available(self) -> bool:
        return self._client.manual_scene_available(self._scene_key)

    @property
    def icon(self) -> str:
        return {
            'local': 'mdi:hub-outline',
            'cloud': 'mdi:cloud-outline'
        }.get(self._client.manual_scene_route(self._scene_key),
              'mdi:cloud-off-outline')

    async def async_added_to_hass(self) -> None:
        await super().async_added_to_hass()
        self._client.sub_manual_scene_state(
            self._scene_key, self._handle_scene_state)
        self.async_on_remove(lambda: self._client.unsub_manual_scene_state(
            self._scene_key))
        self._handle_scene_state()

    @callback
    def _handle_scene_state(self) -> None:
        scene = self._client.manual_scenes.get(self._scene_key)
        if scene and scene.scene_name != self._attr_name:
            self._attr_name = scene.scene_name
            entity_registry.async_get(self.hass).async_update_entity(
                self.entity_id, original_name=scene.scene_name)
        self.async_write_ha_state()

    async def async_activate(self, **kwargs: Any) -> None:
        # pylint: disable=unused-argument
        try:
            await self._client.run_manual_scene_async(self._scene_key)
        except MIoTClientError as err:
            key = err.message if err.message in (
                'scene_unavailable', 'scene_busy', 'scene_failed',
                'scene_result_unknown') else 'scene_result_unknown'
            raise HomeAssistantError(
                translation_domain=DOMAIN, translation_key=key) from None
