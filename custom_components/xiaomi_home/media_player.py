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

Media player entities for Xiaomi Home.
"""
from __future__ import annotations
import logging
from typing import Optional

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.components.media_player import (MediaPlayerEntity,
                                                   MediaPlayerEntityFeature,
                                                   MediaPlayerDeviceClass,
                                                   MediaPlayerState, MediaType)

from .miot.const import DOMAIN
from .miot.miot_device import MIoTDevice, MIoTServiceEntity, MIoTEntityData
from .miot.miot_spec import MIoTSpecProperty, MIoTSpecAction

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(hass: HomeAssistant, config_entry: ConfigEntry,
                            async_add_entities: AddEntitiesCallback) -> None:
    """Set up a config entry."""
    device_list: list[MIoTDevice] = hass.data[DOMAIN]['devices'][
        config_entry.entry_id]

    new_entities = []
    for miot_device in device_list:
        for data in miot_device.entity_list.get('wifi-speaker', []):
            new_entities.append(
                WifiSpeaker(miot_device=miot_device, entity_data=data))
        for data in miot_device.entity_list.get('television', []):
            new_entities.append(
                Television(miot_device=miot_device, entity_data=data))

    if new_entities:
        async_add_entities(new_entities)


class FeatureVolumeMute(MIoTServiceEntity, MediaPlayerEntity):
    """VOLUME_MUTE feature of the media player entity."""
    _prop_mute: Optional[MIoTSpecProperty]

    def __init__(self, miot_device: MIoTDevice,
                 entity_data: MIoTEntityData) -> None:
        """Initialize the feature class."""
        self._prop_mute = None

        super().__init__(miot_device=miot_device, entity_data=entity_data)
        # properties
        for prop in entity_data.props:
            if prop.name == 'mute':
                self._attr_supported_features |= (
                    MediaPlayerEntityFeature.VOLUME_MUTE)
                self._prop_mute = prop

    @property
    def is_volume_muted(self) -> Optional[bool]:
        """True if volume is currently muted."""
        return self.get_prop_value(
            prop=self._prop_mute) if self._prop_mute else None

    async def async_mute_volume(self, mute: bool) -> None:
        """Mute the volume."""
        await self.set_property_async(prop=self._prop_mute, value=mute)


class FeatureVolumeSet(MIoTServiceEntity, MediaPlayerEntity):
    """VOLUME_SET feature of the media player entity."""
    _prop_volume: Optional[MIoTSpecProperty]
    _volume_value_min: Optional[float]
    _volume_value_max: Optional[float]
    _volume_value_range: Optional[float]

    def __init__(self, miot_device: MIoTDevice,
                 entity_data: MIoTEntityData) -> None:
        """Initialize the feature class."""
        self._prop_volume = None
        self._volume_value_min = None
        self._volume_value_max = None
        self._volume_value_range = None

        super().__init__(miot_device=miot_device, entity_data=entity_data)
        # properties
        for prop in entity_data.props:
            if prop.name == 'volume':
                if not prop.value_range:
                    _LOGGER.error('invalid volume value_range format, %s',
                                  self.entity_id)
                    continue
                self._volume_value_min = prop.value_range.min_
                self._volume_value_max = prop.value_range.max_
                self._volume_value_range = (prop.value_range.max_ -
                                            prop.value_range.min_)
                self._attr_volume_step = (prop.value_range.step /
                                          self._volume_value_range)
                self._attr_supported_features |= (
                    MediaPlayerEntityFeature.VOLUME_SET |
                    MediaPlayerEntityFeature.VOLUME_STEP)
                self._prop_volume = prop

    async def async_set_volume_level(self, volume: float) -> None:
        """Set volume level."""
        value = volume * self._volume_value_range + self._volume_value_min
        if value > self._volume_value_max:
            value = self._volume_value_max
        elif value < self._volume_value_min:
            value = self._volume_value_min
        await self.set_property_async(prop=self._prop_volume, value=value)

    @property
    def volume_level(self) -> Optional[float]:
        """The current volume level, range [0, 1]."""
        value = self.get_prop_value(
            prop=self._prop_volume) if self._prop_volume else None
        if value is None:
            return None
        return (value - self._volume_value_min) / self._volume_value_range


class FeaturePlay(MIoTServiceEntity, MediaPlayerEntity):
    """PLAY feature of the media player entity."""
    _action_play: Optional[MIoTSpecAction]

    def __init__(self, miot_device: MIoTDevice,
                 entity_data: MIoTEntityData) -> None:
        """Initialize the feature class."""
        self._action_play = None

        super().__init__(miot_device=miot_device, entity_data=entity_data)
        # actions
        for act in entity_data.actions:
            if act.name == 'play':
                self._attr_supported_features |= (MediaPlayerEntityFeature.PLAY)
                self._action_play = act

    async def async_media_play(self) -> None:
        """Send play command."""
        await self.action_async(action=self._action_play)


class FeaturePause(MIoTServiceEntity, MediaPlayerEntity):
    """PAUSE feature of the media player entity."""
    _action_pause: Optional[MIoTSpecAction]

    def __init__(self, miot_device: MIoTDevice,
                 entity_data: MIoTEntityData) -> None:
        """Initialize the feature class."""
        self._action_pause = None

        super().__init__(miot_device=miot_device, entity_data=entity_data)
        # actions
        for act in entity_data.actions:
            if act.name == 'pause':
                self._attr_supported_features |= (
                    MediaPlayerEntityFeature.PAUSE)
                self._action_pause = act

    async def async_media_pause(self) -> None:
        """Send pause command."""
        await self.action_async(action=self._action_pause)


class FeatureStop(MIoTServiceEntity, MediaPlayerEntity):
    """STOP feature of the media player entity."""
    _action_stop: Optional[MIoTSpecAction]

    def __init__(self, miot_device: MIoTDevice,
                 entity_data: MIoTEntityData) -> None:
        """Initialize the feature class."""
        self._action_stop = None

        super().__init__(miot_device=miot_device, entity_data=entity_data)
        # actions
        for act in entity_data.actions:
            if act.name == 'stop':
                self._attr_supported_features |= (MediaPlayerEntityFeature.STOP)
                self._action_stop = act

    async def async_media_stop(self) -> None:
        """Send stop command."""
        await self.action_async(action=self._action_stop)


class FeatureNextTrack(MIoTServiceEntity, MediaPlayerEntity):
    """NEXT_TRACK feature of the media player entity."""
    _action_next: Optional[MIoTSpecAction]

    def __init__(self, miot_device: MIoTDevice,
                 entity_data: MIoTEntityData) -> None:
        """Initialize the feature class."""
        self._action_next = None

        super().__init__(miot_device=miot_device, entity_data=entity_data)
        # actions
        for act in entity_data.actions:
            if act.name == 'next':
                self._attr_supported_features |= (
                    MediaPlayerEntityFeature.NEXT_TRACK)
                self._action_next = act

    async def async_media_next_track(self) -> None:
        """Send next track command."""
        await self.action_async(action=self._action_next)


class FeaturePreviousTrack(MIoTServiceEntity, MediaPlayerEntity):
    """PREVIOUS_TRACK feature of the media player entity."""
    _action_previous: Optional[MIoTSpecAction]

    def __init__(self, miot_device: MIoTDevice,
                 entity_data: MIoTEntityData) -> None:
        """Initialize the feature class."""
        self._action_previous = None

        super().__init__(miot_device=miot_device, entity_data=entity_data)
        # actions
        for act in entity_data.actions:
            if act.name == 'previous':
                self._attr_supported_features |= (
                    MediaPlayerEntityFeature.PREVIOUS_TRACK)
                self._action_previous = act

    async def async_media_previous_track(self) -> None:
        """Send previous track command."""
        await self.action_async(action=self._action_previous)


class FeatureSoundMode(MIoTServiceEntity, MediaPlayerEntity):
    """SELECT_SOUND_MODE feature of the media player entity."""
    _prop_play_loop_mode: Optional[MIoTSpecProperty]
    _sound_mode_map: Optional[dict[int, str]]

    def __init__(self, miot_device: MIoTDevice,
                 entity_data: MIoTEntityData) -> None:
        """Initialize the feature class."""
        self._prop_play_loop_mode = None
        self._sound_mode_map = None

        super().__init__(miot_device=miot_device, entity_data=entity_data)
        # properties
        for prop in entity_data.props:
            if prop.name == 'play-loop-mode':
                if not prop.value_list:
                    _LOGGER.error('invalid play-loop-mode value_list, %s',
                                  self.entity_id)
                    continue
                self._sound_mode_map = prop.value_list.to_map()
                self._attr_sound_mode_list = list(self._sound_mode_map.values())
                self._attr_supported_features |= (
                    MediaPlayerEntityFeature.SELECT_SOUND_MODE)
                self._prop_play_loop_mode = prop

    async def async_select_sound_mode(self, sound_mode: str):
        """Switch the sound mode of the entity."""
        await self.set_property_async(prop=self._prop_play_loop_mode,
                                      value=self.get_map_key(
                                          map_=self._sound_mode_map,
                                          value=sound_mode))

    @property
    def sound_mode(self) -> Optional[str]:
        """The current sound mode."""
        return (self.get_map_value(map_=self._sound_mode_map,
                                   key=self.get_prop_value(
                                       prop=self._prop_play_loop_mode))
                if self._prop_play_loop_mode else None)


class FeatureTurnOn(MIoTServiceEntity, MediaPlayerEntity):
    """TURN_ON feature of the media player entity."""
    _action_turn_on: Optional[MIoTSpecAction]

    def __init__(self, miot_device: MIoTDevice,
                 entity_data: MIoTEntityData) -> None:
        """Initialize the feature class."""
        self._action_turn_on = None

        super().__init__(miot_device=miot_device, entity_data=entity_data)
        # actions
        for act in entity_data.actions:
            if act.name == 'turn-on':
                self._attr_supported_features |= (
                    MediaPlayerEntityFeature.TURN_ON)
                self._action_turn_on = act

    async def async_turn_on(self) -> None:
        """Turn the media player on."""
        await self.action_async(action=self._action_turn_on)


class FeatureTurnOff(MIoTServiceEntity, MediaPlayerEntity):
    """TURN_OFF feature of the media player entity."""
    _action_turn_off: Optional[MIoTSpecAction]

    def __init__(self, miot_device: MIoTDevice,
                 entity_data: MIoTEntityData) -> None:
        """Initialize the feature class."""
        self._action_turn_off = None

        super().__init__(miot_device=miot_device, entity_data=entity_data)
        # actions
        for act in entity_data.actions:
            if act.name == 'turn-off':
                self._attr_supported_features |= (
                    MediaPlayerEntityFeature.TURN_OFF)
                self._action_turn_off = act

    async def async_turn_off(self) -> None:
        """Turn the media player off."""
        await self.action_async(action=self._action_turn_off)


class FeatureSource(MIoTServiceEntity, MediaPlayerEntity):
    """SELECT_SOURCE feature of the media player entity."""
    _prop_input_control: Optional[MIoTSpecProperty]
    _input_source_map: Optional[dict[int, str]]

    def __init__(self, miot_device: MIoTDevice,
                 entity_data: MIoTEntityData) -> None:
        """Initialize the feature class."""
        self._prop_input_control = None
        self._input_source_map = None

        super().__init__(miot_device=miot_device, entity_data=entity_data)
        # properties
        for prop in entity_data.props:
            if prop.name == 'input-control':
                if not prop.value_list:
                    _LOGGER.error('invalid input-control value_list, %s',
                                  self.entity_id)
                    continue
                self._input_source_map = prop.value_list.to_map()
                self._attr_source_list = list(self._input_source_map.values())
                self._attr_supported_features |= (
                    MediaPlayerEntityFeature.SELECT_SOURCE)
                self._prop_input_control = prop

    async def async_select_source(self, source: str) -> None:
        """Select input source."""
        await self.set_property_async(prop=self._prop_input_control,
                                      value=self.get_map_key(
                                          map_=self._input_source_map,
                                          value=source))

    @property
    def source(self) -> Optional[str]:
        """The current input source."""
        return (self.get_map_value(map_=self._input_source_map,
                                   key=self.get_prop_value(
                                       prop=self._prop_input_control))
                if self._prop_input_control else None)


class FeatureState(MIoTServiceEntity, MediaPlayerEntity):
    """States feature of the media player entity."""
    _prop_playing_state: Optional[MIoTSpecProperty]
    _playing_state_map: Optional[dict[int, str]]

    def __init__(self, miot_device: MIoTDevice,
                 entity_data: MIoTEntityData) -> None:
        """Initialize the feature class."""
        self._prop_playing_state = None
        self._playing_state_map = None

        super().__init__(miot_device=miot_device, entity_data=entity_data)
        # properties
        for prop in entity_data.props:
            if prop.name == 'playing-state':
                if not prop.value_list:
                    _LOGGER.error('invalid mode value_list, %s', self.entity_id)
                    continue
                self._playing_state_map = {}
                for item in prop.value_list.items:
                    if item.name in {'off'}:
                        self._playing_state_map[
                            item.value] = MediaPlayerState.OFF
                    elif item.name in {'idle', 'stop', 'stopped'}:
                        self._playing_state_map[
                            item.value] = MediaPlayerState.IDLE
                    elif item.name in {'playing'}:
                        self._playing_state_map[
                            item.value] = MediaPlayerState.PLAYING
                    elif item.name in {'pause', 'paused'}:
                        self._playing_state_map[
                            item.value] = MediaPlayerState.PAUSED
                self._prop_playing_state = prop

    @property
    def state(self) -> Optional[MediaPlayerState]:
        """The current state."""
        current_state = self.get_prop_value(
            prop=self._prop_playing_state) if self._prop_playing_state else None
        return (MediaPlayerState.ON if
                (current_state is None) else self.get_map_value(
                    map_=self._playing_state_map, key=current_state))


class WifiSpeaker(FeatureVolumeSet, FeatureVolumeMute, FeaturePlay,
                  FeaturePause, FeatureStop, FeatureNextTrack,
                  FeaturePreviousTrack, FeatureSoundMode, FeatureState):
    """WiFi speaker, aka XiaoAI sound speaker."""

    def __init__(self, miot_device: MIoTDevice,
                 entity_data: MIoTEntityData) -> None:
        """Initialize the device."""
        super().__init__(miot_device=miot_device, entity_data=entity_data)

        self._attr_device_class = MediaPlayerDeviceClass.SPEAKER
        self._attr_media_content_type = MediaType.MUSIC


class Television(FeatureVolumeSet, FeatureVolumeMute, FeaturePlay, FeaturePause,
                 FeatureStop, FeatureNextTrack, FeaturePreviousTrack,
                 FeatureSoundMode, FeatureState, FeatureSource, FeatureTurnOn,
                 FeatureTurnOff):
    """Television"""

    def __init__(self, miot_device: MIoTDevice,
                 entity_data: MIoTEntityData) -> None:
        """Initialize the device."""
        super().__init__(miot_device=miot_device, entity_data=entity_data)

        self._attr_device_class = MediaPlayerDeviceClass.TV
        self._attr_media_content_type = MediaType.VIDEO
