# -*- coding: utf-8 -*-
"""Response-capable Xiaomi Home services."""
from __future__ import annotations

from functools import partial

import voluptuous as vol

from homeassistant.const import ATTR_ENTITY_ID
from homeassistant.core import HassJob, HomeAssistant, ServiceCall, SupportsResponse
from homeassistant.exceptions import HomeAssistantError, ServiceValidationError
from homeassistant.helpers import config_validation as cv
from homeassistant.helpers.entity import Entity
from homeassistant.helpers.service import entity_service_call

from .miot.const import DATA_ACTION_ENTITIES, DOMAIN
from .miot.miot_device import MIoTActionEntity

SERVICE_EXECUTE_ACTION = 'execute_action'
ATTR_PARAMS = 'params'

SERVICE_EXECUTE_ACTION_SCHEMA = vol.Schema({
    vol.Required(ATTR_ENTITY_ID): vol.All(
        cv.entity_id,
        cv.entity_domain(['button', 'notify', 'text'])),
    vol.Optional(ATTR_PARAMS, default=[]): list,
})


async def _async_execute_action(
    entity: Entity, call: ServiceCall
) -> dict:
    """Execute one loaded MIoT action entity."""
    if not isinstance(entity, MIoTActionEntity):
        raise ServiceValidationError(
            'target is not a Xiaomi Home MIoT action entity')

    try:
        raw_output = await entity.async_execute(call.data[ATTR_PARAMS])
    except ValueError as err:
        raise ServiceValidationError(str(err)) from err
    except RuntimeError as err:
        raise HomeAssistantError(str(err)) from err

    raw_output = raw_output or []
    if not call.return_response:
        return {}

    return {
        'output': [
            {
                'piid': prop.iid,
                'name': prop.name,
                'format': prop.format_.__name__,
                'value': (
                    raw_output[index]
                    if index < len(raw_output) else None),
            }
            for index, prop in enumerate(entity.spec.out)
        ],
        # Preserve the protocol payload if it diverges from the MIoT spec.
        'raw_output': raw_output,
    }


def async_setup_services(hass: HomeAssistant) -> None:
    """Set up Xiaomi Home services."""
    hass.services.async_register(
        DOMAIN,
        SERVICE_EXECUTE_ACTION,
        partial(
            entity_service_call,
            hass,
            hass.data[DOMAIN][DATA_ACTION_ENTITIES],
            HassJob(
                _async_execute_action,
                f'{DOMAIN}.{SERVICE_EXECUTE_ACTION}')),
        schema=SERVICE_EXECUTE_ACTION_SCHEMA,
        supports_response=SupportsResponse.OPTIONAL)
