"""Runtime tests for the Xiaomi Home MIoT action service."""
# pylint: disable=redefined-outer-name,protected-access
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

import pytest
import voluptuous as vol

from homeassistant.auth.permissions import PolicyPermissions
from homeassistant.core import Context, HomeAssistant
from homeassistant.exceptions import (
    HomeAssistantError,
    ServiceValidationError,
    Unauthorized,
)
from custom_components.xiaomi_home.miot.const import (
    DATA_ACTION_ENTITIES,
    DOMAIN,
)
from custom_components.xiaomi_home.miot.miot_device import MIoTActionEntity
from custom_components.xiaomi_home.miot.miot_error import MIoTClientError
from custom_components.xiaomi_home.services import (
    SERVICE_EXECUTE_ACTION,
    async_setup_services,
)


class MockActionEntity(MIoTActionEntity):
    """Minimal loaded MIoT action entity for service tests."""

    def __init__(
        self,
        entity_id: str,
        *,
        available: bool = True,
        output: list | None = None,
    ) -> None:
        self.entity_id = entity_id
        self._attr_available = available
        self.spec = SimpleNamespace(
            iid=9,
            out=[
                SimpleNamespace(
                    iid=18,
                    name="temp-history-data",
                    format_=str,
                )
            ],
        )
        self.service = SimpleNamespace(iid=3)
        self.async_execute = AsyncMock(
            return_value=output if output is not None else [])


@pytest.fixture
def action_service(hass: HomeAssistant) -> HomeAssistant:
    """Register the Xiaomi Home action service."""
    hass.data.setdefault(DOMAIN, {})
    hass.data[DOMAIN][DATA_ACTION_ENTITIES] = {}
    async_setup_services(hass)
    return hass


def register_action(
    hass: HomeAssistant,
    entity: MockActionEntity,
) -> MockActionEntity:
    """Register a loaded action entity in the Xiaomi runtime registry."""
    entity.hass = hass
    hass.data[DOMAIN][DATA_ACTION_ENTITIES][entity.entity_id] = entity
    return entity


async def test_service_registered(action_service: HomeAssistant) -> None:
    """The public action service is registered."""
    assert action_service.services.has_service(DOMAIN, SERVICE_EXECUTE_ACTION)


async def test_response_and_no_response(action_service: HomeAssistant) -> None:
    """Execute an action with and without response data."""
    entity = register_action(
        action_service,
        MockActionEntity("button.test_action", output=["abc"]),
    )

    response = await action_service.services.async_call(
        DOMAIN,
        SERVICE_EXECUTE_ACTION,
        {"entity_id": entity.entity_id, "params": []},
        blocking=True,
        return_response=True,
    )

    assert response == {
        entity.entity_id: {
            "output": [
                {
                    "piid": 18,
                    "name": "temp-history-data",
                    "format": "str",
                    "value": "abc",
                }
            ],
            "raw_output": ["abc"],
        }
    }

    result = await action_service.services.async_call(
        DOMAIN,
        SERVICE_EXECUTE_ACTION,
        {"entity_id": entity.entity_id, "params": []},
        blocking=True,
        return_response=False,
    )

    assert result is None
    assert entity.async_execute.await_count == 2


async def test_empty_output_is_valid(action_service: HomeAssistant) -> None:
    """A successful action may legitimately return no output values."""
    entity = register_action(
        action_service,
        MockActionEntity("button.empty_action", output=[]),
    )

    response = await action_service.services.async_call(
        DOMAIN,
        SERVICE_EXECUTE_ACTION,
        {"entity_id": entity.entity_id, "params": []},
        blocking=True,
        return_response=True,
    )

    assert response == {
        entity.entity_id: {
            "output": [
                {
                    "piid": 18,
                    "name": "temp-history-data",
                    "format": "str",
                    "value": None,
                }
            ],
            "raw_output": [],
        }
    }


async def test_unavailable_entity_is_not_executed(
    action_service: HomeAssistant,
) -> None:
    """Home Assistant filters unavailable entities before execution."""
    entity = register_action(
        action_service,
        MockActionEntity("button.unavailable_action", available=False),
    )

    with pytest.raises(HomeAssistantError):
        await action_service.services.async_call(
            DOMAIN,
            SERVICE_EXECUTE_ACTION,
            {"entity_id": entity.entity_id, "params": []},
            blocking=True,
            return_response=True,
        )

    entity.async_execute.assert_not_awaited()


async def test_non_action_entity_is_not_executed(
    action_service: HomeAssistant,
) -> None:
    """Entities outside the loaded Xiaomi action registry do not match."""
    with pytest.raises(HomeAssistantError):
        await action_service.services.async_call(
            DOMAIN,
            SERVICE_EXECUTE_ACTION,
            {"entity_id": "button.not_an_action", "params": []},
            blocking=True,
            return_response=True,
        )


async def test_group_target_is_rejected_by_schema(
    action_service: HomeAssistant,
) -> None:
    """Expandable group targets cannot bypass the single-action contract."""
    with pytest.raises(vol.Invalid):
        await action_service.services.async_call(
            DOMAIN,
            SERVICE_EXECUTE_ACTION,
            {"entity_id": "group.xiaomi_actions", "params": []},
            blocking=True,
            return_response=True,
        )


async def test_multiple_targets_are_rejected(
    action_service: HomeAssistant,
) -> None:
    """The service contract accepts exactly one loaded action target."""
    first = register_action(
        action_service,
        MockActionEntity("button.first_action"),
    )
    second = register_action(
        action_service,
        MockActionEntity("button.second_action"),
    )

    with pytest.raises(vol.Invalid):
        await action_service.services.async_call(
            DOMAIN,
            SERVICE_EXECUTE_ACTION,
            {
                "entity_id": [first.entity_id, second.entity_id],
                "params": [],
            },
            blocking=True,
            return_response=True,
        )

    first.async_execute.assert_not_awaited()
    second.async_execute.assert_not_awaited()


async def test_permission_denial_prevents_execution(
    action_service: HomeAssistant,
) -> None:
    """Home Assistant enforces POLICY_CONTROL before the Xiaomi handler."""
    entity = register_action(
        action_service,
        MockActionEntity("button.protected_action"),
    )

    user = Mock(
        permissions=PolicyPermissions({}, None),
        is_admin=False,
    )
    with (
        patch(
            "homeassistant.auth.AuthManager.async_get_user",
            return_value=user,
        ),
        pytest.raises(Unauthorized),
    ):
        await action_service.services.async_call(
            DOMAIN,
            SERVICE_EXECUTE_ACTION,
            {"entity_id": entity.entity_id, "params": []},
            blocking=True,
            return_response=True,
            context=Context(user_id="test-user"),
        )

    entity.async_execute.assert_not_awaited()


async def test_real_parameter_validation_reaches_formatter(
    action_service: HomeAssistant,
) -> None:
    """Invalid params are rejected by the real MIoT action formatter."""
    entity = MIoTActionEntity.__new__(MIoTActionEntity)
    entity.entity_id = "button.real_validation"
    entity._attr_available = True
    entity._attr_name = "Real validation"
    entity.spec = SimpleNamespace(
        iid=9,
        in_=[SimpleNamespace(iid=1, name="level", format_=int)],
        out=[],
    )
    entity.service = SimpleNamespace(iid=3)
    entity.miot_device = SimpleNamespace(
        action_async=AsyncMock(return_value=[]))
    register_action(action_service, entity)

    with pytest.raises(
        ServiceValidationError,
        match="invalid value for level: expected int, got str",
    ):
        await action_service.services.async_call(
            DOMAIN,
            SERVICE_EXECUTE_ACTION,
            {"entity_id": entity.entity_id, "params": ["bad"]},
            blocking=True,
            return_response=True,
        )

    entity.miot_device.action_async.assert_not_awaited()


async def test_real_client_error_reaches_home_assistant_error(
    action_service: HomeAssistant,
) -> None:
    """MIoT client failures traverse the real action entity error chain."""
    entity = MIoTActionEntity.__new__(MIoTActionEntity)
    entity.entity_id = "button.real_client_error"
    entity._attr_available = True
    entity._attr_name = "Real client error"
    entity.spec = SimpleNamespace(iid=9, in_=[], out=[])
    entity.service = SimpleNamespace(iid=3)
    entity.miot_device = SimpleNamespace(
        action_async=AsyncMock(side_effect=MIoTClientError("client failed"))
    )
    register_action(action_service, entity)

    with pytest.raises(HomeAssistantError, match="client failed"):
        await action_service.services.async_call(
            DOMAIN,
            SERVICE_EXECUTE_ACTION,
            {"entity_id": entity.entity_id, "params": []},
            blocking=True,
            return_response=True,
        )

    entity.miot_device.action_async.assert_awaited_once_with(
        siid=3,
        aiid=9,
        in_list=[],
    )


async def test_loaded_registry_lifecycle(hass: HomeAssistant) -> None:
    """Check action entities add/remove themselves from the runtime registry."""
    hass.data.setdefault(DOMAIN, {})
    hass.data[DOMAIN][DATA_ACTION_ENTITIES] = {}

    entity = MockActionEntity("button.lifecycle_action")
    entity.hass = hass
    entity.miot_device = SimpleNamespace(
        sub_device_state=Mock(return_value=42),
        unsub_device_state=Mock(),
    )

    await MIoTActionEntity.async_added_to_hass(entity)

    assert hass.data[DOMAIN][DATA_ACTION_ENTITIES] == {
        entity.entity_id: entity
    }

    await MIoTActionEntity.async_will_remove_from_hass(entity)

    assert hass.data[DOMAIN][DATA_ACTION_ENTITIES] == {}
    entity.miot_device.unsub_device_state.assert_called_once()
