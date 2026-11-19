"""Test missed cloud availability pushes without live devices."""

# Tests intentionally inspect client-internal timers and state.
# pylint: disable=protected-access, unused-argument
import importlib.util
import asyncio
import copy
from pathlib import Path
import sys
import unittest
from types import ModuleType, SimpleNamespace as NS
from unittest.mock import AsyncMock, Mock, patch

import pytest

pytestmark = pytest.mark.github
MODULE = None
DEVICE_STATE = CTRL_MODE = None


def load():
    """Import the production client; only optional HA imports are stubbed.

    The session fixture prepares the real miot dependency modules. Do not copy
    method implementations or require a running Home Assistant instance.
    """
    global MODULE, DEVICE_STATE, CTRL_MODE  # pylint: disable=global-statement
    if MODULE is None:
        stubs = {
            name: ModuleType(name)
            for name in [
                "homeassistant",
                "homeassistant.core",
                "homeassistant.components",
                "homeassistant.components.zeroconf",
            ]
        }
        stubs["homeassistant.core"].HomeAssistant = Mock
        source = (
            Path(__file__).resolve().parents[1]
            / "custom_components/xiaomi_home/miot/miot_client.py"
        )
        spec = importlib.util.spec_from_file_location(
            "miot.miot_client", source
        )
        module = importlib.util.module_from_spec(spec)
        with patch.dict(sys.modules, stubs):
            spec.loader.exec_module(module)
        MODULE = module
        DEVICE_STATE, CTRL_MODE = module.MIoTDeviceState, module.CtrlMode
    return MODULE


class Handle:
    """Deterministic cancellable timer."""

    def __init__(self, delay, fn):
        self.delay, self.fn, self.cancelled = delay, fn, False

    def cancel(self):
        self.cancelled = True


class Clock:
    """Manual event-loop clock; only explicit firing creates tasks."""

    def __init__(self):
        self.handles = []
        self.tasks = []

    def call_later(self, delay, fn):
        h = Handle(delay, fn)
        self.handles.append(h)
        return h

    def create_task(self, coro):
        t = asyncio.create_task(coro)
        self.tasks.append(t)
        return t

    async def fire(self, h):
        assert not h.cancelled
        h.fn()
        await asyncio.gather(*self.tasks)
        self.tasks.clear()


def client():
    module = load()
    c = module.MIoTClient.__new__(module.MIoTClient)
    c._main_loop = Clock()
    c._uid, c._cloud_server = "test", "cn"
    c._entry_data = {"home_selected": {"home": {}}}
    c._ctrl_mode = CTRL_MODE.CLOUD
    c._refresh_cloud_devices_timer = None
    c._refresh_cloud_devices_running = c._refresh_cloud_devices_stopped = False
    c._device_list_cache = {"lamp": {"did": "lamp", "online": False}}
    c._device_list_cloud = copy.deepcopy(c._device_list_cache)
    c._device_list_gateway, c._device_list_lan = {}, {}
    c._sub_device_state = {"lamp": NS(handler=Mock(), handler_ctx=None)}
    c._storage = NS(save_async=AsyncMock(return_value=True))
    c._http = NS(
        get_devices_async=AsyncMock(return_value={"devices": {}}),
        get_devices_with_dids_async=AsyncMock(return_value={}),
        deinit_async=AsyncMock(),
    )
    c._network = NS(network_status=True, unsub_network_status=Mock())
    c._miot_lan = NS(init_done=False, update_devices=Mock())
    c._i18n = NS(translate=lambda key: key)
    c._MIoTClient__show_client_error_notify = Mock()
    c._MIoTClient__request_show_devices_changed_notify = Mock()
    c._MIoTClient__update_device_msg_sub = Mock()
    c._MIoTClient__gen_notify_key = lambda x: x
    c._persistence_notify = Mock()
    c._mips_cloud = NS(
        unsub_mips_state=Mock(),
        deinit=Mock(),
        connect=Mock(),
        disconnect=Mock(),
    )
    c._oauth = NS(deinit_async=AsyncMock())
    c._refresh_props_timer = c._refresh_token_timer = c._refresh_cert_timer = (
        None
    )
    c._show_devices_changed_notify_timer = None
    c._refresh_props_list = {}
    c.refresh_oauth_info_async = AsyncMock(return_value=True)
    c.refresh_user_cert_async = AsyncMock(return_value=True)
    return c


class Recovery(unittest.IsolatedAsyncioTestCase):
    """Exercise the production cloud refresh and lifecycle methods."""

    async def refresh(self, c, **kwargs):
        await c._MIoTClient__refresh_cloud_devices_async(**kwargs)

    async def test_successful_discovery_schedules_status_fallback(self):
        c = client()
        c._http.get_devices_async.return_value = {
            "devices": {"lamp": {"online": False}}
        }
        await self.refresh(c)
        self.assertEqual(c._refresh_cloud_devices_timer.delay, 30)

    def test_constructor_initializes_recovery_guards(self):
        module = load()
        c = module.MIoTClient(
            entry_id="test",
            entry_data={"uid": "test", "cloud_server": "cn"},
            network=Mock(spec=module.MIoTNetwork),
            storage=Mock(spec=module.MIoTStorage),
            mips_service=Mock(spec=module.MipsService),
            miot_lan=Mock(),
            loop=Clock(),
        )
        self.assertFalse(c._refresh_cloud_devices_running)
        self.assertFalse(c._refresh_cloud_devices_stopped)

    async def test_missed_online_push_recovers_on_tick(self):
        c = client()
        c._http.get_devices_async.return_value = {
            "devices": {"lamp": {"online": False}}
        }
        c._http.get_devices_with_dids_async.side_effect = lambda **_kw: {
            "lamp": {"online": True}
        }
        await self.refresh(c)
        h = c._refresh_cloud_devices_timer
        self.assertEqual(h.delay, 30)
        await c._main_loop.fire(h)
        self.assertTrue(c._device_list_cache["lamp"]["online"])
        c._sub_device_state["lamp"].handler.assert_called_once_with(
            "lamp", DEVICE_STATE.ONLINE, None
        )
        c._http.get_devices_with_dids_async.assert_awaited_once_with(
            dids=["lamp"]
        )
        self.assertEqual(c._http.get_devices_async.await_count, 1)
        self.assertEqual(c._refresh_cloud_devices_timer.delay, 30)
        # Unchanged online state does not trigger another property refresh.
        await c._main_loop.fire(c._refresh_cloud_devices_timer)
        self.assertEqual(c._sub_device_state["lamp"].handler.call_count, 1)

    async def test_missed_offline_push_or_removal(self):
        for devices, expected in [
            ({"lamp": {"online": False}}, False),
            ({}, None),
        ]:
            with self.subTest(devices=devices):
                c = client()
                c._device_list_cache["lamp"]["online"] = True
                c._device_list_cloud["lamp"]["online"] = True
                c._http.get_devices_with_dids_async.return_value = devices
                await self.refresh(c, reconcile_only=True)
                self.assertIs(c._device_list_cache["lamp"]["online"], expected)
                c._sub_device_state["lamp"].handler.assert_called_once_with(
                    "lamp", DEVICE_STATE.OFFLINE, None
                )

    async def test_cloud_offline_does_not_override_lan_online(self):
        c = client()
        c._device_list_cache["lamp"]["online"] = True
        c._device_list_lan["lamp"] = {"online": True}
        c._http.get_devices_with_dids_async.return_value = {
            "lamp": {"online": False}
        }
        await self.refresh(c, reconcile_only=True)
        self.assertTrue(c._device_list_cache["lamp"]["online"])
        c._sub_device_state["lamp"].handler.assert_not_called()

    async def test_ble_and_proxy_conventions_preserved(self):
        c = client()
        c._device_list_cache = {
            did: {"online": False} for did in ["blt.1", "proxy.1"]
        }
        c._device_list_cloud = copy.deepcopy(c._device_list_cache)
        c._http.get_devices_with_dids_async.return_value = copy.deepcopy(
            c._device_list_cache
        )
        await self.refresh(c, reconcile_only=True)
        self.assertTrue(
            all(v["online"] for v in c._device_list_cache.values())
        )

    async def test_mqtt_push_remains_immediate(self):
        c = client()
        c._MIoTClient__on_cloud_device_state_changed(
            "lamp", DEVICE_STATE.ONLINE, None
        )
        c._sub_device_state["lamp"].handler.assert_called_once_with(
            "lamp", DEVICE_STATE.ONLINE, None
        )
        c._http.get_devices_async.assert_not_awaited()

    async def test_invalid_http_payload_retains_state_and_retries(self):
        for response in [None, {}, [], {"devices": None}, {"devices": []}]:
            with self.subTest(response=response):
                c = client()
                c._http.get_devices_async.return_value = response
                await self.refresh(c)
                self.assertFalse(c._device_list_cache["lamp"]["online"])
                self.assertEqual(c._refresh_cloud_devices_timer.delay, 60)
                c._storage.save_async.assert_not_awaited()

    async def test_failed_batch_retains_state_and_retries(self):
        c = client()
        c._http.get_devices_with_dids_async.return_value = None
        await self.refresh(c, reconcile_only=True)
        self.assertFalse(c._device_list_cache["lamp"]["online"])
        self.assertEqual(c._refresh_cloud_devices_timer.delay, 60)

    async def test_exception_retry_then_recovery(self):
        c = client()
        c._http.get_devices_async.side_effect = OSError("test cloud outage")
        with self.assertLogs("miot.miot_client", level="ERROR"):
            await self.refresh(c)
        self.assertEqual(c._refresh_cloud_devices_timer.delay, 60)
        c._http.get_devices_with_dids_async.return_value = {
            "lamp": {"online": True}
        }
        await c._main_loop.fire(c._refresh_cloud_devices_timer)
        self.assertTrue(c._device_list_cache["lamp"]["online"])
        self.assertEqual(c._refresh_cloud_devices_timer.delay, 30)

    async def test_no_concurrent_refreshes(self):
        c = client()
        gate = asyncio.Event()

        async def slow(**kwargs):
            await gate.wait()
            return {"lamp": {"online": True}}

        c._http.get_devices_with_dids_async.side_effect = slow
        task = asyncio.create_task(self.refresh(c, reconcile_only=True))
        await asyncio.sleep(0)
        await self.refresh(c, reconcile_only=True)
        self.assertEqual(c._http.get_devices_with_dids_async.await_count, 1)
        gate.set()
        await task
        self.assertEqual(len(c._main_loop.handles), 1)

    async def test_network_loss_cancels_and_return_restarts_refresh(self):
        c = client()
        await self.refresh(c)
        h = c._refresh_cloud_devices_timer
        c._network.network_status = False
        await c._MIoTClient__on_network_status_changed(False)
        self.assertTrue(h.cancelled)
        self.assertIsNone(c._refresh_cloud_devices_timer)
        await self.refresh(c)
        self.assertEqual(c._http.get_devices_async.await_count, 1)
        c._network.network_status = True
        await c._MIoTClient__on_network_status_changed(True)
        self.assertEqual(c._refresh_cloud_devices_timer.delay, 6)
        c._MIoTClient__request_refresh_cloud_devices(immediately=True)
        self.assertEqual(c._refresh_cloud_devices_timer.delay, 0)

    async def test_unload_cancels_timer_and_late_response_is_ignored(self):
        c = client()
        c._http.get_devices_async.return_value = {
            "devices": {"lamp": {"online": False}}
        }
        await self.refresh(c)
        h = c._refresh_cloud_devices_timer
        gate = asyncio.Event()

        async def slow(**kwargs):
            await gate.wait()
            return {"lamp": {"online": True}}

        c._http.get_devices_with_dids_async.side_effect = slow
        task = asyncio.create_task(self.refresh(c, reconcile_only=True))
        await asyncio.sleep(0)
        await c.deinit_async()
        self.assertTrue(h.cancelled)
        gate.set()
        await task
        self.assertFalse(c._device_list_cache["lamp"]["online"])
        self.assertIsNone(c._refresh_cloud_devices_timer)
        c._sub_device_state["lamp"].handler.assert_not_called()
        c._MIoTClient__request_refresh_cloud_devices(immediately=True)
        self.assertIsNone(c._refresh_cloud_devices_timer)

    async def test_network_loss_during_request_drops_late_response(self):
        c = client()

        async def lose_network(**kwargs):
            c._network.network_status = False
            return {"lamp": {"online": True}}

        c._http.get_devices_with_dids_async.side_effect = lose_network
        await self.refresh(c, reconcile_only=True)
        self.assertFalse(c._device_list_cache["lamp"]["online"])
        self.assertIsNone(c._refresh_cloud_devices_timer)

    async def test_reconnect_replaces_pending_timer(self):
        c = client()
        await self.refresh(c)
        old = c._refresh_cloud_devices_timer
        c._MIoTClient__request_refresh_cloud_devices(immediately=True)
        self.assertTrue(old.cancelled)
        self.assertEqual(c._refresh_cloud_devices_timer.delay, 0)


if __name__ == "__main__":
    unittest.main()
