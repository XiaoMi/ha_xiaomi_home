# -*- coding: utf-8 -*-
"""Unit test for miot_network.py."""
import logging
import pytest
import asyncio

_LOGGER = logging.getLogger(__name__)

# pylint: disable=import-outside-toplevel, unused-argument


@pytest.mark.asyncio
async def test_network_monitor_loop_async():
    from miot.miot_network import MIoTNetwork, InterfaceStatus, NetworkInfo
    miot_net = MIoTNetwork()

    async def on_network_status_changed(status: bool):
        _LOGGER.info('on_network_status_changed, %s', status)
    miot_net.sub_network_status(key='test', handler=on_network_status_changed)

    async def on_network_info_changed(
            status: InterfaceStatus, info: NetworkInfo):
        _LOGGER.info('on_network_info_changed, %s, %s', status, info)
    miot_net.sub_network_info(key='test', handler=on_network_info_changed)

    await miot_net.init_async()
    await asyncio.sleep(3)
    _LOGGER.info('net status: %s', miot_net.network_status)
    _LOGGER.info('net info: %s', miot_net.network_info)
    await miot_net.deinit_async()
