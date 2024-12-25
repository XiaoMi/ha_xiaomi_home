# -*- coding: utf-8 -*-
"""Unit test for miot_network.py."""
import pytest
import asyncio

# pylint: disable=import-outside-toplevel, unused-argument

@pytest.mark.asyncio
async def test_network_monitor_loop_async():
    """
    Test asynchronous network monitoring logic of MIoTNetwork.
    """

    from miot.miot_network import MIoTNetwork, InterfaceStatus, NetworkInfo

    # Initialize MIoTNetwork instance
    miot_net = MIoTNetwork()

    # Define handlers for network events
    async def handle_network_status_change(status: bool):
        print(f"Network status changed: {status}")

    async def handle_network_info_change(
        status: InterfaceStatus, info: NetworkInfo
    ):
        print(f"Network info changed: {status}, {info}")

    # Subscribe handlers to network events
    miot_net.sub_network_status(key="test", handler=handle_network_status_change)
    miot_net.sub_network_info(key="test", handler=handle_network_info_change)

    # Test the network monitoring functionality
    try:
        await miot_net.init_async(timeout=3)  
        await asyncio.sleep(3) 

        # Log current network state
        print(f"Network Status: {miot_net.network_status}")
        print(f"Network Info: {miot_net.network_info}")

    finally:
        # Ensure proper cleanup
        await miot_net.deinit_async()
