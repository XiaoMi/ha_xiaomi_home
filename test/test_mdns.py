# -*- coding: utf-8 -*-
"""Unit test for miot_mdns.py."""
import asyncio
import logging
import pytest
from zeroconf import IPVersion
from zeroconf.asyncio import AsyncZeroconf

_LOGGER = logging.getLogger(__name__)

# pylint: disable=import-outside-toplevel, unused-argument


@pytest.mark.asyncio
async def test_service_loop_async():
    from miot.miot_mdns import MipsService, MipsServiceState

    async def on_service_state_change(
            group_id: str, state: MipsServiceState, data: dict):
        _LOGGER.info(
            'on_service_state_change, %s, %s, %s', group_id, state, data)

    async with AsyncZeroconf(ip_version=IPVersion.V4Only) as aiozc:
        mips_service = MipsService(aiozc)
        mips_service.sub_service_change('test', '*', on_service_state_change)
        await mips_service.init_async()
        # Wait for service to discover
        await asyncio.sleep(3)
        services_detail = mips_service.get_services()
        _LOGGER.info('get all service, %s', list(services_detail.keys()))
        for name, data in services_detail.items():
            _LOGGER.info(
                '\tinfo, %s, %s, %s, %s',
                name, data['did'], data['addresses'], data['port'])
        await mips_service.deinit_async()
