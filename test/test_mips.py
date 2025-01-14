# -*- coding: utf-8 -*-
"""Unit test for miot_mips.py.
NOTICE: When running this test case, you need to run test_cloud.py first to 
obtain the token and certificate information, and at the same time avoid data 
deletion.
"""
import ipaddress
from typing import Any, Tuple
import pytest
import asyncio
import logging

_LOGGER = logging.getLogger(__name__)


# pylint: disable = import-outside-toplevel, unused-argument

@pytest.mark.parametrize('central_info', [
    ('<Group id>', 'Gateway did', 'Gateway ip', 8883),
])
@pytest.mark.asyncio
async def test_mips_local_async(
    test_cache_path: str,
    test_domain_cloud_cache: str,
    test_name_uid: str,
    test_name_rd_did: str,
    central_info: Tuple[str, str, str, int]
):
    """
    NOTICE:
    - Mips local is used to connect to the central gateway and is only 
    supported in the Chinese mainland region.
    - Before running this test case, you need to run test_mdns.py first to 
    obtain the group_id, did, ip, and port of the hub, and then fill in this 
    information in the parametrize. you can enter multiple central connection 
    information items for separate tests.
    - This test case requires running test_cloud.py first to obtain the
    central connection certificate.
    - This test case will control the indicator light switch of the central
    gateway.
    """
    from miot.miot_storage import MIoTStorage, MIoTCert
    from miot.miot_mips import MipsLocalClient

    central_group_id: str = central_info[0]
    assert isinstance(central_group_id, str)
    central_did: str = central_info[1]
    assert central_did.isdigit()
    central_ip: str = central_info[2]
    assert ipaddress.ip_address(central_ip)
    central_port: int = central_info[3]
    assert isinstance(central_port, int)

    miot_storage = MIoTStorage(test_cache_path)
    uid = await miot_storage.load_async(
        domain=test_domain_cloud_cache, name=test_name_uid, type_=str)
    assert isinstance(uid, str)
    random_did = await miot_storage.load_async(
        domain=test_domain_cloud_cache, name=test_name_rd_did, type_=str)
    assert isinstance(random_did, str)
    miot_cert = MIoTCert(storage=miot_storage, uid=uid, cloud_server='CN')
    assert miot_cert.ca_file
    assert miot_cert.cert_file
    assert miot_cert.key_file
    _LOGGER.info(
        'cert info, %s, %s, %s', miot_cert.ca_file, miot_cert.cert_file,
        miot_cert.key_file)

    mips_local = MipsLocalClient(
        did=random_did,
        host=central_ip,
        group_id=central_group_id,
        ca_file=miot_cert.ca_file,
        cert_file=miot_cert.cert_file,
        key_file=miot_cert.key_file,
        port=central_port,
        home_name='mips local test')
    mips_local.enable_logger(logger=_LOGGER)
    mips_local.enable_mqtt_logger(logger=_LOGGER)

    async def on_mips_state_changed_async(key: str, state: bool):
        _LOGGER.info('on mips state changed, %s, %s', key, state)

    async def on_dev_list_changed_async(
        mips: MipsLocalClient, did_list: list[str]
    ):
        _LOGGER.info('dev list changed, %s', did_list)

    def on_prop_changed(payload: dict, ctx: Any):
        _LOGGER.info('prop changed, %s=%s', ctx, payload)

    def on_event_occurred(payload: dict, ctx: Any):
        _LOGGER.info('event occurred, %s=%s', ctx, payload)

    # Reg mips state
    mips_local.sub_mips_state(
        key='mips_local', handler=on_mips_state_changed_async)
    mips_local.on_dev_list_changed = on_dev_list_changed_async
    # Connect
    await mips_local.connect_async()
    await asyncio.sleep(0.5)
    # Get device list
    device_list = await mips_local.get_dev_list_async()
    assert isinstance(device_list, dict)
    _LOGGER.info(
        'get_dev_list, %d, %s', len(device_list), list(device_list.keys()))
    # Sub Prop
    mips_local.sub_prop(
        did=central_did, handler=on_prop_changed,
        handler_ctx=f'{central_did}.*')
    # Sub Event
    mips_local.sub_event(
        did=central_did, handler=on_event_occurred,
        handler_ctx=f'{central_did}.*')
    # Get/set prop
    test_siid = 3
    test_piid = 1
    # mips_local.sub_prop(
    #     did=central_did, siid=test_siid, piid=test_piid,
    #     handler=on_prop_changed,
    #     handler_ctx=f'{central_did}.{test_siid}.{test_piid}')
    result1 = await mips_local.get_prop_async(
        did=central_did, siid=test_siid, piid=test_piid)
    assert isinstance(result1, bool)
    _LOGGER.info('get prop.%s.%s, value=%s', test_siid, test_piid, result1)
    result2 = await mips_local.set_prop_async(
        did=central_did, siid=test_siid, piid=test_piid, value=not result1)
    _LOGGER.info(
        'set prop.%s.%s=%s, result=%s',
        test_siid, test_piid, not result1, result2)
    assert isinstance(result2, dict)
    result3 = await mips_local.get_prop_async(
        did=central_did, siid=test_siid, piid=test_piid)
    assert isinstance(result3, bool)
    _LOGGER.info('get prop.%s.%s, value=%s', test_siid, test_piid, result3)
    # Action
    test_siid = 4
    test_aiid = 1
    in_list = [{'piid': 1, 'value': 'hello world.'}]
    result4 = await mips_local.action_async(
        did=central_did, siid=test_siid, aiid=test_aiid,
        in_list=in_list)
    assert isinstance(result4, dict)
    _LOGGER.info(
        'action.%s.%s=%s, result=%s', test_siid, test_piid, in_list, result4)
    # Disconnect
    await mips_local.disconnect_async()
    await mips_local.deinit_async()


@pytest.mark.asyncio
async def test_mips_cloud_async(
    test_cache_path: str,
    test_name_uuid: str,
    test_cloud_server: str,
    test_domain_cloud_cache: str,
    test_name_oauth2_info: str,
    test_name_devices: str
):
    """
    NOTICE:
    - This test case requires running test_cloud.py first to obtain the
    central connection certificate.
    - This test case will control the indicator light switch of the central
    gateway.
    """
    from miot.const import OAUTH2_CLIENT_ID
    from miot.miot_storage import MIoTStorage
    from miot.miot_mips import MipsCloudClient
    from miot.miot_cloud import MIoTHttpClient

    miot_storage = MIoTStorage(test_cache_path)
    uuid = await miot_storage.load_async(
        domain=test_domain_cloud_cache, name=test_name_uuid, type_=str)
    assert isinstance(uuid, str)
    oauth_info = await miot_storage.load_async(
        domain=test_domain_cloud_cache, name=test_name_oauth2_info, type_=dict)
    assert isinstance(oauth_info, dict) and 'access_token' in oauth_info
    access_token = oauth_info['access_token']
    _LOGGER.info('connect info, %s, %s', uuid, access_token)
    mips_cloud = MipsCloudClient(
        uuid=uuid,
        cloud_server=test_cloud_server,
        app_id=OAUTH2_CLIENT_ID,
        token=access_token)
    mips_cloud.enable_logger(logger=_LOGGER)
    mips_cloud.enable_mqtt_logger(logger=_LOGGER)
    miot_http = MIoTHttpClient(
        cloud_server=test_cloud_server,
        client_id=OAUTH2_CLIENT_ID,
        access_token=access_token)

    async def on_mips_state_changed_async(key: str, state: bool):
        _LOGGER.info('on mips state changed, %s, %s', key, state)

    def on_prop_changed(payload: dict, ctx: Any):
        _LOGGER.info('prop changed, %s=%s', ctx, payload)

    def on_event_occurred(payload: dict, ctx: Any):
        _LOGGER.info('event occurred, %s=%s', ctx, payload)

    await mips_cloud.connect_async()
    await asyncio.sleep(0.5)

    # Sub mips state
    mips_cloud.sub_mips_state(
        key='mips_cloud', handler=on_mips_state_changed_async)
    # Load devices
    local_devices = await miot_storage.load_async(
        domain=test_domain_cloud_cache, name=test_name_devices, type_=dict)
    assert isinstance(local_devices, dict)
    central_did = ''
    for did, info in local_devices.items():
        if info['model'] != 'xiaomi.gateway.hub1':
            continue
        central_did = did
        break
    if central_did:
        # Sub Prop
        mips_cloud.sub_prop(
            did=central_did, handler=on_prop_changed,
            handler_ctx=f'{central_did}.*')
        # Sub Event
        mips_cloud.sub_event(
            did=central_did, handler=on_event_occurred,
            handler_ctx=f'{central_did}.*')
        # Get/set prop
        test_siid = 3
        test_piid = 1
        # mips_cloud.sub_prop(
        #     did=central_did, siid=test_siid, piid=test_piid,
        #     handler=on_prop_changed,
        #     handler_ctx=f'{central_did}.{test_siid}.{test_piid}')
        result1 = await miot_http.get_prop_async(
            did=central_did, siid=test_siid, piid=test_piid)
        assert isinstance(result1, bool)
        _LOGGER.info('get prop.%s.%s, value=%s', test_siid, test_piid, result1)
        result2 = await miot_http.set_prop_async(params=[{
            'did': central_did, 'siid': test_siid, 'piid': test_piid,
            'value': not result1}])
        _LOGGER.info(
            'set prop.%s.%s=%s, result=%s',
            test_siid, test_piid, not result1, result2)
        assert isinstance(result2, list)
        result3 = await miot_http.get_prop_async(
            did=central_did, siid=test_siid, piid=test_piid)
        assert isinstance(result3, bool)
        _LOGGER.info('get prop.%s.%s, value=%s', test_siid, test_piid, result3)
        # Action
        test_siid = 4
        test_aiid = 1
        in_list = [{'piid': 1, 'value': 'hello world.'}]
        result4 = await miot_http.action_async(
            did=central_did, siid=test_siid, aiid=test_aiid,
            in_list=in_list)
        assert isinstance(result4, dict)
        _LOGGER.info(
            'action.%s.%s=%s, result=%s',
            test_siid, test_piid, in_list, result4)
        await asyncio.sleep(1)
    # Disconnect
    await mips_cloud.disconnect_async()
    await mips_cloud.deinit_async()
    await miot_http.deinit_async()
