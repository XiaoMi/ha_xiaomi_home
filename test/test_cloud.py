# -*- coding: utf-8 -*-
"""Unit test for miot_cloud.py."""
import asyncio
import logging
import time
import webbrowser
import pytest

# pylint: disable=import-outside-toplevel, unused-argument
_LOGGER = logging.getLogger(__name__)


@pytest.mark.asyncio
@pytest.mark.dependency()
async def test_miot_oauth_async(
    test_cache_path: str,
    test_cloud_server: str,
    test_oauth2_redirect_url: str,
    test_uuid: str,
    test_domain_cloud_cache: str,
    test_name_oauth2_info: str,
    test_name_uuid: str
) -> dict:
    from miot.const import OAUTH2_CLIENT_ID
    from miot.miot_cloud import MIoTOauthClient
    from miot.miot_storage import MIoTStorage

    miot_storage = MIoTStorage(test_cache_path)
    local_uuid = await miot_storage.load_async(
        domain=test_domain_cloud_cache, name=test_name_uuid, type_=str)
    uuid = str(local_uuid or test_uuid)
    _LOGGER.info('uuid: %s', uuid)
    miot_oauth = MIoTOauthClient(
        client_id=OAUTH2_CLIENT_ID,
        redirect_url=test_oauth2_redirect_url,
        cloud_server=test_cloud_server,
        uuid=uuid)

    oauth_info = None
    load_info = await miot_storage.load_async(
        domain=test_domain_cloud_cache, name=test_name_oauth2_info, type_=dict)
    if (
        isinstance(load_info, dict)
        and 'access_token' in load_info
        and 'expires_ts' in load_info
        and load_info['expires_ts'] > int(time.time())
    ):
        _LOGGER.info('load oauth info, %s', load_info)
        oauth_info = load_info
    if oauth_info is None:
        # gen oauth url
        auth_url: str = miot_oauth.gen_auth_url()
        assert isinstance(auth_url, str)
        _LOGGER.info('auth url: %s', auth_url)
        # get code
        webbrowser.open(auth_url)
        code: str = input('input code: ')
        assert code is not None
        # get access_token
        res_obj = await miot_oauth.get_access_token_async(code=code)
        assert res_obj is not None
        oauth_info = res_obj
        _LOGGER.info('get_access_token result: %s', res_obj)
        rc = await miot_storage.save_async(
            test_domain_cloud_cache, test_name_oauth2_info, oauth_info)
        assert rc
        _LOGGER.info('save oauth info')
        rc = await miot_storage.save_async(
            test_domain_cloud_cache, test_name_uuid, uuid)
        assert rc
        _LOGGER.info('save uuid')

    access_token = oauth_info.get('access_token', None)
    assert isinstance(access_token, str)
    _LOGGER.info('access_token: %s', access_token)
    refresh_token = oauth_info.get('refresh_token', None)
    assert isinstance(refresh_token, str)
    _LOGGER.info('refresh_token: %s', refresh_token)

    await miot_oauth.deinit_async()
    return oauth_info


@pytest.mark.asyncio
@pytest.mark.dependency(on=['test_miot_oauth_async'])
async def test_miot_oauth_refresh_token(
    test_cache_path: str,
    test_cloud_server: str,
    test_oauth2_redirect_url: str,
    test_domain_cloud_cache: str,
    test_name_oauth2_info: str,
    test_name_uuid: str
):
    from miot.const import OAUTH2_CLIENT_ID
    from miot.miot_cloud import MIoTOauthClient
    from miot.miot_storage import MIoTStorage

    miot_storage = MIoTStorage(test_cache_path)
    uuid = await miot_storage.load_async(
        domain=test_domain_cloud_cache, name=test_name_uuid, type_=str)
    assert isinstance(uuid, str)
    oauth_info = await miot_storage.load_async(
        domain=test_domain_cloud_cache, name=test_name_oauth2_info, type_=dict)
    assert isinstance(oauth_info, dict)
    assert 'access_token' in oauth_info
    assert 'refresh_token' in oauth_info
    assert 'expires_ts' in oauth_info
    remaining_time = oauth_info['expires_ts'] - int(time.time())
    _LOGGER.info('token remaining valid time: %ss', remaining_time)
    # Refresh token
    miot_oauth = MIoTOauthClient(
        client_id=OAUTH2_CLIENT_ID,
        redirect_url=test_oauth2_redirect_url,
        cloud_server=test_cloud_server,
        uuid=uuid)
    refresh_token = oauth_info.get('refresh_token', None)
    assert refresh_token
    update_info = await miot_oauth.refresh_access_token_async(
        refresh_token=refresh_token)
    assert update_info
    assert 'access_token' in update_info
    assert 'refresh_token' in update_info
    assert 'expires_ts' in update_info
    remaining_time = update_info['expires_ts'] - int(time.time())
    assert remaining_time > 0
    _LOGGER.info('refresh token, remaining valid time: %ss', remaining_time)
    # Save oauth2 info
    rc = await miot_storage.save_async(
        test_domain_cloud_cache, test_name_oauth2_info, update_info)
    assert rc
    _LOGGER.info('refresh token success, %s', update_info)

    await miot_oauth.deinit_async()


@pytest.mark.asyncio
@pytest.mark.dependency()
async def test_miot_cloud_get_nickname_async(
    test_cache_path: str,
    test_cloud_server: str,
    test_domain_cloud_cache: str,
    test_name_oauth2_info: str
):
    from miot.const import OAUTH2_CLIENT_ID
    from miot.miot_cloud import MIoTHttpClient
    from miot.miot_storage import MIoTStorage

    miot_storage = MIoTStorage(test_cache_path)
    oauth_info = await miot_storage.load_async(
        domain=test_domain_cloud_cache, name=test_name_oauth2_info, type_=dict)
    assert isinstance(oauth_info, dict) and 'access_token' in oauth_info
    miot_http = MIoTHttpClient(
        cloud_server=test_cloud_server, client_id=OAUTH2_CLIENT_ID,
        access_token=oauth_info['access_token'])

    # Get nickname
    user_info = await miot_http.get_user_info_async()
    assert isinstance(user_info, dict) and 'miliaoNick' in user_info
    nickname = user_info['miliaoNick']
    _LOGGER.info('your nickname: %s', nickname)

    await miot_http.deinit_async()


@pytest.mark.asyncio
@pytest.mark.dependency()
async def test_miot_cloud_get_uid_async(
    test_cache_path: str,
    test_cloud_server: str,
    test_domain_cloud_cache: str,
    test_name_oauth2_info: str,
    test_name_uid: str
):
    from miot.const import OAUTH2_CLIENT_ID
    from miot.miot_cloud import MIoTHttpClient
    from miot.miot_storage import MIoTStorage

    miot_storage = MIoTStorage(test_cache_path)
    oauth_info = await miot_storage.load_async(
        domain=test_domain_cloud_cache, name=test_name_oauth2_info, type_=dict)
    assert isinstance(oauth_info, dict) and 'access_token' in oauth_info
    miot_http = MIoTHttpClient(
        cloud_server=test_cloud_server, client_id=OAUTH2_CLIENT_ID,
        access_token=oauth_info['access_token'])

    uid = await miot_http.get_uid_async()
    assert isinstance(uid, str)
    _LOGGER.info('your uid: %s', uid)
    # Save uid
    rc = await miot_storage.save_async(
        domain=test_domain_cloud_cache, name=test_name_uid, data=uid)
    assert rc

    await miot_http.deinit_async()


@pytest.mark.asyncio
@pytest.mark.dependency()
async def test_miot_cloud_get_homeinfos_async(
    test_cache_path: str,
    test_cloud_server: str,
    test_domain_cloud_cache: str,
    test_name_oauth2_info: str,
    test_name_uid: str
):
    from miot.const import OAUTH2_CLIENT_ID
    from miot.miot_cloud import MIoTHttpClient
    from miot.miot_storage import MIoTStorage

    miot_storage = MIoTStorage(test_cache_path)
    oauth_info = await miot_storage.load_async(
        domain=test_domain_cloud_cache, name=test_name_oauth2_info, type_=dict)
    assert isinstance(oauth_info, dict) and 'access_token' in oauth_info
    miot_http = MIoTHttpClient(
        cloud_server=test_cloud_server, client_id=OAUTH2_CLIENT_ID,
        access_token=oauth_info['access_token'])

    # Get homeinfos
    homeinfos = await miot_http.get_homeinfos_async()
    assert isinstance(homeinfos, dict)
    assert 'uid' in homeinfos and isinstance(homeinfos['uid'], str)
    assert 'home_list' in homeinfos and isinstance(
        homeinfos['home_list'], dict)
    assert 'share_home_list' in homeinfos and isinstance(
        homeinfos['share_home_list'], dict)
    # Get uid
    uid = homeinfos.get('uid', '')
    # Compare uid with uid in storage
    uid2 = await miot_storage.load_async(
        domain=test_domain_cloud_cache, name=test_name_uid, type_=str)
    assert uid == uid2
    _LOGGER.info('your uid: %s', uid)
    # Get homes
    home_list = homeinfos.get('home_list', {})
    _LOGGER.info('your home_list: ,%s', home_list)
    # Get share homes
    share_home_list = homeinfos.get('share_home_list', {})
    _LOGGER.info('your share_home_list: %s', share_home_list)

    await miot_http.deinit_async()


@pytest.mark.asyncio
@pytest.mark.dependency()
async def test_miot_cloud_get_devices_async(
    test_cache_path: str,
    test_cloud_server: str,
    test_domain_cloud_cache: str,
    test_name_oauth2_info: str,
    test_name_uid: str,
    test_name_homes: str,
    test_name_devices: str
):
    from miot.const import OAUTH2_CLIENT_ID
    from miot.miot_cloud import MIoTHttpClient
    from miot.miot_storage import MIoTStorage

    miot_storage = MIoTStorage(test_cache_path)
    oauth_info = await miot_storage.load_async(
        domain=test_domain_cloud_cache, name=test_name_oauth2_info, type_=dict)
    assert isinstance(oauth_info, dict) and 'access_token' in oauth_info
    miot_http = MIoTHttpClient(
        cloud_server=test_cloud_server, client_id=OAUTH2_CLIENT_ID,
        access_token=oauth_info['access_token'])

    # Get devices
    devices = await miot_http.get_devices_async()
    assert isinstance(devices, dict)
    assert 'uid' in devices and isinstance(devices['uid'], str)
    assert 'homes' in devices and isinstance(devices['homes'], dict)
    assert 'devices' in devices and isinstance(devices['devices'], dict)
    # Compare uid with uid in storage
    uid = devices.get('uid', '')
    uid2 = await miot_storage.load_async(
        domain=test_domain_cloud_cache, name=test_name_uid, type_=str)
    assert uid == uid2
    _LOGGER.info('your uid: %s', uid)
    # Get homes
    homes = devices['homes']
    _LOGGER.info('your homes: %s', homes)
    # Get devices
    devices = devices['devices']
    _LOGGER.info('your devices count: %s', len(devices))
    # Storage homes and devices
    rc = await miot_storage.save_async(
        domain=test_domain_cloud_cache, name=test_name_homes, data=homes)
    assert rc
    rc = await miot_storage.save_async(
        domain=test_domain_cloud_cache, name=test_name_devices, data=devices)
    assert rc

    await miot_http.deinit_async()


@pytest.mark.asyncio
@pytest.mark.dependency()
async def test_miot_cloud_get_devices_with_dids_async(
    test_cache_path: str,
    test_cloud_server: str,
    test_domain_cloud_cache: str,
    test_name_oauth2_info: str,
    test_name_devices: str
):
    from miot.const import OAUTH2_CLIENT_ID
    from miot.miot_cloud import MIoTHttpClient
    from miot.miot_storage import MIoTStorage

    miot_storage = MIoTStorage(test_cache_path)
    oauth_info = await miot_storage.load_async(
        domain=test_domain_cloud_cache, name=test_name_oauth2_info, type_=dict)
    assert isinstance(oauth_info, dict) and 'access_token' in oauth_info
    miot_http = MIoTHttpClient(
        cloud_server=test_cloud_server, client_id=OAUTH2_CLIENT_ID,
        access_token=oauth_info['access_token'])

    # Load devices
    local_devices = await miot_storage.load_async(
        domain=test_domain_cloud_cache, name=test_name_devices, type_=dict)
    assert isinstance(local_devices, dict)
    did_list = list(local_devices.keys())
    assert len(did_list) > 0
    # Get device with dids
    test_list = did_list[:6]
    devices_info = await miot_http.get_devices_with_dids_async(
        dids=test_list)
    assert isinstance(devices_info, dict)
    _LOGGER.info('test did list, %s, %s', len(test_list), test_list)
    _LOGGER.info(
        'test result: %s, %s', len(devices_info), list(devices_info.keys()))

    await miot_http.deinit_async()


@pytest.mark.asyncio
async def test_miot_cloud_get_cert(
    test_cache_path: str,
    test_cloud_server: str,
    test_random_did: str,
    test_domain_cloud_cache: str,
    test_name_oauth2_info: str,
    test_name_uid: str,
    test_name_rd_did: str
):
    """
    NOTICE: Currently, only certificate acquisition in the CN region is 
    supported.
    """
    from miot.const import OAUTH2_CLIENT_ID
    from miot.miot_cloud import MIoTHttpClient
    from miot.miot_storage import MIoTCert, MIoTStorage

    if test_cloud_server.lower() != 'cn':
        _LOGGER.info('only support CN region')
        return

    miot_storage = MIoTStorage(test_cache_path)
    uid = await miot_storage.load_async(
        domain=test_domain_cloud_cache, name=test_name_uid, type_=str)
    assert isinstance(uid, str)
    _LOGGER.info('your uid: %s', uid)
    random_did = await miot_storage.load_async(
        domain=test_domain_cloud_cache, name=test_name_rd_did, type_=str)
    if not random_did:
        random_did = test_random_did
        rc = await miot_storage.save_async(
            domain=test_domain_cloud_cache, name=test_name_rd_did,
            data=random_did)
        assert rc
    assert isinstance(random_did, str)
    _LOGGER.info('your random_did: %s', random_did)
    oauth_info = await miot_storage.load_async(
        domain=test_domain_cloud_cache, name=test_name_oauth2_info, type_=dict)
    assert isinstance(oauth_info, dict)
    assert 'access_token' in oauth_info
    access_token = oauth_info['access_token']

    # Get certificates
    miot_cert = MIoTCert(storage=miot_storage, uid=uid, cloud_server='CN')
    assert await miot_cert.verify_ca_cert_async(), 'invalid ca cert'
    remaining_time: int = await miot_cert.user_cert_remaining_time_async()
    if remaining_time > 0:
        _LOGGER.info(
            'user cert is valid, remaining time, %ss', remaining_time)
        _LOGGER.info((
            'if you want to obtain it again, please delete the '
            'key, csr, and cert files in %s.'), test_cache_path)
        return

    miot_http = MIoTHttpClient(
        cloud_server=test_cloud_server,
        client_id=OAUTH2_CLIENT_ID,
        access_token=access_token)

    user_key = miot_cert.gen_user_key()
    assert isinstance(user_key, str)
    _LOGGER.info('user_key str, %s', user_key)
    user_csr = miot_cert.gen_user_csr(user_key=user_key, did=random_did)
    assert isinstance(user_csr, str)
    _LOGGER.info('user_csr str, %s', user_csr)
    cert_str = await miot_http.get_central_cert_async(csr=user_csr)
    assert isinstance(cert_str, str)
    _LOGGER.info('user_cert str, %s', cert_str)
    rc = await miot_cert.update_user_key_async(key=user_key)
    assert rc
    rc = await miot_cert.update_user_cert_async(cert=cert_str)
    assert rc
    # verify user certificates
    remaining_time = await miot_cert.user_cert_remaining_time_async(
        cert_data=cert_str.encode('utf-8'), did=random_did)
    assert remaining_time > 0
    _LOGGER.info('user cert remaining time, %ss', remaining_time)

    await miot_http.deinit_async()


@pytest.mark.asyncio
@pytest.mark.dependency()
async def test_miot_cloud_get_prop_async(
    test_cache_path: str,
    test_cloud_server: str,
    test_domain_cloud_cache: str,
    test_name_oauth2_info: str,
    test_name_devices: str
):
    from miot.const import OAUTH2_CLIENT_ID
    from miot.miot_cloud import MIoTHttpClient
    from miot.miot_storage import MIoTStorage

    miot_storage = MIoTStorage(test_cache_path)
    oauth_info = await miot_storage.load_async(
        domain=test_domain_cloud_cache, name=test_name_oauth2_info, type_=dict)
    assert isinstance(oauth_info, dict) and 'access_token' in oauth_info
    miot_http = MIoTHttpClient(
        cloud_server=test_cloud_server, client_id=OAUTH2_CLIENT_ID,
        access_token=oauth_info['access_token'])

    # Load devices
    local_devices = await miot_storage.load_async(
        domain=test_domain_cloud_cache, name=test_name_devices, type_=dict)
    assert isinstance(local_devices, dict)
    did_list = list(local_devices.keys())
    assert len(did_list) > 0
    # Get prop
    test_list = did_list[:6]
    for did in test_list:
        prop_value = await miot_http.get_prop_async(did=did, siid=2, piid=1)
        device_name = local_devices[did]['name']
        _LOGGER.info('%s(%s), prop.2.1: %s', device_name, did, prop_value)

    await miot_http.deinit_async()


@pytest.mark.asyncio
@pytest.mark.dependency()
async def test_miot_cloud_get_props_async(
    test_cache_path: str,
    test_cloud_server: str,
    test_domain_cloud_cache: str,
    test_name_oauth2_info: str,
    test_name_devices: str
):
    from miot.const import OAUTH2_CLIENT_ID
    from miot.miot_cloud import MIoTHttpClient
    from miot.miot_storage import MIoTStorage

    miot_storage = MIoTStorage(test_cache_path)
    oauth_info = await miot_storage.load_async(
        domain=test_domain_cloud_cache, name=test_name_oauth2_info, type_=dict)
    assert isinstance(oauth_info, dict) and 'access_token' in oauth_info
    miot_http = MIoTHttpClient(
        cloud_server=test_cloud_server, client_id=OAUTH2_CLIENT_ID,
        access_token=oauth_info['access_token'])

    # Load devices
    local_devices = await miot_storage.load_async(
        domain=test_domain_cloud_cache, name=test_name_devices, type_=dict)
    assert isinstance(local_devices, dict)
    did_list = list(local_devices.keys())
    assert len(did_list) > 0
    # Get props
    test_list = did_list[:6]
    prop_values = await miot_http.get_props_async(params=[
        {'did': did, 'siid': 2, 'piid': 1} for did in test_list])

    _LOGGER.info('test did list, %s, %s', len(test_list), test_list)
    _LOGGER.info('test result, %s, %s', len(prop_values), prop_values)

    await miot_http.deinit_async()


@pytest.mark.skip(reason='skip danger operation')
@pytest.mark.asyncio
@pytest.mark.dependency()
async def test_miot_cloud_set_prop_async(
    test_cache_path: str,
    test_cloud_server: str,
    test_domain_cloud_cache: str,
    test_name_oauth2_info: str,
    test_name_devices: str
):
    """
    WARNING: This test case will control the actual device and is not enabled
    by default. You can uncomment @pytest.mark.skip to enable it.
    """
    from miot.const import OAUTH2_CLIENT_ID
    from miot.miot_cloud import MIoTHttpClient
    from miot.miot_storage import MIoTStorage

    miot_storage = MIoTStorage(test_cache_path)
    oauth_info = await miot_storage.load_async(
        domain=test_domain_cloud_cache, name=test_name_oauth2_info, type_=dict)
    assert isinstance(oauth_info, dict) and 'access_token' in oauth_info
    miot_http = MIoTHttpClient(
        cloud_server=test_cloud_server, client_id=OAUTH2_CLIENT_ID,
        access_token=oauth_info['access_token'])

    # Load devices
    local_devices = await miot_storage.load_async(
        domain=test_domain_cloud_cache, name=test_name_devices, type_=dict)
    assert isinstance(local_devices, dict)
    assert len(local_devices) > 0
    # Set prop
    # Find central hub gateway, control its indicator light switch
    # You can replace it with the device you want to control.
    test_did = ''
    for did, dev in local_devices.items():
        if dev['model'] == 'xiaomi.gateway.hub1':
            test_did = did
            break
    assert test_did != '', 'no central hub gateway found'
    result = await miot_http.set_prop_async(params=[{
        'did': test_did, 'siid': 3, 'piid': 1, 'value': False}])
    _LOGGER.info('test did, %s, prop.3.1=False -> %s', test_did, result)
    await asyncio.sleep(1)
    result = await miot_http.set_prop_async(params=[{
        'did': test_did, 'siid': 3, 'piid': 1, 'value': True}])
    _LOGGER.info('test did, %s, prop.3.1=True -> %s', test_did, result)

    await miot_http.deinit_async()


@pytest.mark.skip(reason='skip danger operation')
@pytest.mark.asyncio
@pytest.mark.dependency()
async def test_miot_cloud_action_async(
    test_cache_path: str,
    test_cloud_server: str,
    test_domain_cloud_cache: str,
    test_name_oauth2_info: str,
    test_name_devices: str
):
    """
    WARNING: This test case will control the actual device and is not enabled
    by default. You can uncomment @pytest.mark.skip to enable it.
    """
    from miot.const import OAUTH2_CLIENT_ID
    from miot.miot_cloud import MIoTHttpClient
    from miot.miot_storage import MIoTStorage

    miot_storage = MIoTStorage(test_cache_path)
    oauth_info = await miot_storage.load_async(
        domain=test_domain_cloud_cache, name=test_name_oauth2_info, type_=dict)
    assert isinstance(oauth_info, dict) and 'access_token' in oauth_info
    miot_http = MIoTHttpClient(
        cloud_server=test_cloud_server, client_id=OAUTH2_CLIENT_ID,
        access_token=oauth_info['access_token'])

    # Load devices
    local_devices = await miot_storage.load_async(
        domain=test_domain_cloud_cache, name=test_name_devices, type_=dict)
    assert isinstance(local_devices, dict)
    assert len(local_devices) > 0
    # Action
    # Find central hub gateway, trigger its virtual events
    # You can replace it with the device you want to control.
    test_did = ''
    for did, dev in local_devices.items():
        if dev['model'] == 'xiaomi.gateway.hub1':
            test_did = did
            break
    assert test_did != '', 'no central hub gateway found'
    result = await miot_http.action_async(
        did=test_did, siid=4, aiid=1,
        in_list=[{'piid': 1, 'value': 'hello world.'}])
    _LOGGER.info('test did, %s, action.4.1 -> %s', test_did, result)

    await miot_http.deinit_async()
