# -*- coding: utf-8 -*-
"""Unit test for miot_cloud.py."""
import asyncio
import time
import webbrowser
import pytest

# pylint: disable=import-outside-toplevel, unused-argument


@pytest.mark.asyncio
@pytest.mark.dependency()
async def test_miot_oauth_async(
    test_cache_path: str,
    test_cloud_server: str,
    test_oauth2_redirect_url: str,
    test_domain_oauth2: str,
    test_uuid: str
) -> dict:
    from miot.const import OAUTH2_CLIENT_ID
    from miot.miot_cloud import MIoTOauthClient
    from miot.miot_storage import MIoTStorage
    print('')  # separate from previous output

    miot_storage = MIoTStorage(test_cache_path)
    local_uuid = await miot_storage.load_async(
        domain=test_domain_oauth2, name=f'{test_cloud_server}_uuid', type_=str)
    uuid = str(local_uuid or test_uuid)
    print(f'uuid: {uuid}')
    miot_oauth = MIoTOauthClient(
        client_id=OAUTH2_CLIENT_ID,
        redirect_url=test_oauth2_redirect_url,
        cloud_server=test_cloud_server,
        uuid=uuid)

    oauth_info = None
    load_info = await miot_storage.load_async(
        domain=test_domain_oauth2, name=test_cloud_server, type_=dict)
    if (
        isinstance(load_info, dict)
        and 'access_token' in load_info
        and 'expires_ts' in load_info
        and load_info['expires_ts'] > int(time.time())
    ):
        print(f'load oauth info, {load_info}')
        oauth_info = load_info
    if oauth_info is None:
        # gen oauth url
        auth_url: str = miot_oauth.gen_auth_url()
        assert isinstance(auth_url, str)
        print('auth url: ', auth_url)
        # get code
        webbrowser.open(auth_url)
        code: str = input('input code: ')
        assert code is not None
        # get access_token
        res_obj = await miot_oauth.get_access_token_async(code=code)
        assert res_obj is not None
        oauth_info = res_obj
        print(f'get_access_token result: {res_obj}')
        rc = await miot_storage.save_async(
            test_domain_oauth2, test_cloud_server, oauth_info)
        assert rc
        print('save oauth info')
        rc = await miot_storage.save_async(
            test_domain_oauth2, f'{test_cloud_server}_uuid', uuid)
        assert rc
        print('save uuid')

    access_token = oauth_info.get('access_token', None)
    assert isinstance(access_token, str)
    print(f'access_token: {access_token}')
    refresh_token = oauth_info.get('refresh_token', None)
    assert isinstance(refresh_token, str)
    print(f'refresh_token: {refresh_token}')
    return oauth_info


@pytest.mark.asyncio
@pytest.mark.dependency(on=['test_miot_oauth_async'])
async def test_miot_oauth_refresh_token(
    test_cache_path: str,
    test_cloud_server: str,
    test_oauth2_redirect_url: str,
    test_domain_oauth2: str
):
    from miot.const import OAUTH2_CLIENT_ID
    from miot.miot_cloud import MIoTOauthClient
    from miot.miot_storage import MIoTStorage
    print('')  # separate from previous output

    miot_storage = MIoTStorage(test_cache_path)
    uuid = await miot_storage.load_async(
        domain=test_domain_oauth2, name=f'{test_cloud_server}_uuid', type_=str)
    assert isinstance(uuid, str)
    oauth_info = await miot_storage.load_async(
        domain=test_domain_oauth2, name=test_cloud_server, type_=dict)
    assert isinstance(oauth_info, dict)
    assert 'access_token' in oauth_info
    assert 'refresh_token' in oauth_info
    assert 'expires_ts' in oauth_info
    remaining_time = oauth_info['expires_ts'] - int(time.time())
    print(f'token remaining valid time: {remaining_time}s')
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
    print(f'refresh token, remaining valid time: {remaining_time}s')
    # Save token
    rc = await miot_storage.save_async(
        test_domain_oauth2, test_cloud_server, update_info)
    assert rc
    print(f'refresh token success, {update_info}')


@pytest.mark.asyncio
@pytest.mark.dependency()
async def test_miot_cloud_get_nickname_async(
    test_cache_path: str,
    test_cloud_server: str,
    test_domain_oauth2: str
):
    from miot.const import OAUTH2_CLIENT_ID
    from miot.miot_cloud import MIoTHttpClient
    from miot.miot_storage import MIoTStorage
    print('')  # separate from previous output

    miot_storage = MIoTStorage(test_cache_path)
    oauth_info = await miot_storage.load_async(
        domain=test_domain_oauth2, name=test_cloud_server, type_=dict)
    assert isinstance(oauth_info, dict) and 'access_token' in oauth_info
    miot_http = MIoTHttpClient(
        cloud_server=test_cloud_server, client_id=OAUTH2_CLIENT_ID,
        access_token=oauth_info['access_token'])

    # Get nickname
    user_info = await miot_http.get_user_info_async()
    assert isinstance(user_info, dict) and 'miliaoNick' in user_info
    nickname = user_info['miliaoNick']
    print(f'your nickname: {nickname}\n')


@pytest.mark.asyncio
@pytest.mark.dependency()
async def test_miot_cloud_get_uid_async(
    test_cache_path: str,
    test_cloud_server: str,
    test_domain_oauth2: str,
    test_domain_user_info: str
):
    from miot.const import OAUTH2_CLIENT_ID
    from miot.miot_cloud import MIoTHttpClient
    from miot.miot_storage import MIoTStorage
    print('')  # separate from previous output

    miot_storage = MIoTStorage(test_cache_path)
    oauth_info = await miot_storage.load_async(
        domain=test_domain_oauth2, name=test_cloud_server, type_=dict)
    assert isinstance(oauth_info, dict) and 'access_token' in oauth_info
    miot_http = MIoTHttpClient(
        cloud_server=test_cloud_server, client_id=OAUTH2_CLIENT_ID,
        access_token=oauth_info['access_token'])

    uid = await miot_http.get_uid_async()
    assert isinstance(uid, str)
    print(f'your uid: {uid}\n')
    # Save uid
    rc = await miot_storage.save_async(
        domain=test_domain_user_info,
        name=f'uid_{test_cloud_server}', data=uid)
    assert rc


@pytest.mark.asyncio
@pytest.mark.dependency()
async def test_miot_cloud_get_homeinfos_async(
    test_cache_path: str,
    test_cloud_server: str,
    test_domain_oauth2: str,
    test_domain_user_info: str
):
    from miot.const import OAUTH2_CLIENT_ID
    from miot.miot_cloud import MIoTHttpClient
    from miot.miot_storage import MIoTStorage
    print('')  # separate from previous output

    miot_storage = MIoTStorage(test_cache_path)
    oauth_info = await miot_storage.load_async(
        domain=test_domain_oauth2, name=test_cloud_server, type_=dict)
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
        domain=test_domain_user_info,
        name=f'uid_{test_cloud_server}', type_=str)
    assert uid == uid2
    print(f'your uid: {uid}\n')
    # Get homes
    home_list = homeinfos.get('home_list', {})
    print(f'your home_list: {home_list}\n')
    # Get share homes
    share_home_list = homeinfos.get('share_home_list', {})
    print(f'your share_home_list: {share_home_list}\n')


@pytest.mark.asyncio
@pytest.mark.dependency()
async def test_miot_cloud_get_devices_async(
    test_cache_path: str,
    test_cloud_server: str,
    test_domain_oauth2: str,
    test_domain_user_info: str
):
    from miot.const import OAUTH2_CLIENT_ID
    from miot.miot_cloud import MIoTHttpClient
    from miot.miot_storage import MIoTStorage
    print('')  # separate from previous output

    miot_storage = MIoTStorage(test_cache_path)
    oauth_info = await miot_storage.load_async(
        domain=test_domain_oauth2, name=test_cloud_server, type_=dict)
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
        domain=test_domain_user_info,
        name=f'uid_{test_cloud_server}', type_=str)
    assert uid == uid2
    print(f'your uid: {uid}\n')
    # Get homes
    homes = devices['homes']
    print(f'your homes: {homes}\n')
    # Get devices
    devices = devices['devices']
    print(f'your devices count: {len(devices)}\n')
    # Storage homes and devices
    rc = await miot_storage.save_async(
        domain=test_domain_user_info,
        name=f'homes_{test_cloud_server}', data=homes)
    assert rc
    rc = await miot_storage.save_async(
        domain=test_domain_user_info,
        name=f'devices_{test_cloud_server}', data=devices)
    assert rc


@pytest.mark.asyncio
@pytest.mark.dependency()
async def test_miot_cloud_get_devices_with_dids_async(
    test_cache_path: str,
    test_cloud_server: str,
    test_domain_oauth2: str,
    test_domain_user_info: str
):
    from miot.const import OAUTH2_CLIENT_ID
    from miot.miot_cloud import MIoTHttpClient
    from miot.miot_storage import MIoTStorage
    print('')  # separate from previous output

    miot_storage = MIoTStorage(test_cache_path)
    oauth_info = await miot_storage.load_async(
        domain=test_domain_oauth2, name=test_cloud_server, type_=dict)
    assert isinstance(oauth_info, dict) and 'access_token' in oauth_info
    miot_http = MIoTHttpClient(
        cloud_server=test_cloud_server, client_id=OAUTH2_CLIENT_ID,
        access_token=oauth_info['access_token'])

    # Load devices
    local_devices = await miot_storage.load_async(
        domain=test_domain_user_info,
        name=f'devices_{test_cloud_server}', type_=dict)
    assert isinstance(local_devices, dict)
    did_list = list(local_devices.keys())
    assert len(did_list) > 0
    # Get device with dids
    test_list = did_list[:6]
    devices_info = await miot_http.get_devices_with_dids_async(
        dids=test_list)
    assert isinstance(devices_info, dict)
    print(f'test did list, {len(test_list)}, {test_list}\n')
    print(f'test result: {len(devices_info)}, {list(devices_info.keys())}\n')


@pytest.mark.asyncio
@pytest.mark.dependency()
async def test_miot_cloud_get_prop_async(
    test_cache_path: str,
    test_cloud_server: str,
    test_domain_oauth2: str,
    test_domain_user_info: str
):
    from miot.const import OAUTH2_CLIENT_ID
    from miot.miot_cloud import MIoTHttpClient
    from miot.miot_storage import MIoTStorage
    print('')  # separate from previous output

    miot_storage = MIoTStorage(test_cache_path)
    oauth_info = await miot_storage.load_async(
        domain=test_domain_oauth2, name=test_cloud_server, type_=dict)
    assert isinstance(oauth_info, dict) and 'access_token' in oauth_info
    miot_http = MIoTHttpClient(
        cloud_server=test_cloud_server, client_id=OAUTH2_CLIENT_ID,
        access_token=oauth_info['access_token'])

    # Load devices
    local_devices = await miot_storage.load_async(
        domain=test_domain_user_info,
        name=f'devices_{test_cloud_server}', type_=dict)
    assert isinstance(local_devices, dict)
    did_list = list(local_devices.keys())
    assert len(did_list) > 0
    # Get prop
    test_list = did_list[:6]
    for did in test_list:
        prop_value = await miot_http.get_prop_async(did=did, siid=2, piid=1)
        device_name = local_devices[did]['name']
        print(f'{device_name}({did}), prop.2.1: {prop_value}\n')


@pytest.mark.asyncio
@pytest.mark.dependency()
async def test_miot_cloud_get_props_async(
    test_cache_path: str,
    test_cloud_server: str,
    test_domain_oauth2: str,
    test_domain_user_info: str
):
    from miot.const import OAUTH2_CLIENT_ID
    from miot.miot_cloud import MIoTHttpClient
    from miot.miot_storage import MIoTStorage
    print('')  # separate from previous output

    miot_storage = MIoTStorage(test_cache_path)
    oauth_info = await miot_storage.load_async(
        domain=test_domain_oauth2, name=test_cloud_server, type_=dict)
    assert isinstance(oauth_info, dict) and 'access_token' in oauth_info
    miot_http = MIoTHttpClient(
        cloud_server=test_cloud_server, client_id=OAUTH2_CLIENT_ID,
        access_token=oauth_info['access_token'])

    # Load devices
    local_devices = await miot_storage.load_async(
        domain=test_domain_user_info,
        name=f'devices_{test_cloud_server}', type_=dict)
    assert isinstance(local_devices, dict)
    did_list = list(local_devices.keys())
    assert len(did_list) > 0
    # Get props
    test_list = did_list[:6]
    prop_values = await miot_http.get_props_async(params=[
        {'did': did, 'siid': 2, 'piid': 1} for did in test_list])
    print(f'test did list, {len(test_list)}, {test_list}\n')
    print(f'test result: {len(prop_values)}, {prop_values}\n')


@pytest.mark.skip(reason='skip danger operation')
@pytest.mark.asyncio
@pytest.mark.dependency()
async def test_miot_cloud_set_prop_async(
    test_cache_path: str,
    test_cloud_server: str,
    test_domain_oauth2: str,
    test_domain_user_info: str
):
    """
    WARNING: This test case will control the actual device and is not enabled
    by default. You can uncomment @pytest.mark.skip to enable it.
    """
    from miot.const import OAUTH2_CLIENT_ID
    from miot.miot_cloud import MIoTHttpClient
    from miot.miot_storage import MIoTStorage
    print('')  # separate from previous output

    miot_storage = MIoTStorage(test_cache_path)
    oauth_info = await miot_storage.load_async(
        domain=test_domain_oauth2, name=test_cloud_server, type_=dict)
    assert isinstance(oauth_info, dict) and 'access_token' in oauth_info
    miot_http = MIoTHttpClient(
        cloud_server=test_cloud_server, client_id=OAUTH2_CLIENT_ID,
        access_token=oauth_info['access_token'])

    # Load devices
    local_devices = await miot_storage.load_async(
        domain=test_domain_user_info,
        name=f'devices_{test_cloud_server}', type_=dict)
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
    print(f'test did, {test_did}, prop.3.1=False -> {result}\n')
    await asyncio.sleep(1)
    result = await miot_http.set_prop_async(params=[{
        'did': test_did, 'siid': 3, 'piid': 1, 'value': True}])
    print(f'test did, {test_did}, prop.3.1=True -> {result}\n')


@pytest.mark.skip(reason='skip danger operation')
@pytest.mark.asyncio
@pytest.mark.dependency()
async def test_miot_cloud_action_async(
    test_cache_path: str,
    test_cloud_server: str,
    test_domain_oauth2: str,
    test_domain_user_info: str
):
    """
    WARNING: This test case will control the actual device and is not enabled
    by default. You can uncomment @pytest.mark.skip to enable it.
    """
    from miot.const import OAUTH2_CLIENT_ID
    from miot.miot_cloud import MIoTHttpClient
    from miot.miot_storage import MIoTStorage
    print('')  # separate from previous output

    miot_storage = MIoTStorage(test_cache_path)
    oauth_info = await miot_storage.load_async(
        domain=test_domain_oauth2, name=test_cloud_server, type_=dict)
    assert isinstance(oauth_info, dict) and 'access_token' in oauth_info
    miot_http = MIoTHttpClient(
        cloud_server=test_cloud_server, client_id=OAUTH2_CLIENT_ID,
        access_token=oauth_info['access_token'])

    # Load devices
    local_devices = await miot_storage.load_async(
        domain=test_domain_user_info,
        name=f'devices_{test_cloud_server}', type_=dict)
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
    print(f'test did, {test_did}, action.4.1 -> {result}\n')
