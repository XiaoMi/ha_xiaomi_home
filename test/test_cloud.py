# -*- coding: utf-8 -*-
"""Unit test for miot_cloud.py."""
import time
import webbrowser
import pytest

# pylint: disable=import-outside-toplevel, unused-argument


@pytest.mark.asyncio
@pytest.mark.dependency()
async def test_miot_oauth_async(
    test_cache_path, test_cloud_server, test_oauth2_redirect_url,
    test_domain_oauth2, test_uuid
) -> dict:
    from miot.const import OAUTH2_CLIENT_ID
    from miot.miot_cloud import MIoTOauthClient
    from miot.miot_storage import MIoTStorage
    print('')  # separate from previous output

    miot_oauth = MIoTOauthClient(
        client_id=OAUTH2_CLIENT_ID,
        redirect_url=test_oauth2_redirect_url,
        cloud_server=test_cloud_server,
        uuid=test_uuid)
    miot_storage = MIoTStorage(test_cache_path)
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
    print(f'access_token: {oauth_info["access_token"]}')
    print(f'refresh_token: {oauth_info["refresh_token"]}')

    return oauth_info


@pytest.mark.asyncio
@pytest.mark.dependency(on=['test_miot_oauth_async'])
async def test_miot_oauth_refresh_token(
        test_cache_path: str, test_cloud_server: str,
        test_oauth2_redirect_url: str, test_domain_oauth2: str,
        test_uuid: str
):
    from miot.const import OAUTH2_CLIENT_ID
    from miot.miot_cloud import MIoTOauthClient
    from miot.miot_storage import MIoTStorage
    print('')  # separate from previous output

    miot_storage = MIoTStorage(test_cache_path)
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
        uuid=test_uuid)
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
    test_cache_path, test_cloud_server, test_domain_oauth2
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
    print(f'your nickname: {user_info["miliaoNick"]}\n')


@pytest.mark.asyncio
@pytest.mark.dependency()
async def test_miot_cloud_get_uid_async(
    test_cache_path,
    test_cloud_server,
    test_domain_oauth2,
    test_domain_user_info
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
    test_cache_path, test_cloud_server,
    test_domain_oauth2, test_domain_user_info
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
    print(f'your home_list: {homeinfos["home_list"]}\n')
    # Get share homes
    print(f'your share_home_list: {homeinfos["share_home_list"]}\n')


@pytest.mark.asyncio
@pytest.mark.dependency()
async def test_miot_cloud_get_devices_async(
    test_cache_path, test_cloud_server,
    test_domain_oauth2, test_domain_user_info
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
    test_cache_path, test_cloud_server,
    test_domain_oauth2, test_domain_user_info
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
    print(f'your devices id list: {did_list}\n')

    devices_info = await miot_http.get_devices_with_dids_async(
        dids=did_list[:6])
    assert isinstance(devices_info, dict)


@pytest.mark.asyncio
@pytest.mark.dependency()
async def test_miot_cloud_get_prop_async(
    test_cache_path, test_cloud_server,
    test_domain_oauth2, test_domain_user_info
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


@pytest.mark.asyncio
@pytest.mark.dependency()
async def test_miot_cloud_get_props_async(
    test_cache_path, test_cloud_server,
    test_domain_oauth2, test_domain_user_info
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


@pytest.mark.asyncio
@pytest.mark.dependency()
async def test_miot_cloud_set_prop_async(
    test_cache_path, test_cloud_server,
    test_domain_oauth2, test_domain_user_info
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


@pytest.mark.asyncio
@pytest.mark.dependency()
async def test_miot_cloud_action_async(
    test_cache_path, test_cloud_server,
    test_domain_oauth2, test_domain_user_info
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
