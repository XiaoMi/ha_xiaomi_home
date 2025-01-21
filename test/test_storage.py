# -*- coding: utf-8 -*-
"""Unit test for miot_storage.py."""
import asyncio
import logging
from os import path
import pytest

_LOGGER = logging.getLogger(__name__)

# pylint: disable=import-outside-toplevel, unused-argument


@pytest.mark.asyncio
@pytest.mark.github
@pytest.mark.dependency()
async def test_variable_async(test_cache_path):
    from miot.miot_storage import MIoTStorage

    storage = MIoTStorage(test_cache_path)
    test_domain = 'variable'
    test_count = 50

    for index in range(test_count):
        # bytes
        var_name = f'bytes_var{index}'
        write_value: bytes = b'bytes value->{index}\n\n\n'
        assert await storage.save_async(test_domain, var_name, write_value)
        read_value: bytes = await storage.load_async(
            test_domain, var_name, type_=bytes)
        assert read_value == write_value
        if index > test_count/2:
            assert await storage.remove_async(
                test_domain, var_name, type_=bytes)
        # str
        var_name = f'str_var{index}'
        write_value: str = f'str value->{index}\n\n\n'
        assert await storage.save_async(test_domain, var_name, write_value)
        read_value: str = await storage.load_async(
            test_domain, var_name, type_=str)
        assert read_value == write_value
        if index >= test_count/2:
            assert await storage.remove_async(test_domain, var_name, type_=str)
        # list
        var_name = f'list_var{index}'
        write_value: list = [1, 2, 3, 4, 5, 'test_list', index]
        assert await storage.save_async(test_domain, var_name, write_value)
        read_value: list = await storage.load_async(
            test_domain, var_name, type_=list)
        assert read_value == write_value
        if index >= test_count/2:
            assert await storage.remove_async(test_domain, var_name, type_=list)
        # dict
        var_name = f'dict_var{index}'
        write_value: dict = {'k1': 'v1', 'k2': 'v2', 'index': f'index-{index}'}
        assert await storage.save_async(test_domain, var_name, write_value)
        read_value: dict = await storage.load_async(
            test_domain, var_name, type_=dict)
        assert read_value == write_value
        if index >= test_count/2:
            assert await storage.remove_async(test_domain, var_name, type_=dict)

    # Delete all bytes
    names: list[str] = storage.get_names(domain=test_domain, type_=bytes)
    for name in names:
        assert await storage.remove_async(
            domain=test_domain, name=name, type_=bytes)
    assert len(storage.get_names(domain=test_domain, type_=bytes)) == 0
    assert len(storage.get_names(
        domain=test_domain, type_=str)) == test_count/2
    assert len(storage.get_names(
        domain=test_domain, type_=list)) == test_count/2
    assert len(storage.get_names(
        domain=test_domain, type_=dict)) == test_count/2


@pytest.mark.asyncio
@pytest.mark.github
@pytest.mark.dependency()
async def test_load_domain_async(test_cache_path):
    from miot.miot_storage import MIoTStorage

    storage = MIoTStorage(test_cache_path)
    test_domain = 'variable'
    names: list[str] = storage.get_names(domain=test_domain, type_=dict)
    assert len(names) > 0
    for name in names:
        r_data = await storage.load_async(test_domain, name=name, type_=dict)
        assert r_data


@pytest.mark.asyncio
@pytest.mark.github
@pytest.mark.dependency()
async def test_multi_task_load_async(test_cache_path):
    from miot.miot_storage import MIoTStorage

    storage = MIoTStorage(test_cache_path)
    test_domain = 'variable'
    task_count = 50

    names: list[str] = storage.get_names(domain=test_domain, type_=dict)
    task_list: list = []
    for name in names:
        for _ in range(task_count):
            task_list.append(asyncio.create_task(storage.load_async(
                domain=test_domain, name=name, type_=dict)))
    _LOGGER.info('task count, %s', len(task_list))
    result: list = await asyncio.gather(*task_list)
    assert None not in result


@pytest.mark.asyncio
@pytest.mark.github
@pytest.mark.dependency()
async def test_file_save_load_async(test_cache_path):
    from miot.miot_storage import MIoTStorage

    storage = MIoTStorage(test_cache_path)
    test_count = 50
    test_domain = 'file'
    for index in range(test_count):
        file_name = f'test-{index}.txt'
        file_content = f'this is a test file, the index={index}\r\r\r'.encode(
            'utf-8')
        assert await storage.save_file_async(
            test_domain, file_name, file_content)
        read_content = await storage.load_file_async(test_domain, file_name)
        assert file_content == read_content
        # Read the contents of the file directly
        with open(
            path.join(test_cache_path, test_domain, file_name), 'rb'
        ) as r_file:
            data = r_file.read()
            assert data == file_content
        if index > test_count/2:
            assert await storage.remove_file_async(
                domain=test_domain, name_with_suffix=file_name)
    # Delete domain path
    assert await storage.remove_domain_async(test_domain)


@pytest.mark.asyncio
@pytest.mark.github
@pytest.mark.dependency()
async def test_user_config_async(
        test_cache_path, test_uid, test_cloud_server):
    from miot.miot_storage import MIoTStorage

    storage = MIoTStorage(test_cache_path)
    config_base = {
        'str': 'test string',
        'list': ['test', 'list'],
        'dict': {
            'test': 'dict',
            'key1': 'value1'
        },
        'bool': False,
        'number_int': 123456,
        'number_float': 123.456
    }
    config = config_base.copy()
    assert await storage.update_user_config_async(
        uid=test_uid, cloud_server=test_cloud_server, config=config)
    # Test load all
    assert (await storage.load_user_config_async(
        uid=test_uid, cloud_server=test_cloud_server)) == config
    # Test update
    config_update = {
        'test_str': 'test str',
        'number_float': 456.123
    }
    assert await storage.update_user_config_async(
        uid=test_uid, cloud_server=test_cloud_server, config=config_update)
    config.update(config_update)
    assert (await storage.load_user_config_async(
        uid=test_uid, cloud_server=test_cloud_server)) == config
    # Test replace
    config_replace = None
    assert await storage.update_user_config_async(
        uid=test_uid, cloud_server=test_cloud_server,
        config=config_update, replace=True)
    assert (config_replace := await storage.load_user_config_async(
        uid=test_uid, cloud_server=test_cloud_server)) == config_update
    _LOGGER.info('replace result, %s', config_replace)
    # Test query
    query_keys = list(config_base.keys())
    _LOGGER.info('query keys, %s', query_keys)
    query_result = await storage.load_user_config_async(
        uid=test_uid, cloud_server=test_cloud_server, keys=query_keys)
    _LOGGER.info('query result 1, %s', query_result)
    assert await storage.update_user_config_async(
        uid=test_uid, cloud_server=test_cloud_server,
        config=config_base, replace=True)
    query_result = await storage.load_user_config_async(
        uid=test_uid, cloud_server=test_cloud_server, keys=query_keys)
    _LOGGER.info('query result 2, %s', query_result)
    query_result = await storage.load_user_config_async(
        uid=test_uid, cloud_server=test_cloud_server)
    _LOGGER.info('query result all, %s', query_result)
    # Remove config
    assert await storage.update_user_config_async(
        uid=test_uid, cloud_server=test_cloud_server, config=None)
    query_result = await storage.load_user_config_async(
        uid=test_uid, cloud_server=test_cloud_server)
    _LOGGER.info('remove result, %s', query_result)
    # Remove domain
    assert await storage.remove_domain_async(domain='miot_config')


@pytest.mark.asyncio
@pytest.mark.skip(reason='clean')
@pytest.mark.dependency()
async def test_clear_async(test_cache_path):
    from miot.miot_storage import MIoTStorage

    storage = MIoTStorage(test_cache_path)
    assert await storage.clear_async()
