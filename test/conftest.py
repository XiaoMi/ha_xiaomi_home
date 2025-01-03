# -*- coding: utf-8 -*-
"""Pytest fixtures."""
import shutil
import pytest
from os import path, makedirs

TEST_ROOT_PATH: str = path.dirname(path.abspath(__file__))
TEST_FILES_PATH: str = path.join(TEST_ROOT_PATH, 'miot')
TEST_CACHE_PATH: str = path.join(TEST_ROOT_PATH, 'test_cache')
TEST_LANG: str = 'zh-Hans'
TEST_UID: str = '123456789'
TEST_CLOUD_SERVER: str = 'cn'


@pytest.fixture(scope='session', autouse=True)
def load_py_file():
    # Copy py file to test folder
    file_list = [
        'common.py',
        'const.py',
        'miot_cloud.py',
        'miot_error.py',
        'miot_i18n.py',
        'miot_lan.py',
        'miot_mdns.py',
        'miot_network.py',
        'miot_spec.py',
        'miot_storage.py']
    makedirs(TEST_CACHE_PATH, exist_ok=True)
    makedirs(TEST_FILES_PATH, exist_ok=True)
    for file_name in file_list:
        shutil.copyfile(
            path.join(
                TEST_ROOT_PATH, '../custom_components/xiaomi_home/miot',
                file_name),
            path.join(TEST_FILES_PATH, file_name))
    print('\nloaded test py files, ', file_list)
    # Copy spec files to test folder
    shutil.copytree(
        src=path.join(
            TEST_ROOT_PATH, '../custom_components/xiaomi_home/miot/specs'),
        dst=path.join(TEST_FILES_PATH, 'specs'),
        dirs_exist_ok=True)
    print('loaded spec test folder, specs')
    # Copy lan files to test folder
    shutil.copytree(
        src=path.join(
            TEST_ROOT_PATH, '../custom_components/xiaomi_home/miot/lan'),
        dst=path.join(TEST_FILES_PATH, 'lan'),
        dirs_exist_ok=True)
    print('loaded lan test folder, lan')
    # Copy i18n files to test folder
    shutil.copytree(
        src=path.join(
            TEST_ROOT_PATH, '../custom_components/xiaomi_home/miot/i18n'),
        dst=path.join(TEST_FILES_PATH, 'i18n'),
        dirs_exist_ok=True)
    print('loaded i18n test folder, i18n')

    yield

    if path.exists(TEST_FILES_PATH):
        shutil.rmtree(TEST_FILES_PATH)
        print('\nremoved test files, ', TEST_FILES_PATH)

    if path.exists(TEST_CACHE_PATH):
        shutil.rmtree(TEST_CACHE_PATH)
        print('removed test cache, ', TEST_CACHE_PATH)


@pytest.fixture(scope='session')
def test_root_path() -> str:
    return TEST_ROOT_PATH


@pytest.fixture(scope='session')
def test_cache_path() -> str:
    makedirs(TEST_CACHE_PATH, exist_ok=True)
    return TEST_CACHE_PATH


@pytest.fixture(scope='session')
def test_lang() -> str:
    return TEST_LANG


@pytest.fixture(scope='session')
def test_uid() -> str:
    return TEST_UID


@pytest.fixture(scope='session')
def test_cloud_server() -> str:
    return TEST_CLOUD_SERVER
