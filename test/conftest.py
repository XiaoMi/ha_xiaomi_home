# -*- coding: utf-8 -*-
"""Pytest fixtures."""
import logging
import random
import shutil
import pytest
from os import path, makedirs
from uuid import uuid4

TEST_ROOT_PATH: str = path.dirname(path.abspath(__file__))
TEST_FILES_PATH: str = path.join(TEST_ROOT_PATH, 'miot')
TEST_CACHE_PATH: str = path.join(TEST_ROOT_PATH, 'test_cache')
TEST_OAUTH2_REDIRECT_URL: str = 'http://homeassistant.local:8123'
TEST_LANG: str = 'zh-Hans'
TEST_UID: str = '123456789'
TEST_CLOUD_SERVER: str = 'cn'

DOMAIN_CLOUD_CACHE: str = 'cloud_cache'

_LOGGER = logging.getLogger(__name__)


@pytest.fixture(scope='session', autouse=True)
def set_logger():
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    _LOGGER.info('set logger, %s', logger)


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
        'miot_mips.py',
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
    _LOGGER.info('\nloaded test py files, %s', file_list)
    # Copy spec files to test folder
    shutil.copytree(
        src=path.join(
            TEST_ROOT_PATH, '../custom_components/xiaomi_home/miot/specs'),
        dst=path.join(TEST_FILES_PATH, 'specs'),
        dirs_exist_ok=True)
    _LOGGER.info('loaded spec test folder, specs')
    # Copy lan files to test folder
    shutil.copytree(
        src=path.join(
            TEST_ROOT_PATH, '../custom_components/xiaomi_home/miot/lan'),
        dst=path.join(TEST_FILES_PATH, 'lan'),
        dirs_exist_ok=True)
    _LOGGER.info('loaded lan test folder, lan')
    # Copy i18n files to test folder
    shutil.copytree(
        src=path.join(
            TEST_ROOT_PATH, '../custom_components/xiaomi_home/miot/i18n'),
        dst=path.join(TEST_FILES_PATH, 'i18n'),
        dirs_exist_ok=True)
    _LOGGER.info('loaded i18n test folder, i18n')

    yield

    # NOTICE: All test files and data (tokens, device information, etc.) will
    # be deleted after the test is completed. For some test cases that
    # require caching data, you can comment out the following code.

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
def test_oauth2_redirect_url() -> str:
    return TEST_OAUTH2_REDIRECT_URL


@pytest.fixture(scope='session')
def test_lang() -> str:
    return TEST_LANG


@pytest.fixture(scope='session')
def test_uid() -> str:
    return TEST_UID


@pytest.fixture(scope='session')
def test_random_did() -> str:
    # Gen random did
    return str(random.getrandbits(64))


@pytest.fixture(scope='session')
def test_uuid() -> str:
    # Gen uuid
    return uuid4().hex


@pytest.fixture(scope='session')
def test_cloud_server() -> str:
    return TEST_CLOUD_SERVER


@pytest.fixture(scope='session')
def test_domain_cloud_cache() -> str:
    return DOMAIN_CLOUD_CACHE


@pytest.fixture(scope='session')
def test_name_oauth2_info() -> str:
    return f'{TEST_CLOUD_SERVER}_oauth2_info'


@pytest.fixture(scope='session')
def test_name_uid() -> str:
    return f'{TEST_CLOUD_SERVER}_uid'


@pytest.fixture(scope='session')
def test_name_uuid() -> str:
    return f'{TEST_CLOUD_SERVER}_uuid'


@pytest.fixture(scope='session')
def test_name_rd_did() -> str:
    return f'{TEST_CLOUD_SERVER}_rd_did'


@pytest.fixture(scope='session')
def test_name_homes() -> str:
    return f'{TEST_CLOUD_SERVER}_homes'


@pytest.fixture(scope='session')
def test_name_devices() -> str:
    return f'{TEST_CLOUD_SERVER}_devices'
