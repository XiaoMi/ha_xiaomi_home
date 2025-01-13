# -*- coding: utf-8 -*-
"""Unit test for miot_spec.py."""
import json
import logging
import random
import time
from urllib.request import Request, urlopen
import pytest

_LOGGER = logging.getLogger(__name__)

# pylint: disable=import-outside-toplevel, unused-argument


@pytest.mark.parametrize('urn', [
    'urn:miot-spec-v2:device:gateway:0000A019:xiaomi-hub1:3',
    'urn:miot-spec-v2:device:light:0000A001:mijia-group3:3:0000C802',
    'urn:miot-spec-v2:device:air-conditioner:0000A004:xiaomi-ar03r1:1',
    'urn:miot-spec-v2:device:air-purifier:0000A007:xiaomi-va5:1:0000D050',
    'urn:miot-spec-v2:device:humidifier:0000A00E:xiaomi-p800:1',
    'urn:miot-spec-v2:device:curtain:0000A00C:xiaomi-acn010:1:0000D031',
    'urn:miot-spec-v2:device:motion-sensor:0000A014:xiaomi-pir1:2',
    'urn:miot-spec-v2:device:light:0000A001:philips-strip3:2'])
@pytest.mark.asyncio
@pytest.mark.dependency()
async def test_spec_parse_async(test_cache_path, test_lang, urn):
    from miot.miot_spec import MIoTSpecParser
    from miot.miot_storage import MIoTStorage

    storage = MIoTStorage(test_cache_path)
    spec_parser = MIoTSpecParser(lang=test_lang, storage=storage)
    await spec_parser.init_async()
    assert await spec_parser.parse(urn=urn)


@pytest.mark.parametrize('urn_list', [[
    'urn:miot-spec-v2:device:gateway:0000A019:xiaomi-hub1:3',
    'urn:miot-spec-v2:device:light:0000A001:mijia-group3:3:0000C802',
    'urn:miot-spec-v2:device:air-conditioner:0000A004:xiaomi-ar03r1:1',
    'urn:miot-spec-v2:device:air-purifier:0000A007:xiaomi-va5:1:0000D050',
    'urn:miot-spec-v2:device:humidifier:0000A00E:xiaomi-p800:1',
    'urn:miot-spec-v2:device:curtain:0000A00C:xiaomi-acn010:1:0000D031',
    'urn:miot-spec-v2:device:motion-sensor:0000A014:xiaomi-pir1:2',
    'urn:miot-spec-v2:device:light:0000A001:philips-strip3:2']])
@pytest.mark.asyncio
@pytest.mark.dependency()
async def test_spec_refresh_async(test_cache_path, test_lang, urn_list):
    from miot.miot_spec import MIoTSpecParser
    from miot.miot_storage import MIoTStorage

    storage = MIoTStorage(test_cache_path)
    spec_parser = MIoTSpecParser(lang=test_lang, storage=storage)
    await spec_parser.init_async()
    assert await spec_parser.refresh_async(urn_list=urn_list) == len(urn_list)


@pytest.mark.asyncio
@pytest.mark.dependency()
async def test_spec_random_parse_async(test_cache_path, test_lang):
    from miot.miot_spec import MIoTSpecParser
    from miot.miot_storage import MIoTStorage

    test_count = 10
    # get test data

    def get_release_instance() -> list[str]:
        request = Request(
            'https://miot-spec.org/miot-spec-v2/instances?status=released',
            method='GET')
        with urlopen(request) as response:
            content = response.read()
            res_obj = json.loads(str(content, 'utf-8'))
            result: list[str] = []
            for item in res_obj['instances']:
                result.append(item['type'])
            return result
    test_urns: list[str] = get_release_instance()
    test_urn_index: list[int] = random.sample(
        list(range(len(test_urns))), test_count)

    # get local cache
    storage = MIoTStorage(test_cache_path)
    spec_parser = MIoTSpecParser(lang=test_lang, storage=storage)
    await spec_parser.init_async()
    start_ts = time.time()*1000
    for index in test_urn_index:
        urn: str = test_urns[int(index)]
        result = await spec_parser.parse(urn=urn, skip_cache=True)
        assert result is not None
    end_ts = time.time()*1000
    _LOGGER.info('takes time, %s, %s', test_count, end_ts-start_ts)
