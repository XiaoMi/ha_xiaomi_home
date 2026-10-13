# -*- coding: utf-8 -*-
"""Offline tests for Xiaomi cloud MQTT topic validation."""
from unittest.mock import Mock

from paho.mqtt.client import Client, MQTT_ERR_NO_CONN, MQTT_ERR_SUCCESS, MQTTv5
import pytest

# Source modules are copied by the session fixture before these imports.
# pylint: disable=import-outside-toplevel, protected-access

pytestmark = [
    pytest.mark.github,
    pytest.mark.filterwarnings(
        'ignore:Callback API version 1 is deprecated:DeprecationWarning')]


@pytest.mark.parametrize('suffix', [
    'up/properties_changed/#',
    'up/properties_changed/2/1',
    'up/event_occured/#',
    'up/event_occured/3/1',
    'state/#'])
def test_cloud_subscribe_literal_hash(suffix: str, monkeypatch):
    """Validate subscriptions and preserve the original topic on the wire."""
    from miot.miot_mips import MipsCloudClient

    topic: str = f'device/x.synthetic-C#5:13/{suffix}'
    client = MipsCloudClient._mqtt_client_class(
        client_id='offline-cloud', protocol=MQTTv5)
    queue = Mock(return_value=MQTT_ERR_SUCCESS)
    with monkeypatch.context() as context:
        context.setattr(client, '_sock', Mock())
        context.setattr(client, '_packet_queue', queue)
        result, _ = client.subscribe(topic, qos=2)
        assert result == MQTT_ERR_SUCCESS
        queue.assert_called_once()
        packet = queue.call_args.args[1]
        encoded_topic: bytes = topic.encode('utf-8')
        assert packet.endswith(
            len(encoded_topic).to_bytes(2, 'big') + encoded_topic + b'\x02')


@pytest.mark.parametrize('topic', [
    'device/123/up/properties_changed/#',
    'device/123/up/event_occured/2/1',
    'device/123/state/#',
    'device/+/state/#',
    'device/#',
    '#',
    'other/topic/+',
    'device/x.synthetic-C#5:13/state/' + 'a' * 65503])
def test_valid_cloud_subscriptions(topic: str):
    """Accept standard filters and a cloud filter at the byte length limit."""
    from miot.miot_mips import MipsCloudClient

    client = MipsCloudClient._mqtt_client_class(
        client_id='offline-cloud', protocol=MQTTv5)
    assert client.subscribe(topic) == (MQTT_ERR_NO_CONN, None)


@pytest.mark.parametrize('topic', [
    '',
    'device/#/state/#',
    'device/x#y/unknown/#',
    'device/x#+y/state/#',
    'device/x#y/state/#/invalid',
    'device/x#y/up/properties_changed/invalid#',
    'device/x#y/up/event_occured/invalid+',
    'other/x#y/state/#',
    'device/123/up/properties_changed/invalid#',
    'device/x.synthetic-C#5:13/state/' + 'a' * 65504])
def test_invalid_cloud_subscriptions(topic: str):
    """Preserve unrelated wildcard and maximum length validation."""
    from miot.miot_mips import MipsCloudClient

    client = MipsCloudClient._mqtt_client_class(
        client_id='offline-cloud', protocol=MQTTv5)
    with pytest.raises(ValueError, match='Invalid subscription filter'):
        client.subscribe(topic)


def test_local_and_standard_clients_reject_literal_hash():
    """Keep the exception scoped to the Xiaomi cloud client."""
    from miot.miot_mips import MipsLocalClient

    for factory in (Client, MipsLocalClient._mqtt_client_class):
        client = factory(client_id='offline-local', protocol=MQTTv5)
        with pytest.raises(ValueError, match='Invalid subscription filter'):
            client.subscribe('device/x.synthetic-C#5:13/state/#')
        assert client.subscribe('device/123/state/#') == (
            MQTT_ERR_NO_CONN, None)


def test_literal_hash_message_routing():
    """Route notifications only to the matching device identifier."""
    from miot.common import MIoTMatcher

    matcher = MIoTMatcher()
    matcher['device/x.synthetic-C#5:13/up/properties_changed/#'] = 'selected'
    assert list(matcher.iter_match(
        'device/x.synthetic-C#5:13/up/properties_changed/2/1')) == ['selected']
    assert not list(matcher.iter_match(
        'device/x.synthetic-C#5:14/up/properties_changed/2/1'))
