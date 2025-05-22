# -*- coding: utf-8 -*-
"""Unit test for miot_common.py."""
import pytest

# pylint: disable=import-outside-toplevel, unused-argument


@pytest.mark.github
def test_miot_matcher():
    from miot.common import MIoTMatcher

    matcher: MIoTMatcher = MIoTMatcher()
    # Add
    for l1 in range(1, 11):
        matcher[f'test/{l1}/#'] = f'test/{l1}/#'
        for l2 in range(1, 11):
            matcher[f'test/{l1}/{l2}'] = f'test/{l1}/{l2}'
            if not matcher.get(topic=f'test/+/{l2}'):
                matcher[f'test/+/{l2}'] = f'test/+/{l2}'
    # Match
    match_result: list[str] = list(matcher.iter_all_nodes())
    assert len(match_result) == 120
    match_result: list[str] = list(matcher.iter_match(topic='test/1/1'))
    assert len(match_result) == 3
    assert set(match_result) == set(['test/1/1', 'test/+/1', 'test/1/#'])
    # Delete
    if matcher.get(topic='test/1/1'):
        del matcher['test/1/1']
    assert len(list(matcher.iter_all_nodes())) == 119
    match_result: list[str] = list(matcher.iter_match(topic='test/1/1'))
    assert len(match_result) == 2
    assert set(match_result) == set(['test/+/1', 'test/1/#'])
