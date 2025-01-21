# -*- coding: utf-8 -*-
"""Test rule format."""
import json
import logging
from os import listdir, path
from typing import Optional
import pytest
import yaml

_LOGGER = logging.getLogger(__name__)

ROOT_PATH: str = path.dirname(path.abspath(__file__))
TRANS_RELATIVE_PATH: str = path.join(
    ROOT_PATH, '../custom_components/xiaomi_home/translations')
MIOT_I18N_RELATIVE_PATH: str = path.join(
    ROOT_PATH, '../custom_components/xiaomi_home/miot/i18n')
SPEC_BOOL_TRANS_FILE = path.join(
    ROOT_PATH,
    '../custom_components/xiaomi_home/miot/specs/bool_trans.yaml')
SPEC_FILTER_FILE = path.join(
    ROOT_PATH,
    '../custom_components/xiaomi_home/miot/specs/spec_filter.yaml')
SPEC_MODIFY_FILE = path.join(
    ROOT_PATH,
    '../custom_components/xiaomi_home/miot/specs/spec_modify.yaml')


def load_json_file(file_path: str) -> Optional[dict]:
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            return json.load(file)
    except FileNotFoundError:
        _LOGGER.info('%s is not found.', file_path,)
        return None
    except json.JSONDecodeError:
        _LOGGER.info('%s is not a valid JSON file.', file_path)
        return None


def save_json_file(file_path: str, data: dict) -> None:
    with open(file_path, 'w', encoding='utf-8') as file:
        json.dump(data, file, ensure_ascii=False, indent=4)


def load_yaml_file(file_path: str) -> Optional[dict]:
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            return yaml.safe_load(file)
    except FileNotFoundError:
        _LOGGER.info('%s is not found.', file_path)
        return None
    except yaml.YAMLError:
        _LOGGER.info('%s, is not a valid YAML file.', file_path)
        return None


def save_yaml_file(file_path: str, data: dict) -> None:
    with open(file_path, 'w', encoding='utf-8') as file:
        yaml.safe_dump(
            data, file, default_flow_style=False,
            allow_unicode=True, indent=2, sort_keys=False)


def dict_str_str(d: dict) -> bool:
    """restricted format: dict[str, str]"""
    if not isinstance(d, dict):
        return False
    for k, v in d.items():
        if not isinstance(k, str) or not isinstance(v, str):
            return False
    return True


def dict_str_dict(d: dict) -> bool:
    """restricted format: dict[str, dict]"""
    if not isinstance(d, dict):
        return False
    for k, v in d.items():
        if not isinstance(k, str) or not isinstance(v, dict):
            return False
    return True


def nested_2_dict_str_str(d: dict) -> bool:
    """restricted format: dict[str, dict[str, str]]"""
    if not dict_str_dict(d):
        return False
    for v in d.values():
        if not dict_str_str(v):
            return False
    return True


def nested_3_dict_str_str(d: dict) -> bool:
    """restricted format: dict[str, dict[str, dict[str, str]]]"""
    if not dict_str_dict(d):
        return False
    for v in d.values():
        if not nested_2_dict_str_str(v):
            return False
    return True


def spec_filter(d: dict) -> bool:
    """restricted format: dict[str, dict[str, list<str>]]"""
    if not dict_str_dict(d):
        return False
    for value in d.values():
        for k, v in value.items():
            if not isinstance(k, str) or not isinstance(v, list):
                return False
            if not all(isinstance(i, str) for i in v):
                return False
    return True


def bool_trans(d: dict) -> bool:
    """dict[str,  dict[str, str] | dict[str, dict[str, str]] ]"""
    if not isinstance(d, dict):
        return False
    if 'data' not in d or 'translate' not in d:
        return False
    if not dict_str_str(d['data']):
        return False
    if not nested_3_dict_str_str(d['translate']):
        return False
    default_trans: dict = d['translate'].pop('default')
    if not default_trans:
        _LOGGER.info('default trans is empty')
        return False
    default_keys: set[str] = set(default_trans.keys())
    for key, trans in d['translate'].items():
        trans_keys: set[str] = set(trans.keys())
        if set(trans.keys()) != default_keys:
            _LOGGER.info(
                'bool trans inconsistent, %s, %s, %s',
                key, default_keys, trans_keys)
            return False
    return True


def spec_modify(data: dict) -> bool:
    """dict[str, str | dict[str, dict]]"""
    if not isinstance(data, dict):
        return False
    for urn, content in data.items():
        if not isinstance(urn, str) or not isinstance(content, (dict, str)):
            return False
        if isinstance(content, str):
            continue
        for key, value in content.items():
            if not isinstance(key, str) or not isinstance(value, dict):
                return False
    return True


def compare_dict_structure(dict1: dict, dict2: dict) -> bool:
    if not isinstance(dict1, dict) or not isinstance(dict2, dict):
        _LOGGER.info('invalid type')
        return False
    if dict1.keys() != dict2.keys():
        _LOGGER.info(
            'inconsistent key values, %s, %s', dict1.keys(), dict2.keys())
        return False
    for key in dict1:
        if isinstance(dict1[key], dict) and isinstance(dict2[key], dict):
            if not compare_dict_structure(dict1[key], dict2[key]):
                _LOGGER.info(
                    'inconsistent key values, dict, %s', key)
                return False
        elif isinstance(dict1[key], list) and isinstance(dict2[key], list):
            if not all(
                    isinstance(i, type(j))
                    for i, j in zip(dict1[key], dict2[key])):
                _LOGGER.info(
                    'inconsistent key values, list, %s', key)
                return False
        elif not isinstance(dict1[key], type(dict2[key])):
            _LOGGER.info(
                'inconsistent key values, type, %s', key)
            return False
    return True


def sort_bool_trans(file_path: str):
    trans_data = load_yaml_file(file_path=file_path)
    assert isinstance(trans_data, dict), f'{file_path} format error'
    trans_data['data'] = dict(sorted(trans_data['data'].items()))
    for key, trans in trans_data['translate'].items():
        trans_data['translate'][key] = dict(sorted(trans.items()))
    return trans_data


def sort_spec_filter(file_path: str):
    filter_data = load_yaml_file(file_path=file_path)
    assert isinstance(filter_data, dict), f'{file_path} format error'
    filter_data = dict(sorted(filter_data.items()))
    for urn, spec in filter_data.items():
        filter_data[urn] = dict(sorted(spec.items()))
    return filter_data


def sort_spec_modify(file_path: str):
    filter_data = load_yaml_file(file_path=file_path)
    assert isinstance(filter_data, dict), f'{file_path} format error'
    return dict(sorted(filter_data.items()))


@pytest.mark.github
def test_bool_trans():
    data = load_yaml_file(SPEC_BOOL_TRANS_FILE)
    assert isinstance(data, dict)
    assert data, f'load {SPEC_BOOL_TRANS_FILE} failed'
    assert bool_trans(data), f'{SPEC_BOOL_TRANS_FILE} format error'


@pytest.mark.github
def test_spec_filter():
    data = load_yaml_file(SPEC_FILTER_FILE)
    assert isinstance(data, dict)
    assert data, f'load {SPEC_FILTER_FILE} failed'
    assert spec_filter(data), f'{SPEC_FILTER_FILE} format error'


@pytest.mark.github
def test_spec_modify():
    data = load_yaml_file(SPEC_MODIFY_FILE)
    assert isinstance(data, dict)
    assert data, f'load {SPEC_MODIFY_FILE} failed'
    assert spec_modify(data), f'{SPEC_MODIFY_FILE} format error'


@pytest.mark.github
def test_miot_i18n():
    for file_name in listdir(MIOT_I18N_RELATIVE_PATH):
        file_path: str = path.join(MIOT_I18N_RELATIVE_PATH, file_name)
        data = load_json_file(file_path)
        assert isinstance(data, dict)
        assert data, f'load {file_path} failed'
        assert nested_3_dict_str_str(data), f'{file_path} format error'


@pytest.mark.github
def test_translations():
    for file_name in listdir(TRANS_RELATIVE_PATH):
        file_path: str = path.join(TRANS_RELATIVE_PATH, file_name)
        data = load_json_file(file_path)
        assert isinstance(data, dict)
        assert data, f'load {file_path} failed'
        assert dict_str_dict(data), f'{file_path} format error'


@pytest.mark.github
def test_miot_lang_integrity():
    # pylint: disable=import-outside-toplevel
    from miot.const import INTEGRATION_LANGUAGES
    integration_lang_list: list[str] = [
        f'{key}.json' for key in list(INTEGRATION_LANGUAGES.keys())]
    translations_names: set[str] = set(listdir(TRANS_RELATIVE_PATH))
    assert len(translations_names) == len(integration_lang_list)
    assert translations_names == set(integration_lang_list)
    i18n_names: set[str] = set(listdir(MIOT_I18N_RELATIVE_PATH))
    assert len(i18n_names) == len(translations_names)
    assert i18n_names == translations_names
    bool_trans_data = load_yaml_file(SPEC_BOOL_TRANS_FILE)
    assert isinstance(bool_trans_data, dict)
    bool_trans_names: set[str] = set(
        bool_trans_data['translate']['default'].keys())
    assert len(bool_trans_names) == len(translations_names)
    # Check translation files structure
    default_dict = load_json_file(
        path.join(TRANS_RELATIVE_PATH, integration_lang_list[0]))
    for name in list(integration_lang_list)[1:]:
        compare_dict = load_json_file(
            path.join(TRANS_RELATIVE_PATH, name))
        if not compare_dict_structure(default_dict, compare_dict):
            _LOGGER.info(
                'compare_dict_structure failed /translations, %s', name)
            assert False
    # Check i18n files structure
    default_dict = load_json_file(
        path.join(MIOT_I18N_RELATIVE_PATH, integration_lang_list[0]))
    for name in list(integration_lang_list)[1:]:
        compare_dict = load_json_file(
            path.join(MIOT_I18N_RELATIVE_PATH, name))
        if not compare_dict_structure(default_dict, compare_dict):
            _LOGGER.info(
                'compare_dict_structure failed /miot/i18n, %s', name)
            assert False


@pytest.mark.github
def test_miot_data_sort():
    # pylint: disable=import-outside-toplevel
    from miot.const import INTEGRATION_LANGUAGES
    sort_langs: dict = dict(sorted(INTEGRATION_LANGUAGES.items()))
    assert list(INTEGRATION_LANGUAGES.keys()) == list(sort_langs.keys()), (
        'INTEGRATION_LANGUAGES not sorted, correct order\r\n'
        f'{list(sort_langs.keys())}')
    assert json.dumps(
        load_yaml_file(file_path=SPEC_BOOL_TRANS_FILE)) == json.dumps(
            sort_bool_trans(file_path=SPEC_BOOL_TRANS_FILE)), (
                f'{SPEC_BOOL_TRANS_FILE} not sorted, goto project root path'
                ' and run the following command sorting, ',
                'pytest -s -v -m update ./test/check_rule_format.py')
    assert json.dumps(
        load_yaml_file(file_path=SPEC_FILTER_FILE)) == json.dumps(
            sort_spec_filter(file_path=SPEC_FILTER_FILE)), (
                f'{SPEC_FILTER_FILE} not sorted, goto project root path'
                ' and run the following command sorting, ',
                'pytest -s -v -m update ./test/check_rule_format.py')


@pytest.mark.update
def test_sort_spec_data():
    sort_data: dict = sort_bool_trans(file_path=SPEC_BOOL_TRANS_FILE)
    save_yaml_file(file_path=SPEC_BOOL_TRANS_FILE, data=sort_data)
    _LOGGER.info('%s formatted.', SPEC_BOOL_TRANS_FILE)
    sort_data = sort_spec_filter(file_path=SPEC_FILTER_FILE)
    save_yaml_file(file_path=SPEC_FILTER_FILE, data=sort_data)
    _LOGGER.info('%s formatted.', SPEC_FILTER_FILE)
    sort_data = sort_spec_modify(file_path=SPEC_MODIFY_FILE)
    save_yaml_file(file_path=SPEC_MODIFY_FILE, data=sort_data)
    _LOGGER.info('%s formatted.', SPEC_MODIFY_FILE)
