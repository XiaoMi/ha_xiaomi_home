# -*- coding: utf-8 -*-
"""Test rule format."""
import json
from os import listdir, path
from typing import Optional
import pytest
import yaml

ROOT_PATH: str = path.dirname(path.abspath(__file__))
TRANS_RELATIVE_PATH: str = path.join(
    ROOT_PATH, '../custom_components/xiaomi_home/translations')
MIOT_I18N_RELATIVE_PATH: str = path.join(
    ROOT_PATH, '../custom_components/xiaomi_home/miot/i18n')
SPEC_BOOL_TRANS_FILE = path.join(
    ROOT_PATH,
    '../custom_components/xiaomi_home/miot/specs/bool_trans.json')
SPEC_MULTI_LANG_FILE = path.join(
    ROOT_PATH,
    '../custom_components/xiaomi_home/miot/specs/multi_lang.json')
SPEC_FILTER_FILE = path.join(
    ROOT_PATH,
    '../custom_components/xiaomi_home/miot/specs/spec_filter.json')
CUSTOM_SERVICE_FILE = path.join(
    ROOT_PATH,
    '../custom_components/xiaomi_home/miot/specs/custom_service.json')

BOOL_TRANS_URN_KEY_COLON_NUM: int = 4
CUSTOM_SERVICE_URN_KEY_COLON_NUM: int = 5
MULTI_LANG_URN_KEY_COLON_NUM: int = 5
SPEC_FILTER_URN_KEY_COLON_NUM: int = 5


def load_json_file(file_path: str) -> Optional[dict]:
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            return json.load(file)
    except FileNotFoundError:
        print(file_path, 'is not found.')
        return None
    except json.JSONDecodeError:
        print(file_path, 'is not a valid JSON file.')
        return None


def save_json_file(file_path: str, data: dict) -> None:
    with open(file_path, 'w', encoding='utf-8') as file:
        json.dump(data, file, ensure_ascii=False, indent=4)


def load_yaml_file(file_path: str) -> Optional[dict]:
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            return yaml.safe_load(file)
    except FileNotFoundError:
        print(file_path, 'is not found.')
        return None
    except yaml.YAMLError:
        print(file_path, 'is not a valid YAML file.')
        return None


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

def urn_key(d: dict, cnt: int) -> bool:
    for k in d.keys():
        if cnt != k.count(':'):
            return False
    return True

def spec_filter(d: dict) -> bool:
    """restricted format: dict[str, dict[str, list<str>]]"""
    if not dict_str_dict(d):
        return False
    if not urn_key(d, SPEC_FILTER_URN_KEY_COLON_NUM):
        return False
    for value in d.values():
        for k, v in value.items():
            if not isinstance(k, str) or not isinstance(v, list):
                return False
            if not all(isinstance(i, str) for i in v):
                return False
    return True


def spec_instance_format(d: dict) -> bool:
    """restricted format of MIoT-Spec-V2 instance"""
    if ('iid' not in d) or ('type' not in d) or ('description' not in d):
        return False
    if not isinstance(d['iid'], int) or not isinstance(d['type'], str) or (
        not isinstance(d['description'], str)):
        return False
    # optional keys for property
    if 'format' in d:
        if not isinstance(d['format'], str):
            return False
    if 'unit' in d:
        if not isinstance(d['unit'], str):
            return False
    if 'access' in d:
        if not isinstance(d['access'], list):
            return False
        for i in d['access']:
            if not isinstance(i, str):
                return False
    if 'value-list' in d:
        if not isinstance(d['value-list'], list):
            return False
        for i in d['value-list']:
            if not isinstance(i, dict):
                return False
            if 'value' not in i or 'description' not in i:
                return False
            if not isinstance(i['value'], int) or not isinstance(i[
                'description'], str):
                return False
            if i['description'].replace(' ','') == '':
                return False
    # optional keys for action
    if 'in' in d:
        if not isinstance(d['in'], list):
            return False
        for i in d['in']:
            if not isinstance(i, int):
                return False
    if 'out' in d:
        if not isinstance(d['out'], list):
            return False
        for i in d['out']:
            if not isinstance(i, int):
                return False
    # optional keys for event
    if 'arguments' in d:
        if not isinstance(d['arguments'], list):
            return False
        for i in d['arguments']:
            if not isinstance(i, int):
                return False
    # optional keys for service
    if 'properties' in d:
        if not isinstance(d['properties'], list):
            return False
        for i in d['properties']:
            if not spec_instance_format(i):
                return False
    if 'actions' in d:
        if not isinstance(d['actions'], list):
            return False
        for i in d['actions']:
            if not spec_instance_format(i):
                return False
    if 'events' in d:
        if not isinstance(d['events'], list):
            return False
        for i in d['events']:
            if not spec_instance_format(i):
                return False
    return True


def is_integer(s: str) -> bool:
    try:
        int(s)
        return True
    except ValueError:
        return False


def custom_service(d: dict) -> bool:
    """restricted format: dict[str, dict[str, Any]] or dict[str, str]"""
    if not isinstance(d, dict):
        return False
    for k, v in d.items():
        if not isinstance(k, str):
            return False
        if not (isinstance(v, dict) or isinstance(v, str)):
            return False
    if not urn_key(d, CUSTOM_SERVICE_URN_KEY_COLON_NUM):
        return False
    for v in d.values():
        if isinstance(v, str):
            if CUSTOM_SERVICE_URN_KEY_COLON_NUM != v.count(':'):
                return False
            continue
        for key, value in v.items():
            if key=='new':
                if not isinstance(value, list):
                    return False
                for i in value:
                    if not spec_instance_format(i):
                        return False
            elif is_integer(key):
                if not isinstance(value, dict):
                    return False
                if not spec_instance_format(value):
                    return False
            else:
                return False
    return True


def bool_trans(d: dict) -> bool:
    """dict[str,  dict[str, str] | dict[str, dict[str, str]] ]"""
    if not isinstance(d, dict):
        return False
    if 'data' not in d or 'translate' not in d:
        return False
    if not urn_key(d['data'], BOOL_TRANS_URN_KEY_COLON_NUM):
        return False
    if not dict_str_str(d['data']):
        return False
    if not nested_3_dict_str_str(d['translate']):
        return False
    default_trans: dict = d['translate'].pop('default')
    if not default_trans:
        print('default trans is empty')
        return False
    default_keys: set[str] = set(default_trans.keys())
    for key, trans in d['translate'].items():
        trans_keys: set[str] = set(trans.keys())
        if set(trans.keys()) != default_keys:
            print('bool trans inconsistent', key, default_keys, trans_keys)
            return False
    return True

def multi_lang(d: dict) -> bool:
    """dict[str,  dict[str, dict[str, dict[str, str]] ] ]"""
    if not nested_3_dict_str_str(d):
        return False
    if not urn_key(d, MULTI_LANG_URN_KEY_COLON_NUM):
        return False
    return True

def compare_dict_structure(dict1: dict, dict2: dict) -> bool:
    if not isinstance(dict1, dict) or not isinstance(dict2, dict):
        print('invalid type')
        return False
    if dict1.keys() != dict2.keys():
        print('inconsistent key values, ', dict1.keys(), dict2.keys())
        return False
    for key in dict1:
        if isinstance(dict1[key], dict) and isinstance(dict2[key], dict):
            if not compare_dict_structure(dict1[key], dict2[key]):
                print('inconsistent key values, dict, ', key)
                return False
        elif isinstance(dict1[key], list) and isinstance(dict2[key], list):
            if not all(
                    isinstance(i, type(j))
                    for i, j in zip(dict1[key], dict2[key])):
                print('inconsistent key values, list, ', key)
                return False
        elif not isinstance(dict1[key], type(dict2[key])):
            print('inconsistent key values, type, ', key)
            return False
    return True


def sort_bool_trans(file_path: str):
    trans_data: dict = load_json_file(file_path=file_path)
    trans_data['data'] = dict(sorted(trans_data['data'].items()))
    for key, trans in trans_data['translate'].items():
        trans_data['translate'][key] = dict(sorted(trans.items()))
    return trans_data


def sort_multi_lang(file_path: str):
    lang_data: dict = load_json_file(file_path=file_path)
    lang_data = dict(sorted(lang_data.items()))
    for urn, trans in lang_data.items():
        lang_data[urn] = dict(sorted(trans.items()))
        for lang, spec in lang_data[urn].items():
            lang_data[urn][lang] = dict(sorted(spec.items()))
    return lang_data


def sort_spec_filter(file_path: str):
    filter_data: dict = load_json_file(file_path=file_path)
    filter_data = dict(sorted(filter_data.items()))
    for urn, spec in filter_data.items():
        filter_data[urn] = dict(sorted(spec.items()))
    return filter_data


def sort_custom_service(file_path: str):
    service_data: dict = load_json_file(file_path=file_path)
    service_data = dict(sorted(service_data.items()))
    for urn, spec in service_data.items():
        if isinstance(spec, dict):
            service_data[urn] = dict(sorted(spec.items()))
        else:
            service_data[urn] = spec
    return service_data


@pytest.mark.github
def test_bool_trans():
    data: dict = load_json_file(SPEC_BOOL_TRANS_FILE)
    assert data, f'load {SPEC_BOOL_TRANS_FILE} failed'
    assert bool_trans(data), f'{SPEC_BOOL_TRANS_FILE} format error'


@pytest.mark.github
def test_spec_filter():
    data: dict = load_json_file(SPEC_FILTER_FILE)
    assert data, f'load {SPEC_FILTER_FILE} failed'
    assert spec_filter(data), f'{SPEC_FILTER_FILE} format error'


@pytest.mark.github
def test_multi_lang():
    data: dict = load_json_file(SPEC_MULTI_LANG_FILE)
    assert data, f'load {SPEC_MULTI_LANG_FILE} failed'
    assert multi_lang(data), f'{SPEC_MULTI_LANG_FILE} format error'


@pytest.mark.github
def test_custom_service():
    data: dict = load_json_file(CUSTOM_SERVICE_FILE)
    assert data, f'load {CUSTOM_SERVICE_FILE} failed'
    assert custom_service(data), f'{CUSTOM_SERVICE_FILE} format error'


@pytest.mark.github
def test_miot_i18n():
    for file_name in listdir(MIOT_I18N_RELATIVE_PATH):
        file_path: str = path.join(MIOT_I18N_RELATIVE_PATH, file_name)
        data: dict = load_json_file(file_path)
        assert data, f'load {file_path} failed'
        assert nested_3_dict_str_str(data), f'{file_path} format error'


@pytest.mark.github
def test_translations():
    for file_name in listdir(TRANS_RELATIVE_PATH):
        file_path: str = path.join(TRANS_RELATIVE_PATH, file_name)
        data: dict = load_json_file(file_path)
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
    bool_trans_data: set[str] = load_json_file(SPEC_BOOL_TRANS_FILE)
    bool_trans_names: set[str] = set(
        bool_trans_data['translate']['default'].keys())
    assert len(bool_trans_names) == len(translations_names)
    # Check translation files structure
    default_dict: dict = load_json_file(
        path.join(TRANS_RELATIVE_PATH, integration_lang_list[0]))
    for name in list(integration_lang_list)[1:]:
        compare_dict: dict = load_json_file(
            path.join(TRANS_RELATIVE_PATH, name))
        if not compare_dict_structure(default_dict, compare_dict):
            print('compare_dict_structure failed /translations, ', name)
            assert False
    # Check i18n files structure
    default_dict = load_json_file(
        path.join(MIOT_I18N_RELATIVE_PATH, integration_lang_list[0]))
    for name in list(integration_lang_list)[1:]:
        compare_dict: dict = load_json_file(
            path.join(MIOT_I18N_RELATIVE_PATH, name))
        if not compare_dict_structure(default_dict, compare_dict):
            print('compare_dict_structure failed /miot/i18n, ', name)
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
        load_json_file(file_path=SPEC_BOOL_TRANS_FILE)) == json.dumps(
            sort_bool_trans(file_path=SPEC_BOOL_TRANS_FILE)), (
                f'{SPEC_BOOL_TRANS_FILE} not sorted, goto project root path'
                ' and run the following command sorting, ',
                'pytest -s -v -m update ./test/check_rule_format.py')
    assert json.dumps(
        load_json_file(file_path=SPEC_MULTI_LANG_FILE)) == json.dumps(
            sort_multi_lang(file_path=SPEC_MULTI_LANG_FILE)), (
                f'{SPEC_MULTI_LANG_FILE} not sorted, goto project root path'
                ' and run the following command sorting, ',
                'pytest -s -v -m update ./test/check_rule_format.py')
    assert json.dumps(
        load_json_file(file_path=SPEC_FILTER_FILE)) == json.dumps(
            sort_spec_filter(file_path=SPEC_FILTER_FILE)), (
                f'{SPEC_FILTER_FILE} not sorted, goto project root path'
                ' and run the following command sorting, ',
                'pytest -s -v -m update ./test/check_rule_format.py')
    assert json.dumps(
        load_json_file(file_path=CUSTOM_SERVICE_FILE)) == json.dumps(
            sort_custom_service(file_path=CUSTOM_SERVICE_FILE)), (
                f'{CUSTOM_SERVICE_FILE} not sorted, goto project root path'
                ' and run the following command sorting, ',
                'pytest -s -v -m update ./test/check_rule_format.py')


@pytest.mark.update
def test_sort_spec_data():
    sort_data: dict = sort_bool_trans(file_path=SPEC_BOOL_TRANS_FILE)
    save_json_file(file_path=SPEC_BOOL_TRANS_FILE, data=sort_data)
    print(SPEC_BOOL_TRANS_FILE, 'formatted.')
    sort_data = sort_multi_lang(file_path=SPEC_MULTI_LANG_FILE)
    save_json_file(file_path=SPEC_MULTI_LANG_FILE, data=sort_data)
    print(SPEC_MULTI_LANG_FILE, 'formatted.')
    sort_data = sort_spec_filter(file_path=SPEC_FILTER_FILE)
    save_json_file(file_path=SPEC_FILTER_FILE, data=sort_data)
    print(SPEC_FILTER_FILE, 'formatted.')
    sort_data = sort_custom_service(file_path=CUSTOM_SERVICE_FILE)
    save_json_file(file_path=CUSTOM_SERVICE_FILE, data=sort_data)
    print(CUSTOM_SERVICE_FILE, 'formatted.')
