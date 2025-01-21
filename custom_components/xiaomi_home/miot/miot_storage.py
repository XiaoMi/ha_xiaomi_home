# -*- coding: utf-8 -*-
"""
Copyright (C) 2024 Xiaomi Corporation.

The ownership and intellectual property rights of Xiaomi Home Assistant
Integration and related Xiaomi cloud service API interface provided under this
license, including source code and object code (collectively, "Licensed Work"),
are owned by Xiaomi. Subject to the terms and conditions of this License, Xiaomi
hereby grants you a personal, limited, non-exclusive, non-transferable,
non-sublicensable, and royalty-free license to reproduce, use, modify, and
distribute the Licensed Work only for your use of Home Assistant for
non-commercial purposes. For the avoidance of doubt, Xiaomi does not authorize
you to use the Licensed Work for any other purpose, including but not limited
to use Licensed Work to develop applications (APP), Web services, and other
forms of software.

You may reproduce and distribute copies of the Licensed Work, with or without
modifications, whether in source or object form, provided that you must give
any other recipients of the Licensed Work a copy of this License and retain all
copyright and disclaimers.

Xiaomi provides the Licensed Work on an "AS IS" BASIS, WITHOUT WARRANTIES OR
CONDITIONS OF ANY KIND, either express or implied, including, without
limitation, any warranties, undertakes, or conditions of TITLE, NO ERROR OR
OMISSION, CONTINUITY, RELIABILITY, NON-INFRINGEMENT, MERCHANTABILITY, or
FITNESS FOR A PARTICULAR PURPOSE. In any event, you are solely responsible
for any direct, indirect, special, incidental, or consequential damages or
losses arising from the use or inability to use the Licensed Work.

Xiaomi reserves all rights not expressly granted to you in this License.
Except for the rights expressly granted by Xiaomi under this License, Xiaomi
does not authorize you in any form to use the trademarks, copyrights, or other
forms of intellectual property rights of Xiaomi and its affiliates, including,
without limitation, without obtaining other written permission from Xiaomi, you
shall not use "Xiaomi", "Mijia" and other words related to Xiaomi or words that
may make the public associate with Xiaomi in any form to publicize or promote
the software or hardware devices that use the Licensed Work.

Xiaomi has the right to immediately terminate all your authorization under this
License in the event:
1. You assert patent invalidation, litigation, or other claims against patents
or other intellectual property rights of Xiaomi or its affiliates; or,
2. You make, have made, manufacture, sell, or offer to sell products that knock
off Xiaomi or its affiliates' products.

MIoT storage and certificate management.
"""
import os
import asyncio
import binascii
import json
import shutil
import time
import traceback
import hashlib
from datetime import datetime, timezone
from enum import Enum, auto
from pathlib import Path
from typing import Any, Optional, Union
import logging
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ed25519


# pylint: disable=relative-beyond-top-level
from .const import (
    MANUFACTURER_EFFECTIVE_TIME,
    MIHOME_CA_CERT_STR,
    MIHOME_CA_CERT_SHA256)
from .common import MIoTHttp
from .miot_error import MIoTCertError, MIoTError, MIoTStorageError

_LOGGER = logging.getLogger(__name__)


class MIoTStorageType(Enum):
    LOAD = auto()
    LOAD_FILE = auto()
    SAVE = auto()
    SAVE_FILE = auto()
    DEL = auto()
    DEL_FILE = auto()
    CLEAR = auto()


class MIoTStorage:
    """File management.

    User data will be stored in the `.storage` directory of Home Assistant.
    """
    _main_loop: asyncio.AbstractEventLoop
    _file_future: dict[str, tuple[MIoTStorageType, asyncio.Future]]

    _root_path: str

    def __init__(
        self, root_path: str,
        loop: Optional[asyncio.AbstractEventLoop] = None
    ) -> None:
        """Initialize with a root path."""
        self._main_loop = loop or asyncio.get_running_loop()
        self._file_future = {}

        self._root_path = os.path.abspath(root_path)
        os.makedirs(self._root_path, exist_ok=True)

        _LOGGER.debug('root path, %s', self._root_path)

    def __get_full_path(self, domain: str, name: str, suffix: str) -> str:
        return os.path.join(
            self._root_path, domain, f'{name}.{suffix}')

    def __add_file_future(
        self, key: str, op_type: MIoTStorageType, fut: asyncio.Future
    ) -> None:
        def fut_done_callback(fut: asyncio.Future):
            del fut
            self._file_future.pop(key, None)

        fut.add_done_callback(fut_done_callback)
        self._file_future[key] = op_type, fut

    def __load(
        self, full_path: str, type_: type = bytes, with_hash_check: bool = True
    ) -> Union[bytes, str, dict, list, None]:
        if not os.path.exists(full_path):
            _LOGGER.debug('load error, file does not exist, %s', full_path)
            return None
        if not os.access(full_path, os.R_OK):
            _LOGGER.error('load error, file not readable, %s', full_path)
            return None
        try:
            with open(full_path, 'rb') as r_file:
                r_data: bytes = r_file.read()
                if r_data is None:
                    _LOGGER.error('load error, empty file, %s', full_path)
                    return None
                data_bytes: bytes
                # Hash check
                if with_hash_check:
                    if len(r_data) <= 32:
                        return None
                    data_bytes = r_data[:-32]
                    hash_value = r_data[-32:]
                    if hashlib.sha256(data_bytes).digest() != hash_value:
                        _LOGGER.error(
                            'load error, hash check failed, %s', full_path)
                        return None
                else:
                    data_bytes = r_data
                if type_ == bytes:
                    return data_bytes
                if type_ == str:
                    return str(data_bytes, 'utf-8')
                if type_ in [dict, list]:
                    return json.loads(data_bytes)
                _LOGGER.error(
                    'load error, unsupported data type, %s', type_.__name__)
                return None
        except (OSError, TypeError) as e:
            _LOGGER.error('load error, %s, %s', e, traceback.format_exc())
            return None

    def load(
        self, domain: str, name: str, type_: type = bytes
    ) -> Union[bytes, str, dict, list, None]:
        full_path = self.__get_full_path(
            domain=domain, name=name, suffix=type_.__name__)
        return self.__load(full_path=full_path, type_=type_)

    async def load_async(
        self, domain: str, name: str, type_: type = bytes
    ) -> Union[bytes, str, dict, list, None]:
        full_path = self.__get_full_path(
            domain=domain, name=name, suffix=type_.__name__)
        if full_path in self._file_future:
            # Waiting for the last task to be completed
            op_type, fut = self._file_future[full_path]
            if op_type == MIoTStorageType.LOAD:
                if not fut.done():
                    return await fut
            else:
                await fut
        fut = self._main_loop.run_in_executor(
            None, self.__load, full_path, type_)
        if not fut.done():
            self.__add_file_future(full_path, MIoTStorageType.LOAD, fut)
        return await fut

    def __save(
        self, full_path: str, data: Union[bytes, str, dict, list, None],
        cover: bool = True, with_hash: bool = True
    ) -> bool:
        if data is None:
            _LOGGER.error('save error, save data is None')
            return False
        if os.path.exists(full_path):
            if not cover:
                _LOGGER.error('save error, file exists, cover is False')
                return False
            if not os.access(full_path, os.W_OK):
                _LOGGER.error('save error, file not writeable, %s', full_path)
                return False
        else:
            os.makedirs(os.path.dirname(full_path), exist_ok=True)
        try:
            w_bytes: bytes
            if isinstance(data, bytes):
                w_bytes = data
            elif isinstance(data, str):
                w_bytes = data.encode('utf-8')
            elif isinstance(data, (dict, list)):
                w_bytes = json.dumps(data).encode('utf-8')
            else:
                _LOGGER.error(
                    'save error, unsupported data type, %s',
                    type(data).__name__)
                return False
            with open(full_path, 'wb') as w_file:
                w_file.write(w_bytes)
                if with_hash:
                    w_file.write(hashlib.sha256(w_bytes).digest())
            return True
        except (OSError, TypeError) as e:
            _LOGGER.error('save error, %s, %s', e, traceback.format_exc())
            return False

    def save(
        self, domain: str, name: str, data: Union[bytes, str, dict, list, None]
    ) -> bool:
        full_path = self.__get_full_path(
            domain=domain, name=name, suffix=type(data).__name__)
        return self.__save(full_path=full_path, data=data)

    async def save_async(
        self, domain: str, name: str, data: Union[bytes, str, dict, list, None]
    ) -> bool:
        full_path = self.__get_full_path(
            domain=domain, name=name, suffix=type(data).__name__)
        if full_path in self._file_future:
            # Waiting for the last task to be completed
            fut = self._file_future[full_path][1]
            await fut
        fut = self._main_loop.run_in_executor(
            None, self.__save, full_path, data)
        if not fut.done():
            self.__add_file_future(full_path, MIoTStorageType.SAVE, fut)
        return await fut

    def __remove(self, full_path: str) -> bool:
        item = Path(full_path)
        if item.is_file() or item.is_symlink():
            item.unlink()
        return True

    def remove(self, domain: str, name: str, type_: type) -> bool:
        full_path = self.__get_full_path(
            domain=domain, name=name, suffix=type_.__name__)
        return self.__remove(full_path=full_path)

    async def remove_async(self, domain: str, name: str, type_: type) -> bool:
        full_path = self.__get_full_path(
            domain=domain, name=name, suffix=type_.__name__)
        if full_path in self._file_future:
            # Waiting for the last task to be completed
            op_type, fut = self._file_future[full_path]
            if op_type == MIoTStorageType.DEL:
                if not fut.done():
                    return await fut
            else:
                await fut
        fut = self._main_loop.run_in_executor(None, self.__remove, full_path)
        if not fut.done():
            self.__add_file_future(full_path, MIoTStorageType.DEL, fut)
        return await fut

    def __remove_domain(self, full_path: str) -> bool:
        path_obj = Path(full_path)
        if path_obj.exists():
            # Recursive deletion
            shutil.rmtree(path_obj)
        return True

    def remove_domain(self, domain: str) -> bool:
        full_path = os.path.join(self._root_path, domain)
        return self.__remove_domain(full_path=full_path)

    async def remove_domain_async(self, domain: str) -> bool:
        full_path = os.path.join(self._root_path, domain)
        if full_path in self._file_future:
            # Waiting for the last task to be completed
            op_type, fut = self._file_future[full_path]
            if op_type == MIoTStorageType.DEL:
                if not fut.done():
                    return await fut
            else:
                await fut
        # Waiting domain tasks finish
        for path, value in self._file_future.items():
            if path.startswith(full_path):
                await value[1]
        fut = self._main_loop.run_in_executor(
            None, self.__remove_domain, full_path)
        if not fut.done():
            self.__add_file_future(full_path, MIoTStorageType.DEL, fut)
        return await fut

    def get_names(self, domain: str, type_: type) -> list[str]:
        path: str = os.path.join(self._root_path, domain)
        type_str = f'.{type_.__name__}'
        names: list[str] = []
        for item in Path(path).glob(f'*{type_str}'):
            if not item.is_file() and not item.is_symlink():
                continue
            names.append(item.name.replace(type_str, ''))
        return names

    def file_exists(self, domain: str, name_with_suffix: str) -> bool:
        return os.path.exists(
            os.path.join(self._root_path, domain, name_with_suffix))

    def save_file(
        self, domain: str, name_with_suffix: str, data: bytes
    ) -> bool:
        if not isinstance(data, bytes):
            _LOGGER.error('save file error, file must be bytes')
            return False
        full_path = os.path.join(self._root_path, domain, name_with_suffix)
        return self.__save(full_path=full_path, data=data,  with_hash=False)

    async def save_file_async(
        self, domain: str, name_with_suffix: str, data: bytes
    ) -> bool:
        if not isinstance(data, bytes):
            _LOGGER.error('save file error, file must be bytes')
            return False
        full_path = os.path.join(self._root_path, domain, name_with_suffix)
        if full_path in self._file_future:
            # Waiting for the last task to be completed
            fut = self._file_future[full_path][1]
            await fut
        fut = self._main_loop.run_in_executor(
            None, self.__save, full_path, data, True, False)
        if not fut.done():
            self.__add_file_future(full_path, MIoTStorageType.SAVE_FILE, fut)
        return await fut

    def load_file(self, domain: str, name_with_suffix: str) -> Optional[bytes]:
        full_path = os.path.join(self._root_path, domain, name_with_suffix)
        return self.__load(
            full_path=full_path, type_=bytes,
            with_hash_check=False)  # type: ignore

    async def load_file_async(
        self, domain: str, name_with_suffix: str
    ) -> Optional[bytes]:
        full_path = os.path.join(self._root_path, domain, name_with_suffix)
        if full_path in self._file_future:
            # Waiting for the last task to be completed
            op_type, fut = self._file_future[full_path]
            if op_type == MIoTStorageType.LOAD_FILE:
                if not fut.done():
                    return await fut
            else:
                await fut
        fut = self._main_loop.run_in_executor(
            None, self.__load, full_path, bytes, False)
        if not fut.done():
            self.__add_file_future(full_path, MIoTStorageType.LOAD_FILE, fut)
        return await fut  # type: ignore

    def remove_file(self, domain: str, name_with_suffix: str) -> bool:
        full_path = os.path.join(self._root_path, domain, name_with_suffix)
        return self.__remove(full_path=full_path)

    async def remove_file_async(
        self, domain: str, name_with_suffix: str
    ) -> bool:
        full_path = os.path.join(self._root_path, domain, name_with_suffix)
        if full_path in self._file_future:
            # Waiting for the last task to be completed
            op_type, fut = self._file_future[full_path]
            if op_type == MIoTStorageType.DEL_FILE:
                if not fut.done():
                    return await fut
            else:
                await fut
        fut = self._main_loop.run_in_executor(None, self.__remove, full_path)
        if not fut.done():
            self.__add_file_future(full_path, MIoTStorageType.DEL_FILE, fut)
        return await fut

    def clear(self) -> bool:
        root_path = Path(self._root_path)
        for item in root_path.iterdir():
            if item.is_file() or item.is_symlink():
                item.unlink()
            elif item.is_dir():
                shutil.rmtree(item)
        return True

    async def clear_async(self) -> bool:
        if self._root_path in self._file_future:
            op_type, fut = self._file_future[self._root_path]
            if op_type == MIoTStorageType.CLEAR and not fut.done():
                return await fut
        # Waiting all future resolve
        for value in self._file_future.values():
            await value[1]

        fut = self._main_loop.run_in_executor(None, self.clear)
        if not fut.done():
            self.__add_file_future(
                self._root_path, MIoTStorageType.CLEAR, fut)
        return await fut

    def update_user_config(
        self, uid: str, cloud_server: str, config: Optional[dict[str, Any]],
        replace: bool = False
    ) -> bool:
        if config is not None and len(config) == 0:
            # Do nothing
            return True

        config_domain = 'miot_config'
        config_name = f'{uid}_{cloud_server}'
        if config is None:
            # Remove config file
            return self.remove(
                domain=config_domain, name=config_name, type_=dict)
        if replace:
            # Replace config file
            return self.save(
                domain=config_domain, name=config_name, data=config)
        local_config = (self.load(domain=config_domain,
                        name=config_name, type_=dict)) or {}
        local_config.update(config)  # type: ignore
        return self.save(
            domain=config_domain, name=config_name, data=local_config)

    async def update_user_config_async(
        self, uid: str, cloud_server: str, config: Optional[dict[str, Any]],
        replace: bool = False
    ) -> bool:
        """Update user configuration.

        Args:
            uid (str): user_id
            config (Optional[dict[str]]):
                remove config file if config is None
            replace (bool, optional):
                replace all config item. Defaults to False.

        Returns:
            bool: result code
        """
        if config is not None and len(config) == 0:
            # Do nothing
            return True

        config_domain = 'miot_config'
        config_name = f'{uid}_{cloud_server}'
        if config is None:
            # Remove config file
            return await self.remove_async(
                domain=config_domain, name=config_name, type_=dict)
        if replace:
            # Replace config file
            return await self.save_async(
                domain=config_domain, name=config_name, data=config)
        local_config = (await self.load_async(
            domain=config_domain, name=config_name, type_=dict)) or {}
        local_config.update(config)  # type: ignore
        return await self.save_async(
            domain=config_domain, name=config_name, data=local_config)

    def load_user_config(
        self, uid: str, cloud_server: str, keys: Optional[list[str]] = None
    ) -> dict[str, Any]:
        if isinstance(keys, list) and len(keys) == 0:
            # Do nothing
            return {}
        config_domain = 'miot_config'
        config_name = f'{uid}_{cloud_server}'
        local_config = (self.load(domain=config_domain,
                        name=config_name, type_=dict))
        if not isinstance(local_config, dict):
            return {}
        if keys is None:
            return local_config
        return {
            key: local_config[key] for key in keys
            if key in local_config}

    async def load_user_config_async(
        self, uid: str, cloud_server: str, keys: Optional[list[str]] = None
    ) -> dict:
        """Load user configuration.

        Args:
            uid (str): user id
            keys (list[str]):
                query key list, return all config item if keys is None

        Returns:
            dict[str, Any]: query result
        """
        if isinstance(keys, list) and len(keys) == 0:
            # Do nothing
            return {}
        config_domain = 'miot_config'
        config_name = f'{uid}_{cloud_server}'
        local_config = (await self.load_async(
            domain=config_domain, name=config_name, type_=dict))
        if not isinstance(local_config, dict):
            return {}
        if keys is None:
            return local_config
        return {
            key: local_config[key] for key in keys
            if key in local_config}

    def gen_storage_path(
        self, domain: Optional[str] = None,
        name_with_suffix: Optional[str] = None
    ) -> str:
        """Generate file path."""
        result = self._root_path
        if domain:
            result = os.path.join(result, domain)
            if name_with_suffix:
                result = os.path.join(result, name_with_suffix)
        return result


class MIoTCert:
    """MIoT certificate file management."""
    CERT_DOMAIN: str = 'cert'
    CA_NAME: str = 'mihome_ca.cert'
    _loop: asyncio.AbstractEventLoop
    _storage: MIoTStorage
    _uid: str
    _cloud_server: str

    _key_name: str
    _cert_name: str

    def __init__(
        self, storage: MIoTStorage, uid: str, cloud_server: str,
        loop: Optional[asyncio.AbstractEventLoop] = None
    ) -> None:
        if not isinstance(storage, MIoTStorage) or not isinstance(uid, str):
            raise MIoTError('invalid params')
        self._loop = loop or asyncio.get_running_loop()
        self._storage = storage
        self._uid = uid
        self._cloud_server = cloud_server
        self._key_name = f'{uid}_{cloud_server}.key'
        self._cert_name = f'{uid}_{cloud_server}.cert'

    @property
    def ca_file(self) -> str:
        """CA certificate file path."""
        return self._storage.gen_storage_path(
            domain=self.CERT_DOMAIN, name_with_suffix=self.CA_NAME)

    @property
    def key_file(self) -> str:
        """User private key file file path."""
        return self._storage.gen_storage_path(
            domain=self.CERT_DOMAIN, name_with_suffix=self._key_name)

    @property
    def cert_file(self) -> str:
        """User certificate file path."""
        return self._storage.gen_storage_path(
            domain=self.CERT_DOMAIN, name_with_suffix=self._cert_name)

    async def verify_ca_cert_async(self) -> bool:
        """Verify the integrity of the CA certificate file."""
        ca_data = await self._storage.load_file_async(
            domain=self.CERT_DOMAIN, name_with_suffix=self.CA_NAME)
        if ca_data is None:
            if not await self._storage.save_file_async(
                    domain=self.CERT_DOMAIN,
                    name_with_suffix=self.CA_NAME,
                    data=MIHOME_CA_CERT_STR.encode('utf-8')):
                raise MIoTStorageError('ca cert save failed')
            ca_data = await self._storage.load_file_async(
                domain=self.CERT_DOMAIN, name_with_suffix=self.CA_NAME)
            if ca_data is None:
                raise MIoTStorageError('ca cert load failed')
            _LOGGER.debug('ca cert save success')
        # Compare the file sha256sum
        ca_cert_hash = hashlib.sha256(ca_data).digest()
        hash_str = binascii.hexlify(ca_cert_hash).decode('utf-8')
        if hash_str != MIHOME_CA_CERT_SHA256:
            return False
        return True

    async def user_cert_remaining_time_async(
        self, cert_data: Optional[bytes] = None, did: Optional[str] = None
    ) -> int:
        """Get the remaining time of user certificate validity.

        Returns:
            If the certificate is not valid, return 0.
        """
        if cert_data is None:
            cert_data = await self._storage.load_file_async(
                domain=self.CERT_DOMAIN, name_with_suffix=self._cert_name)
        if cert_data is None:
            return 0
        # Check user cert
        try:
            user_cert: x509.Certificate = x509.load_pem_x509_certificate(
                cert_data, default_backend())
            cert_info = {}
            for attribute in user_cert.subject:
                if attribute.oid == x509.NameOID.COMMON_NAME:
                    cert_info['CN'] = attribute.value
                elif attribute.oid == x509.NameOID.COUNTRY_NAME:
                    cert_info['C'] = attribute.value
                elif attribute.oid == x509.NameOID.ORGANIZATION_NAME:
                    cert_info['O'] = attribute.value

            if len(cert_info) != 3:
                raise MIoTCertError('invalid cert info')
            if (
                did and cert_info['CN'] !=
                    f'mips.{self._uid}.{self.__did_hash(did=did)}.2'
            ):
                raise MIoTCertError('invalid COMMON_NAME')
            if 'C' not in cert_info or cert_info['C'] != 'CN':
                raise MIoTCertError('invalid COUNTRY_NAME')
            if 'O' not in cert_info or cert_info['O'] != 'Mijia Device':
                raise MIoTCertError('invalid ORGANIZATION_NAME')
            now_utc: datetime = datetime.now(timezone.utc)
            if (
                now_utc < user_cert.not_valid_before_utc or
                    now_utc > user_cert.not_valid_after_utc
            ):
                raise MIoTCertError('cert is not valid')
            return int((user_cert.not_valid_after_utc-now_utc).total_seconds())
        except (MIoTCertError, ValueError) as error:
            _LOGGER.error(
                'load_pem_x509_certificate failed, %s, %s',
                error, traceback.format_exc())
            return 0

    def gen_user_key(self) -> str:
        """Generate user private key."""
        private_key = ed25519.Ed25519PrivateKey.generate()
        return private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')

    def gen_user_csr(self, user_key: str, did: str) -> str:
        """Generate CSR of user certificate."""
        private_key = serialization.load_pem_private_key(
            data=user_key.encode('utf-8'), password=None)
        did_hash = self.__did_hash(did=did)
        builder = x509.CertificateSigningRequestBuilder().subject_name(
            x509.Name([
                # Central hub gateway service is only supported in China.
                x509.NameAttribute(NameOID.COUNTRY_NAME, 'CN'),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'Mijia Device'),
                x509.NameAttribute(
                    NameOID.COMMON_NAME, f'mips.{self._uid}.{did_hash}.2'),
            ]))
        csr = builder.sign(
            private_key, algorithm=None,  # type: ignore
            backend=default_backend())
        return csr.public_bytes(serialization.Encoding.PEM).decode('utf-8')

    async def load_user_key_async(self) -> Optional[str]:
        """Load user private key."""
        data = await self._storage.load_file_async(
            domain=self.CERT_DOMAIN, name_with_suffix=self._key_name)
        return data.decode('utf-8') if data else None

    async def update_user_key_async(self, key: str) -> bool:
        """Update user private key."""
        return await self._storage.save_file_async(
            domain=self.CERT_DOMAIN,
            name_with_suffix=self._key_name,
            data=key.encode('utf-8'))

    async def load_user_cert_async(self) -> Optional[str]:
        """Load user certificate."""
        data = await self._storage.load_file_async(
            domain=self.CERT_DOMAIN, name_with_suffix=self._cert_name)
        return data.decode('utf-8') if data else None

    async def update_user_cert_async(self, cert: str) -> bool:
        """Update user certificate."""
        return await self._storage.save_file_async(
            domain=self.CERT_DOMAIN,
            name_with_suffix=self._cert_name,
            data=cert.encode('utf-8'))

    async def remove_ca_cert_async(self) -> bool:
        """Remove CA certificate."""
        return await self._storage.remove_file_async(
            domain=self.CERT_DOMAIN, name_with_suffix=self.CA_NAME)

    async def remove_user_key_async(self) -> bool:
        """Remove user private key."""
        return await self._storage.remove_file_async(
            domain=self.CERT_DOMAIN, name_with_suffix=self._key_name)

    async def remove_user_cert_async(self) -> bool:
        """Remove user certificate."""
        return await self._storage.remove_file_async(
            domain=self.CERT_DOMAIN, name_with_suffix=self._cert_name)

    def __did_hash(self, did: str) -> str:
        sha1_hash = hashes.Hash(hashes.SHA1(), backend=default_backend())
        sha1_hash.update(did.encode('utf-8'))
        return binascii.hexlify(sha1_hash.finalize()).decode('utf-8')


class DeviceManufacturer:
    """Device manufacturer."""
    DOMAIN: str = 'miot_specs'
    _main_loop: asyncio.AbstractEventLoop
    _storage: MIoTStorage
    _data: dict

    def __init__(
        self, storage: MIoTStorage,
        loop: Optional[asyncio.AbstractEventLoop] = None
    ) -> None:
        self._main_loop = loop or asyncio.get_event_loop()
        self._storage = storage
        self._data = {}

    async def init_async(self) -> None:
        if self._data:
            return
        data_cache = await self._storage.load_async(
            domain=self.DOMAIN, name='manufacturer', type_=dict)
        if (
            isinstance(data_cache, dict)
            and 'data' in data_cache
            and 'ts' in data_cache
            and (int(time.time()) - data_cache['ts']) <
                MANUFACTURER_EFFECTIVE_TIME
        ):
            self._data = data_cache['data']
            _LOGGER.debug('load manufacturer data success')
            return

        data_cloud = None
        try:
            data_cloud = await MIoTHttp.get_json_async(
                url='https://cdn.cnbj1.fds.api.mi-img.com/res-conf/xiaomi-home/'
                'manufacturer.json',
                loop=self._main_loop)
        except Exception as err:  # pylint: disable=broad-exception-caught
            _LOGGER.error('get manufacturer info failed, %s', err)

        if data_cloud:
            await self._storage.save_async(
                domain=self.DOMAIN, name='manufacturer',
                data={'data': data_cloud, 'ts': int(time.time())})
            self._data = data_cloud
            _LOGGER.debug('update manufacturer data success')
        else:
            if isinstance(data_cache, dict):
                self._data = data_cache.get('data', {})
                _LOGGER.error('load manufacturer data failed, use local data')
            else:
                _LOGGER.error('load manufacturer data failed')

    async def deinit_async(self) -> None:
        self._data.clear()

    def get_name(self, short_name: str) -> str:
        if not self._data or not short_name or short_name not in self._data:
            return short_name
        return self._data[short_name].get('name', None) or short_name
