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

MIoT error code and exception.
"""
from enum import Enum
from typing import Any


class MIoTErrorCode(Enum):
    """MIoT error code."""
    # Base error code
    CODE_UNKNOWN = -10000
    CODE_UNAVAILABLE = -10001
    CODE_INVALID_PARAMS = -10002
    CODE_RESOURCE_ERROR = -10003
    CODE_INTERNAL_ERROR = -10004
    CODE_UNAUTHORIZED_ACCESS = -10005
    CODE_TIMEOUT = -10006
    # OAuth error code
    CODE_OAUTH_UNAUTHORIZED = -10020
    # Http error code
    CODE_HTTP_INVALID_ACCESS_TOKEN = -10030
    # MIoT mips error code
    CODE_MIPS_INVALID_RESULT = -10040
    # MIoT cert error code
    CODE_CERT_INVALID_CERT = -10050
    # MIoT spec error code, -10060
    # MIoT storage error code, -10070
    # MIoT ev error code, -10080
    # Mips service error code, -10090
    # Config flow error code, -10100
    CODE_CONFIG_INVALID_INPUT = -10100
    CODE_CONFIG_INVALID_STATE = -10101
    # Options flow error code , -10110
    # MIoT lan error code, -10120
    CODE_LAN_UNAVAILABLE = -10120


class MIoTError(Exception):
    """MIoT error."""
    code: MIoTErrorCode
    message: Any

    def __init__(
        self,  message: Any, code: MIoTErrorCode = MIoTErrorCode.CODE_UNKNOWN
    ) -> None:
        self.message = message
        self.code = code
        super().__init__(self.message)

    def to_str(self) -> str:
        return f'{{"code":{self.code.value},"message":"{self.message}"}}'

    def to_dict(self) -> dict:
        return {"code": self.code.value, "message": self.message}


class MIoTOauthError(MIoTError):
    ...


class MIoTHttpError(MIoTError):
    ...


class MIoTMipsError(MIoTError):
    ...


class MIoTDeviceError(MIoTError):
    ...


class MIoTSpecError(MIoTError):
    ...


class MIoTStorageError(MIoTError):
    ...


class MIoTCertError(MIoTError):
    ...


class MIoTClientError(MIoTError):
    ...


class MIoTEvError(MIoTError):
    ...


class MipsServiceError(MIoTError):
    ...


class MIoTConfigError(MIoTError):
    ...


class MIoTOptionsError(MIoTError):
    ...


class MIoTLanError(MIoTError):
    ...
