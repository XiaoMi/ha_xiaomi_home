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

Constants.
"""
DOMAIN: str = 'xiaomi_home'
DEFAULT_NAME: str = 'Xiaomi Home'

DEFAULT_NICK_NAME: str = 'Xiaomi'

MIHOME_HTTP_API_TIMEOUT: int = 30
MIHOME_MQTT_KEEPALIVE: int = 60
# seconds, 3 days
MIHOME_CERT_EXPIRE_MARGIN: int = 3600*24*3

NETWORK_REFRESH_INTERVAL: int = 30

OAUTH2_CLIENT_ID: str = '2882303761520251711'
OAUTH2_AUTH_URL: str = 'https://account.xiaomi.com/oauth2/authorize'
DEFAULT_OAUTH2_API_HOST: str = 'ha.api.io.mi.com'
DEFAULT_CLOUD_BROKER_HOST: str = 'ha.mqtt.io.mi.com'

# seconds, 14 days
SPEC_STD_LIB_EFFECTIVE_TIME = 3600*24*14
# seconds, 14 days
MANUFACTURER_EFFECTIVE_TIME = 3600*24*14

SUPPORTED_PLATFORMS: list = [
    'binary_sensor',
    'button',
    'climate',
    'cover',
    'device_tracker',
    'event',
    'fan',
    'humidifier',
    'light',
    'media_player',
    'notify',
    'number',
    'select',
    'sensor',
    'switch',
    'text',
    'vacuum',
    'water_heater',
]

UNSUPPORTED_MODELS: list = [
    'chuangmi.ir.v2',
    'era.airp.cwb03',
    'hmpace.motion.v6nfc',
    'k0918.toothbrush.t700'
]

DEFAULT_CLOUD_SERVER: str = 'cn'
CLOUD_SERVERS: dict = {
    'cn': '中国大陆',
    'de': 'Europe',
    'i2': 'India',
    'ru': 'Russia',
    'sg': 'Singapore',
    'us': 'United States'
}

SUPPORT_CENTRAL_GATEWAY_CTRL: list = ['cn']

DEFAULT_INTEGRATION_LANGUAGE: str = 'en'
INTEGRATION_LANGUAGES = {
    'de': 'Deutsch',
    'en': 'English',
    'es': 'Español',
    'fr': 'Français',
    'it': 'Italiano',
    'ja': '日本語',
    'nl': 'Nederlands',
    'pt': 'Português',
    'pt-BR': 'Português (Brasil)',
    'ru': 'Русский',
    'tr': 'Türkçe',
    'zh-Hans': '简体中文',
    'zh-Hant': '繁體中文'
}

DEFAULT_COVER_DEAD_ZONE_WIDTH: int = 0
MIN_COVER_DEAD_ZONE_WIDTH: int = 0
MAX_COVER_DEAD_ZONE_WIDTH: int = 5

DEFAULT_CTRL_MODE: str = 'auto'

# Registered in Xiaomi OAuth 2.0 Service
# DO NOT CHANGE UNLESS YOU HAVE AN ADMINISTRATOR PERMISSION
OAUTH_REDIRECT_URL: str = 'http://homeassistant.local:8123'

MIHOME_CA_CERT_STR: str = '-----BEGIN CERTIFICATE-----\n' \
    'MIIBazCCAQ+gAwIBAgIEA/UKYDAMBggqhkjOPQQDAgUAMCIxEzARBgNVBAoTCk1p\n' \
    'amlhIFJvb3QxCzAJBgNVBAYTAkNOMCAXDTE2MTEyMzAxMzk0NVoYDzIwNjYxMTEx\n' \
    'MDEzOTQ1WjAiMRMwEQYDVQQKEwpNaWppYSBSb290MQswCQYDVQQGEwJDTjBZMBMG\n' \
    'ByqGSM49AgEGCCqGSM49AwEHA0IABL71iwLa4//4VBqgRI+6xE23xpovqPCxtv96\n' \
    '2VHbZij61/Ag6jmi7oZ/3Xg/3C+whglcwoUEE6KALGJ9vccV9PmjLzAtMAwGA1Ud\n' \
    'EwQFMAMBAf8wHQYDVR0OBBYEFJa3onw5sblmM6n40QmyAGDI5sURMAwGCCqGSM49\n' \
    'BAMCBQADSAAwRQIgchciK9h6tZmfrP8Ka6KziQ4Lv3hKfrHtAZXMHPda4IYCIQCG\n' \
    'az93ggFcbrG9u2wixjx1HKW4DUA5NXZG0wWQTpJTbQ==\n' \
    '-----END CERTIFICATE-----\n' \
    '-----BEGIN CERTIFICATE-----\n' \
    'MIIBjzCCATWgAwIBAgIBATAKBggqhkjOPQQDAjAiMRMwEQYDVQQKEwpNaWppYSBS\n' \
    'b290MQswCQYDVQQGEwJDTjAgFw0yMjA2MDkxNDE0MThaGA8yMDcyMDUyNzE0MTQx\n' \
    'OFowLDELMAkGA1UEBhMCQ04xHTAbBgNVBAoMFE1JT1QgQ0VOVFJBTCBHQVRFV0FZ\n' \
    'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEdYrzbnp/0x/cZLZnuEDXTFf8mhj4\n' \
    'CVpZPwgj9e9Ve5r3K7zvu8Jjj7JF1JjQYvEC6yhp1SzBgglnK4L8xQzdiqNQME4w\n' \
    'HQYDVR0OBBYEFCf9+YBU7pXDs6K6CAQPRhlGJ+cuMB8GA1UdIwQYMBaAFJa3onw5\n' \
    'sblmM6n40QmyAGDI5sURMAwGA1UdEwQFMAMBAf8wCgYIKoZIzj0EAwIDSAAwRQIh\n' \
    'AKUv+c8v98vypkGMTzMwckGjjVqTef8xodsy6PhcSCq+AiA/n9mDs62hAo5zXyJy\n' \
    'Bs1s7mqXPf1XgieoxIvs1MqyiA==\n' \
    '-----END CERTIFICATE-----\n'

MIHOME_CA_CERT_SHA256: str = \
    '8b7bf306be3632e08b0ead308249e5f2b2520dc921ad143872d5fcc7c68d6759'
