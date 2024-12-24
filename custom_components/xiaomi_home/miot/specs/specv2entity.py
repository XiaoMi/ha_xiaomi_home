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

Conversion rules of MIoT-Spec-V2 instance to Home Assistant entity.
"""
from homeassistant.components.sensor import SensorDeviceClass
from homeassistant.components.sensor import SensorStateClass
from homeassistant.components.event import EventDeviceClass

from homeassistant.const import (
    UnitOfEnergy,
    UnitOfPower,
    UnitOfElectricCurrent,
    UnitOfElectricPotential,
)

# pylint: disable=pointless-string-statement
"""SPEC_DEVICE_TRANS_MAP
{
    '<device instance name>':{
        'required':{
            '<service instance name>':{
                'required':{
                    'properties': {
                        '<property instance name>': set<property access: str>
                    },
                    'events': set<event instance name: str>,
                    'actions': set<action instance name: str>
                },
                'optional':{
                    'properties': set<property instance name: str>,
                    'events': set<event instance name: str>,
                    'actions': set<action instance name: str>
                }
            }
        },
        'optional':{
            '<service instance name>':{
                'required':{
                    'properties': {
                        '<property instance name>': set<property access: str>
                    },
                    'events': set<event instance name: str>,
                    'actions': set<action instance name: str>
                },
                'optional':{
                    'properties': set<property instance name: str>,
                    'events': set<event instance name: str>,
                    'actions': set<action instance name: str>
                }
            }
        },
        'entity': str
    }
}
"""
SPEC_DEVICE_TRANS_MAP: dict[str, dict | str] = {
    'humidifier': {
        'required': {
            'humidifier': {
                'required':  {
                    'properties': {
                        'on': {'read', 'write'}
                    }
                },
                'optional': {
                    'properties': {'mode', 'target-humidity'}
                }
            }
        },
        'optional': {
            'environment': {
                'required':  {
                    'properties': {
                        'relative-humidity': {'read'}
                    }
                }
            }
        },
        'entity': 'humidifier'
    },
    'dehumidifier': {
        'required': {
            'dehumidifier': {
                'required':  {
                    'properties': {
                        'on': {'read', 'write'}
                    }
                },
                'optional': {
                    'properties': {'mode', 'target-humidity'}
                }
            },
        },
        'optional': {
            'environment': {
                'required':  {
                    'properties': {
                        'relative-humidity': {'read'}
                    }
                }
            }
        },
        'entity': 'dehumidifier'
    },
    'vacuum': {
        'required': {
            'vacuum': {
                'required':  {
                    'actions': {'start-sweep', 'stop-sweeping'},
                },
                'optional': {
                    'properties': {'status', 'fan-level'},
                    'actions': {
                        'pause-sweeping',
                        'continue-sweep',
                        'stop-and-gocharge'
                    }
                },

            }
        },
        'optional': {
            'identify': {
                'required': {
                    'actions':  {'identify'}
                }
            },
            'battery': {
                'required': {
                    'properties': {
                        'battery-level': {'read'}
                    },
                }
            },
        },
        'entity': 'vacuum'
    },
    'air-conditioner': {
        'required': {
            'air-conditioner': {
                'required': {
                    'properties': {
                        'on': {'read', 'write'},
                        'mode': {'read', 'write'},
                        'target-temperature': {'read', 'write'}
                    }
                },
                'optional': {
                    'properties': {'target-humidity'}
                },
            }
        },
        'optional': {
            'fan-control': {
                'required': {},
                'optional': {
                    'properties': {
                        'on',
                        'fan-level',
                        'horizontal-swing',
                        'vertical-swing'}}
            },
            'environment': {
                'required': {},
                'optional': {
                    'properties': {'temperature', 'relative-humidity'}
                }
            },
            'air-condition-outlet-matching': {
                'required': {},
                'optional': {
                    'properties': {'ac-state'}
                }
            }
        },
        'entity': 'air-conditioner'
    },
    'air-condition-outlet': 'air-conditioner',
    'heater': {
        'required': {
            'heater': {
                'required': {
                    'properties': {
                        'on': {'read', 'write'}
                    }
                },
                'optional': {
                    'properties': {'target-temperature', 'heat-level'}
                },
            }
        },
        'optional': {
            'environment': {
                'required': {},
                'optional': {
                    'properties': {'temperature', 'relative-humidity'}
                }
            },
        },
        'entity': 'heater'
    }
}

"""SPEC_SERVICE_TRANS_MAP
{
    '<service instance name>':{
        'required':{
            'properties': {
                '<property instance name>': set<property access: str>
            },
            'events': set<event instance name: str>,
            'actions': set<action instance name: str>
        },
        'optional':{
            'properties': set<property instance name: str>,
            'events': set<event instance name: str>,
            'actions': set<action instance name: str>
        },
        'entity': str
    }
}
"""
SPEC_SERVICE_TRANS_MAP: dict[str, dict | str] = {
    'light': {
        'required': {
            'properties': {
                'on': {'read', 'write'}
            }
        },
        'optional': {
            'properties': {
                'mode', 'brightness', 'color', 'color-temperature'
            }
        },
        'entity': 'light'
    },
    'indicator-light': 'light',
    'ambient-light': 'light',
    'night-light': 'light',
    'white-light': 'light',
    'fan': {
        'required': {
            'properties': {
                'on': {'read', 'write'},
                'fan-level': {'read', 'write'}
            }
        },
        'optional': {
            'properties': {'mode', 'horizontal-swing'}
        },
        'entity': 'fan'
    },
    'fan-control': 'fan',
    'ceiling-fan': 'fan',
    'water-heater': {
        'required': {
            'properties': {
                'on': {'read', 'write'}
            }
        },
        'optional': {
            'properties': {'on', 'temperature', 'target-temperature', 'mode'}
        },
        'entity': 'water_heater'
    },
    'curtain':  {
        'required': {
            'properties': {
                'motor-control': {'write'}
            }
        },
        'optional': {
            'properties': {
                'motor-control', 'status', 'current-position', 'target-position'
            }
        },
        'entity': 'cover'
    },
    'window-opener': 'curtain'
}

"""SPEC_PROP_TRANS_MAP
{
    'entities':{
        '<entity name>':{
            'format': set<str>,
            'access': set<str>
        }
    },
    'properties': {
        '<property instance name>':{
            'device_class': str,
            'entity': str,
            'optional':{
                'state_class': str,
                'unit_of_measurement': str
            }
        }
    }
}
"""
SPEC_PROP_TRANS_MAP: dict[str, dict | str] = {
    'entities': {
        'sensor': {
            'format': {'int', 'float'},
            'access': {'read'}
        },
        'switch': {
            'format': {'bool'},
            'access': {'read', 'write'}
        }
    },
    'properties': {
        'temperature': {
            'device_class': SensorDeviceClass.TEMPERATURE,
            'entity': 'sensor'
        },
        'relative-humidity': {
            'device_class': SensorDeviceClass.HUMIDITY,
            'entity': 'sensor'
        },
        'air-quality-index': {
            'device_class': SensorDeviceClass.AQI,
            'entity': 'sensor'
        },
        'pm2.5-density': {
            'device_class': SensorDeviceClass.PM25,
            'entity': 'sensor'
        },
        'pm10-density': {
            'device_class': SensorDeviceClass.PM10,
            'entity': 'sensor'
        },
        'pm1': {
            'device_class': SensorDeviceClass.PM1,
            'entity': 'sensor'
        },
        'atmospheric-pressure': {
            'device_class': SensorDeviceClass.ATMOSPHERIC_PRESSURE,
            'entity': 'sensor'
        },
        'tvoc-density': {
            'device_class': SensorDeviceClass.VOLATILE_ORGANIC_COMPOUNDS,
            'entity': 'sensor'
        },
        'voc-density': 'tvoc-density',
        'battery-level': {
            'device_class': SensorDeviceClass.BATTERY,
            'entity': 'sensor'
        },
        'voltage': {
            'device_class': SensorDeviceClass.VOLTAGE,
            'entity': 'sensor',
            'optional': {
                'state_class': SensorStateClass.MEASUREMENT,
                'unit_of_measurement': UnitOfElectricPotential.VOLT
            }
        },
        'illumination': {
            'device_class': SensorDeviceClass.ILLUMINANCE,
            'entity': 'sensor'
        },
        'no-one-determine-time': {
            'device_class': SensorDeviceClass.DURATION,
            'entity': 'sensor'
        },
	    'electric-power': {
            'device_class': SensorDeviceClass.POWER,
            'entity': 'sensor',
            'optional': {
                'state_class': SensorStateClass.MEASUREMENT,
                'unit_of_measurement': UnitOfPower.WATT
            }
	    },
	    'electric-current': {
            'device_class': SensorDeviceClass.CURRENT,
            'entity': 'sensor',
            'optional': {
                'state_class': SensorStateClass.MEASUREMENT,
                'unit_of_measurement': UnitOfElectricCurrent.AMPERE
            }
	    },
	    'power-consumption': {
            'device_class': SensorDeviceClass.ENERGY,
            'entity': 'sensor',
            'optional': {
                'state_class': SensorStateClass.TOTAL_INCREASING,
                'unit_of_measurement': UnitOfEnergy.KILO_WATT_HOUR
            }
	    },
	    'total-battery': {
            'device_class': SensorDeviceClass.ENERGY,
            'entity': 'sensor',
            'optional': {
                'state_class': SensorStateClass.TOTAL_INCREASING,
                'unit_of_measurement': UnitOfEnergy.KILO_WATT_HOUR
            }
	    },
        'has-someone-duration': 'no-one-determine-time',
        'no-one-duration': 'no-one-determine-time'
    }
}

"""SPEC_EVENT_TRANS_MAP
{
    '<event instance name>': str
}
"""
SPEC_EVENT_TRANS_MAP: dict[str, str] = {
    'click': EventDeviceClass.BUTTON,
    'double-click': EventDeviceClass.BUTTON,
    'long-press': EventDeviceClass.BUTTON,
    'motion-detected': EventDeviceClass.MOTION,
    'no-motion': EventDeviceClass.MOTION,
    'doorbell-ring': EventDeviceClass.DOORBELL
}

SPEC_ACTION_TRANS_MAP = {

}
