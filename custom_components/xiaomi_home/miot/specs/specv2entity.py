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
from homeassistant.components.binary_sensor import BinarySensorDeviceClass

from homeassistant.const import (CONCENTRATION_MICROGRAMS_PER_CUBIC_METER,
                                 EntityCategory, LIGHT_LUX, UnitOfEnergy,
                                 UnitOfPower, UnitOfElectricCurrent,
                                 UnitOfElectricPotential, UnitOfTemperature,
                                 UnitOfPressure, PERCENTAGE)

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
SPEC_DEVICE_TRANS_MAP: dict = {
    'humidifier': {
        'required': {
            'humidifier': {
                'required': {
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
                'required': {
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
                'required': {
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
                'required': {
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
                'required': {
                    'actions': {'start-sweep', 'stop-sweeping'},
                },
                'optional': {
                    'properties': {'status', 'fan-level'},
                    'actions': {
                        'pause-sweeping', 'continue-sweep', 'stop-and-gocharge'
                    }
                }
            }
        },
        'optional': {
            'identify': {
                'required': {
                    'actions': {'identify'}
                }
            },
            'battery': {
                'required': {
                    'actions': {
                        'start-charge'
                    }
                }
            }
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
                }
            }
        },
        'optional': {
            'fan-control': {
                'required': {},
                'optional': {
                    'properties': {
                        'on', 'fan-level', 'horizontal-swing', 'vertical-swing'
                    }
                }
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
    'thermostat': {
        'required': {
            'thermostat': {
                'required': {
                    'properties': {
                        'on': {'read', 'write'}
                    }
                },
                'optional': {
                    'properties': {
                        'target-temperature', 'mode', 'fan-level', 'temperature'
                    }
                }
            }
        },
        'optional': {
            'environment': {
                'required': {},
                'optional': {
                    'properties': {'temperature', 'relative-humidity'}
                }
            }
        },
        'entity': 'thermostat'
    },
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
                }
            }
        },
        'optional': {
            'environment': {
                'required': {},
                'optional': {
                    'properties': {'temperature', 'relative-humidity'}
                }
            }
        },
        'entity': 'heater'
    },
    'bath-heater': {
        'required': {
            'ptc-bath-heater': {
                'required': {
                    'properties': {
                        'mode': {'read', 'write'}
                    }
                },
                'optional': {
                    'properties': {'target-temperature', 'temperature'}
                }
            }
        },
        'optional': {
            'fan-control': {
                'required': {},
                'optional': {
                    'properties': {
                        'on', 'fan-level', 'horizontal-swing', 'vertical-swing'
                    }
                }
            },
            'environment': {
                'required': {},
                'optional': {
                    'properties': {'temperature'}
                }
            }
        },
        'entity': 'bath-heater',
    },
    'electric-blanket': {
        'required': {
            'electric-blanket': {
                'required': {
                    'properties': {
                        'on': {'read', 'write'},
                        'target-temperature': {'read', 'write'}
                    }
                },
                'optional': {
                    'properties': {'mode', 'temperature'}
                }
            }
        },
        'optional': {},
        'entity': 'electric-blanket'
    },
    'speaker': {
        'required': {
            'speaker': {
                'required': {
                    'properties': {
                        'volume': {'read', 'write'}
                    }
                },
                'optional': {
                    'properties': {'mute'}
                }
            },
            'play-control': {
                'required': {
                    'properties': {
                        'playing-state': {'read'}
                    },
                    'actions': {'play'}
                },
                'optional': {
                    'properties': {'play-loop-mode'},
                    'actions': {'pause', 'stop', 'next', 'previous'}
                }
            }
        },
        'optional': {},
        'entity': 'wifi-speaker'
    },
    'television': {
        'required': {
            'speaker': {
                'required': {
                    'properties': {
                        'volume': {'read', 'write'}
                    }
                },
                'optional': {
                    'properties': {'mute'}
                }
            },
            'television': {
                'required': {
                    'actions': {'turn-off'}
                },
                'optional': {
                    'properties': {'input-control'},
                    'actions': {'turn-on'}
                }
            }
        },
        'optional': {
            'play-control': {
                'required': {
                    'properties': {
                        'playing-state': {'read'}
                    }
                },
                'optional': {
                    'properties': {'play-loop-mode'},
                    'actions': {'play', 'pause', 'stop', 'next', 'previous'}
                }
            }
        },
        'entity': 'television'
    },
    'tv-box':{
        'required': {
            'speaker': {
                'required': {
                    'properties': {
                        'volume': {'read', 'write'}
                    }
                },
                'optional': {
                    'properties': {'mute'}
                }
            },
            'tv-box': {
                'required': {
                    'actions': {'turn-off'}
                },
                'optional': {
                    'actions': {'turn-on'}
                }
            }
        },
        'optional': {
            'play-control': {
                'required': {
                    'properties': {
                        'playing-state': {'read'}
                    }
                },
                'optional': {
                    'properties': {'play-loop-mode'},
                    'actions': {'play', 'pause', 'stop', 'next', 'previous'}
                }
            }
        },
        'entity': 'television'
    },
    'watch': {
        'required': {
            'watch': {
                'required': {
                    'properties': {
                        'longitude': {'read'},
                        'latitude': {'read'}
                    }
                },
                'optional': {
                    'properties': {'area-id'}
                }
            }
        },
        'optional': {
            'battery': {
                'required': {
                    'properties': {
                        'battery-level': {'read'}
                    }
                }
            }
        },
        'entity': 'device_tracker'
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
        'entity': str,
        'entity_category'?: str
    }
}
"""
SPEC_SERVICE_TRANS_MAP: dict = {
    'light': {
        'required': {
            'properties': {
                'on': {'read', 'write'}
            }
        },
        'optional': {
            'properties': {'mode', 'brightness', 'color', 'color-temperature'}
        },
        'entity': 'light'
    },
    'ambient-light': 'light',
    'night-light': 'light',
    'white-light': 'light',
    'indicator-light': {
        'required': {
            'properties': {
                'on': {'read', 'write'}
            }
        },
        'optional': {
            'properties': {
                'mode',
                'brightness',
            }
        },
        'entity': 'light',
        'entity_category': EntityCategory.CONFIG
    },
    'fan': {
        'required': {
            'properties': {
                'on': {'read', 'write'},
                'fan-level': {'read', 'write'}
            }
        },
        'optional': {
            'properties': {'mode', 'horizontal-swing', 'wind-reverse'}
        },
        'entity': 'fan'
    },
    'fan-control': 'fan',
    'ceiling-fan': 'fan',
    'air-fresh': 'fan',
    'air-purifier': 'fan',
    'water-heater': {
        'required': {
            'properties': {
                'on': {'read', 'write'}
            }
        },
        'optional': {
            'properties': {'temperature', 'target-temperature', 'mode'}
        },
        'entity': 'water_heater'
    },
    'curtain': {
        'required': {
            'properties': {
                'motor-control': {'write'}
            }
        },
        'optional': {
            'properties': {'status', 'current-position', 'target-position'}
        },
        'entity': 'cover'
    },
    'window-opener': 'curtain',
    'motor-controller': 'curtain',
    'airer': 'curtain',
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
        'entity': 'air-conditioner'
    }
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
            'state_class'?: str,
            'unit_of_measurement'?: str
        }
    }
}
"""
SPEC_PROP_TRANS_MAP: dict = {
    'entities': {
        'sensor': {
            'format': {'int', 'float'},
            'access': {'read'}
        },
        'binary_sensor': {
            'format': {'bool', 'int'},
            'access': {'read'}
        },
        'switch': {
            'format': {'bool'},
            'access': {'read', 'write'}
        }
    },
    'properties': {
        'submersion-state': {
            'device_class': BinarySensorDeviceClass.MOISTURE,
            'entity': 'binary_sensor'
        },
        'contact-state': {
            'device_class': BinarySensorDeviceClass.DOOR,
            'entity': 'binary_sensor'
        },
        'occupancy-status': {
            'device_class': BinarySensorDeviceClass.OCCUPANCY,
            'entity': 'binary_sensor',
        },
        'temperature': {
            'device_class': SensorDeviceClass.TEMPERATURE,
            'entity': 'sensor',
            'state_class': SensorStateClass.MEASUREMENT,
            'unit_of_measurement': UnitOfTemperature.CELSIUS
        },
        'relative-humidity': {
            'device_class': SensorDeviceClass.HUMIDITY,
            'entity': 'sensor',
            'state_class': SensorStateClass.MEASUREMENT,
            'unit_of_measurement': PERCENTAGE
        },
        'air-quality-index': {
            'device_class': SensorDeviceClass.AQI,
            'entity': 'sensor',
            'state_class': SensorStateClass.MEASUREMENT,
        },
        'pm2.5-density': {
            'device_class': SensorDeviceClass.PM25,
            'entity': 'sensor',
            'state_class': SensorStateClass.MEASUREMENT,
            'unit_of_measurement': CONCENTRATION_MICROGRAMS_PER_CUBIC_METER
        },
        'pm10-density': {
            'device_class': SensorDeviceClass.PM10,
            'entity': 'sensor',
            'state_class': SensorStateClass.MEASUREMENT,
            'unit_of_measurement': CONCENTRATION_MICROGRAMS_PER_CUBIC_METER
        },
        'pm1': {
            'device_class': SensorDeviceClass.PM1,
            'entity': 'sensor',
            'state_class': SensorStateClass.MEASUREMENT,
            'unit_of_measurement': CONCENTRATION_MICROGRAMS_PER_CUBIC_METER
        },
        'atmospheric-pressure': {
            'device_class': SensorDeviceClass.ATMOSPHERIC_PRESSURE,
            'entity': 'sensor',
            'state_class': SensorStateClass.MEASUREMENT,
            'unit_of_measurement': UnitOfPressure.PA
        },
        'tvoc-density': {
            'device_class': SensorDeviceClass.VOLATILE_ORGANIC_COMPOUNDS,
            'entity': 'sensor',
            'state_class': SensorStateClass.MEASUREMENT
        },
        'voc-density': {
            'device_class': SensorDeviceClass.VOLATILE_ORGANIC_COMPOUNDS_PARTS,
            'entity': 'sensor',
            'state_class': SensorStateClass.MEASUREMENT
        },
        'battery-level': {
            'device_class': SensorDeviceClass.BATTERY,
            'entity': 'sensor',
            'state_class': SensorStateClass.MEASUREMENT,
            'unit_of_measurement': PERCENTAGE
        },
        'voltage': {
            'device_class': SensorDeviceClass.VOLTAGE,
            'entity': 'sensor',
            'state_class': SensorStateClass.MEASUREMENT,
            'unit_of_measurement': UnitOfElectricPotential.VOLT
        },
        'electric-current': {
            'device_class': SensorDeviceClass.CURRENT,
            'entity': 'sensor',
            'state_class': SensorStateClass.MEASUREMENT,
            'unit_of_measurement': UnitOfElectricCurrent.AMPERE
        },
        'illumination': {
            'device_class': SensorDeviceClass.ILLUMINANCE,
            'entity': 'sensor',
            'state_class': SensorStateClass.MEASUREMENT,
            'unit_of_measurement': LIGHT_LUX
        },
        'no-one-determine-time': {
            'device_class': SensorDeviceClass.DURATION,
            'entity': 'sensor'
        },
        'has-someone-duration': 'no-one-determine-time',
        'no-one-duration': 'no-one-determine-time',
        'electric-power': {
            'device_class': SensorDeviceClass.POWER,
            'entity': 'sensor',
            'state_class': SensorStateClass.MEASUREMENT,
            'unit_of_measurement': UnitOfPower.WATT
        },
        'surge-power': {
            'device_class': SensorDeviceClass.POWER,
            'entity': 'sensor',
            'state_class': SensorStateClass.MEASUREMENT,
            'unit_of_measurement': UnitOfPower.WATT
        },
        'power-consumption': {
            'device_class': SensorDeviceClass.ENERGY,
            'entity': 'sensor',
            'state_class': SensorStateClass.TOTAL_INCREASING,
            'unit_of_measurement': UnitOfEnergy.KILO_WATT_HOUR
        },
        'power': {
            'device_class': SensorDeviceClass.POWER,
            'entity': 'sensor',
            'state_class': SensorStateClass.MEASUREMENT,
            'unit_of_measurement': UnitOfPower.WATT
        }
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

SPEC_ACTION_TRANS_MAP = {}
