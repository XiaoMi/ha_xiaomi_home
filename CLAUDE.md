# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Xiaomi Home Integration is an official Home Assistant integration for controlling Xiaomi IoT smart devices. It connects to devices via Xiaomi Cloud (MQTT) or locally through Xiaomi Central Hub Gateway. The integration converts MIoT-Spec-V2 device specifications into Home Assistant entities.

## Development Commands

### Installation & Setup
```bash
# Install to Home Assistant config directory
./install.sh /path/to/config

# Install test dependencies
pip install pytest pytest-asyncio pytest-dependency zeroconf paho.mqtt psutil cryptography slugify
```

### Testing
```bash
# Run all tests
pytest -v -s -m github ./test/

# Run specific test files
pytest -v -s ./test/test_spec.py
pytest -v -s ./test/test_cloud.py
pytest -v -s ./test/test_lan.py

# Check rule format
pytest -v -s -m github ./test/check_rule_format.py
```

### Code Quality
```bash
# Run pylint (follows Google Python Style Guide)
pylint $(git ls-files '*.py')

# Lint specific files
pylint custom_components/xiaomi_home/*.py
```

### Validation
```bash
# HACS validation (run by GitHub Actions)
# Uses: hacs/action@main

# Hassfest validation (run by GitHub Actions)
# Uses: home-assistant/actions/hassfest@master
```

## Architecture Overview

### Core Components (miot/)

The integration is built around the `miot/` core package:

**miot_client.py**: Top-level client instance representing a logged-in Xiaomi user. Each user login creates one MIoTClient. Manages authentication, device list, and message routing.

**miot_cloud.py**: OAuth 2.0 authentication and HTTP API calls to Xiaomi Cloud. Handles token refresh, user info, device control commands, and spec downloads.

**miot_mips.py**: Message bus (MQTT) for subscribing to device property changes and events. Implements both cloud (MipsCloudClient) and local (MipsLocalClient) message handling.

**miot_device.py**: Device entity class. Each MIoT device creates multiple MIoTDevice instances (one per Home Assistant entity). Handles property updates, action execution, and event processing.

**miot_spec.py**: MIoT-Spec-V2 parser. Parses device specifications (URN-based type system) from cloud or local cache. Each spec defines services, properties, events, and actions.

**miot_lan.py**: Local LAN control for IP devices in same network. Discovery and control without cloud (optional).

**miot_mdns.py**: mDNS discovery for Xiaomi Central Hub Gateway services.

**miot_storage.py**: File storage for certificates, device specs, translations, and cached data.

**miot_network.py**: Network status monitoring and IP address detection.

**miot_i18n.py**: Multi-language support (13 languages). Manages translations for entity names.

### Entity Conversion (specs/specv2entity.py)

MIoT-Spec-V2 instances are converted to Home Assistant entities using three mapping dictionaries:

- **SPEC_DEVICE_TRANS_MAP**: Whole-device patterns (e.g., vacuum, humidifier, climate)
- **SPEC_SERVICE_TRANS_MAP**: Service-level patterns (e.g., battery, air-purifier)
- **SPEC_PROP_TRANS_MAP**: Property-level patterns (e.g., temperature, humidity)

Conversion priority: Device > Service > Property > General rules

### Spec Customization Files (miot/specs/)

**spec_filter.yaml**: Filters out MIoT-Spec-V2 instances that should NOT be converted to entities. Uses device URN keys and supports wildcard matching for service/property/event/action IIDs.

**spec_modify.yaml**: Modifies spec instances before conversion (e.g., changing value ranges, access modes).

**multi_lang.json**: Local translation overrides with higher priority than cloud translations. Keyed by device URN (without version).

**spec_add.json**: Additional spec definitions for devices not in cloud database.

**bool_trans.yaml**: Boolean value translation mappings.

After editing spec files, you MUST update conversion rules via Integration CONFIGURE page in Home Assistant.

### Platform Files (custom_components/xiaomi_home/)

Standard Home Assistant platform files (sensor.py, switch.py, climate.py, etc.) implement entity registration and state management. Each platform imports from miot_device.py and creates entity subclasses.

**config_flow.py**: Configuration flow for OAuth login and device selection.

**__init__.py**: Integration setup, entry management, and data structure initialization.

## MIoT-Spec-V2 Concepts

**URN Format**: `urn:<namespace>:<type>:<name>:<value>[:<vendor-product>:<version>]`
- namespace: miot-spec-v2 (Xiaomi), bluetooth-spec (SIG), or vendor-specific
- type: device, service, property, event, action
- name: human-readable identifier (used for mapping)

**IIDs (Instance IDs)**: Decimal identifiers
- siid: Service Instance ID
- piid: Property Instance ID
- eiid: Event Instance ID
- aiid: Action Instance ID

**Instance Code Format**:
```
service:<siid>                              # service
service:<siid>:property:<piid>              # property
service:<siid>:property:<piid>:valuelist:<index>  # value list item
service:<siid>:event:<eiid>                 # event
service:<siid>:action:<aiid>                # action
```

## Naming Conventions

From CONTRIBUTING.md:

- **Xiaomi**: Always "Xiaomi" in text. Variables: "xiaomi" or "mi"
- **Xiaomi Home**: Always "Xiaomi Home" in text. Variables: "mihome" or "MiHome"
- **Xiaomi IoT**: Always "MIoT" in text. Variables: "miot" or "MIoT"
- **Home Assistant**: Always "Home Assistant" in text. Variables: "hass" or "hass_xxx"

Mixed Chinese/English: Add space between Chinese and English or use Chinese quotation marks.

## Commit Message Format

```
<type>: <subject>

<body>

<footer>
```

Types: feat, fix, docs, style, refactor, perf, test, chore, revert

Subject: Imperative, present tense. Not capitalized. No period.

Body: Detailed description (mandatory except for docs type).

## Code Style

Follow [Google Python Style Guide](https://google.github.io/styleguide/pyguide.html). Use the provided `.pylintrc` for linting.

## Debugging

Enable debug logging in Home Assistant configuration.yaml:
```yaml
logger:
  default: critical
  logs:
    custom_components.xiaomi_home: debug
```

## Control Modes

- **Cloud Control**: MQTT message subscription + HTTP command API
- **Local Control**: Via Xiaomi Central Hub Gateway (firmware 3.3.0_0023+) or LAN control (IP devices only, may be unstable)

Central gateway local control takes priority over LAN control when both are available.

## Multi-Region Support

Regions: China (cn), Europe (eu), India (in), Russia (ru), Singapore (sg), USA (us)

User data is isolated per region. Integration supports multiple regions in same Home Assistant instance.

## Important Files Location

- Integration source: `custom_components/xiaomi_home/`
- Spec mappings: `custom_components/xiaomi_home/miot/specs/specv2entity.py`
- Spec filters: `custom_components/xiaomi_home/miot/specs/spec_filter.yaml`
- Translations: `custom_components/xiaomi_home/translations/` and `custom_components/xiaomi_home/miot/i18n/`
- Tests: `test/`
