# CHANGELOG

## v0.1.5b2
### Added
- Support binary sensors to be displayed as text sensor entities and binary sensor entities. [#592](https://github.com/XiaoMi/ha_xiaomi_home/pull/592)
- Add miot cloud test case. [#620](https://github.com/XiaoMi/ha_xiaomi_home/pull/620)
- Add test case for user cert. [#638](https://github.com/XiaoMi/ha_xiaomi_home/pull/638)
- Add mips test case & Change mips reconnect logic. [#641](https://github.com/XiaoMi/ha_xiaomi_home/pull/641)
- Support remove device. [#622](https://github.com/XiaoMi/ha_xiaomi_home/pull/622)
- Support italian translation. [#183](https://github.com/XiaoMi/ha_xiaomi_home/pull/183)
### Changed
- Refactor miot spec. [#592](https://github.com/XiaoMi/ha_xiaomi_home/pull/592)
- Refactor miot mips & fix type errors. [#365](https://github.com/XiaoMi/ha_xiaomi_home/pull/365)
- Using logging for test case log print. [#636](https://github.com/XiaoMi/ha_xiaomi_home/pull/636)
- Add power properties trans. [#571](https://github.com/XiaoMi/ha_xiaomi_home/pull/571)
- Move web page to html. [#627](https://github.com/XiaoMi/ha_xiaomi_home/pull/627)
### Fixed
- Fix miot cloud and mdns error. [#637](https://github.com/XiaoMi/ha_xiaomi_home/pull/637)
- Fix type error

## v0.1.5b1
This version will cause some Xiaomi routers that do not support access (#564) to become unavailable. You can update the device list in the configuration or delete it manually.
### Added
- Fan entity support direction ctrl [#556](https://github.com/XiaoMi/ha_xiaomi_home/pull/556)
### Changed
- Filter miwifi.* devices and xiaomi.router.rd03 [#564](https://github.com/XiaoMi/ha_xiaomi_home/pull/564)
### Fixed
- Fix multi ha instance login [#560](https://github.com/XiaoMi/ha_xiaomi_home/pull/560)
- Fix fan speed [#464](https://github.com/XiaoMi/ha_xiaomi_home/pull/464)
- The number of profile models updated from 660 to 823. [#583](https://github.com/XiaoMi/ha_xiaomi_home/pull/583)

## v0.1.5b0
### Added
- Add missing parameter state_class  [#101](https://github.com/XiaoMi/ha_xiaomi_home/pull/101)
### Changed
- Make git update guide more accurate [#561](https://github.com/XiaoMi/ha_xiaomi_home/pull/561)
### Fixed
- Limit *light.mode count (value-range) [#535](https://github.com/XiaoMi/ha_xiaomi_home/pull/535)
- Update miot cloud raise error msg [#551](https://github.com/XiaoMi/ha_xiaomi_home/pull/551)
- Fix table header misplacement [#554](https://github.com/XiaoMi/ha_xiaomi_home/pull/554)

## v0.1.4
### Added
- Refactor miot network, add network detection logic, improve devices filter logic. [458](https://github.com/XiaoMi/ha_xiaomi_home/pull/458) [#191](https://github.com/XiaoMi/ha_xiaomi_home/pull/191)
### Changed
- Remove tev dependency for lan control & fixs. [#333](https://github.com/XiaoMi/ha_xiaomi_home/pull/333)
- Use yaml to parse action params. [#447](https://github.com/XiaoMi/ha_xiaomi_home/pull/447)
- Update issue template. [#445](https://github.com/XiaoMi/ha_xiaomi_home/pull/445)
- Remove duplicate dependency(aiohttp) [#390](https://github.com/XiaoMi/ha_xiaomi_home/pull/390)
### Fixed

## v0.1.4b1
### Added
- Support devices filter, and device changed notify logical refinement. [#332](https://github.com/XiaoMi/ha_xiaomi_home/pull/332)
### Changed
- Readme amend HACS installation. [#404](https://github.com/XiaoMi/ha_xiaomi_home/pull/404)
### Fixed
- Fix unit_convert AttributeError, Change to catch all Exception. [#396](https://github.com/XiaoMi/ha_xiaomi_home/pull/396)
- Ignore undefined piid and keep processing following arguments. [#377](https://github.com/XiaoMi/ha_xiaomi_home/pull/377)
- Fix some type error, wrong use of any and Any. [#338](https://github.com/XiaoMi/ha_xiaomi_home/pull/338)
- Fix lumi.switch.acn040 identify service translation of zh-Hans [#412](https://github.com/XiaoMi/ha_xiaomi_home/pull/412)

## v0.1.4b0
### Added
### Changed
### Fixed
- Fix miot cloud token refresh logic. [#307](https://github.com/XiaoMi/ha_xiaomi_home/pull/307)
- Fix lan ctrl filter logic. [#303](https://github.com/XiaoMi/ha_xiaomi_home/pull/303)

## v0.1.3
### Added
### Changed
- Remove default bug label. [#276](https://github.com/XiaoMi/ha_xiaomi_home/pull/276)
- Improve multi-language translation actions. [#256](https://github.com/XiaoMi/ha_xiaomi_home/pull/256)
- Use aiohttp instead of waiting for blocking calls. [#227](https://github.com/XiaoMi/ha_xiaomi_home/pull/227)
- Language supports dt. [#237](https://github.com/XiaoMi/ha_xiaomi_home/pull/237)
### Fixed
- Fix local control error. [#271](https://github.com/XiaoMi/ha_xiaomi_home/pull/271)
- Fix README_zh and miot_storage. [#270](https://github.com/XiaoMi/ha_xiaomi_home/pull/270)

## v0.1.2
### Added
- Support Xiaomi Heater devices. https://github.com/XiaoMi/ha_xiaomi_home/issues/124 https://github.com/XiaoMi/ha_xiaomi_home/issues/117
- Language supports pt, pt-BR.
### Changed
- Adjust the minimum version of HASS core to 2024.4.4 and above versions.
### Fixed

## v0.1.1
### Added
### Changed
### Fixed
- Fix humidifier trans rule. https://github.com/XiaoMi/ha_xiaomi_home/issues/59
- Fix get homeinfo error.  https://github.com/XiaoMi/ha_xiaomi_home/issues/22 
- Fix air-conditioner switch on. https://github.com/XiaoMi/ha_xiaomi_home/issues/37 https://github.com/XiaoMi/ha_xiaomi_home/issues/16
- Fix invalid cover status. https://github.com/XiaoMi/ha_xiaomi_home/issues/11  https://github.com/XiaoMi/ha_xiaomi_home/issues/85 
- Water heater entity add STATE_OFF. https://github.com/XiaoMi/ha_xiaomi_home/issues/105 https://github.com/XiaoMi/ha_xiaomi_home/issues/17 

## v0.1.0
### Added
- First version
### Changed
### Fixed
