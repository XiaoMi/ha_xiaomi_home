# CHANGELOG
## v0.2.3
### Changed
- Specify the service name and the property name during the climate entity's on/off feature initialization. [#899](https://github.com/XiaoMi/ha_xiaomi_home/pull/899)
- Remove the useless total-battery property from `SPEC_PROP_TRANS_MAP`.
### Fixed
- Fix the hvac mode setting error when changing the preset mode of the ptc-bath-heater.
- Fix the ambiguous descriptions of yeelink.bhf_light.v10 ptc-bath-heater mode value-list.
- Fix the power consumption value of chuangmi.plug.212a01. [#910](https://github.com/XiaoMi/ha_xiaomi_home/pull/910)

## v0.2.2
This version has modified the conversion rules of the climate entity, which will have effect on the devices with the ptc-bath-heater, the air-conditioner and the air-fresh service. After updating, you need to restart Home Assistant and check `xiaomi_home > CONFIGURE >
Update entity conversion rules > NEXT` to reload the integration.

这个版本修改了浴霸、空调、新风机的实体转换规则，更新之后需要重启 Home Assistant，并且勾选 `xiaomi_home > 配置 > 更新实体转换规则 > 下一步` 重新加载集成。
### Added
- Add conversion rules for the air-conditioner service and the air-fresh service. [#879](https://github.com/XiaoMi/ha_xiaomi_home/pull/879)
### Changed
- Convert the mode of the ptc bath heater to the preset mode of the climate entity. [#874](https://github.com/XiaoMi/ha_xiaomi_home/pull/874)
- Use Home Assistant default icon when device_class is set. [#855](https://github.com/XiaoMi/ha_xiaomi_home/pull/855)
### Fixed
- Fix xiaomi.aircondition.m9 humidity-range unit. [#878](https://github.com/XiaoMi/ha_xiaomi_home/pull/878)
- Fix MIoT-Spec-V2 conflicts of xiaomi.fan.p5 and mike.bhf_light.2. [#866](https://github.com/XiaoMi/ha_xiaomi_home/pull/866)

## v0.2.1
### Added
- Add the preset mode for the thermostat. [#833](https://github.com/XiaoMi/ha_xiaomi_home/pull/833)
### Changed
- Change paho-mqtt version to adapt Home Assistant 2025.03. [#839](https://github.com/XiaoMi/ha_xiaomi_home/pull/839)
- Revert to use multi_lang.json. [#834](https://github.com/XiaoMi/ha_xiaomi_home/pull/834)
### Fixed
- Fix the opening and the closing status of linp.wopener.wd1lb. [#826](https://github.com/XiaoMi/ha_xiaomi_home/pull/826)
- Fix the format type of the wind-reverse property. [#810](https://github.com/XiaoMi/ha_xiaomi_home/pull/810)
- Fix the fan-level property without value-list but with value-range. [#808](https://github.com/XiaoMi/ha_xiaomi_home/pull/808)

## v0.2.0
This version has modified some default units of sensors. After updating, it may cause Home Assistant to pop up some compatibility warnings. You can re-add the integration to resolve it.

这个版本修改了一些传感器默认单位，更新后会导致 Home Assistant 弹出一些兼容性提示，您可以重新添加集成解决。

### Added
- Add prop trans rule for surge-power. [#595](https://github.com/XiaoMi/ha_xiaomi_home/pull/595)
- Support modify spec and value conversion. [#663](https://github.com/XiaoMi/ha_xiaomi_home/pull/663)
- Support the electric blanket. [#781](https://github.com/XiaoMi/ha_xiaomi_home/pull/781)
- Add device with motor-control service as cover entity. [#688](https://github.com/XiaoMi/ha_xiaomi_home/pull/688)
### Changed
- Update README file. [#681](https://github.com/XiaoMi/ha_xiaomi_home/pull/681) [#747](https://github.com/XiaoMi/ha_xiaomi_home/pull/747)
- Update CONTRIBUTING.md. [#681](https://github.com/XiaoMi/ha_xiaomi_home/pull/681)
- Refactor climate.py. [#614](https://github.com/XiaoMi/ha_xiaomi_home/pull/614)
### Fixed
- Fix variable name or comment errors & fix test_lan error. [#678](https://github.com/XiaoMi/ha_xiaomi_home/pull/678) [#690](https://github.com/XiaoMi/ha_xiaomi_home/pull/690)
- Fix water heater error & some type error. [#684](https://github.com/XiaoMi/ha_xiaomi_home/pull/684)
- Fix fan level with value-list & fan reverse [#689](https://github.com/XiaoMi/ha_xiaomi_home/pull/689)
- Fix sensor display precision [#708](https://github.com/XiaoMi/ha_xiaomi_home/pull/708)
- Fix event:motion-detected without arguments [#712](https://github.com/XiaoMi/ha_xiaomi_home/pull/712)

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
