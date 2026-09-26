# CHANGELOG
## v0.4.7
### Added
- Add turkish language in multi_lang.json. [#1593](https://github.com/XiaoMi/ha_xiaomi_home/pull/1593)
### Changed
- Remove unused info getting from central hub gateway. [#1574](https://github.com/XiaoMi/ha_xiaomi_home/pull/1574)
- Remove xiaomi.router.rd03 from `UNSUPPORTED_MODELS` and add era.airp.cwb03, k0918.toothbrush.t700 into it. [#1567](https://github.com/XiaoMi/ha_xiaomi_home/pull/1567)
### Fixed
- Update the BLE mesh device online state from the central hub gateway. Partially fix the BLE mesh device online state. [#1579](https://github.com/XiaoMi/ha_xiaomi_home/pull/1579)
- Add unit for xiaomi.toothbrush.p001 brush-head-left-level property. [#1588](https://github.com/XiaoMi/ha_xiaomi_home/pull/1588)
- Fix the playing-state property's access field of xiaomi.wifispeaker.lx04, xiaomi.wifispeaker.lx06, xiaomi.wifispeaker.x08c and xiaomi.wifispeaker.l04m. [#1567](https://github.com/XiaoMi/ha_xiaomi_home/pull/1567)
- Fix the MIoT-Spec-V2 of xiaomi.airc.h09h00 humidity-range unit. [#1567](https://github.com/XiaoMi/ha_xiaomi_home/pull/1567)

## v0.4.6
### Added
- Add tv-box device as the media player entity. [#1562](https://github.com/XiaoMi/ha_xiaomi_home/pull/1562)
- Set play-control service's play-loop-mode property as the sound mode. [#1562](https://github.com/XiaoMi/ha_xiaomi_home/pull/1562)
### Changed
- Use constant value to indicate the cloud MQTT broker host domain. [#1530](https://github.com/XiaoMi/ha_xiaomi_home/pull/1530)
- Use constant value to indicate the timer delay of refreshing devices. [#1555](https://github.com/XiaoMi/ha_xiaomi_home/pull/1555)
- Set the playing-state property as the required property in the play-control service of the speaker device. [#1552](https://github.com/XiaoMi/ha_xiaomi_home/pull/1552)
- Set the playing-state property as the required property in the optional play-control service of the television. [#1562](https://github.com/XiaoMi/ha_xiaomi_home/pull/1562)
### Fixed
- Catch paho-mqtt subscribe error properly. [#1551](https://github.com/XiaoMi/ha_xiaomi_home/pull/1551)
- After the network resumes, keep retrying to fetch the device list until it succeeds. [#1555](https://github.com/XiaoMi/ha_xiaomi_home/pull/1555)
- Catch the http post error properly. [#1555](https://github.com/XiaoMi/ha_xiaomi_home/pull/1555)
- Fix the format and the access field of daikin.aircondition.k2 and daikin.airfresh.k33 string value properties. [#1561](https://github.com/XiaoMi/ha_xiaomi_home/pull/1561)
