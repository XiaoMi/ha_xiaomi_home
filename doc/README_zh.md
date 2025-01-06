# Home Assistant 米家集成

[English](../README.md) | [简体中文](./README_zh.md)

米家集成是一个由小米官方提供支持的 Home Assistant 的集成组件，它可以让您在 Home Assistant 中使用小米 IoT 智能设备。

## 安装

> Home Assistant 版本要求：
>
> - Core $\geq$ 2024.4.4
> - Operating System $\geq$ 13.0

### 方法 1：使用 git clone 命令从 GitHub 下载

```bash
cd config
git clone https://github.com/XiaoMi/ha_xiaomi_home.git
cd ha_xiaomi_home
./install.sh /config
```

推荐使用此方法安装米家集成。当您想要更新至特定版本时，只需要切换至相应的 Tag 。

例如，更新米家集成版本至 v1.0.0

```bash
cd config/ha_xiaomi_home
git fetch
git checkout v1.0.0
./install.sh /config
```

### 方法 2: [HACS](https://hacs.xyz/)

HACS > 右上角三个点 > Custom repositories > Repository: https://github.com/XiaoMi/ha_xiaomi_home.git & Category or Type: Integration > ADD > 点击 HACS 的 New 或 Available for download 分类下的 Xiaomi Home ，进入集成详情页  > DOWNLOAD

> 米家集成暂未添加到 HACS 商店，敬请期待。

### 方法 3：通过 [Samba](https://github.com/home-assistant/addons/tree/master/samba) 或 [FTPS](https://github.com/hassio-addons/addon-ftp) 手动安装

下载并将 `custom_components/xiaomi_home` 文件夹复制到 Home Assistant 的 `config/custom_components` 文件夹下。

## 配置

### 登录

[设置 > 设备与服务 > 添加集成](https://my.home-assistant.io/redirect/brand/?brand=xiaomi_home) > 搜索“`Xiaomi Home`” > 下一步 > 请点击此处进行登录 > 使用小米账号登录

[![Open your Home Assistant instance and start setting up a new integration.](https://my.home-assistant.io/badges/config_flow_start.svg)](https://my.home-assistant.io/redirect/config_flow_start/?domain=xiaomi_home)

### 添加 MIoT 设备

登录成功后，会弹出会话框“选择家庭与设备”。您可以选择需要添加的米家家庭，该家庭内的所有设备将导入 Home Assistant 。

### 多账号登录

用一个小米账号登录并配置完成后，您可以在 Xiaomi Home Integration 页面中继续添加其他小米账号。

方法：[设置 > 设备与服务 > 已配置 > Xiaomi Home](https://my.home-assistant.io/redirect/integration/?domain=xiaomi_home) > 添加中枢 > 下一步 > 请点击此处进行登录 > 使用小米账号登录

[![Open your Home Assistant instance and show an integration.](https://my.home-assistant.io/badges/integration.svg)](https://my.home-assistant.io/redirect/integration/?domain=xiaomi_home)

### 修改配置项

在会话框“配置选项”中，可选择需要变更的配置项。您可以修改用户昵称或更新从米家 APP 导入的设备列表。

方法：[设置 > 设备与服务 > 已配置 > Xiaomi Home](https://my.home-assistant.io/redirect/integration/?domain=xiaomi_home) > 配置 > 选择需要变更的配置项

### Action 调试模式

开启该模式后，您可手动向设备发送带参数的 Action 控制指令。发送带参数的 Action 控制指令的用户入口显示为一个文本实体。

方法：[设置 > 设备与服务 > 已配置 > Xiaomi Home](https://my.home-assistant.io/redirect/integration/?domain=xiaomi_home) > 配置 > Action 调试模式

## 安全性

米家集成及其使用的云端接口由小米官方提供。您需要使用小米账号登录以获取设备列表。米家集成使用 OAuth 2.0 的登录方式，不会在 Home Assistant 中保存您的小米账号密码。但由于 Home Assistant 平台的限制，登录成功后，您的小米用户信息（包括设备信息、证书、 token 等）会明文保存在 Home Assistant 的配置文件中。因此，您需要保管好自己 Home Assistant 配置文件。一旦该文件泄露，其他人可能会冒用您的身份登录。

> 如果您怀疑您的 OAuth 2.0 令牌已泄露，您可以通过以下步骤取消小米账号的登录授权： 米家 APP -> 我的 -> 点击用户名进入小米账号页面 -> 应用授权 -> Xiaomi Home (Home Assistant Integration) -> 取消授权

## 常见问题

- 米家集成是否支持所有的小米米家设备？

  米家集成目前支持大部分米家设备品类，但仍有一小部分设备品类（蓝牙、红外及虚拟设备）并不支持。

- 米家集成是否可以同时使用多个小米账号？

  是的，米家集成支持多个小米账号同时登录。另外，米家集成还支持不同账号的米家设备添加至同一个 Home Assistant 区域。

- 米家集成是否支持本地化控制？

  米家集成支持通过[小米中枢网关](https://www.mi.com/shop/buy/detail?product_id=15755&cfrom=search)（固件版本 3.4.0_000 以上）或内置中枢网关（软件版本 0.8.0 以上）的米家设备实现本地化控制。如果没有小米中枢网关或其他带中枢网关功能的设备，那么所有控制指令都会通过小米云发送。支持 Home Assistant 本地化控制的小米中枢网关（含内置中枢网关）的固件尚未发布，固件升级计划请参阅 MIoT 团队的通知。

  小米中枢网关仅在中国大陆可用，在其他地区不可用。

  米家集成也能通过开启小米局域网控制功能实现部分本地化控制效果。小米局域网控制功能只能控制与 Home Assistant 处于同一局域网内的 IP 设备（使用 WiFi、网线连接路由器的设备），无法控制蓝牙 Mesh、ZigBee 等协议接入的设备。该功能可能会引起一些异常，我们建议不要使用该功能。小米局域网控制功能开启方法：[设置 > 设备与服务 > 已配置 > Xiaomi Home](https://my.home-assistant.io/redirect/integration/?domain=xiaomi_home) > 配置 > 更新局域网控制配置

  小米局域网控制功能不受地区限制，在全球范围内均可用。如果 Home Assistant 所在的局域网内存在中枢网关，那么即便米家集成开启了小米局域网控制功能，该功能也不会生效。

- 米家集成在哪些地区可用？

  米家集成所用的云服务接口已部署在中国大陆、欧洲、印度、俄罗斯、新加坡、美国共六个地区的机房。由于用户数据在不同地区的小米云上相互隔离，您需要在配置 Home Assistant 时选择用户所在地区，才能导入相应的米家设备。米家集成支持将不同地区的米家设备添加至同一个 Home Assistant 区域。

## 消息收发原理

### 云端控制

<div align=center>
<img src="./images/cloud_control_zh.jpg" width=300>

图 1：云端控制架构

</div>

米家集成向小米云 MQTT Broker 订阅关注的设备消息。当设备属性发生改变或产生设备事件时，设备向小米云发送上行消息， MQTT Broker 向米家集成推送订阅的设备消息。由于米家集成不需要向云端轮询以获取设备当前的属性值，因此米家集成能第一时间获知设备属性变化或事件发生。得益于消息订阅机制，米家集成只在配置完成时向云端查询一次所有的设备属性，对云端产生的访问压力很小。

米家集成需要控制设备时，通过小米云 HTTP 接口向设备发送控制消息。设备收到小米云发来的下行消息后做出响应。

### 本地控制

<div align=center>
<img src="./images/local_control_zh.jpg" width=300>

图 2：本地控制架构

</div>

小米中枢网关内包含一个标准的 MQTT Broker ，实现了完整的订阅发布机制。米家集成向小米中枢网关订阅关注的设备消息。当设备属性发生改变或产生设备事件时，设备向小米中枢网关发送上行消息， MQTT Broker 向米家集成推送订阅的设备消息。

米家集成需要控制设备时，向 MQTT Broker 发布设备控制消息，再经由小米中枢网关转发给设备。设备收到小米中枢网关发来的下行消息后做出响应。

## MIoT-Spec-V2 与 Home Assistant 实体的映射关系

[MIoT-Spec-V2](https://iot.mi.com/v2/new/doc/introduction/knowledge/spec) 的全称为 MIoT Specification Version 2 ，是小米 IoT 平台制订的物联网协议，用于对 IoT 设备进行规范化的功能性描述，其中包含功能定义（其他 IoT 平台称之为物模型）、交互模型、消息格式以及编码。

在 MIoT-Spec-V2 中，一个产品定义为一个设备，一个设备包含若干服务，一个服务包含若干属性、方法和事件。米家集成根据 MIoT-Spec-V2 生成对应的 Home Assistant 实体。

具体的转换关系如下：

### 一般转换规则

- 属性（Property）

| access（访问方式） | format（数据格式） | value-list（取值列表） | value-range（取值范围） | 转换后的实体 |
| ------------------ | ------------------ | ---------------------- | ----------------------- | ------------ |
| 可写               | string             | -                      | -                       | Text         |
| 可写               | bool               | -                      | -                       | Switch       |
| 可写               | 非 string、非 bool | 有                     | -                       | Select       |
| 可写               | 非 string、非 bool | 无                     | 有                      | Number       |
| 不可写             | -                  | -                      | -                       | Sensor       |

- 事件（Event）

转换后的实体为 Event，事件参数同时传递给实体的 `_trigger_event` 。

- 方法（Action）

| in（输入参数列表） | 转换后的实体 |
| ------------------ | ------------ |
| 空                 | Button       |
| 非空               | Notify       |

如果开启了“Action 调试模式”，方法的 in 字段为非空时，还会生成 Text 实体。

Notify 实体详情页中 Attributes 会显示输入参数的格式。输入参数为有序的列表，英文中括号[]包括。字符串元素由英文双引号""包括。

例如， xiaomi.wifispeaker.s12 siid=5 aiid=5 方法（ Intelligent Speaker Execute Text Directive ）在 Notify 实体详情页显示的输入参数格式为 `[Text Content(str), Silent Execution(bool)]` ，使用的输入参数可以是 `["Hello", true]` 。

### 特殊转换规则

MIoT-Spec-V2 定义类型使用的 URN 格式为 `urn:<namespace>:<type>:<name>:<value>[:<vendor-product>:<version>]`，其中 `name` 是用于描述实例（设备、服务、属性、事件、方法）的有意义的单词或词组。米家集成先用实例名称（ name ）判断是否将 MIoT-Spec-V2 实例转换成特定的 Home Assistant 实体。对于不符合特殊转换规则的 MIoT-Spec-V2 实例，再使用一般转换规则进行转换。

`namespace` 用于描述实例所属的命名空间，取值为“miot-spec-v2”表示小米定义的规范， 取值为“bluetooth-spec”表示蓝牙联盟定义的规范，其他则为厂商自定义的规范。当 `namespace` 不是“miot-spec-v2”时，转换后的实体名称前会显示一个星号\*。

- 设备（Device）

转换规则为 `SPEC_DEVICE_TRANS_MAP` ：

```
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
```

device instance name 下的 required 表示必须包含的服务， optional 表示可选的服务， entity 表示转换后的实体。 service instance name 下的 required 表示必须包含的属性、事件、方法，optional 表示可选的属性、事件、方法。 required 、 properties 域下的 property instance name 的值表示属性的访问方式，匹配成功的条件是 property instance name 的值是相应 MIoT-Spec-V2 属性实例的访问方式的子集。

如果 MIoT-Spec-V2 设备实例缺少必选的服务、属性、事件、方法，则不会生成 Home Assistant 实体。

- 服务（Service）

转换规则为 `SPEC_SERVICE_TRANS_MAP` ：

```
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
```

service instance name 下的 required 表示必须包含的属性、事件、方法，optional 表示可选的属性、事件、方法， entity 表示转换后的实体。 required 、 properties 域下的 property instance name 的值表示属性的访问方式，匹配成功的条件是 property instance name 的值是相应 MIoT-Spec-V2 属性实例的访问方式的子集。

如果 MIoT-Spec-V2 服务实例缺少必选的属性、事件、方法，则不会生成 Home Assistant 实体。

- 属性（Property）

转换规则为 `SPEC_PROP_TRANS_MAP` ：

```
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
            'entity': str
        }
    }
}
```

entity name 下的 format 表示属性的数据格式，匹配上一个值即为匹配成功； access 表示属性的访问方式，匹配上所有值才算匹配成功。

property instance name 下的 entity 表示转换后的实体，取值为 entities 下的 entity name ； device_class 表示转换后实体所用的 `_attr_device_class` 。

- 事件（Event）

转换规则为 `SPEC_EVENT_TRANS_MAP` ：

```
{
    '<event instance name>': str
}
```

event instance name 下的值表示转换后实体所用的 `_attr_device_class` 。

### MIoT-Spec-V2 过滤规则

`spec_filter.json` 用于过滤掉不需要的 MIoT-Spec-V2 实例，过滤掉的实例不会转换成 Home Assistant 实体。

`spec_filter.json`的格式如下：

```
{
    "<MIoT-Spec-V2 device instance>":{
        "services": list<service_iid: str>,
        "properties": list<service_iid.property_iid: str>,
        "events": list<service_iid.event_iid: str>,
        "actions": list<service_iid.action_iid: str>,
    }
}
```

`spec_filter.json` 的键值为 MIoT-Spec-V2 设备实例的 urn （不含版本号“version”字段）。一个产品的不同版本的固件可能会关联不同版本的 MIoT-Spec-V2 设备实例。 MIoT 平台要求厂商定义产品的 MIoT-Spec-V2 时，高版本的 MIoT-Spec-V2 实例必须包含全部低版本的 MIoT-Spec-V2 实例。因此， `spec_filter.json` 的键值不需要指定设备实例的版本号。

设备实例下的 services 、 properties 、 events 、 actions 域的值表示需要过滤掉的服务、属性、事件、方法的实例号（ iid ，即 instance id ）。支持通配符匹配。

示例：

```
{
    "urn:miot-spec-v2:device:television:0000A010:xiaomi-rmi1":{
        "services": ["*"]   # Filter out all services. It is equivalent to completely ignoring the device with such MIoT-Spec-V2 device instance.
    },
    "urn:miot-spec-v2:device:gateway:0000A019:xiaomi-hub1": {
        "services": ["3"],  # Filter out the service whose iid=3.
        "properties": ["4.*"]   # Filter out all properties in the service whose iid=4.
        "events": ["4.1"],  # Filter out the iid=1 event in the iid=4 service.
        "actions": ["4.1"]  # Filter out the iid=1 action in the iid=4 service.
    }
}
```

所有设备的设备信息服务（ urn:miot-spec-v2:service:device-information:00007801 ）均不会生成 Home Assistant 实体。

## 多语言支持

米家集成配置选项中可选择的集成使用的语言有简体中文、繁体中文、英文、西班牙语、俄语、法语、德语、日语这八种语言。目前，米家集成配置页面的简体中文和英文已经过人工校审，其他语言由机器翻译。如果您希望修改配置页面的词句，则需要修改 `custom_components/xiaomi_home/translations/` 以及 `custom_components/xiaomi_home/miot/i18n/` 目录下相应语言的 json 文件。

在显示 Home Assistant 实体名称时，米家集成会从小米云下载设备厂商为设备配置的多语言文件，该文件包含设备 MIoT-Spec-V2 实例的多语言翻译。 `multi_lang.json` 是本地维护的多语言配置字典，其优先级高于从云端获取的多语言文件，可用于补充或修改设备的多语言翻译。

`multi_lang.json` 的格式如下：

```
{
    "<MIoT-Spec-V2 device instance>": {
        "<language code>": {
            "<instance code>": <translation: str>
        }
    }
}
```

`multi_lang.json` 的键值为 MIoT-Spec-V2 设备实例的 urn （不含版本号“version”字段）。

language code 为语言代码，取值为 zh-Hans、zh-Hant、en、es、ru、fr、de、ja （对应上述米家集成可选的八种语言）。

instance code 为 MIoT-Spec-V2 实例代码，格式如下：

```
service:<siid>                  # 服务
service:<siid>:property:<piid>  # 属性
service:<siid>:property:<piid>:valuelist:<value> # 属性取值列表的值
service:<siid>:event:<eiid>     # 事件
service:<siid>:action:<aiid>    # 方法
```

siid、piid、eiid、aiid、value 均为十进制三位整数。

示例：

```
{
    "urn:miot-spec-v2:device:health-pot:0000A051:chunmi-a1": {
        "zh-Hant": {
            "service:002": "養生壺",
            "service:002:property:001": "工作狀態",
            "service:002:property:001:valuelist:000": "待機中",
            "service:002:action:002": "停止烹飪",
            "service:005:event:001": "烹飪完成"
        }
    }
}
```

> 在 Home Assistant 中修改了 `custom_components/xiaomi_home/translations/` 路径下的 `specv2entity.py`、`spec_filter.json`、`multi_lang.json` 文件的内容，需要在集成配置中更新实体转换规则才能生效。方法：[设置 > 设备与服务 > 已配置 > Xiaomi Home](https://my.home-assistant.io/redirect/integration/?domain=xiaomi_home) > 配置 > 更新实体转换规则

## 文档

- [许可证](../LICENSE.md)
- 贡献指南： [English](../CONTRIBUTING.md) | [简体中文](./CONTRIBUTING_zh.md)
- [更新日志](../CHANGELOG.md)
- 开发文档： https://developers.home-assistant.io/docs/creating_component_index

## 目录结构

- miot：核心代码。
- miot/miot_client：每添加一个用户需要增加一个 miot_client 实例。
- miot/miot_cloud：云服务相关功能，包括 OAuth 登录、 HTTP 接口功能（获取用户信息、发送设备控制指令等）。
- miot/miot_device：设备实体，包含设备信息以及属性、事件、方法的处理逻辑。
- miot/miot_mips：消息总线，用于订阅和发布消息。
- miot/miot_spec：解析 MIoT-Spec-V2 。
- miot/miot_lan: 设备局域网控制，包括设备发现、设备控制等。
- miot/miot_mdns: 中枢网关服务局域网发现。
- miot/miot_network：获取网络状态和网络信息。
- miot/miot_storage: 集成文件存储。
- miot/test：测试脚本。
- config_flow：配置流程。
