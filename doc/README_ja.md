# Home Assistant Xiaomi Home Integration

[English](../README.md) | [简体中文](./README_zh.md) | [日本語](./README_ja.md)

Xiaomi Home Integrationは、Xiaomi公式がサポートするHome Assistantの統合コンポーネントであり、Home AssistantでXiaomi IoTスマートデバイスを使用できるようにします。

## インストール

> Home Assistantのバージョン要件：
>
> - Core $\geq$ 2024.11.0
> - Operating System $\geq$ 13.0

### 方法1：GitHubからgit cloneコマンドを使用してダウンロード

```bash
cd config
git clone https://github.com/XiaoMi/ha_xiaomi_home.git
cd ha_xiaomi_home
./install.sh /config
```

この方法でXiaomi Home Integrationをインストールすることをお勧めします。特定のバージョンに更新したい場合は、対応するタグに切り替えるだけです。

例：Xiaomi Home Integrationのバージョンをv1.0.0に更新する

```bash
cd config/ha_xiaomi_home
git checkout v1.0.0
./install.sh /config
```

### 方法2：[HACS](https://hacs.xyz/)

HACS > オーバーフローメニュー > カスタムリポジトリ > リポジトリ：https://github.com/XiaoMi/ha_xiaomi_home.git & カテゴリ：Integration > 追加

> Xiaomi HomeはまだHACSストアにデフォルトとして追加されていません。近日中に追加予定です。

### 方法3：[Samba](https://github.com/home-assistant/addons/tree/master/samba)または[FTPS](https://github.com/hassio-addons/addon-ftp)を使用して手動でインストール

ダウンロードして、`custom_components/xiaomi_home`フォルダをHome Assistantの`config/custom_components`フォルダにコピーします。

## 設定

### ログイン

[設定 > デバイスとサービス > 統合を追加](https://my.home-assistant.io/redirect/brand/?brand=xiaomi_home) > `Xiaomi Home`を検索 > 次へ > ここをクリックしてログイン > Xiaomiアカウントでサインイン

[![Open your Home Assistant instance and start setting up a new integration.](https://my.home-assistant.io/badges/config_flow_start.svg)](https://my.home-assistant.io/redirect/config_flow_start/?domain=xiaomi_home)

### MIoTデバイスを追加

ログインに成功すると、「家庭とデバイスを選択」ダイアログボックスが表示されます。Home Assistantにインポートしたいデバイスを含む家庭を選択できます。

### 複数ユーザーログイン

Xiaomiアカウントのログインとユーザー設定が完了した後、設定済みのXiaomi Home Integrationページで他のXiaomiアカウントを追加できます。

方法：[設定 > デバイスとサービス > 設定済み > Xiaomi Home](https://my.home-assistant.io/redirect/integration/?domain=xiaomi_home) > 中枢を追加 > 次へ > ここをクリックしてログイン > Xiaomiアカウントでサインイン

[![Open your Home Assistant instance and show an integration.](https://my.home-assistant.io/badges/integration.svg)](https://my.home-assistant.io/redirect/integration/?domain=xiaomi_home)

### 設定の更新

「設定オプション」ダイアログボックスで設定を変更できます。ユーザーのニックネームやXiaomi Home APPからインポートするデバイスのリストなどを更新できます。

方法：[設定 > デバイスとサービス > 設定済み > Xiaomi Home](https://my.home-assistant.io/redirect/integration/?domain=xiaomi_home) > 設定 > 更新するオプションを選択

### アクションのデバッグモード

アクションのデバッグモードを有効にすると、パラメータ付きのアクションコマンドメッセージをデバイスに手動で送信できます。パラメータ付きのアクションコマンドを送信するためのユーザーインターフェースは、テキストエンティティとして表示されます。

方法：[設定 > デバイスとサービス > 設定済み > Xiaomi Home](https://my.home-assistant.io/redirect/integration/?domain=xiaomi_home) > 設定 > アクションのデバッグモード

## セキュリティ

Xiaomi Home Integrationと関連するクラウドインターフェースは、Xiaomi公式が提供しています。デバイスリストを取得するためにXiaomiアカウントを使用してログインする必要があります。Xiaomi Home IntegrationはOAuth 2.0のログインプロセスを実装しており、Home Assistantアプリケーションにアカウントのパスワードを保存しません。ただし、Home Assistantプラットフォームの制限により、ログインに成功した後、Xiaomiアカウントのユーザー情報（デバイス情報、証明書、トークンなど）がHome Assistantの設定ファイルに平文で保存されます。Home Assistantの設定ファイルを適切に保管する必要があります。設定ファイルが漏洩すると、他の人があなたの身元でログインする可能性があります。

## FAQ

- Xiaomi Home IntegrationはすべてのXiaomi Homeデバイスをサポートしていますか？

  Xiaomi Home Integrationは現在、ほとんどのXiaomi Homeデバイスカテゴリをサポートしていますが、Bluetoothデバイス、赤外線デバイス、仮想デバイスなどの一部のカテゴリはサポートしていません。

- Xiaomi Home Integrationは複数のXiaomiアカウントをサポートしていますか？

  はい、複数のXiaomiアカウントをサポートしています。さらに、Xiaomi Home Integrationは、異なるアカウントに属するデバイスを同じエ���アに追加することができます。

- Xiaomi Home Integrationはローカルコントロールをサポートしていますか？

  ローカルコントロールは、[Xiaomi Central Hub Gateway](https://www.mi.com/shop/buy/detail?product_id=15755&cfrom=search)（ファームウェアバージョン3.4.0_0000以上）または内蔵の中央ハブゲートウェイ（ソフトウェアバージョン0.8.0以上）を持つXiaomi Homeデバイスによって実装されます。Xiaomi Central Hub Gatewayまたは中央ハブゲートウェイ機能を持つ他のデバイスがない場合、すべてのコントロールコマンドはXiaomi Cloudを介して送信されます。Home Assistantのローカルコントロール機能をサポートするXiaomi Central Hub Gateway（内蔵中央ハブゲートウェイを含む）のファームウェアはまだリリースされていません。アップグレード計画については、MIoTチーム��通知を参照してください。

  Xiaomi Central Hub Gatewayは中国本土でのみ利用可能であり、他の地域では利用できません。

  Xiaomi Home Integrationは、Xiaomi LANコントロール機能を有効にすることで部分的なローカルコントロールを実装することもできます。Xiaomi LANコントロール機能は、Home Assistantと同じローカルエリアネットワーク内のIPデバイス（WiFiまたはイーサネットケーブルでルーターに接続されたデバイス）のみを制御できます。BLE Mesh、ZigBeeなどのデバイスは制御できません。この機能は一部の異常を引き起こす可能性があります。この機能を使用しないことをお勧めします。Xiaomi LANコントロール機能は、[設定 > デバイスとサービス > 設定済み > Xiaomi Home](https://my.home-assistant.io/redirect/integration/?domain=xiaomi_home) > 設定 > LANコントロール設定の更新で有効にできます。

  Xiaomi LANコントロール機能は地域制限がなく、すべての地域で利用可能です。ただし、Home Assistantが存在するローカルエリアネットワーク内に中央ゲートウェイがある場合、統合でXiaomi LANコントロール機能が有効になっていても、機能は有効になりません。

- Xiaomi Home Integrationはどの地域で利用可能ですか？

  Xiaomi Home Integrationは、中国本土、ヨーロッパ、インド、ロシア、シンガポール、アメリカの6つの地域で利用できます。異なる地域のXiaomi Cloudのユーザーデータは相互に隔離されているため、設定プロセスでMIoTデバイスをインポートする際に地域を選択する必要があります。Xiaomi Home Integrationは、異なる地域のデバイスを同じエリアにインポートすることができます。

## メッセージングの原理

### クラウドを介したコントロール

<div align=center>
<img src="./images/cloud_control.jpg" width=300>

図1：クラウドコントロールアーキテクチャ

</div>

Xiaomi Home Integrationは、MIoT CloudのMQTT Brokerで関心のあるデバイスメッセージを購読します。デバイスのプロパティが変更されたり、デバイスイベントが発生したりすると、デバイスはMIoT Cloudに上りメッセージを送信し、MQTT Brokerは購読されたデバイスメッセージをXiaomi Home Integrationにプッシュします。Xiaomi Home Integrationは、クラウドで現在のデバイスプロパティ値を取得するためにポーリングする必要がないため、プロパティが変更されたりイベントが発生したりするとすぐに通知メッセージを受信できます。メッセージ購読メカニズムのおかげで、Xiaomi Home Integrationは、統合設定が完了したときにクラウドからすべてのデバイスのプロパティを一度だけクエリし、クラウドへのアクセス圧力はほとんどありません。

Xiaomi Home Integrationは、MIoT CloudのHTTPインター���ェースを介してデバイスにコマンドメッセージを送信してデバイスを制御します。デバイスは、MIoT Cloudから送信された下りメッセージを受信した後に反応し、応答します。

### ローカルでのコントロール

<div align=center>
<img src="./images/local_control.jpg" width=300>

図2：ローカルコントロールアーキテクチャ

</div>

Xiaomi Central Hub Gatewayには標準のMQTT Brokerが含まれており、完全な購読公開メカニズムを実装しています。Xiaomi Home Integrationは、Xiaomi Central Hub Gatewayを介して関心のあるデバイスメッセージを購読します。デバイスのプロパティが変更されたり、デバイスイベントが発生したりすると、デバイスはXiaomi Central Hub Gatewayに上りメッセージを送信し、MQTT Brokerは購読されたデバイスメッセージをXiaomi Home Integrationにプッシュします。

Xiaomi Home Integrationがデバイスを制御する必要がある場合、MQTT Brokerにデバイスコマンドメッセージを公開し、Xiaomi Central Hub Gatewayがデバイスに転送します。デバイスは、ゲートウェイから送信された下りメッセージを���信した後に反応し、応答します。

## MIoT-Spec-V2とHome Assistantエンティティのマッピング関係

[MIoT-Spec-V2](https://iot.mi.com/v2/new/doc/introduction/knowledge/spec)は、MIoT Specification Version 2の略であり、Xiaomi IoTプラットフォームが策定したIoTプロトコルであり、IoTデバイスの機能を標準的に記述するために使用されます。これには、機能定義（他のIoTプラットフォームではデータモデルと呼ばれる）、インタラクションモデル、メッセージ形式、およびエンコーディングが含まれます。

MIoT-Spec-V2プロトコルでは、製品はデバイスとして定義されます。デバイスにはいくつかのサービスが含まれます。サービスにはいくつかのプロパティ、イベント、およびアクションが含まれる場合があります。Xiaomi Home Integrationは、MIoT-Spec-V2に従ってHome Assistantエンティティを作成します。変換関係は次のとおりです。

### 一般的な変換

- プロパティ

| フォーマット | アクセス | 値リスト | 値範囲 | Home Assistantのエンティティ |
| ------------ | -------- | -------- | ------ | ---------------------------- |
| 書き込み可能 | 文字列   | -        | -      | テキスト                     |
| 書き込み可能 | ブール   | -        | -      | スイッチ                     |
| 書き込み可能 | 文字列以外 & ブール以外 | 存在する | - | セレクト                     |
| 書き込み可能 | 文字列以外 & ブール以外 | 存在しない | 存在する | ナンバー                     |
| 書き込み不可 | -        | -        | -      | センサー                     |

- イベント

MIoT-Spec-V2イベントは、Home Assistantのイベントエンティティに変換されます。イベントのパラメータもエンティティの`_trigger_event`に渡されます。

- アクション

| in        | Home Assistantのエンティティ |
| --------- | ---------------------------- |
| 空        | ボタン                       |
| 空でない  | 通知                         |

アクションのデバッグモードが有効になっている場合、アクションの`in`フィールドが空でない場合、テキストエンティティも作成されます。

エンティティの詳細ページの「属性」項目には、入力パラメータの形式が表示されます。入力パラメータは順序付きリストであり、角括弧[]で囲まれています。リスト内の文字列要素は二重引用符""で囲まれています。

例：xiaomi.wifispeaker.s12 siid=5 aiid=5インスタンスの「Intelligent Speaker Execute Text Directive」アクションによって変換された通知エンティティの詳細ページの「属性」項目には、アクションパラメータとして`[Text Content(str), Silent Execution(bool)]`が表示されます。適切にフォーマットされた入力は`["Hello", true]`です。

### 特定の変換

MIoT-Spec-V2は、タイプを定義するためにURNを使用します。形式は`urn:<namespace>:<type>:<name>:<value>[:<vendor-product>:<version>]`であり、`name`はデバイス、サービス、プロパティ、イベント、アクションのインスタンスを説明するための人間が読める単語またはフレーズです。Xiaomi Home Integrationは、インスタンスの名前に基づいてMIoT-Spec-V2インスタンスを特定のHome Assistantエンティティに変換するかどうかを最初に判断します。特定の変換ルールに一致しないインスタンスについては、一般的な変換ルールを使用して変換します。

`namespace`はMIoT-Spec-V2インスタンスの名前空間です。その値がmiot-spec-v2の場合、仕様はXiaomiによって定義されたことを意味します。その値がbluetooth-specの場合、仕様はBluetooth Special Interest Group（SIG）によって定義されたことを意味します。その値がmiot-spec-v2またはbluetooth-specでない場合、仕様は他のベンダーによって定義されたことを意味します。MIoT-Spec-V2の`namespace`がmiot-spec-v2でない場合、エンティティの名前の前に星印`*`が追加されます。

- デバイス

変換は`SPEC_DEVICE_TRANS_MAP`に従います。

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

"device instance name"の下の"required"フィールドは、デバイスの必須サービスを示します。"optional"フィールドは、デバイスのオプションサービスを示します。"entity"フィールドは、作成されるHome Assistantエンティティを示します。"service instance name"の下の"required"フィールドと"optional"フィールドは、それぞれサービスの必須プロパティ、イベント、およびアクションを示します。"required"フィールドの"properties"フィールドの"property instance name"の値は、プロパティのアクセスモードです。成功した一致の条件は、"property instance name"の値が対応するMIoT-Spec-V2プロパティインスタンスのアクセスモードのサブセットであることです。

MIoT-Spec-V2デバイスインスタンスがすべての必須サービス、プロパティ、イベント、アクションを含まない場合、Home Assistantエンティティは作成されません。

- サービス

変換は`SPEC_SERVICE_TRANS_MAP`に従います。

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

"service instance name"の下の"required"フィールドは、サービスの必須プロパティ、イベント、およびアクションを示します。"optional"フィールドは、サービスのオプションプロパティ、イベント、およびアクションを示します。"entity"フィールドは、作成されるHome Assistantエンティティを示します。"required"フィールドの"properties"フィールドの"property instance name"の値は、プロパティのアクセスモードです。成功した一致の条件は、"property instance name"の値が対応するMIoT-Spec-V2プロパティインスタンスのアクセスモードのサブセットであることです。

MIoT-Spec-V2サービスインスタンスがすべての必須プロパティ、イベント、アクションを含まない場合、Home Assistantエンティティは作成されません。

- プロパティ

変換は`SPEC_PROP_TRANS_MAP`に従います。

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

"entity name"の下の"format"フィールドは、プロパティのデータ形式を表し、1つの値と一致することが成功した一致を示します。"entity name"の下の"access"フィールドは、プロパティのアクセスモードを表し、すべての値と一致することが成功した一致を示します。

"property instance name"の下の"entity"フィールドの値は、"entities"フィールドの"entity name"の1つであり、作成されるHome Assistantエンティティを示します。"property instance name"の下の"device_class"フィールドは、作成されるHome Assistantエンティティの`_attr_device_class`を示します。

- イベント

変換は`SPEC_EVENT_TRANS_MAP`に従います。

```
{
    '<event instance name>': str
}
```

イベントインスタンス名の値は、作成されるHome Assistantエンティティの`_attr_device_class`を示します。

### MIoT-Spec-V2フィルタ

`spec_filter.json`は、Home Assistantエンティティに変換されないMIoT-Spec-V2インスタンスをフィルタリングするために使用されます。

`spec_filter.json`の形式は次のとおりです。

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

`spec_filter.json`辞書のキーは、MIoT-Spec-V2デバイスインスタンスのURN（"version"フィールドを除く）です。同じ製品の異なるバージョンのファームウェアは、異なるバージョンのMIoT-Spec-V2デバイスインスタンスに関連付けられる場合があります。MIoTプラットフォームでは、ベンダーが製品のMIoT-Spec-V2を定義する際に、高バージョンのMIoT-Spec-V2インスタンスが低バージョンのMIoT-Spec-V2インスタンスをすべて含む必要があります。そのため、`spec_filter.json`のキーはMIoT-Spec-V2デバイスインスタンスのバージョン番号を指定する必要はありません。

デバイスインスタンスの下の"services"、"properties"、"events"、"actions"フィールドの値は、変換プロセスで無視されるサービス、プロパティ、イベント、アクションのインスタンスID（iid）です。ワイルドカードマッチングがサポートされています。

例：

```
{
    "urn:miot-spec-v2:device:television:0000A010:xiaomi-rmi1":{
        "services": ["*"]   # すべてのサービスをフィルタリングします。これは、そのようなMIoT-Spec-V2デバイスインスタンスを完全に無視することと同等です。
    },
    "urn:miot-spec-v2:device:gateway:0000A019:xiaomi-hub1": {
        "services": ["3"],  # iid=3のサービスをフィルタリングします。
        "properties": ["4.*"]   # iid=4のサービス内のすべてのプロパティをフィルタリングします。
        "events": ["4.1"],  # iid=4のサービス内のiid=1のイベントをフィルタリングします。
        "actions": ["4.1"]  # iid=4のサービス内のiid=1のアクションをフィルタリングします。
    }
}
```

すべてのデバイスのデバイス情報サービス（urn:miot-spec-v2:service:device-information:00007801）は、Home Assistantエンティティに変換されません。

## 多言語サポート

Xiaomi Homeの設定フロー言語オプションで選択可能な言語は、簡体字中国語、繁体字中国語、英語、スペイン語、ロシア語、フランス語、ドイツ語、日本語の8つの言語です。設定フローページの簡体字中国語と英語は開発者によって手動でレビューされています。他の言語は機械翻訳によって翻訳されています。設定フローページの単語や文を変更したい場合は、`custom_components/xiaomi_home/translations/`および`custom_components/xiaomi_home/miot/i18n/`ディレクトリ内の該当する言語のjsonファイルを変更する必要があります。

Home Assistantエンティティ名を表示する際、Xiaomi HomeはデバイスベンダーがMIoT Cloudからダウンロードした多言語ファイルを使用します。このファイルには、デバイスのMIoT-Spec-V2インスタンスの翻訳が含まれています。`multi_lang.json`はローカルで管理されている多言語辞書であり、クラウドから取得した多言語ファイルよりも優先され、デバイスの翻訳を補完または修正するために使用できます。

`multi_lang.json`の形式は次のとおりです。

```
{
    "<MIoT-Spec-V2 device instance>": {
        "<language code>": {
            "<instance code>": <translation: str>
        }
    }
}
```

`multi_lang.json`辞書のキーは、MIoT-Spec-V2デバイスインスタンスのURN（"version"フィールドを除く）です。

言語コードは、zh-Hans、zh-Hant、en、es、ru、fr、de、jaのいずれかであり、上記の選択可能な8つの言語に対応しています。

インスタンスコードは、MIoT-Spec-V2インスタンスのコードであり、次の形式です：

```
service:<siid>                  # サービス
service:<siid>:property:<piid>  # プロパティ
service:<siid>:property:<piid>:valuelist:<value> # プロパティの値リストの値
service:<siid>:event:<eiid>     # イベント
service:<siid>:action:<aiid>    # アクション
```

siid、piid、eiid、aiid、およびvalueはすべて10進数の3桁の整数です。

例：

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

> Home Assistantで`custom_components/xiaomi_home/miot/specs`ディレクトリ内の`specv2entity.py`、`spec_filter.json`、`multi_lang.json`ファイルの内容を編集した場合、統合の設定ページでエンティティ変換ルールを更新する必要があります。方法：[設定 > デバイスとサービス > 設定済み > Xiaomi Home](https://my.home-assistant.io/redirect/integration/?domain=xiaomi_home) > 設定 > エンティティ変換ルールの更新

## ドキュメント

- [ライセンス](../LICENSE.md)
- 貢献ガイドライン：[English](../CONTRIBUTING.md) | [简体中文](./CONTRIBUTING_zh.md)
- [変更履歴](./CHANGELOG.md)
- 開発ドキュメント：https://developers.home-assistant.io/docs/creating_component_index

## ディレクトリ構造

- miot：コアコード。
- miot/miot_client：統合にユーザーを追加するには、miot_clientインスタンスを追加する必要があります。
- miot/miot_cloud：クラウドサービスに関連する機能を含みます。OAuthログインプロセス、HTTPインターフェース機能（ユーザー情報の取得、デバイス制御コマンドの送信など）。
- miot/miot_device：デバイスエンティティ。デバイス情報、プロパティ、イベント、アクションの処理ロジックを含みます。
- miot/miot_mips：メッセージバス。メソッドの購読と公開のためのものです。
- miot/miot_spec：MIoT-Spec-V2を解析します。
- miot/miot_lan：デバイスLANコントロール。デバイスの発見、デバイスの制御などを含みます。
- miot/miot_mdns：中央ハブゲートウェイサービスのLAN発見。
- miot/miot_network：ネットワーク状態とネットワーク情報の取得。
- miot/miot_storage：統合のファイルストレージ。
- miot/test：テストスクリプト。
- config_flow：設定フロー。
