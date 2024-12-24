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

MIoT redirect web pages.
"""

# pylint: disable=line-too-long

def oauth_redirect_page(lang: str, status: str) -> str:
    """Return oauth redirect page."""
    return '''
        <html>
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <link rel="icon" href="https://cdn.web-global.fds.api.mi-img.com/mcfe--mi-account/static/favicon_new.ico">
            <link as="style"
                href="https://font.sec.miui.com/font/css?family=MiSans:300,400,500,600,700:Chinese_Simplify,Chinese_Traditional,Latin&amp;display=swap"
                rel="preload">
            <title></title>
            <style>
                body {
                    background: white;
                    color: black;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    font-family: MiSans, -apple-system, BlinkMacSystemFont, Segoe UI, Roboto, Helvetica Neue, Arial, Noto Sans, sans-serif, Apple Color Emoji, Segoe UI Emoji, Segoe UI Symbol, Noto Color Emoji;
                }
                @media (prefers-color-scheme: dark) {
                    body {
                        background: black;
                        color: white;
                    }
                }
                .frame {
                    background: rgb(255 255 255 / 5%);
                    width: 360px;
                    padding: 40 45;
                    border-radius: 4px;
                    box-shadow: 0 20px 50px 0 hsla(0, 0%, 64%, .1);
                    text-align: center;
                }
                .logo-frame {
                    text-align: center;
                }
                .title-frame {
                    margin: 20px 0 20px 0;
                    font-size: 26px;
                    font-weight: 500;
                    line-height: 40px;
                    opacity: 0.8;
                }
                .content-frame {
                    font-size: 17px;
                    font-weight: 500;
                    line-height: 20px;
                    opacity: 0.8;
                }
                button {
                    margin-top: 20px;
                    background-color: #ff5c00;
                    border: none;
                    border-radius: 4px;
                    padding: 0 20px;
                    text-align: center;
                    width: 100%;
                    display: inline-block;
                    font-size: 18px;
                    font-weight: 400;
                    height: 60px;
                    line-height: 60px;
                    overflow: hidden;
                    position: relative;
                    text-overflow: ellipsis;
                    transition: all .3s cubic-bezier(.645, .045, .355, 1);
                    vertical-align: top;
                    white-space: nowrap;
                    cursor: pointer;
                    color: #fff;
                }
            </style>
        </head>
        <body>
        <div class="frame">
            <!-- XIAOMI LOGO-->
            <div class="logo-frame">
                <svg width="50" height="50" viewBox="0 0 193 193" xmlns="http://www.w3.org/2000/svg"
                    xmlns:xlink="http://www.w3.org/1999/xlink"><title>编组</title>
                    <desc>Created with Sketch.</desc>
                    <defs>
                        <polygon id="path-1"
                                points="1.78097075e-14 0.000125324675 192.540685 0.000125324675 192.540685 192.540058 1.78097075e-14 192.540058"></polygon>
                    </defs>
                    <g id="\u9875\u9762-1" stroke="none" stroke-width="1" fill="none" fill-rule="evenodd">
                        <g id="\u7F16\u7EC4">
                            <mask id="mask-2" fill="white">
                                <use xlink:href="#path-1"></use>
                            </mask>
                            <g id="Clip-2"></g>
                            <path d="M172.473071,20.1164903 C154.306633,2.02148701 128.188344,-1.78097075e-14 96.2706558,-1.78097075e-14 C64.312237,-1.78097075e-14 38.155724,2.0452987 19.9974318,20.1872987 C1.84352597,38.3261656 1.78097075e-14,64.4406948 1.78097075e-14,96.3640227 C1.78097075e-14,128.286724 1.84352597,154.415039 20.0049513,172.556412 C38.1638701,190.704052 64.3141169,192.540058 96.2706558,192.540058 C128.225942,192.540058 154.376815,190.704052 172.53636,172.556412 C190.694653,154.409399 192.540685,128.286724 192.540685,96.3640227 C192.540685,64.3999643 190.672721,38.2553571 172.473071,20.1164903"
                                id="Fill-1" fill="#FF6900" mask="url(#mask-2)"></path>
                            <path d="M89.1841721,131.948836 C89.1841721,132.594885 88.640263,133.130648 87.9779221,133.130648 L71.5585097,133.130648 C70.8848896,133.130648 70.338474,132.594885 70.338474,131.948836 L70.338474,89.0100961 C70.338474,88.3584078 70.8848896,87.8251513 71.5585097,87.8251513 L87.9779221,87.8251513 C88.640263,87.8251513 89.1841721,88.3584078 89.1841721,89.0100961 L89.1841721,131.948836 Z"
                                id="Fill-3" fill="#FFFFFF" mask="url(#mask-2)"></path>
                            <path d="M121.332896,131.948836 C121.332896,132.594885 120.786481,133.130648 120.121633,133.130648 L104.492393,133.130648 C103.821906,133.130648 103.275491,132.594885 103.275491,131.948836 L103.275491,131.788421 L103.275491,94.9022357 C103.259198,88.4342292 102.889491,81.7863818 99.5502146,78.445226 C96.6790263,75.5652649 91.3251562,74.9054305 85.7557276,74.7669468 L57.4242049,74.7669468 C56.7555977,74.7669468 56.2154484,75.3045896 56.2154484,75.9512649 L56.2154484,128.074424 L56.2154484,131.948836 C56.2154484,132.594885 55.6640198,133.130648 54.9954127,133.130648 L39.3555198,133.130648 C38.6875393,133.130648 38.1498964,132.594885 38.1498964,131.948836 L38.1498964,60.5996188 C38.1498964,59.9447974 38.6875393,59.4121675 39.3555198,59.4121675 L84.4786692,59.4121675 C96.2717211,59.4121675 108.599909,59.9498104 114.680036,66.0380831 C120.786481,72.1533006 121.332896,84.4595571 121.332896,96.2657682 L121.332896,131.948836 Z"
                                id="Fill-5" fill="#FFFFFF" mask="url(#mask-2)"></path>
                            <path d="M153.53056,131.948836 C153.53056,132.594885 152.978505,133.130648 152.316164,133.130648 L136.678778,133.130648 C136.010797,133.130648 135.467515,132.594885 135.467515,131.948836 L135.467515,60.5996188 C135.467515,59.9447974 136.010797,59.4121675 136.678778,59.4121675 L152.316164,59.4121675 C152.978505,59.4121675 153.53056,59.9447974 153.53056,60.5996188 L153.53056,131.948836 Z"
                                id="Fill-7" fill="#FFFFFF" mask="url(#mask-2)"></path>
                        </g>
                    </g>
                </svg>
            </div>
            <!-- TITLE -->
            <div class="title-frame">
                <a id="titleArea"></a>
            </div>
            <!-- CONTENT -->
            <div class="content-frame">
                <a id="contentArea"></a>
            </div>
            <!-- BUTTON -->
            <button onClick="window.close();" id="buttonArea"></button>
        </div>
        <script>
            // get language (user language -> system language)
            const locale = (localStorage.getItem('selectedLanguage')?? "''' + lang + '''").replaceAll('"','');
            const language = locale.includes("-") ? locale.substring(0, locale.indexOf("-")).trim() : locale;
            const status = "''' + status + '''";
            console.log(locale);
            // translation
            let translation = {
                zh: {
                    success: {
                        title: "认证完成",
                        content: "请关闭此页面，返回账号认证页面点击“下一步”",
                        button: "关闭页面"
                    },
                    fail: {
                        title: "认证失败",
                        content: "请关闭此页面，返回账号认证页面重新点击认链接进行认证。",
                        button: "关闭页面"
                    }
                },
                'zh-Hant': {
                    success: {
                        title: "認證完成",
                        content: "請關閉此頁面，返回帳號認證頁面點擊「下一步」。",
                        button: "關閉頁面"
                    },
                    fail: {
                        title: "認證失敗",
                        content: "請關閉此頁面，返回帳號認證頁面重新點擊認鏈接進行認證。",
                        button: "關閉頁面"
                    }
                },
                en: {
                    success: {
                        title: "Authentication Completed",
                        content: "Please close this page and return to the account authentication page to click NEXT",
                        button: "Close Page"
                    },
                    fail: {
                        title: "Authentication Failed",
                        content: "Please close this page and return to the account authentication page to click the authentication link again.",
                        button: "Close Page"
                    }
                },
                "it": {
                    "success": {
                        "title": "Autenticazione Completata",
                        "content": "Si prega di chiudere questa pagina e tornare alla pagina di autenticazione dell'account per cliccare AVANTI",
                        "button": "Chiudi Pagina"
                    },
                    "fail": {
                        "title": "Autenticazione Fallita",
                        "content": "Si prega di chiudere questa pagina e tornare alla pagina di autenticazione dell'account per cliccare nuovamente sul link di autenticazione.",
                        "button": "Chiudi Pagina"
                    }
                },
                fr: {
                    success: {
                        title: "Authentification Terminée",
                        content: "Veuillez fermer cette page et revenir à la page d'authentification du compte pour cliquer sur « SUIVANT »",
                        button: "Fermer la page"
                    },
                    fail: {
                        title: "Échec de l'Authentification",
                        content: "Veuillez fermer cette page et revenir à la page d'authentification du compte pour cliquer de nouveau sur le lien d'authentification.",
                        button: "Fermer la page"
                    }
                },
                ru: {
                    success: {
                        title: "Подтверждение завершено",
                        content: "Пожалуйста, закройте эту страницу, вернитесь на страницу аутентификации учетной записи и нажмите кнопку «Далее».",
                        button: "Закрыть страницу"
                    },
                    fail: {
                        title: "Ошибка аутентификации",
                        content: "Пожалуйста, закройте эту страницу, вернитесь на страницу аутентификации учетной записи и повторите процесс аутентификации, щелкнув ссылку.",
                        button: "Закрыть страницу"
                    }
                },
                de: {
                    success: {
                        title: "Authentifizierung abgeschlossen",
                        content: "Bitte schließen Sie diese Seite, kehren Sie zur Kontobestätigungsseite zurück und klicken Sie auf „WEITER“.",
                        button: "Seite schließen"
                    },
                    fail: {
                        title: "Authentifizierung fehlgeschlagen",
                        content: "Bitte schließen Sie diese Seite, kehren Sie zur Kontobestätigungsseite zurück und wiederholen Sie den Authentifizierungsprozess, indem Sie auf den Link klicken.",
                        button: "Seite schließen"
                    }
                },
                es: {
                    success: {
                        title: "Autenticación completada",
                        content: "Por favor, cierre esta página, regrese a la página de autenticación de la cuenta y haga clic en 'SIGUIENTE'.",
                        button: "Cerrar página"
                    },
                    fail: {
                        title: "Error de autenticación",
                        content: "Por favor, cierre esta página, regrese a la página de autenticación de la cuenta y vuelva a hacer clic en el enlace de autenticación.",
                        button: "Cerrar página"
                    }
                },
                ja: {
                    success: {
                        title: "認証完了",
                        content: "このページを閉じて、アカウント認証ページに戻り、「次」をクリックしてください。",
                        button: "ページを閉じる"
                    },
                    fail: {
                        title: "認証失敗",
                        content: "このページを閉じて、アカウント認証ページに戻り、認証リンクを再度クリックしてください。",
                        button: "ページを閉じる"
                    }
                }
            }
            // insert translate into page / match order: locale > language > english
            document.title = translation[locale]?.[status]?.title ?? translation[language]?.[status]?.title ?? translation["en"]?.[status]?.title;
            document.getElementById("titleArea").innerText = translation[locale]?.[status]?.title ?? translation[language]?.[status]?.title ?? translation["en"]?.[status]?.title;
            document.getElementById("contentArea").innerText = translation[locale]?.[status]?.content ?? translation[language]?.[status]?.content ?? translation["en"]?.[status]?.content;
            document.getElementById("buttonArea").innerText = translation[locale]?.[status]?.button ?? translation[language]?.[status]?.button ?? translation["en"]?.[status]?.button;
            window.opener=null;
            window.open('','_self');
            window.close();
        </script>
        </body>
        </html>
    '''
