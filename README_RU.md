<div align="center">

<H1>FPTN</H1>
<H6>Custom VPN technology</H6>

[\[English\]](README.md)
•
[\[Русский\]](README_RU.md)


[![Ubuntu](https://img.shields.io/badge/Ubuntu-E95420?style=for-the-badge&logo=ubuntu&logoColor=white)](https://github.com/batchar2/fptn/releases/latest)
[![Mac OS](https://img.shields.io/badge/mac%20os-000000?style=for-the-badge&logo=macos&logoColor=F0F0F0)](https://github.com/batchar2/fptn/releases/latest)
[![Windows](https://img.shields.io/badge/Windows-0078D6?style=for-the-badge&logo=windows&logoColor=white)](https://github.com/batchar2/fptn/releases/latest)
[![OpenWrt](https://img.shields.io/badge/OpenWrt-8A2BE2?style=for-the-badge&logo=openwrt&logoColor=white)](https://github.com/batchar2/fptn/releases/latest)
[![Android](https://img.shields.io/badge/Android-3DDC84?style=for-the-badge&logo=android&logoColor=white)](https://github.com/batchar2/FptnClient-Android/releases/latest)
[![Build and Test](https://img.shields.io/github/actions/workflow/status/batchar2/fptn/main.yml?style=for-the-badge&logo=github-actions&logoColor=white&label=Build&labelColor=2088FF)](https://github.com/batchar2/fptn/actions/workflows/main.yml)
[![GitHub All Releases](https://img.shields.io/github/downloads/batchar2/fptn/total.svg?style=for-the-badge&logo=github&logoColor=white&label=Downloads&labelColor=181717)](https://github.com/batchar2/fptn/releases)
</div>

---

### Основные возможности FPTN


FPTN — это VPN-технология, созданная с нуля для безопасного и устойчивого к блокировкам соединения, позволяющего обходить цензуру и сетевую фильтрацию.

Сайт проекта: [https://storage.googleapis.com/fptn.org/index.html](https://storage.googleapis.com/fptn.org/index.html)

Основные возможности включают:

1. **L3-туннель (IP-уровень)**
  - Передача IP-пакетов (IPv4 и IPv6) через VPN-туннель до сервера.
  - Поддержка **split-tunneling** — возможность направлять через VPN только определённый трафик, а остальной трафик идёт напрямую. Позволяет гибко настраивать политику маршрутизации на основе указания правил для доменов и сетей.
  - На серверной стороне реализован **NAT**. В дальнейшем планируется поддержка объединения пользователей в группы с созданием виртуальных локальных сетей для совместного взаимодействия.

2. **Маскировка трафика и обход блокировок**
  - **Устойчивость к активному DPI**: сервер способен идентифицировать клиентов по TLS-handshake, анализируя session_id (значение которого умеет устанавливать FPTN-клиент по специальному методу от времени). Если определяется, что клиент не является FPTN-клиентом, сервер возвращает легитимный контент запрашиваемого домена, выступая в роли прозрачного прокси.
  - VPN-соединение маскируется под обычный HTTPS-трафик (еще в разработке — режим короткоживущих HTTPS-соединений).
  - Реализованы три метода обхода блокировок:
    1. **Подмена SNI**: в инициирующем соединение TLS-пакете устанавливается поддельный домен. Системы анализа трафика видят легитимное соединение, а на самом деле трафик направляется на VPN-сервер.
    2. **Обфускация**: трафик выглядит как уже установленная TLS-сессия, скрывая TLS-handshake и предотвращая детектирование DPI.
    3. **Reality Mode + SNI**: клиент инициирует соединение с VPN-сервером с подменой SNI, получает реальный TLS-handshake от настоящего сайта, после чего в том же соединении продолжается обмен данными с VPN-сервером.
  - В десктопной версии клиента реализован `сканнер SNI`.

3. **Транспортный протокол**
  - Используется собственный транспортный протокол на основе **Protobuf** для передачи данных между клиентом и сервером.
  - **Padding на уровне протокола**: пакеты данных дополняются случайными данными для рандомизации трафика и затруднения анализа.
  - Сервер предоставляет **REST API** для авторизации клиентов и получения специальных настроек.

4. **Специальные возможности**
  - Встроенная фильтрация нежелательного трафика (например, протокол BitTorrent).
  - Контроль скорости и трафика каждого пользователя: сервер включает шейпер на основе алгоритма **Leaky Bucket**, что позволяет гибко настраивать политику скорости.
  - Поддержка многосерверной архитектуры с одним мастер-сервером, где хранится вся информация о пользователях.
  - Мониторинг работы системы через **Prometheus** и визуализация в **Grafana**.
  - Возможность подключения пользователей через **Telegram-бота**.

5. **Кроссплатформенные клиенты**
  - Разработана кроссплатформенная библиотека **`libfptn`**, которая может использоваться на различных операционных системах. Внутри реализованы сетевой протокол FPTN, управление соединением и механизмы передачи данных через VPN-туннель.
  - **Десктоп:** Windows, macOS, Linux — минималистичный клиент с акцентом на простоту использования.
  - **Мобильные устройства:** Android, iOS (в разработке).

6. **Простая настройка через токен**
  - **Токен** — это специально сгенерированный конфигурационный файл, который содержит все необходимые настройки системы.
  - Позволяет подключаться к VPN без ручной конфигурации и лишних действий: достаточно добавить токен в клиент, чтобы начать работу.

---

### Демонстрация работы

*🍏🍎Пользователям MacOS рекомендуется ознакомиться с [руководством по установке для macOS](docs/macos/README.md), так как в macOS присутствуют дополнительные меры безопасности, которые могут потребовать особых действий.*

Скачайте клиент FPTN с [веб-сайта](http://batchar2.github.io/fptn/) или [GitHub](https://github.com/batchar2/fptn/releases). После скачивания установите и запустите клиент.

Клиент представляет собой компактное приложение, значок которого находится в системном трее.

Просто нажмите на значок, чтобы открыть контекстное меню.

<img style="max-height: 100px" class="img-center" src="docs/images/macos/ru/client.png" alt="Приложение"/>

Перейдите в меню "Настройки", где необходимо добавить токен доступа.
Получите токен, обратившись к нашему <a target="_blank" href="https://t.me/fptn_bot">Telegram-боту</a>,

<img style="max-height: 200px" class="img-center" src="docs/images/telegram_token_ru.png" alt="Настройки"/>

Скопируйте токен, нажмите кнопку "Добавить токен", вставьте его в форму и сохраните.

<img style="max-height: 250px" class="img-center" src="docs/images/macos/ru/settings-2.png" alt="Настройки"/>

После этого в списке появятся доступные серверы.

<img style="max-height: 250px" class="img-center" src="docs/images/macos/ru/settings-3.png" alt="Настройки"/>

Простота использования:

<img style="max-height: 250px" class="img-center" src="docs/images/macos/ru/running-client.png" alt="Настройки"/>

Вы также можете легко превратить свой Raspberry Pi или Orange Pi в точку доступа WiFi и установить на него клиент FPTN.
В этом случае все устройства, подключенные к этой WiFi-сети, смогут выходить в интернет, обходя любые ограничения.
[Подробнее читайте здесь](https://github.com/batchar2/fptn/blob/master/deploy/linux/wifi/README.md)

<img style="max-height: 350px" class="img-center" src="docs/images/orangepi.jpg" alt="Настройки"/>


---

### Установка, сборка и настройка


<details>
  <summary><strong>Установка и настройка FPTN сервера</strong></summary>

Настройка и запуск собственного сервера FPTN выполняются через Docker.  
Это обеспечивает простое развертывание, удобное обновление и изоляцию окружения.
Инструкция доступна в [DockerHub](https://hub.docker.com/r/fptnvpn/fptn-vpn-server).

Так же вы можете развернуть собственные инструменты для управления и мониторинга:
- **Telegram-бот** — выдача токенов пользователям [sysadmin-tools/telegram-bot/README.md](sysadmin-tools/telegram-bot/README.md).
- **Grafana + Prometheus** — мониторинг состояния серверов и пользователей   [sysadmin-tools/grafana/README.md](sysadmin-tools/grafana/README.md)

</details>




<details>
  <summary><strong>Установка FPTN на роутер с OpenWrt</strong></summary>

В пакет для роутера входят клиент, сервис автозапуска и страница в веб-интерфейсе. Через VPN идет вся сеть целиком, на телефоны и ноутбуки ставить ничего не нужно.

Поддерживаются две ветки OpenWrt. Они отличаются пакетным менеджером, поэтому отличается и файл:

| Ветка | Пакетный менеджер | Файл |
|---|---|---|
| 25.12.x | apk | `.apk` |
| 24.10.x | opkg | `.ipk` |

Значение имеет не конкретная модель, а архитектура пакетов: один пакет подходит всем устройствам с такой же архитектурой.

| Архитектура пакетов | Цели OpenWrt | Примеры устройств |
|---|---|---|
| `aarch64_generic` | armsr/armv8, rockchip/armv8 | виртуальные машины, NanoPi R2S / R4S / R5S |
| `aarch64_cortex-a53` | mediatek/filogic, qualcommax/ipq807x | Xiaomi AX3000T, Cudy TR3000, Xiaomi AX3600 / AX9000 |
| `arm_cortex-a7_neon-vfpv4` | ipq40xx | GL.iNet GL-A1300 Slate Plus, GL-B1300, ZyXEL NBG6617 |
| `x86_64` | x86/64 | мини-ПК, виртуальные машины, Proxmox |

Спросите у роутера, что ему нужно:

```bash
apk --print-arch
```

На 24.10 вместо этого `opkg print-architecture`.

И ветка, и архитектура есть в имени файла, поэтому возьмите подходящий из [релизов](https://github.com/batchar2/fptn/releases) — например, `fptn-client-0.4.4-openwrt-25.12.x-aarch64_generic.apk`. Как собрать пакет самому, описано в разделе *Сборка под OpenWrt*.

Перенесите пакет на роутер и установите. На 25.12:

```bash
scp fptn-client-*.apk root@192.168.1.1:/tmp/
```

```bash
apk add --allow-untrusted /tmp/fptn-client-*.apk
```

На 24.10:

```bash
scp fptn-client-*.ipk root@192.168.1.1:/tmp/
```

```bash
opkg update && opkg install /tmp/fptn-client-*.ipk
```

Во время установки роутеру нужен работающий интернет: `kmod-tun` и `ip-full` тянутся из репозитория OpenWrt.

Остальное установка настраивает сама: создает зону файрвола, которая заворачивает трафик локальной сети в туннель, включает автозапуск сервиса и перезапускает `rpcd`, чтобы появилась страница в веб-интерфейсе.

Откройте в веб-интерфейсе роутера раздел `VPN` → `FPTN`, вставьте токен доступа из [@fptn_bot](https://t.me/fptn_bot), поставьте галку `Enabled` и нажмите `Save & Apply` — сервис запустится сразу. То же самое из консоли:

```bash
uci set fptn.config.access_token='<токен>'; uci set fptn.config.enabled='1'; uci commit fptn; /etc/init.d/fptn restart
```

Если вы администрируете роутер удаленно, впишите свой публичный адрес в `Routing` → `Exclude tunnel networks` (например, `203.0.113.45/32`) **до** подключения. Иначе туннель заберет себе маршрут по умолчанию, ответы вашей сессии уйдут в него, и доступ к роутеру пропадет.

Кнопка `Diagnostics` на странице FPTN проверяет туннель, маршруты, зону файрвола и DNS и показывает, что именно сломано. Полная картина — в системном журнале:

```bash
logread -e fptn -f
```

Удаление пакета останавливает клиент и снимает его с автозапуска:

```bash
apk del fptn-client
```

На 24.10 то же самое делает `opkg remove fptn-client`.

</details>







<details>
  <summary><strong>Сборка под Linux, Windows и macOS</strong></summary>

1. Установите требуемые зависимости
- Для [Windows](deploy/windows/README.md)
- Для [Ubuntu](deploy/linux/deb/README.md)
- Для [macOS](deploy/macos/README.md)

2. Установите Conan (версия 2.24.0):

```bash
pip install conan
```

3. Определите и настройте профиль Conan:

```bash
conan profile detect --force
```

4. Установите зависимости, выполните сборку и установку:

- Linux:

```bash
conan install . --output-folder=build --build=missing -s compiler.cppstd=17 -o with_gui_client=True --settings build_type=Release -c "tools.build:defines=['QT_NO_INT128']"

cd build
cmake .. -DCMAKE_TOOLCHAIN_FILE=conan_toolchain.cmake -DCMAKE_BUILD_TYPE=Release
cmake --build . --config Release
ctest
```

- macOS:

```bash
conan install . --output-folder=build --build=missing -s compiler.cppstd=17 -o with_gui_client=True --settings build_type=Release

cd build
cmake .. -DCMAKE_TOOLCHAIN_FILE=conan_toolchain.cmake -DCMAKE_BUILD_TYPE=Release
cmake --build . --config Release
ctest
```

- Windows:

```bash
conan install . --output-folder=build --build=missing -s compiler.cppstd=17 -o with_gui_client=True --settings build_type=Release

cd build
cmake .. -G "Visual Studio 17 2022" -DCMAKE_TOOLCHAIN_FILE="conan_toolchain.cmake" -DCMAKE_BUILD_TYPE=Release
cmake --build . --config Release
ctest
```

5. Сборка установщика
  - Windows
    
    ```bash
    cmake --build . --config Release --target build-installer
    ```
    
  - Ubuntu
    
    ```bash
    cmake --build . --config Release --target build-deb-gui
    ```
    
  - macOS
  
    ```bash
    cmake --build . --target build-pkg
    ```

</details>




<details>
  <summary><strong>Сборка под OpenWrt</strong></summary>

Клиент для роутера кросс-компилируется в докере: в образе лежит OpenWrt SDK, сборка собирает CLI-клиент и упаковывает его вместе с procd-сервисом и страницей LuCI в один пакет. На хосте, кроме самого докера, ничего ставить не нужно. Установка и работа с готовым пакетом описаны в разделе *Установка FPTN на роутер с OpenWrt*.

Докерфайлы разложены по каталогам `deploy/openwrt/target-<архитектура>/<ветка OpenWrt>`. Каталоги 25.12.5 дают `.apk`, каталоги 24.10.7 — `.ipk`:

| Архитектура пакетов | Каталог | Устройства |
|---|---|---|
| `aarch64_generic` | `target-armsr-armv8` | виртуальные машины, NanoPi R2S / R4S / R5S |
| `aarch64_cortex-a53` | `target-mediatek-filogic` | Xiaomi AX3000T, Cudy TR3000, Xiaomi AX3600 / AX9000 |
| `arm_cortex-a7_neon-vfpv4` | `target-ipq40xx` | GL.iNet GL-A1300 Slate Plus, GL-B1300, ZyXEL NBG6617 |
| `x86_64` | `target-x86-64` | мини-ПК, виртуальные машины, Proxmox |

Выполните блок, соответствующий вашему устройству и вашей ветке OpenWrt, — он собирает образ и кладет пакет в текущий каталог.

**OpenWrt 25.12.x, `.apk`**

`aarch64_generic`:

```bash
docker build -t openwrt-armv8-25.12.5 -f ./deploy/openwrt/target-armsr-armv8/25.12.5/Dockerfile .
docker run --rm -v "$PWD:/dst" openwrt-armv8-25.12.5 cp -av /out/. /dst/
```

`aarch64_cortex-a53`:

```bash
docker build -t openwrt-filogic-25.12.5 -f ./deploy/openwrt/target-mediatek-filogic/25.12.5/Dockerfile .
docker run --rm -v "$PWD:/dst" openwrt-filogic-25.12.5 cp -av /out/. /dst/
```

`arm_cortex-a7_neon-vfpv4`:

```bash
docker build -t openwrt-ipq40xx-25.12.5 -f ./deploy/openwrt/target-ipq40xx/25.12.5/Dockerfile .
docker run --rm -v "$PWD:/dst" openwrt-ipq40xx-25.12.5 cp -av /out/. /dst/
```

`x86_64`:

```bash
docker build -t openwrt-x86-64-25.12.5 -f ./deploy/openwrt/target-x86-64/25.12.5/Dockerfile .
docker run --rm -v "$PWD:/dst" openwrt-x86-64-25.12.5 cp -av /out/. /dst/
```

**OpenWrt 24.10.x, `.ipk`**

`aarch64_generic`:

```bash
docker build -t openwrt-armv8-24.10.7 -f ./deploy/openwrt/target-armsr-armv8/24.10.7/Dockerfile .
docker run --rm -v "$PWD:/dst" openwrt-armv8-24.10.7 cp -av /out/. /dst/
```

`aarch64_cortex-a53`:

```bash
docker build -t openwrt-filogic-24.10.7 -f ./deploy/openwrt/target-mediatek-filogic/24.10.7/Dockerfile .
docker run --rm -v "$PWD:/dst" openwrt-filogic-24.10.7 cp -av /out/. /dst/
```

`arm_cortex-a7_neon-vfpv4`:

```bash
docker build -t openwrt-ipq40xx-24.10.7 -f ./deploy/openwrt/target-ipq40xx/24.10.7/Dockerfile .
docker run --rm -v "$PWD:/dst" openwrt-ipq40xx-24.10.7 cp -av /out/. /dst/
```

`x86_64`:

```bash
docker build -t openwrt-x86-64-24.10.7 -f ./deploy/openwrt/target-x86-64/24.10.7/Dockerfile .
docker run --rm -v "$PWD:/dst" openwrt-x86-64-24.10.7 cp -av /out/. /dst/
```

У каждой комбинации свой тег образа, поэтому сборки не затирают друг друга.

Образы SDK существуют только под `linux/amd64`, поэтому на Apple Silicon сборка идет через эмуляцию. Первый запуск занимает около часа: зависимости собираются из исходников, дальше они кешируются в слоях образа.

Без указания версии пакет получает номер `0.0.0`. Для релизной сборки передайте ее явно:

```bash
docker build --build-arg PKG_VERSION=0.4.4 -t openwrt-armv8-25.12.5 -f ./deploy/openwrt/target-armsr-armv8/25.12.5/Dockerfile .
```

Все, что попадает в пакет, лежит в `deploy/openwrt/data`: UCI-конфиг, procd-сервис, страница LuCI и скрипты упаковки для обоих форматов. Для другой архитектуры скопируйте один из каталогов `target-*` и поправьте тег базового образа, `TOOLCHAIN_DIR`, `CROSS_PREFIX`, `CONAN_ARCH` и `PKG_ARCH`. Имя каталога тулчейна можно посмотреть в самом образе SDK:

```bash
docker run --rm openwrt/sdk:mediatek-filogic-25.12.5 ls /builder/staging_dir
```

</details>

<details>
  <summary><strong>Использование CLion IDE для разработки</strong></summary>

Выполните следующую команду в корневой папке проекта:

```bash
conan install . --output-folder=cmake-build-debug --build=missing -s compiler.cppstd=17 -o with_gui_client=True --settings build_type=Debug
```

Откройте проект в CLion. После открытия автоматически появится окно **Open Project Wizard**. В нём необходимо добавить следующий параметр CMake:


```bash
-DCMAKE_TOOLCHAIN_FILE=conan_toolchain.cmake
```

</details>

---

### О проекте

FPTN развивается командой волонтёров и независимых разработчиков.

Если вы хотите поддержать проект, вы можете оформить донат на [Boosty](https://boosty.to/fptn). Спонсорам проекта снимаем ограничения скорости на наших серверах и (по желанию) публикуем их ники в FPTN-клиентах.

Наш Telegram-чат для пользователей и разработчиков [FPTN Project](https://t.me/fptn_project)

Присоединяйтесь к сообществу и команде разработчиков!

---

## Инструменты сообщества

Следующие инструменты разработаны и поддерживаются сообществом для расширения возможностей или упрощения работы с FPTN.

### fptn-manager ⚠️ Не поддерживается

> Этот инструмент давно не обновлялся и может не работать с текущей версией FPTN.
> Для установки и управления сервером используйте официальную инструкцию на [DockerHub](https://hub.docker.com/r/fptnvpn/fptn-vpn-server).

Небольшой внешний инструмент управления, построенный вокруг FPTN и ориентированный на упрощение развёртывания и повседневных административных задач.

Возможности:
- Установщик на базе Docker
- Интерактивный CLI для управления пользователями, паролями и токенами
- Упрощённая первичная настройка и повторяющиеся операции

Репозиторий проекта: https://github.com/FarazFe/fptn-manager
