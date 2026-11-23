# Участие в проекте

Сообщения об ошибках, предложения и pull request принимаются в [GitHub](https://github.com/Dudod1n/KPOT). Для существенного изменения сначала откройте issue с задачей и ожидаемым поведением.

## Подготовка окружения

Нужны Git и Rust 1.90 или новее. Python 3.11 или новее используется только для интеграционных проверок и подготовки ресурсов; приложение от него не зависит.

```sh
git clone https://github.com/Dudod1n/KPOT.git
cd KPOT
git switch dev
cargo build --locked --bins
```

Для тестов SSH создайте виртуальное окружение и установите зависимости:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-test.txt
```

В PowerShell используйте `py -3 -m venv .venv` и `.\.venv\Scripts\python.exe` вместо `.venv/bin/python`.

В Debian/Ubuntu для создания окружения может потребоваться пакет `python3-venv`.

На Linux нужна графическая сессия X11/Wayland для окна; для отдельной проверки трея — `dbus-run-session`. Проверка SSH-agent использует команды `ssh-agent` и `ssh-add` из OpenSSH, если они доступны.

## Проверки

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo build --locked --bins
python scripts/build_icons.py --check
python scripts/build_mascot.py --check
python -m unittest discover -s tests -p 'test_*.py' -v
python scripts/check_rust.py -v
```

Выполняйте команды Python из виртуального окружения. `scripts/check_rust.py` запускает временные SSH-серверы AsyncSSH на loopback-адресах и проверяет собранный `target/debug/krot-cli`. Для другого бинарника задайте переменную `KROT_RUST_BIN`.

Сценарии охватывают L/R/D, два jump-хоста, пароль, зашифрованный ключ, SSH-agent, смену ключа узла, переподключение, отмену, восстановление, локальный протокол и освобождение соединений. Пользовательские настройки и SSH-серверы для них не нужны. Проверка агента пропускается на Windows и при отсутствии OpenSSH.

### Серверный помощник UDP

`proto/` — формат кадров UDP-канала и общие метрики, `relay/` — серверный помощник `krot-relay` (только Linux, без tokio). Клиент встраивает статические сборки помощника для `x86_64` и `aarch64` из каталога `KROT_RELAY_DIR` (файлы `krot-relay-x86_64` и `krot-relay-aarch64`) и считает их SHA-256 при сборке. Без этой переменной клиент собирается без помощника; CI и выпуск задают `KROT_REQUIRE_RELAY=1`, и тогда сборка без обоих файлов завершается ошибкой.

```sh
rustup target add x86_64-unknown-linux-musl aarch64-unknown-linux-musl
mkdir -p relay-bin
cargo build --locked -p krot-relay --profile relay --target x86_64-unknown-linux-musl
CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=rust-lld \
  cargo build --locked -p krot-relay --profile relay --target aarch64-unknown-linux-musl
cp target/x86_64-unknown-linux-musl/relay/krot-relay relay-bin/krot-relay-x86_64
cp target/aarch64-unknown-linux-musl/relay/krot-relay relay-bin/krot-relay-aarch64
KROT_RELAY_DIR="$PWD/relay-bin" KROT_REQUIRE_RELAY=1 cargo build --locked --bins
```

Тесты помощника под `aarch64` запускаются через `qemu-user`: задайте `CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_RUNNER=qemu-aarch64` и `KROT_RELAY_RUNNER=qemu-aarch64`.

Linux-тест трея запускается отдельно на изолированной D-Bus шине:

```sh
dbus-run-session -- cargo test --locked --test tray_linux -- --ignored
```

## Устройство кода

SSH и обращения к фоновому процессу выполняются вне потока окна. Формат конфигурации и локальный протокол требуют совместимости между окном, CLI и фоновым процессом.

## Изменения и pull request

- Порядок работы — GitHub Flow: ветка от `dev` → коммиты и push → PR в `dev` → ревью по [REVIEW.md](REVIEW.md) и CI → слияние. Формат веток, коммитов и заголовков PR описан в [AGENTS.md](AGENTS.md#порядок-работы), выпуск — в [руководстве по релизам](docs/RELEASING.md).
- Для изменения поведения добавляйте проверку результата.
- Сохраняйте защиту паролей, проверку ключей узлов, атомарную запись и освобождение сетевых ресурсов.
- Пользовательские изменения и исправления добавляйте в раздел «Не выпущено» (создайте его при необходимости) файла [CHANGELOG.md](CHANGELOG.md).

Иконки воспроизводятся командой `python scripts/build_icons.py`, маскот для медиа в `assets/mascot` — командой `python scripts/build_mascot.py`; маскот берёт каску и очки из иконки. Если изменили генератор, обновите ресурсы и выполните проверку с `--check`.

## Лицензия

Вклад в код проекта принимается по GNU GPL версии 3, `GPL-3.0-only`. Добавляйте только код и ресурсы, которые вы вправе распространять на совместимых условиях. Уведомления и лицензии зависимостей сохраняйте; порядок подготовки релиза описан в [docs/RELEASING.md](docs/RELEASING.md).
