use std::{path::PathBuf, sync::Arc};

use anyhow::Result;
use clap::{Parser, Subcommand};
use serde_json::Value;

use crate::{
    autostart,
    background::{self, Client},
    config::{Store, default_config_path},
    desktop, journal, launcher,
};

#[derive(Parser)]
#[command(
    name = "krot",
    version,
    about = "КРОТ — оконный менеджер SSH-туннелей в терминальном стиле"
)]
struct Args {
    #[arg(long,global=true,value_name="FILE",default_value_os_t=default_config_path())]
    config: PathBuf,
    #[arg(long, help = "Пропустить заставку восстановления")]
    no_splash: bool,
    #[command(subcommand)]
    command: Option<Command>,
    #[arg(long, hide = true)]
    reuse_running: bool,
    #[arg(long, hide = true)]
    skip_update_check: bool,
    #[arg(long, hide = true)]
    update_ready: Option<PathBuf>,
}

#[derive(Subcommand)]
enum Command {
    /// Показать сохранённые туннели без SSH-подключений
    List,
    /// Проверить JSON-конфигурацию без SSH-подключений
    Check,
    /// Показать путь конфигурации
    Path,
    /// Проверить доступность SSH-сервера из текущей сети без входа на него
    Diagnose {
        /// ID или имя туннеля (проверяется его первый узел) либо host[:port]
        target: String,
        /// Отчёт в JSON
        #[arg(long)]
        json: bool,
        /// Скрыть узел, IP-адреса и отпечаток ключа, чтобы приложить отчёт к задаче
        #[arg(long)]
        redact: bool,
        /// Не проверять контрольные узлы
        #[arg(long)]
        no_control: bool,
        /// Не спрашивать DoH-провайдеров (имя сервера не уходит к Cloudflare и Google)
        #[arg(long)]
        no_doh: bool,
        /// Российский контрольный узел вместо встроенных; можно повторять
        #[arg(long, value_name = "URL")]
        control_domestic: Vec<String>,
        /// Зарубежный контрольный узел вместо встроенных; можно повторять
        #[arg(long, value_name = "URL")]
        control_foreign: Vec<String>,
    },
    /// Запустить туннели в фоне без окна
    Background,
    /// Показать состояние фоновых туннелей
    Status,
    /// Метрики UDP туннелей и правил в JSON
    Metrics {
        /// Только этот туннель и его правила
        #[arg(long)]
        tunnel: Option<String>,
    },
    /// Показать путь файла журнала фонового процесса и помощника перехвата
    Diagnostics,
    /// Измерить скорость или стабильность работающего туннеля
    Test {
        /// ID или имя туннеля
        tunnel: String,
        /// Тест стабильности заданной длительности вместо теста скорости: 10m, 30m, 1h
        #[arg(long, value_name = "ВРЕМЯ")]
        stability: Option<String>,
        /// Лимит объёма в каждую сторону, МБ (по умолчанию 100)
        #[arg(long, value_name = "МБ")]
        limit: Option<u64>,
        /// Отчёт в JSON
        #[arg(long)]
        json: bool,
    },
    /// Остановить фон и все туннели, сохранив выбор для следующего запуска
    Stop,
    /// Автозапуск после входа в учётную запись
    Autostart {
        #[arg(default_value="status",value_parser=["enable","disable","status"])]
        action: String,
    },
    #[command(hide = true)]
    Serve,
    /// Перехват трафика приложений; запускается с правами администратора
    #[command(hide = true)]
    Divert {
        /// SID пользователя, для которого запомнить права в планировщике Windows
        #[arg(long)]
        remember: Option<String>,
    },
    /// Перехват приложений без запроса прав администратора при каждом запуске (Windows)
    Elevation {
        #[arg(default_value="status",value_parser=["enable","disable","status"])]
        action: String,
    },
    #[command(hide = true)]
    ApplyUpdate { manifest: PathBuf },
}

#[cfg(windows)]
fn disable_stdio_inheritance() -> Result<()> {
    use windows_sys::Win32::{
        Foundation::{HANDLE_FLAG_INHERIT, INVALID_HANDLE_VALUE, SetHandleInformation},
        System::Console::{GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE},
    };
    // Detached children must not keep a caller's redirected pipes open.
    for stream in [STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE] {
        let handle = unsafe { GetStdHandle(stream) };
        if !handle.is_null()
            && handle != INVALID_HANDLE_VALUE
            && unsafe { SetHandleInformation(handle, HANDLE_FLAG_INHERIT, 0) } == 0
        {
            anyhow::bail!(
                "Не удалось настроить ввод и вывод: {}",
                std::io::Error::last_os_error()
            );
        }
    }
    Ok(())
}

pub fn run() -> Result<()> {
    #[cfg(windows)]
    disable_stdio_inheritance()?;
    let args = Args::parse();
    let runtime = Arc::new(
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?,
    );
    let gui = args.update_ready.is_none()
        && (args.command.is_none() || matches!(args.command, Some(Command::ApplyUpdate { .. })));
    let result = (|| {
        anyhow::ensure!(
            args.update_ready.is_none() || (args.command.is_none() && !args.reuse_running),
            "Подтверждение обновления допустимо только при новом запуске окна."
        );
        let store = Store::new(&args.config)?;
        match args.command {
            Some(Command::List) => {
                let config = store.load()?;
                if config.tunnels.is_empty() { println!("Туннели ещё не созданы. Откройте приложение КРОТ и нажмите «Новый туннель»."); }
                for tunnel in config.tunnels {
                    let chain: Vec<_> = tunnel.jumps.iter().filter(|_| tunnel.jumps_enabled).chain(std::iter::once(&tunnel.server)).map(|e| e.address()).collect();
                    println!("{}\t{}\n  SSH: {}", tunnel.name,tunnel.route(),chain.join(" → "));
                }
                Ok(())
            }
            Some(Command::Check) => { let config = store.load()?; println!("Конфигурация корректна. Туннелей: {}. SSH не запускается.",config.tunnels.len()); Ok(()) }
            Some(Command::Path) => { println!("{}",store.path.display()); Ok(()) }
            Some(Command::Serve) => {
                journal::init(journal::background_path(&store));
                // The start is recorded by the process once it owns the configuration.
                let result = runtime.block_on(background::serve(store));
                journal::finished("Фоновый процесс", &result);
                result
            }
            // The elevated helper writes no file: its events reach the background journal.
            Some(Command::Divert { remember }) => crate::divert::run(store, remember),
            Some(Command::Diagnostics) => {
                let path = journal::background_path(&store);
                println!("Журнал фонового процесса и помощника перехвата: {}", path.display());
                for part in [path.clone(), journal::rotated_path(&path)] {
                    match std::fs::metadata(&part) {
                        Ok(metadata) => println!("  {} — {} КиБ", part.display(), metadata.len().div_ceil(1024)),
                        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                            if part == path { println!("  ещё не создан"); }
                        }
                        Err(error) => println!("  {}: {error}", part.display()),
                    }
                }
                println!("Пароли, парольные фразы и ключи в журнал не записываются, а имена и адреса серверов и ID туннелей записываются: удалите их перед публикацией, если они личные.");
                Ok(())
            }
            Some(Command::Elevation { action }) => {
                use crate::tasks::{Kind, registered, remembering, set_remembering};
                #[cfg(not(windows))]
                anyhow::ensure!(action == "status", "Перехват трафика приложений работает только в Windows.");
                match action.as_str() {
                    "enable" => {
                        set_remembering(&store.path, true)?;
                        #[cfg(windows)]
                        if crate::tasks::elevated() { crate::tasks::register(&store.path, Kind::Divert)?; }
                        else { println!("Права запомнятся при следующем подтверждении запроса Windows («Предоставить права…»)."); }
                    }
                    "disable" => {
                        // The task goes first: if Windows refuses to delete it, remembering stays
                        // on and the status keeps telling that the task still gives the rights.
                        #[cfg(windows)]
                        // A Task Scheduler that cannot be read has no task to remove.
                        if let Err(error) = crate::tasks::unregister(&store.path, Kind::Divert, true)
                            && registered(&store.path, Kind::Divert, true).unwrap_or(false)
                        {
                            return Err(error);
                        }
                        set_remembering(&store.path, false)?;
                    }
                    _ => {}
                }
                // A Task Scheduler that cannot be read gives no rights either: the status is
                // "off", not a failure of the command.
                let enabled = remembering(&store.path) && registered(&store.path, Kind::Divert, false).unwrap_or(false);
                println!("Перехват без запроса прав: {}.", if enabled {"включён"} else {"выключен"});
                if !enabled && registered(&store.path, Kind::Divert, true).unwrap_or(false) {
                    println!("Задание планировщика с правами администратора осталось. Удалите его: krot-cli elevation disable.");
                }
                Ok(())
            }
            Some(Command::ApplyUpdate { manifest }) => runtime.block_on(crate::update::apply_install(&manifest)),
            Some(Command::Autostart {action}) => {
                if action != "status" { store.load()?; autostart::set_enabled(&store.path,action == "enable")?; }
                println!("Автозапуск после входа: {}.",if autostart::is_enabled(&store.path)? {"включён"} else {"выключен"});
                Ok(())
            }
            Some(Command::Diagnose { target, json, redact, no_control, no_doh, control_domestic, control_foreign }) => {
                use crate::diagnose;
                // A broken configuration does not prevent checking an explicit host[:port].
                let tunnels = store.load().map(|config| config.tunnels).unwrap_or_default();
                let target = diagnose::Target::resolve(&target, &tunnels)?;
                let mut options = diagnose::Options::new(store.known_hosts_path());
                if !control_domestic.is_empty() { options.control_domestic = control_domestic; }
                if !control_foreign.is_empty() { options.control_foreign = control_foreign; }
                if no_control { options.control_domestic.clear(); options.control_foreign.clear(); }
                options.doh = !no_doh;
                let cancel = tokio_util::sync::CancellationToken::new();
                let interrupt = cancel.clone();
                runtime.spawn(async move { if tokio::signal::ctrl_c().await.is_ok() { interrupt.cancel(); } });
                let mut report = runtime.block_on(diagnose::run(target, options, cancel));
                if redact { diagnose::redact(&mut report); }
                if json { println!("{}", serde_json::to_string_pretty(&report)?); } else { print!("{}", diagnose::render(&report)); }
                Ok(())
            }
            Some(Command::Metrics { tunnel }) => runtime.block_on(async {
                anyhow::ensure!(store.sidecar(".background.json").exists(), "Фоновый КРОТ не запущен.");
                let snapshot = Client::new(&store).snapshot().await?;
                println!("{}", serde_json::to_string_pretty(&crate::udp::report::metrics(&snapshot, tunnel.as_deref()))?);
                Ok(())
            }),
            Some(Command::Test { tunnel, stability, limit, json }) => {
                runtime.block_on(crate::quality::cli::run(&store, &tunnel, stability, limit, json))
            }
            Some(command @ (Command::Background | Command::Status | Command::Stop)) => runtime.block_on(async {
                if !matches!(command,Command::Background) && !store.sidecar(".background.json").exists() { println!("Фоновый КРОТ не запущен."); return Ok(()); }
                let client = if matches!(command,Command::Background) { background::ensure_running(&store).await? } else { Client::new(&store) };
                let reply = if matches!(command,Command::Stop) { client.request("shutdown",Value::Null).await.map(|_| None) }
                    else { client.snapshot().await.map(Some) };
                let snapshot = match reply {
                    // A killed daemon leaves its address but holds no lease.
                    Err(error) if error.downcast_ref::<std::io::Error>().is_some_and(|cause| cause.kind() == std::io::ErrorKind::ConnectionRefused)
                        && background::try_lease(&store)?.is_some() => { println!("Фоновый КРОТ не запущен."); return Ok(()); }
                    reply => reply?,
                };
                if let Some(snapshot) = snapshot {
                    println!("КРОТ работает в фоне.");
                    for tunnel in snapshot.config.tunnels {
                        let status = if snapshot.prompts.contains_key(&tunnel.id) {"ждёт вашего участия"}
                        else { match snapshot.runtimes.get(&tunnel.id).map(|r|r.state.as_str()).unwrap_or("idle") {
                            "running"=>"работает","connecting"=>"подключение","reconnecting"=>"восстановление","error"=>"ошибка","stopped"=>"остановлен",_=>"выключен",
                        }};
                        println!("{}\t{}",tunnel.name,status);
                        if let Some(udp) = snapshot.udp_runtimes.get(&tunnel.id).filter(|udp| !udp.state.is_empty() && udp.state != "off") {
                            println!("  UDP: {}", crate::udp::state_text(udp));
                        }
                    }
                } else {
                    println!("КРОТ остановлен. Все туннели закрыты; выбор для следующего запуска сохранён.");
                }
                Ok(())
            }),
            None => launcher::run(store, runtime.clone(), args.no_splash,
                args.reuse_running, !args.skip_update_check, args.update_ready),
        }
    })();
    if gui && let Err(ref error) = result {
        let _ = desktop::show_error(format!("Не удалось открыть КРОТ.\n\n{error:#}"));
    }
    result
}

pub async fn open_desktop(store: &Store) -> Result<()> {
    let current = std::env::current_exe()?;
    let executable = match current.file_name().and_then(|name| name.to_str()) {
        Some("krot-cli.exe") => current.with_file_name("krot.exe"),
        Some("krot-cli") => current.with_file_name("krot"),
        _ => current,
    };
    let mut child = tokio::process::Command::new(executable)
        .arg("--config")
        .arg(&store.path)
        .arg("--no-splash")
        .arg("--reuse-running")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()?;
    tokio::spawn(async move {
        let _ = child.wait().await;
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn recovery_and_tray_arguments_are_explicit_hidden_commands() {
        for args in [
            vec!["krot", "--reuse-running"],
            vec!["krot", "--skip-update-check"],
            vec!["krot", "--update-ready", "/tmp/ready.json"],
            vec!["krot", "apply-update", "/tmp/manifest.json"],
        ] {
            assert!(Args::try_parse_from(args).is_ok());
        }
        let help = Args::command().render_help().to_string();
        assert!(!help.contains("reuse-running"));
        assert!(!help.contains("skip-update-check"));
        assert!(!help.contains("apply-update"));
        assert!(!help.contains("update-ready"));
    }
}
