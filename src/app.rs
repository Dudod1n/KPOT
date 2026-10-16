use std::{path::PathBuf, sync::Arc};

use anyhow::Result;
use clap::{Parser, Subcommand};
use serde_json::Value;

use crate::{
    autostart,
    background::{self, Client},
    config::{Store, default_config_path},
    desktop, launcher,
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
    /// Запустить туннели в фоне без окна
    Background,
    /// Показать состояние фоновых туннелей
    Status,
    /// Остановить фон и все туннели, сохранив выбор для следующего запуска
    Stop,
    /// Автозапуск после входа в учётную запись
    Autostart {
        #[arg(default_value="status",value_parser=["enable","disable","status"])]
        action: String,
    },
    #[command(hide = true)]
    Serve,
    #[command(hide = true)]
    ApplyUpdate { manifest: PathBuf },
}

pub fn run() -> Result<()> {
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
            Some(Command::Serve) => runtime.block_on(background::serve(store)),
            Some(Command::ApplyUpdate { manifest }) => runtime.block_on(crate::update::apply_install(&manifest)),
            Some(Command::Autostart {action}) => {
                if action != "status" { store.load()?; autostart::set_enabled(&store.path,action == "enable")?; }
                println!("Автозапуск после входа: {}.",if autostart::is_enabled(&store.path)? {"включён"} else {"выключен"});
                Ok(())
            }
            Some(command @ (Command::Background | Command::Status | Command::Stop)) => runtime.block_on(async {
                if !matches!(command,Command::Background) && !store.sidecar(".background.json").exists() { println!("Фоновый КРОТ не запущен."); return Ok(()); }
                let client = if matches!(command,Command::Background) { background::ensure_running(&store).await? } else { Client::new(&store) };
                if matches!(command,Command::Stop) {
                    client.request("shutdown",Value::Null).await?;
                    println!("КРОТ остановлен. Все туннели закрыты; выбор для следующего запуска сохранён.");
                } else {
                    let snapshot = client.snapshot().await?;
                    println!("КРОТ работает в фоне.");
                    for tunnel in snapshot.config.tunnels {
                        let status = if snapshot.prompts.contains_key(&tunnel.id) {"ждёт вашего участия"}
                        else { match snapshot.runtimes.get(&tunnel.id).map(|r|r.state.as_str()).unwrap_or("idle") {
                            "running"=>"работает","connecting"=>"подключение","reconnecting"=>"восстановление","error"=>"ошибка","stopped"=>"остановлен",_=>"выключен",
                        }};
                        println!("{}\t{}",tunnel.name,status);
                    }
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
