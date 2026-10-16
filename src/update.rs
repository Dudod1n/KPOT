//! Consent-driven updates from the fixed GitHub repository.
use crate::config::{Store, atomic_json, restrict_access};
use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::Duration,
};

const LATEST: &str = "https://api.github.com/repos/Dudod1n/KPOT/releases/latest";
const MAX_METADATA: usize = 1024 * 1024;
const MAX_ASSET: u64 = 256 * 1024 * 1024;
const LOCK_TIMEOUT: Duration = Duration::from_secs(45);

#[derive(Clone, Debug)]
pub struct Release {
    pub version: String,
    assets: Vec<Asset>,
}
#[derive(Clone, Debug, Deserialize)]
struct Asset {
    name: String,
    browser_download_url: String,
    size: u64,
    digest: Option<String>,
}
impl Release {
    #[cfg(test)]
    pub(crate) fn for_test(version: &str) -> Self {
        Self {
            version: version.into(),
            assets: vec![],
        }
    }
}
#[derive(Deserialize)]
struct GithubRelease {
    tag_name: String,
    draft: bool,
    prerelease: bool,
    assets: Vec<Asset>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Preferences {
    skipped_version: String,
}

fn version(value: &str) -> Result<semver::Version> {
    ensure!(value.len() <= 128, "Слишком длинный номер версии.");
    semver::Version::parse(value.strip_prefix('v').unwrap_or(value))
        .context("Некорректный номер версии обновления.")
}
fn parse_release(data: &[u8], current: &str, skip: Option<&str>) -> Result<Option<Release>> {
    ensure!(data.len() <= MAX_METADATA, "Ответ GitHub слишком велик.");
    let raw: GithubRelease = serde_json::from_slice(data).context("Некорректный ответ GitHub.")?;
    if raw.draft || raw.prerelease {
        return Ok(None);
    }
    let candidate = version(&raw.tag_name)?;
    if !candidate.pre.is_empty()
        || !candidate.cmp_precedence(&version(current)?).is_gt()
        || skip == Some(candidate.to_string().as_str())
    {
        return Ok(None);
    }
    ensure!(raw.assets.len() <= 64, "Слишком много файлов в релизе.");
    Ok(Some(Release {
        version: candidate.to_string(),
        assets: raw.assets,
    }))
}
fn skipped(store: &Store) -> Result<Option<String>> {
    let path = store.sidecar(".updates.json");
    let file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let mut data = Vec::new();
    file.take(4097).read_to_end(&mut data)?;
    ensure!(
        data.len() <= 4096,
        "Файл настроек обновления слишком велик."
    );
    let prefs: Preferences = serde_json::from_slice(&data)?;
    Ok(Some(version(&prefs.skipped_version)?.to_string()))
}
pub fn skip_version(store: &Store, value: &str) -> Result<()> {
    atomic_json(
        &store.sidecar(".updates.json"),
        &Preferences {
            skipped_version: version(value)?.to_string(),
        },
        Some(4096),
    )
}
fn trusted_url(url: &reqwest::Url) -> bool {
    if url.scheme() != "https"
        || url.port().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return false;
    }
    match url.host_str() {
        Some("github.com") => url.path().starts_with("/Dudod1n/KPOT/releases/download/"),
        Some("api.github.com") => url.as_str() == LATEST,
        Some(
            "release-assets.githubusercontent.com"
            | "objects.githubusercontent.com"
            | "github-releases.githubusercontent.com",
        ) => true,
        _ => false,
    }
}
fn client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .user_agent(concat!("krot/", env!("CARGO_PKG_VERSION")))
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(180))
        .redirect(reqwest::redirect::Policy::custom(|attempt| {
            if attempt.previous().len() >= 5 || !trusted_url(attempt.url()) {
                attempt.error("Недопустимое перенаправление GitHub.")
            } else {
                attempt.follow()
            }
        }))
        .build()
        .context("Не удалось создать клиент обновления.")
}
async fn bounded_body(mut response: reqwest::Response, limit: usize) -> Result<Vec<u8>> {
    ensure!(
        response
            .content_length()
            .is_none_or(|size| size <= limit as u64),
        "Ответ GitHub слишком велик."
    );
    let mut data = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        ensure!(
            chunk.len() <= limit.saturating_sub(data.len()),
            "Ответ GitHub слишком велик."
        );
        data.extend_from_slice(&chunk);
    }
    Ok(data)
}
async fn fetch_release(
    client: &reqwest::Client,
    endpoint: &str,
    current: &str,
    skip: Option<&str>,
) -> Result<Option<Release>> {
    let response = client
        .get(endpoint)
        .header("Accept", "application/vnd.github+json")
        .timeout(Duration::from_secs(15))
        .send()
        .await?;
    if matches!(response.status().as_u16(), 204 | 404) {
        return Ok(None);
    }
    let data = bounded_body(response.error_for_status()?, MAX_METADATA).await?;
    parse_release(&data, current, skip)
}
pub async fn check(store: &Store) -> Result<Option<Release>> {
    fetch_release(
        &client()?,
        LATEST,
        env!("CARGO_PKG_VERSION"),
        skipped(store)?.as_deref(),
    )
    .await
}
fn asset_digest(asset: &Asset) -> Result<String> {
    ensure!(
        asset.size > 0 && asset.size <= MAX_ASSET,
        "Файл обновления имеет недопустимый размер."
    );
    let url = reqwest::Url::parse(&asset.browser_download_url)?;
    ensure!(
        trusted_url(&url) && url.host_str() == Some("github.com") && url.query().is_none(),
        "Файл обновления находится вне репозитория Dudod1n/KPOT."
    );
    let parts: Vec<_> = url
        .path_segments()
        .context("Некорректный URL файла.")?
        .collect();
    ensure!(
        parts.len() == 6
            && parts[5] == asset.name
            && !asset.name.contains(['/', '\\'])
            && !asset.name.is_empty(),
        "Некорректное имя файла обновления."
    );
    version(parts[4])?;
    let digest = asset
        .digest
        .as_deref()
        .and_then(|digest| digest.strip_prefix("sha256:"))
        .context("GitHub не предоставил SHA-256 файла; установка отменена.")?;
    ensure!(
        digest.len() == 64 && digest.bytes().all(|c| c.is_ascii_hexdigit()),
        "Некорректный SHA-256 файла обновления."
    );
    Ok(digest.to_ascii_lowercase())
}
fn asset_names() -> [&'static str; 2] {
    if cfg!(windows) {
        ["krot-windows-x64.exe", "krot-cli-windows-x64.exe"]
    } else {
        ["krot-linux-x64", "krot-cli-linux-x64"]
    }
}
fn installed_names() -> [&'static str; 2] {
    if cfg!(windows) {
        ["krot.exe", "krot-cli.exe"]
    } else {
        ["krot", "krot-cli"]
    }
}
fn installation_names(executable: &Path) -> Result<[String; 2]> {
    let name = executable
        .file_name()
        .and_then(|name| name.to_str())
        .context("Не удалось определить имя программы.")?;
    let pair = if installed_names().contains(&name) {
        installed_names()
    } else if asset_names().contains(&name) {
        asset_names()
    } else {
        bail!("Обновление поддерживается только для стандартных имён бинарников КРОТ.")
    };
    Ok(pair.map(str::to_owned))
}
#[derive(Debug)]
pub struct PreparedUpdate {
    staging: tempfile::TempDir,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    version: String,
    config: PathBuf,
    names: [String; 2],
    hashes: [String; 2],
    sizes: [u64; 2],
}
fn helper_name() -> &'static str {
    if cfg!(windows) {
        "installer.exe"
    } else {
        "installer"
    }
}
fn executable_permissions(path: &Path) -> Result<()> {
    restrict_access(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}
async fn download(client: &reqwest::Client, asset: &Asset, path: &Path) -> Result<()> {
    asset_digest(asset)?;
    let response = client
        .get(&asset.browser_download_url)
        .send()
        .await?
        .error_for_status()?;
    write_download(response, asset, path).await
}
async fn write_download(mut response: reqwest::Response, asset: &Asset, path: &Path) -> Result<()> {
    let hash = asset_digest(asset)?;
    ensure!(
        response
            .content_length()
            .is_none_or(|size| size == asset.size),
        "Размер скачиваемого файла не совпадает с GitHub."
    );
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    restrict_access(path)?;
    let mut digest = Sha256::new();
    let mut count = 0u64;
    while let Some(chunk) = response.chunk().await? {
        count += chunk.len() as u64;
        ensure!(
            count <= asset.size,
            "Скачанный файл превышает размер из GitHub."
        );
        file.write_all(&chunk)?;
        digest.update(&chunk);
    }
    ensure!(
        count == asset.size && hex::encode(digest.finalize()) == hash,
        "Размер или SHA-256 скачанного файла не совпадает с GitHub; установка отменена."
    );
    file.sync_all()?;
    executable_permissions(path)
}
pub async fn prepare(release: &Release, store: &Store) -> Result<PreparedUpdate> {
    ensure!(
        cfg!(target_arch = "x86_64") && (cfg!(windows) || cfg!(target_os = "linux")),
        "Эта платформа не поддерживает обновление."
    );
    ensure!(
        version(&release.version)?.pre.is_empty(),
        "Предварительные версии не устанавливаются."
    );
    let executable = std::env::current_exe()?.canonicalize()?;
    let names = installation_names(&executable)?;
    let directory = executable
        .parent()
        .context("Не найден каталог программы.")?;
    for name in &names {
        regular_file(&directory.join(name))
            .context("Рядом с программой нужны оба бинарника КРОТ.")?;
    }
    let mut selected = Vec::new();
    for name in asset_names() {
        let matches: Vec<_> = release
            .assets
            .iter()
            .filter(|asset| asset.name == name)
            .collect();
        ensure!(
            matches.len() == 1,
            "В релизе отсутствует единственный файл {name}; установка отменена."
        );
        asset_digest(matches[0])?;
        let url = reqwest::Url::parse(&matches[0].browser_download_url)?;
        ensure!(
            version(url.path_segments().unwrap().nth(4).unwrap())? == version(&release.version)?,
            "Версия файла отличается от версии релиза."
        );
        selected.push(matches[0]);
    }
    let staging = tempfile::Builder::new()
        .prefix(".krot-update-")
        .tempdir_in(directory)
        .context("Нет прав на создание обновления рядом с программой.")?;
    restrict_access(staging.path())?;
    let client = client()?;
    for (index, asset) in selected.iter().enumerate() {
        download(&client, asset, &staging.path().join(format!("new-{index}"))).await?;
    }
    let helper = staging.path().join(helper_name());
    fs::copy(executable, &helper)?;
    executable_permissions(&helper)?;
    let manifest = Manifest {
        version: release.version.clone(),
        config: store.path.clone(),
        names,
        hashes: [asset_digest(selected[0])?, asset_digest(selected[1])?],
        sizes: [selected[0].size, selected[1].size],
    };
    atomic_json(
        &staging.path().join("manifest.json"),
        &manifest,
        Some(16384),
    )?;
    Ok(PreparedUpdate { staging })
}
pub fn launch_installer(prepared: PreparedUpdate) -> Result<()> {
    Command::new(prepared.staging.path().join(helper_name()))
        .arg("apply-update")
        .arg(prepared.staging.path().join("manifest.json"))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .context("Не удалось запустить установщик обновления.")?;
    let _ = prepared.staging.keep();
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn release(tag: &str) -> Vec<u8> {
        serde_json::to_vec(&json!({"tag_name":tag,"draft":false,"prerelease":false,"assets":[]}))
            .unwrap()
    }
    #[test]
    fn release_comparison_is_semantic_and_skip_is_exact() {
        assert!(
            parse_release(&release("v0.10.0"), "0.9.0", None)
                .unwrap()
                .is_some()
        );
        for tag in ["v0.9.0", "0.8.9", "v0.10.0-beta.1"] {
            assert!(
                parse_release(&release(tag), "0.9.0", None)
                    .unwrap()
                    .is_none()
            );
        }
        assert!(
            parse_release(&release("0.10.0"), "0.9.0", Some("0.10.0"))
                .unwrap()
                .is_none()
        );
        assert!(
            parse_release(&release("0.11.0"), "0.9.0", Some("0.10.0"))
                .unwrap()
                .is_some()
        );
    }
    #[test]
    fn invalid_release_metadata_is_rejected() {
        for tag in ["garbage", "../../1.0.0", ""] {
            assert!(parse_release(&release(tag), "0.9.0", None).is_err());
        }
        assert!(parse_release(b"broken", "0.9.0", None).is_err());
        for field in ["draft", "prerelease"] {
            let mut data: serde_json::Value = serde_json::from_slice(&release("1.0.0")).unwrap();
            data[field] = true.into();
            assert!(
                parse_release(&serde_json::to_vec(&data).unwrap(), "0.9.0", None)
                    .unwrap()
                    .is_none()
            );
        }
    }
    #[test]
    fn skip_is_private_sidecar_and_leaves_config_unchanged() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::new(dir.path().join("config.json")).unwrap();
        std::fs::write(&store.path, b"original").unwrap();
        skip_version(&store, "v1.2.3").unwrap();
        assert_eq!(skipped(&store).unwrap().as_deref(), Some("1.2.3"));
        assert_eq!(std::fs::read(&store.path).unwrap(), b"original");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(store.sidecar(".updates.json"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
    }
    #[test]
    fn asset_validation_rejects_foreign_urls_and_bad_hashes() {
        let mut asset = Asset {
            name: "krot-linux-x64".into(),
            browser_download_url:
                "https://github.com/Dudod1n/KPOT/releases/download/v1.0.0/krot-linux-x64".into(),
            size: 10,
            digest: Some(format!("sha256:{}", "a".repeat(64))),
        };
        assert!(asset_digest(&asset).is_ok());
        for url in [
            "http://github.com/Dudod1n/KPOT/releases/download/v1/a",
            "https://evil.test/a",
            "https://github.com/other/KPOT/releases/download/v1/a",
        ] {
            asset.browser_download_url = url.into();
            assert!(asset_digest(&asset).is_err());
        }
    }
}

struct Installation {
    directory: PathBuf,
    staging: PathBuf,
    manifest: Manifest,
}
fn regular_file(path: &Path) -> Result<()> {
    ensure!(
        fs::symlink_metadata(path)?.file_type().is_file(),
        "Ожидался обычный файл без символической ссылки: {}",
        path.display()
    );
    Ok(())
}
fn file_hash(path: &Path, limit: u64) -> Result<(u64, String)> {
    regular_file(path)?;
    let mut file = File::open(path)?;
    let mut digest = Sha256::new();
    let mut size = 0u64;
    let mut buffer = [0u8; 65536];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        size += count as u64;
        ensure!(
            size <= limit,
            "Файл обновления превышает допустимый размер."
        );
        digest.update(&buffer[..count]);
    }
    Ok((size, hex::encode(digest.finalize())))
}
fn validate_install(path: &Path, helper: &Path) -> Result<Installation> {
    ensure!(
        path.is_absolute() && path.file_name() == Some(std::ffi::OsStr::new("manifest.json")),
        "Некорректный путь плана установки."
    );
    regular_file(path)?;
    regular_file(helper)?;
    let staging = path
        .parent()
        .context("Не найден каталог обновления.")?
        .canonicalize()?;
    ensure!(
        path == staging.join("manifest.json")
            && helper == staging.join(helper_name())
            && helper.canonicalize()? == helper,
        "Установщик и план должны находиться в одном каталоге обновления."
    );
    ensure!(
        staging
            .file_name()
            .and_then(|v| v.to_str())
            .is_some_and(|name| name.starts_with(".krot-update-")),
        "Некорректный каталог обновления."
    );
    let directory = staging
        .parent()
        .context("Не найден каталог программы.")?
        .to_owned();
    let mut raw = Vec::new();
    File::open(path)?.take(16385).read_to_end(&mut raw)?;
    ensure!(raw.len() <= 16384, "План установки слишком велик.");
    let manifest: Manifest = serde_json::from_slice(&raw)?;
    ensure!(
        version(&manifest.version)?.pre.is_empty(),
        "Некорректная версия в плане установки."
    );
    ensure!(
        manifest.names == installed_names().map(str::to_owned)
            || manifest.names == asset_names().map(str::to_owned),
        "План установки пытается изменить посторонние файлы."
    );
    ensure!(
        manifest.config.is_absolute(),
        "Путь конфигурации должен быть абсолютным."
    );
    for index in 0..2 {
        regular_file(&directory.join(&manifest.names[index]))?;
        ensure!(
            !staging.join(format!("old-{index}")).try_exists()?,
            "Этот план установки уже использован; резервные копии сохранены."
        );
        ensure!(
            manifest.sizes[index] > 0 && manifest.sizes[index] <= MAX_ASSET,
            "Недопустимый размер файла в плане установки."
        );
        let (size, hash) = file_hash(&staging.join(format!("new-{index}")), manifest.sizes[index])?;
        ensure!(
            size == manifest.sizes[index] && hash == manifest.hashes[index],
            "Проверка SHA-256 перед установкой не пройдена; исходная программа сохранена."
        );
    }
    Ok(Installation {
        directory,
        staging,
        manifest,
    })
}
fn rollback(install: &Installation) -> Result<()> {
    let mut errors = Vec::new();
    for index in 0..2 {
        let backup = install.staging.join(format!("old-{index}"));
        if !backup.exists() {
            continue;
        }
        let target = install.directory.join(&install.manifest.names[index]);
        if let Err(error) = (|| -> std::io::Result<()> {
            if target.try_exists()? {
                fs::remove_file(&target)?;
            }
            rename_file(&backup, &target)
        })() {
            errors.push(format!("{}: {error}", target.display()));
        }
    }
    ensure!(
        errors.is_empty(),
        "Не удалось полностью восстановить программу: {}. Резервные копии сохранены в {}",
        errors.join("; "),
        install.staging.display()
    );
    Ok(())
}
fn replace_pair(
    install: &Installation,
    mut rename: impl FnMut(&Path, &Path) -> std::io::Result<()>,
) -> Result<()> {
    let result = (|| -> Result<()> {
        for index in 0..2 {
            rename(
                &install.directory.join(&install.manifest.names[index]),
                &install.staging.join(format!("old-{index}")),
            )?;
        }
        for index in 0..2 {
            rename(
                &install.staging.join(format!("new-{index}")),
                &install.directory.join(&install.manifest.names[index]),
            )?;
        }
        Ok(())
    })();
    if let Err(error) = result {
        rollback(install).with_context(|| format!("Ошибка замены: {error:#}"))?;
        return Err(error)
            .context("Не удалось установить обновление; прежние файлы восстановлены.");
    }
    Ok(())
}
fn rename_file(source: &Path, target: &Path) -> std::io::Result<()> {
    #[cfg(windows)]
    {
        let until = std::time::Instant::now() + Duration::from_secs(10);
        loop {
            match fs::rename(source, target) {
                Err(error)
                    if matches!(error.raw_os_error(), Some(5 | 32 | 33))
                        && std::time::Instant::now() < until =>
                {
                    std::thread::sleep(Duration::from_millis(100))
                }
                result => return result,
            }
        }
    }
    #[cfg(not(windows))]
    fs::rename(source, target)
}
fn lock_directory() -> PathBuf {
    #[cfg(test)]
    {
        std::env::temp_dir().join(format!("krot-update-locks-test-{}", std::process::id()))
    }
    #[cfg(not(test))]
    {
        crate::config::default_config_path()
            .parent()
            .expect("default config has parent")
            .join("updates")
    }
}
async fn install_guard(directory: &Path, exclusive: bool, root: &Path) -> Result<File> {
    fs::create_dir_all(root)?;
    restrict_access(root)?;
    let key = hex::encode(Sha256::digest(directory.as_os_str().as_encoded_bytes()));
    let path = root.join(format!("{key}.lock"));
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&path)?;
    restrict_access(&path)?;
    let until = tokio::time::Instant::now()
        + if exclusive {
            LOCK_TIMEOUT
        } else {
            Duration::from_secs(10)
        };
    loop {
        let result = if exclusive {
            fs2::FileExt::try_lock_exclusive(&file)
        } else {
            fs2::FileExt::try_lock_shared(&file)
        };
        match result {
            Ok(()) => return Ok(file),
            Err(error) if error.raw_os_error() == fs2::lock_contended_error().raw_os_error() => {}
            Err(error) => {
                return Err(error).context("Не удалось заблокировать установку обновления.");
            }
        }
        ensure!(
            tokio::time::Instant::now() < until,
            "Обновление уже выполняется; дождитесь завершения и запустите КРОТ снова."
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}
/// Hold only while acquiring process ownership, never for the lifetime of a GUI or daemon.
pub async fn startup_guard() -> Result<File> {
    let executable = std::env::current_exe()?
        .canonicalize()
        .context("Программа была обновлена; запустите КРОТ снова.")?;
    #[cfg(not(test))]
    startup_directory(&executable)?;
    #[cfg(target_os = "linux")]
    let before = fs::metadata("/proc/self/exe")?;
    #[cfg(not(target_os = "linux"))]
    let before = fs::metadata(&executable)?;
    let guard = install_guard(
        executable
            .parent()
            .context("Не найден каталог программы.")?,
        false,
        &lock_directory(),
    )
    .await?;
    let after =
        fs::metadata(&executable).context("Программа была обновлена; запустите КРОТ снова.")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        ensure!(
            (before.dev(), before.ino()) == (after.dev(), after.ino()),
            "Программа была обновлена; запустите КРОТ снова."
        );
    }
    #[cfg(not(unix))]
    ensure!(
        before.len() == after.len() && before.modified()? == after.modified()?,
        "Программа была обновлена; запустите КРОТ снова."
    );
    Ok(guard)
}
fn restart(install: &Installation, skip_check: bool) -> Result<std::process::Child> {
    let mut command = Command::new(install.directory.join(&install.manifest.names[0]));
    command.arg("--config").arg(&install.manifest.config);
    if skip_check {
        command.arg("--skip-update-check");
    } else {
        command
            .arg("--update-ready")
            .arg(install.staging.join("ready.json"));
    }
    command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .context("Не удалось запустить КРОТ; запустите программу вручную.")
}
pub async fn apply_install(manifest: &Path) -> Result<()> {
    let helper = std::env::current_exe()?.canonicalize()?;
    let install = validate_install(manifest, &helper)?;
    let _transaction = install_guard(
        &install.directory,
        true,
        &lock_directory().join("transactions"),
    )
    .await?;
    let guard = install_guard(&install.directory, true, &lock_directory()).await?;
    // Recheck under the installation lock before stopping any running tunnels.
    let install = validate_install(manifest, &helper)?;
    let store = Store::new(&install.manifest.config)?;
    crate::background::stop_and_wait(&store).await?;
    if let Err(error) = replace_pair(&install, rename_file) {
        drop(guard);
        if (0..2).any(|index| install.staging.join(format!("old-{index}")).exists()) {
            return Err(error)
                .context("Откат не завершён; резервные копии сохранены. Запуск отменён.");
        }
        let recovery = restart(&install, true);
        return match recovery {
            Ok(_) => Err(error),
            Err(recovery) => {
                Err(error).context(format!("Не удалось открыть прежний КРОТ: {recovery:#}"))
            }
        };
    }
    let started = restart(&install, false);
    drop(guard);
    let mut owner = None;
    let mut process = None;
    let readiness = match started {
        Ok(mut spawned) => {
            let result =
                await_ready(&install, &mut spawned, &mut owner, Duration::from_secs(30)).await;
            process = Some(spawned);
            result
        }
        Err(error) => Err(error),
    };
    let readiness = match readiness {
        Ok(()) => {
            async {
                let snapshot = crate::background::Client::new(&store).snapshot().await?;
                ensure!(
                    snapshot.version.as_deref() == Some(install.manifest.version.as_str()),
                    "Фоновый КРОТ не подтвердил новую версию."
                );
                ensure!(
                    process
                        .as_mut()
                        .context("Новый процесс не запущен.")?
                        .try_wait()?
                        .is_none(),
                    "Новое окно завершилось до окончания проверки."
                );
                Ok(())
            }
            .await
        }
        Err(error) => Err(error),
    };
    if let Err(error) = readiness {
        let guard = install_guard(&install.directory, true, &lock_directory()).await?;
        if let Err(recovery) = restore_failed_restart(&install, &mut process, owner.as_ref()).await
        {
            return Err(error).context(format!("Автоматический откат невозможен: {recovery:#}. Закройте КРОТ; резервные копии old-0 и old-1 сохранены в {}", install.staging.display()));
        }
        drop(guard);
        restart(&install, true)
            .context("Прежние файлы восстановлены, но КРОТ нужно открыть вручную.")?;
        return Err(error).context("Новая версия не запустилась; прежние файлы восстановлены.");
    }
    // Windows keeps the running helper locked until the installer exits.
    let _ = fs::remove_dir_all(&install.staging);
    Ok(())
}

#[cfg(test)]
mod install_tests {
    use super::*;
    pub(super) fn fixture() -> (tempfile::TempDir, PathBuf, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let stage = dir.path().canonicalize().unwrap().join(".krot-update-test");
        fs::create_dir(&stage).unwrap();
        for (i, name) in installed_names().iter().enumerate() {
            fs::write(dir.path().join(name), format!("old{i}")).unwrap();
            fs::write(stage.join(format!("new-{i}")), format!("new{i}")).unwrap();
        }
        let manifest = Manifest {
            version: env!("CARGO_PKG_VERSION").into(),
            config: dir.path().join("config.json"),
            names: installed_names().map(str::to_owned),
            hashes: [
                hex::encode(Sha256::digest(b"new0")),
                hex::encode(Sha256::digest(b"new1")),
            ],
            sizes: [4, 4],
        };
        let path = stage.join("manifest.json");
        atomic_json(&path, &manifest, None).unwrap();
        let helper = stage.join(helper_name());
        fs::write(&helper, b"helper").unwrap();
        (dir, path, helper)
    }
    #[test]
    fn installs_both_real_files() {
        let (dir, path, helper) = fixture();
        let install = validate_install(&path, &helper).unwrap();
        replace_pair(&install, |a, b| fs::rename(a, b)).unwrap();
        for (i, name) in installed_names().iter().enumerate() {
            assert_eq!(
                fs::read(dir.path().join(name)).unwrap(),
                format!("new{i}").as_bytes()
            );
            assert_eq!(
                fs::read(install.staging.join(format!("old-{i}"))).unwrap(),
                format!("old{i}").as_bytes()
            );
        }
    }
    #[test]
    fn failed_second_replacement_restores_both_originals() {
        let (dir, path, helper) = fixture();
        let install = validate_install(&path, &helper).unwrap();
        let mut calls = 0;
        let result = replace_pair(&install, |a, b| {
            calls += 1;
            if calls == 4 {
                Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "fixture",
                ))
            } else {
                fs::rename(a, b)
            }
        });
        assert!(result.is_err());
        for (i, name) in installed_names().iter().enumerate() {
            assert_eq!(
                fs::read(dir.path().join(name)).unwrap(),
                format!("old{i}").as_bytes()
            );
        }
    }
    #[test]
    fn manifest_cannot_change_other_paths_or_use_other_helper() {
        let (dir, path, helper) = fixture();
        assert!(validate_install(&path, &dir.path().join(helper_name())).is_err());
        let mut raw: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        raw["names"][0] = "../config.json".into();
        atomic_json(&path, &raw, None).unwrap();
        assert!(validate_install(&path, &helper).is_err());
    }
    #[test]
    fn corrupt_download_is_rejected_before_any_replacement() {
        let (dir, path, helper) = fixture();
        fs::write(path.parent().unwrap().join("new-1"), b"evil").unwrap();
        assert!(validate_install(&path, &helper).is_err());
        assert_eq!(
            fs::read(dir.path().join(installed_names()[0])).unwrap(),
            b"old0"
        );
    }
    #[cfg(unix)]
    #[test]
    fn staged_symlink_is_rejected() {
        let (_dir, path, helper) = fixture();
        let staged = path.parent().unwrap().join("new-1");
        fs::remove_file(&staged).unwrap();
        std::os::unix::fs::symlink("new-0", staged).unwrap();
        assert!(validate_install(&path, &helper).is_err());
    }
}

#[cfg(test)]
mod network_tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    async fn response(
        status: u16,
        body: &[u8],
        declared: Option<usize>,
    ) -> (String, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/fixture", listener.local_addr().unwrap());
        let body = body.to_vec();
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0; 4096];
            let _ = stream.read(&mut request).await;
            let header = format!(
                "HTTP/1.1 {status} Fixture\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                declared.unwrap_or(body.len())
            );
            let _ = stream.write_all(header.as_bytes()).await;
            let _ = stream.write_all(&body).await;
        });
        (url, task)
    }
    #[tokio::test]
    async fn network_statuses_and_size_limit() {
        let client = client().unwrap();
        for (status, body, declared, expected) in [
            (404, b"private".as_slice(), None, 0),
            (403, b"rate limited".as_slice(), None, -1),
            (500, b"failed".as_slice(), None, -1),
            (200, b"malformed".as_slice(), None, -1),
            (200, b"".as_slice(), Some(MAX_METADATA + 1), -1),
            (
                200,
                b"{\"tag_name\":\"v0.6.0\",\"draft\":false,\"prerelease\":false,\"assets\":[]}"
                    .as_slice(),
                None,
                1,
            ),
        ] {
            let (url, server) = response(status, body, declared).await;
            let result = fetch_release(&client, &url, "0.5.0", None).await;
            match expected {
                0 => assert!(result.unwrap().is_none()),
                1 => assert!(result.unwrap().is_some()),
                _ => assert!(result.is_err()),
            }
            server.await.unwrap();
        }
    }
    #[test]
    fn build_metadata_does_not_create_a_new_release() {
        let data = br#"{"tag_name":"v0.5.0+rebuilt","draft":false,"prerelease":false,"assets":[]}"#;
        assert!(parse_release(data, "0.5.0", None).unwrap().is_none());
    }
    #[tokio::test]
    async fn install_lock_serializes_startup_and_second_installer() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("locks");
        let first = install_guard(dir.path(), true, &root).await.unwrap();
        assert!(
            tokio::time::timeout(
                Duration::from_millis(120),
                install_guard(dir.path(), false, &root)
            )
            .await
            .is_err()
        );
        assert!(
            tokio::time::timeout(
                Duration::from_millis(120),
                install_guard(dir.path(), true, &root)
            )
            .await
            .is_err()
        );
        drop(first);
        let shared = install_guard(dir.path(), false, &root).await.unwrap();
        let shared2 = install_guard(dir.path(), false, &root).await.unwrap();
        drop((shared, shared2));
        assert!(install_guard(dir.path(), true, &root).await.is_ok());
    }
}

#[cfg(test)]
mod download_tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    #[tokio::test]
    async fn real_download_rejects_bad_digest_and_size_and_writes_verified_file() {
        let dir = tempfile::tempdir().unwrap();
        let client = client().unwrap();
        for (index, size, digest, success) in [
            (0, 4, "bad".to_string(), false),
            (1, 5, hex::encode(Sha256::digest(b"data")), false),
            (2, 4, hex::encode(Sha256::digest(b"data")), true),
        ] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let server = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = [0; 4096];
                let _ = stream.read(&mut request).await;
                stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\ndata",
                    )
                    .await
                    .unwrap();
            });
            let response = client
                .get(format!("http://{address}/"))
                .send()
                .await
                .unwrap();
            let asset = Asset {
                name: "krot-linux-x64".into(),
                browser_download_url:
                    "https://github.com/Dudod1n/KPOT/releases/download/v1.0.0/krot-linux-x64".into(),
                size,
                digest: Some(format!(
                    "sha256:{}",
                    if digest == "bad" {
                        "a".repeat(64)
                    } else {
                        digest
                    }
                )),
            };
            let path = dir.path().join(index.to_string());
            let result = write_download(response, &asset, &path).await;
            assert_eq!(result.is_ok(), success);
            if success {
                assert_eq!(fs::read(path).unwrap(), b"data");
            }
            server.await.unwrap();
        }
    }
}

#[cfg(test)]
mod readiness_tests {
    use super::*;
    #[test]
    fn startup_rejects_staged_backups_even_with_a_known_binary_name() {
        assert!(startup_directory(Path::new("/opt/krot/.krot-update-x/old-0")).is_err());
        assert!(startup_directory(Path::new("/opt/krot/.krot-update-x/krot")).is_err());
        assert!(startup_directory(Path::new("/opt/krot/unrelated")).is_err());
        assert_eq!(
            startup_directory(&Path::new("/opt/krot").join(installed_names()[0])).unwrap(),
            Path::new("/opt/krot")
        );
    }
    #[cfg(unix)]
    #[tokio::test]
    async fn readiness_checks_identity_version_config_and_malformed_data() {
        let (_dir, path, helper) = super::install_tests::fixture();
        let install = validate_install(&path, &helper).unwrap();
        for case in ["valid", "pid", "version", "config", "owner", "malformed"] {
            let mut child = Command::new("/bin/sh")
                .args(["-c", "sleep 0.15"])
                .spawn()
                .unwrap();
            let ack = Readiness {
                pid: child.id(),
                version: install.manifest.version.clone(),
                config: install.manifest.config.clone(),
                owner: Some(
                    serde_json::from_value(
                        serde_json::json!({"port":12345,"token":"a".repeat(64)}),
                    )
                    .unwrap(),
                ),
                ready: true,
            };
            let mut raw = serde_json::to_value(ack).unwrap();
            match case {
                "pid" => raw["pid"] = 0.into(),
                "version" => raw["version"] = "99.0.0".into(),
                "config" => raw["config"] = "/wrong/config".into(),
                "owner" => raw["owner"] = serde_json::Value::Null,
                _ => {}
            }
            let ready = install.staging.join("ready.json");
            atomic_json(&ready, &raw, None).unwrap();
            if case == "malformed" {
                fs::write(&ready, b"broken").unwrap();
            }
            let mut owner = None;
            assert_eq!(
                await_ready(&install, &mut child, &mut owner, Duration::from_secs(1))
                    .await
                    .is_ok(),
                case == "valid"
            );
            child.wait().unwrap();
        }
    }
    #[cfg(unix)]
    #[tokio::test]
    async fn occupied_daemon_keeps_backups_and_new_files() {
        let (_dir, path, helper) = super::install_tests::fixture();
        let install = validate_install(&path, &helper).unwrap();
        replace_pair(&install, rename_file).unwrap();
        let store = Store::new(&install.manifest.config).unwrap();
        let lease = store.lock().unwrap();
        assert!(
            restore_failed_restart(&install, &mut None, None)
                .await
                .is_err()
        );
        assert_eq!(fs::read(install.staging.join("old-0")).unwrap(), b"old0");
        assert_eq!(
            fs::read(install.directory.join(installed_names()[0])).unwrap(),
            b"new0"
        );
        drop(lease);
    }
    #[cfg(unix)]
    #[tokio::test]
    async fn successful_spawn_with_early_exit_is_not_a_successful_update() {
        let (dir, path, helper) = super::install_tests::fixture();
        let install = validate_install(&path, &helper).unwrap();
        fs::write(install.staging.join("new-0"), b"#!/bin/sh\nexit 127\n").unwrap();
        executable_permissions(&install.staging.join("new-0")).unwrap();
        replace_pair(&install, rename_file).unwrap();
        let mut child = restart(&install, false).unwrap();
        let mut owner = None;
        assert!(
            await_ready(&install, &mut child, &mut owner, Duration::from_secs(2))
                .await
                .is_err()
        );
        rollback(&install).unwrap();
        assert_eq!(
            fs::read(dir.path().join(installed_names()[0])).unwrap(),
            b"old0"
        );
        assert_eq!(
            fs::read(dir.path().join(installed_names()[1])).unwrap(),
            b"old1"
        );
    }
}

fn startup_directory(path: &Path) -> Result<&Path> {
    installation_names(path)?;
    ensure!(
        !path.ancestors().any(|part| part
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with(".krot-update-"))),
        "Нельзя запускать КРОТ из каталога обновления или резервной копии. Запустите программу из каталога установки."
    );
    path.parent().context("Не найден каталог программы.")
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Readiness {
    pid: u32,
    version: String,
    config: PathBuf,
    owner: Option<crate::background::Owner>,
    ready: bool,
}
pub(crate) fn acknowledge_startup(path: &Path, store: &Store, ready: bool) -> Result<()> {
    let executable = std::env::current_exe()?.canonicalize()?;
    let directory = startup_directory(&executable)?;
    let staging = path
        .parent()
        .context("Не найден каталог подтверждения обновления.")?
        .canonicalize()?;
    ensure!(
        path == staging.join("ready.json")
            && staging.parent() == Some(directory)
            && staging
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with(".krot-update-")),
        "Некорректный путь подтверждения обновления."
    );
    atomic_json(
        path,
        &Readiness {
            pid: std::process::id(),
            version: env!("CARGO_PKG_VERSION").into(),
            config: store.path.clone(),
            owner: Some(
                crate::background::observe_owner(store)?
                    .context("Фоновый процесс не подтвердил владение конфигурацией.")?,
            ),
            ready,
        },
        Some(4096),
    )
}
fn read_ready(install: &Installation, pid: u32) -> Result<Option<Readiness>> {
    let path = install.staging.join("ready.json");
    let file = match File::open(&path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    regular_file(&path)?;
    let mut data = Vec::new();
    file.take(4097).read_to_end(&mut data)?;
    ensure!(data.len() <= 4096, "Подтверждение запуска слишком велико.");
    let ack: Readiness =
        serde_json::from_slice(&data).context("Некорректное подтверждение запуска обновления.")?;
    ensure!(
        ack.pid == pid
            && ack.version == install.manifest.version
            && ack.config == install.manifest.config,
        "Подтверждение запуска относится к другому процессу, версии или конфигурации."
    );
    ensure!(
        !ack.ready || ack.owner.is_some(),
        "Подтверждение готовности не содержит владельца фонового процесса."
    );
    Ok(Some(ack))
}
async fn await_ready(
    install: &Installation,
    child: &mut std::process::Child,
    owner: &mut Option<crate::background::Owner>,
    timeout: Duration,
) -> Result<()> {
    let until = tokio::time::Instant::now() + timeout;
    loop {
        if let Some(ack) = read_ready(install, child.id())? {
            *owner = ack.owner;
            ensure!(
                child.try_wait()?.is_none(),
                "Обновлённый КРОТ завершился во время запуска."
            );
            if ack.ready {
                return Ok(());
            }
        }
        ensure!(
            child.try_wait()?.is_none(),
            "Обновлённый КРОТ завершился до подтверждения готовности."
        );
        ensure!(
            tokio::time::Instant::now() < until,
            "Обновлённый КРОТ не подтвердил готовность вовремя."
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}
async fn restore_failed_restart(
    install: &Installation,
    child: &mut Option<std::process::Child>,
    owner: Option<&crate::background::Owner>,
) -> Result<()> {
    let store = Store::new(&install.manifest.config)?;
    if owner.is_some() {
        crate::background::stop_selected_and_wait(&store, owner).await?;
    }
    if let Some(child) = child {
        let until = tokio::time::Instant::now() + Duration::from_secs(3);
        while child.try_wait()?.is_none() {
            ensure!(
                tokio::time::Instant::now() < until,
                "Новый процесс ещё работает. Закройте его перед восстановлением резервных копий."
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
    let ui = Store::new(store.sidecar(".ui"))?;
    let _daemon = crate::background::try_lease(&store)?
        .context("Фоновый процесс занят; автоматический откат отменён.")?;
    let _window = crate::background::try_lease(&ui)?
        .context("Окно ещё открыто; автоматический откат отменён.")?;
    rollback(install)
}
