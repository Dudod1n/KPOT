//! Screenshots of every screen, for pull requests and visual review.
//!
//! `KROT_SCREENSHOTS=target/screenshots cargo test --lib screenshots -- --ignored`
//! writes one binary PPM image per scene. egui's output is rasterised here in software the
//! way its renderers draw it: premultiplied colours, the font atlas, blending in gamma space.
use super::*;
use crate::{
    apps::{AppRule, AppRuntime},
    config::{Config, Settings},
    ssh::{Prompt, Runtime, UdpRuntime},
};
use std::collections::{HashMap, VecDeque};

fn endpoint(user: &str, host: &str, port: u16, auth: &str) -> Endpoint {
    Endpoint {
        host: host.into(),
        user: user.into(),
        port,
        auth: auth.into(),
        key: if auth == "key" {
            "~/.ssh/id_ed25519".into()
        } else {
            String::new()
        },
    }
}

#[allow(clippy::too_many_arguments)]
fn tunnel(
    id: &str,
    name: &str,
    kind: &str,
    server: Endpoint,
    port: u16,
    target: &str,
    target_port: u16,
    enabled: bool,
) -> Tunnel {
    Tunnel {
        id: id.into(),
        name: name.into(),
        kind: kind.into(),
        server,
        bind: "127.0.0.1".into(),
        port,
        target: target.into(),
        target_port,
        reconnect: true,
        jumps_enabled: false,
        jumps: Vec::new(),
        enabled,
    }
}

fn runtime(state: &str, logs: &[&str]) -> Runtime {
    Runtime {
        state: state.into(),
        logs: logs
            .iter()
            .map(|line| (*line).to_owned())
            .collect::<VecDeque<_>>(),
        ..Default::default()
    }
}

/// Four tunnels in different states, a second SOCKS tunnel, four application rules.
fn demo(extra_tunnels: usize, extra_rules: usize) -> Snapshot {
    let mut tunnels = vec![
        tunnel(
            "db",
            "Рабочая база",
            "L",
            endpoint("deploy", "bastion.example.org", 22, "agent"),
            5432,
            "db.internal",
            5432,
            true,
        ),
        tunnel(
            "socks",
            "SOCKS домой",
            "D",
            endpoint("me", "home.example.net", 2222, "key"),
            1080,
            "",
            0,
            true,
        ),
        tunnel(
            "demo",
            "Демо для заказчика",
            "R",
            endpoint("demo", "stage.example.org", 22, "password"),
            8080,
            "127.0.0.1",
            3000,
            true,
        ),
        tunnel(
            "mon",
            "Мониторинг",
            "L",
            endpoint("ops", "bastion.example.org", 22, "agent"),
            9090,
            "metrics.internal",
            9090,
            false,
        ),
        tunnel(
            "office",
            "SOCKS офис",
            "D",
            endpoint("me", "office.example.org", 22, "agent"),
            1081,
            "",
            0,
            false,
        ),
    ];
    let mut runtimes = HashMap::from([
        (
            "db".to_owned(),
            runtime(
                "running",
                &[
                    "09:14:02  Подключение к bastion.example.org:22",
                    "09:14:02  Ключ узла совпадает с сохранённым",
                    "09:14:03  Вход выполнен: deploy, SSH-agent",
                    "09:14:03  Слушаем 127.0.0.1:5432 → db.internal:5432",
                    "11:52:40  Соединение с сервером потеряно",
                    "11:52:41  Восстановление: попытка 1",
                    "11:52:47  Вход выполнен: deploy, SSH-agent",
                    "11:52:47  Слушаем 127.0.0.1:5432 → db.internal:5432",
                    "13:05:18  Ошибка приёма соединения на локальном порту; повторяем.",
                ],
            ),
        ),
        ("socks".to_owned(), runtime("running", &[])),
        ("demo".to_owned(), runtime("waiting", &[])),
        ("mon".to_owned(), runtime("stopped", &[])),
        ("office".to_owned(), runtime("stopped", &[])),
    ]);
    let states = [
        "running",
        "running",
        "stopped",
        "error",
        "running",
        "connecting",
    ];
    for index in 0..extra_tunnels {
        let id = format!("stand-{index}");
        let number = index + 5;
        tunnels.push(tunnel(
            &id,
            &format!("Стенд {number}"),
            "L",
            endpoint("deploy", "bastion.example.org", 22, "agent"),
            8000 + number as u16,
            &format!("stand-{number}.internal"),
            80,
            true,
        ));
        runtimes.insert(id, runtime(states[index % states.len()], &[]));
    }
    let rule = |id: &str, name: &str, path: &str, tunnel: &str, direct: bool| AppRule {
        id: id.into(),
        name: name.into(),
        path: path.into(),
        tunnel_id: tunnel.into(),
        enabled: true,
        on_tunnel_down: if direct { "direct" } else { "block" }.into(),
        children: true,
    };
    let mut apps = vec![
        rule(
            "tg",
            "Telegram",
            r"C:\Users\user\AppData\Roaming\Telegram Desktop\Telegram.exe",
            "socks",
            false,
        ),
        rule(
            "ff",
            "Firefox",
            r"C:\Program Files\Mozilla Firefox\firefox.exe",
            "socks",
            false,
        ),
        rule(
            "steam",
            "Steam",
            r"C:\Program Files (x86)\Steam\steam.exe",
            "office",
            true,
        ),
        rule(
            "ds",
            "Discord",
            r"C:\Users\user\AppData\Local\Discord\app\Discord.exe",
            "office",
            false,
        ),
    ];
    let app_runtime = |state: &str, connections: u64| AppRuntime {
        state: state.into(),
        connections,
        total: connections * 14,
        sent: connections * 700_000,
        received: connections * 6_100_000,
        logs: vec!["10:02:11  Правило включено".into()],
    };
    let mut app_runtimes = HashMap::from([
        ("tg".to_owned(), app_runtime("running", 3)),
        ("ff".to_owned(), app_runtime("running", 12)),
        ("steam".to_owned(), app_runtime("direct", 0)),
        ("ds".to_owned(), app_runtime("blocked", 0)),
    ]);
    let names = [
        "Chrome",
        "Slack",
        "Zoom",
        "Spotify",
        "Obsidian",
        "Thunderbird",
    ];
    let app_states = [
        "running", "running", "direct", "stopped", "blocked", "running",
    ];
    for index in 0..extra_rules {
        let id = format!("rule-{index}");
        let name = format!("{} {}", names[index % names.len()], index / names.len() + 1);
        apps.push(rule(
            &id,
            &name,
            r"C:\Program Files\App\app.exe",
            "socks",
            false,
        ));
        app_runtimes.insert(id, app_runtime(app_states[index % app_states.len()], 2));
    }
    let mut snapshot = Snapshot {
        config: Config {
            version: 1,
            settings: Settings {
                theme: "build".into(),
                motion: true,
                splash: true,
            },
            tunnels,
        },
        runtimes,
        apps,
        app_runtimes,
        divert_attached: true,
        ..Default::default()
    };
    snapshot.prompts.insert(
        "demo".into(),
        PendingPrompt {
            id: "demo-password".into(),
            request: Prompt {
                kind: "password".into(),
                tunnel_id: "demo".into(),
                tunnel_name: "Демо для заказчика".into(),
                endpoint: endpoint("demo", "stage.example.org", 22, "password"),
                hop: "Конечный SSH-сервер".into(),
                message: String::new(),
                old_fingerprint: String::new(),
                new_fingerprint: String::new(),
            },
        },
    );
    snapshot.udp.tunnels.insert(
        "socks".into(),
        crate::udp::consent::TunnelUdp {
            enabled: true,
            server: crate::udp::consent::server(&snapshot.config.tunnels[1]),
        },
    );
    snapshot.udp_runtimes.insert(
        "socks".into(),
        UdpRuntime {
            state: "running".into(),
            level: 1,
            ..Default::default()
        },
    );
    snapshot
        .udp_metrics
        .insert("socks".into(), Default::default());
    snapshot
}

fn host_key_prompt() -> PromptDialog {
    PromptDialog::new(PendingPrompt {
        id: "db-key".into(),
        request: Prompt {
            kind: "hostchanged".into(),
            tunnel_id: "db".into(),
            tunnel_name: "Рабочая база".into(),
            endpoint: endpoint("deploy", "bastion.example.org", 22, "agent"),
            hop: "Конечный SSH-сервер".into(),
            message: String::new(),
            old_fingerprint: "SHA256:p0Gk3nV8mQ2sXbR7tLw1yZc9HfA4dE6uJ5oN0iKqT8M".into(),
            new_fingerprint: "SHA256:Zt7Lq2Wc8Ny4Bv1Xm6Kp3Rj9Hs0Fd5Ga2Ue8Io7Pl4C".into(),
        },
    })
}

type Setup = Box<dyn Fn(&mut Desktop)>;

/// Every screen of issue #48 in the mock-up's order, with the file name it is saved under.
fn scenes() -> Vec<(&'static str, Setup)> {
    fn base(app: &mut Desktop, extra_tunnels: usize, extra_rules: usize) {
        app.snapshot = Some(demo(extra_tunnels, extra_rules));
        app.deferred.insert("demo-password".into());
        app.initialized = true;
        app.dialog = None;
        app.confirm = None;
        app.update = None;
        app.view = View::Tunnels;
        app.selected = Some("socks".into());
        app.selected_app = Some("tg".into());
        app.filter = Group::All;
        app.app_filter = Group::All;
    }
    vec![
        ("01-tunnels", Box::new(|app| base(app, 0, 0))),
        (
            "01b-tunnels-18",
            Box::new(|app| {
                base(app, 13, 0);
                app.selected = Some("db".into());
            }),
        ),
        (
            "02-apps",
            Box::new(|app| {
                base(app, 0, 0);
                app.view = View::Apps;
            }),
        ),
        (
            "02b-apps-16",
            Box::new(|app| {
                base(app, 0, 12);
                app.view = View::Apps;
            }),
        ),
        (
            "03-splash",
            Box::new(|app| {
                base(app, 0, 0);
                if let Some(snapshot) = &mut app.snapshot {
                    snapshot.runtimes.get_mut("socks").unwrap().state = "connecting".into();
                }
                app.dialog = Some(Dialog::Splash);
            }),
        ),
        (
            "04-tunnel-form",
            Box::new(|app| {
                base(app, 0, 0);
                let mut form = TunnelForm::new(None);
                form.draft.name = "Рабочая база".into();
                form.draft.server = endpoint("deploy", "bastion.example.org", 22, "agent");
                form.draft.target = "db.internal".into();
                form.port = "5432".into();
                form.target_port = "5432".into();
                app.dialog = Some(Dialog::Form(Box::new(form)));
            }),
        ),
        (
            "05-app-form",
            Box::new(|app| {
                base(app, 0, 0);
                let mut form = AppForm::new(None);
                form.draft.path =
                    r"C:\Users\user\AppData\Roaming\Telegram Desktop\Telegram.exe".into();
                form.draft.name = "Telegram".into();
                form.draft.tunnel_id = "socks".into();
                app.view = View::Apps;
                app.dialog = Some(Dialog::AppForm(Box::new(form)));
            }),
        ),
        (
            "06-prompt-host-key",
            Box::new(|app| {
                base(app, 0, 0);
                app.dialog = Some(Dialog::Prompt(Box::new(host_key_prompt())));
            }),
        ),
        (
            "06b-prompt-password",
            Box::new(|app| {
                base(app, 0, 0);
                app.deferred.clear();
            }),
        ),
        (
            "07-logs",
            Box::new(|app| {
                base(app, 0, 0);
                app.dialog = Some(Dialog::Logs("db".into()));
            }),
        ),
        (
            "08-settings",
            Box::new(|app| {
                base(app, 0, 0);
                app.dialog = Some(Dialog::Settings(SettingsDraft {
                    theme: "build".into(),
                    motion: true,
                    splash: true,
                    autostart: Some(false),
                    initial_autostart: Some(false),
                    error: String::new(),
                    busy: false,
                }));
            }),
        ),
        (
            "09-help",
            Box::new(|app| {
                base(app, 0, 0);
                app.dialog = Some(Dialog::Help);
            }),
        ),
        (
            "10-about",
            Box::new(|app| {
                base(app, 0, 0);
                app.about_quote = Some(0);
                app.dialog = Some(Dialog::About);
            }),
        ),
        (
            "11a-delete",
            Box::new(|app| {
                base(app, 0, 0);
                app.confirm = Some(Confirm::Delete {
                    id: "db".into(),
                    name: "Рабочая база".into(),
                });
            }),
        ),
        (
            "11b-exit",
            Box::new(|app| {
                base(app, 0, 0);
                app.confirm = Some(Confirm::Exit);
            }),
        ),
        (
            "11c-close-notice",
            Box::new(|app| {
                base(app, 0, 0);
                app.confirm = Some(Confirm::CloseNotice {
                    dont_show_again: false,
                    busy: false,
                    error: String::new(),
                });
            }),
        ),
        (
            "11d-update",
            Box::new(|app| {
                base(app, 0, 0);
                app.update = Some(UpdateDialog {
                    release: crate::update::Release::for_test("0.7.0"),
                    manual: false,
                    stage: UpdateStage::Offer,
                    error: String::new(),
                });
            }),
        ),
        (
            "11e-udp-consent",
            Box::new(|app| {
                base(app, 0, 0);
                app.confirm = Some(Confirm::UdpConsent {
                    id: "socks".into(),
                    name: "SOCKS домой".into(),
                });
            }),
        ),
    ]
}

type Image = (usize, usize, Vec<[f32; 4]>);

fn apply(textures: &mut HashMap<egui::TextureId, egui::ColorImage>, delta: egui::TexturesDelta) {
    for (id, change) in delta.set {
        let egui::ImageData::Color(image) = change.image;
        match change.pos {
            None => {
                textures.insert(id, (*image).clone());
            }
            Some([x, y]) => {
                let target = textures
                    .get_mut(&id)
                    .expect("partial update of a known texture");
                for row in 0..image.size[1] {
                    for column in 0..image.size[0] {
                        target.pixels[(y + row) * target.size[0] + x + column] =
                            image.pixels[row * image.size[0] + column];
                    }
                }
            }
        }
    }
}

fn unit(color: egui::Color32) -> [f32; 4] {
    color.to_array().map(|channel| f32::from(channel) / 255.0)
}

/// Draws egui's triangles: vertex colour times the texel, premultiplied "over" blending.
fn rasterize(
    primitives: &[egui::ClippedPrimitive],
    textures: &HashMap<egui::TextureId, egui::ColorImage>,
    size: [usize; 2],
) -> Image {
    let [width, height] = size;
    let mut pixels = vec![[0.0, 0.0, 0.0, 1.0]; width * height];
    for primitive in primitives {
        let egui::epaint::Primitive::Mesh(mesh) = &primitive.primitive else {
            continue;
        };
        let texture = &textures[&mesh.texture_id];
        let clip = primitive.clip_rect;
        for triangle in mesh.indices.chunks_exact(3) {
            let [a, b, c] = [0, 1, 2].map(|index| &mesh.vertices[triangle[index] as usize]);
            let area =
                (b.pos - a.pos).x * (c.pos - a.pos).y - (b.pos - a.pos).y * (c.pos - a.pos).x;
            if area.abs() < 1e-6 {
                continue;
            }
            let left = a
                .pos
                .x
                .min(b.pos.x)
                .min(c.pos.x)
                .max(clip.left())
                .max(0.0)
                .floor() as usize;
            let right = a
                .pos
                .x
                .max(b.pos.x)
                .max(c.pos.x)
                .min(clip.right())
                .min(width as f32)
                .ceil() as usize;
            let top = a
                .pos
                .y
                .min(b.pos.y)
                .min(c.pos.y)
                .max(clip.top())
                .max(0.0)
                .floor() as usize;
            let bottom = a
                .pos
                .y
                .max(b.pos.y)
                .max(c.pos.y)
                .min(clip.bottom())
                .min(height as f32)
                .ceil() as usize;
            for y in top..bottom {
                for x in left..right {
                    let point = egui::pos2(x as f32 + 0.5, y as f32 + 0.5);
                    if !clip.contains(point) {
                        continue;
                    }
                    let edge = |p: egui::Pos2, q: egui::Pos2| {
                        ((q - p).x * (point - p).y - (q - p).y * (point - p).x) / area
                    };
                    let (wa, wb, wc) = (edge(b.pos, c.pos), edge(c.pos, a.pos), edge(a.pos, b.pos));
                    if wa < -1e-4 || wb < -1e-4 || wc < -1e-4 {
                        continue;
                    }
                    let mix = |p: [f32; 4], q: [f32; 4], r: [f32; 4]| {
                        [0, 1, 2, 3].map(|i| p[i] * wa + q[i] * wb + r[i] * wc)
                    };
                    let color = mix(unit(a.color), unit(b.color), unit(c.color));
                    let uv = a.uv.to_vec2() * wa + b.uv.to_vec2() * wb + c.uv.to_vec2() * wc;
                    let tx = ((uv.x * texture.size[0] as f32) as usize).min(texture.size[0] - 1);
                    let ty = ((uv.y * texture.size[1] as f32) as usize).min(texture.size[1] - 1);
                    let texel = unit(texture.pixels[ty * texture.size[0] + tx]);
                    let source = [0, 1, 2, 3].map(|i| color[i] * texel[i]);
                    let target = &mut pixels[y * width + x];
                    for i in 0..4 {
                        target[i] = source[i] + target[i] * (1.0 - source[3]);
                    }
                }
            }
        }
    }
    (width, height, pixels)
}

fn save(path: &std::path::Path, (width, height, pixels): &Image) {
    let mut ppm = format!("P6\n{width} {height}\n255\n").into_bytes();
    for pixel in pixels {
        ppm.extend(
            pixel[..3]
                .iter()
                .map(|channel| (channel.clamp(0.0, 1.0) * 255.0).round() as u8),
        );
    }
    std::fs::write(path, ppm).unwrap();
}

#[test]
#[ignore = "writes images: KROT_SCREENSHOTS=dir cargo test --lib screenshots -- --ignored"]
fn screenshots() {
    let out = PathBuf::from(
        std::env::var("KROT_SCREENSHOTS").unwrap_or_else(|_| "target/screenshots".into()),
    );
    std::fs::create_dir_all(&out).unwrap();
    let size = [1280usize, 860];
    let ctx = egui::Context::default();
    configure(&ctx, "build");
    let mut app = Desktop::new(None, true);
    let mut textures = HashMap::new();
    let mut shots: Vec<(String, &str, Setup)> = scenes()
        .into_iter()
        .map(|(name, setup)| (name.to_owned(), "build", setup))
        .collect();
    // The main screen and a form in every other theme, to check that they stay readable.
    for theme in ["night", "danger", "stealth", "dark", "light", "system"] {
        for (name, setup) in scenes()
            .into_iter()
            .filter(|(name, _)| matches!(*name, "01-tunnels" | "04-tunnel-form"))
        {
            shots.push((format!("theme-{theme}-{name}"), theme, setup));
        }
    }
    for (name, theme, setup) in shots {
        configure(&ctx, theme);
        setup(&mut app);
        let mut last = None;
        // Long enough for areas to size themselves and modals to fade in.
        for _ in 0..40 {
            let output = ctx.run(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(
                        egui::Pos2::ZERO,
                        egui::vec2(size[0] as f32, size[1] as f32),
                    )),
                    ..Default::default()
                },
                |ctx| {
                    app.draw(ctx);
                },
            );
            apply(&mut textures, output.textures_delta.clone());
            last = Some(output);
        }
        let output = last.unwrap();
        let primitives = ctx.tessellate(output.shapes, output.pixels_per_point);
        save(
            &out.join(format!("{name}.ppm")),
            &rasterize(&primitives, &textures, size),
        );
    }
}
