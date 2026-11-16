//! Shared look from the accepted mock-up: fonts, colours, buttons, cards, dialogs and the mole.
use super::{AMBER, CYAN, DIM, GREEN, INK, Palette, RED, palette_id};
use eframe::egui::{
    self, Color32, CornerRadius, FontData, FontDefinitions, FontFamily, FontId, Margin, Pos2, Rect,
    RichText, Sense, Stroke, StrokeKind, TextFormat, Vec2, text::LayoutJob,
};
use std::sync::Arc;

const SANS: &str = "MedeoSans-Regular";
const SANS_BOLD: &str = "MedeoSans-Bold";
const MONO: &str = "MedeoMono-Regular";

/// The bold Medeo Sans family as registered in the font definitions.
pub(super) fn bold_family() -> FontFamily {
    FontFamily::Name(SANS_BOLD.into())
}

thread_local! {
    static BOLD_READY: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Bold Medeo Sans for headings and the main buttons; the regular face until it is bound,
/// because a family that is not bound yet would panic in layout.
pub(super) fn bold() -> FontFamily {
    if BOLD_READY.with(std::cell::Cell::get) {
        bold_family()
    } else {
        FontFamily::Proportional
    }
}

/// Called at the start of every frame: binds Medeo once and switches to bold when it is bound.
pub(super) fn sync_fonts(ctx: &egui::Context) {
    // `set_fonts` takes effect from the next pass, and the fonts cannot be read before the
    // first pass, so readiness is the pass after the one that installed them.
    let installed = egui::Id::new("krot-fonts");
    let pass = ctx.cumulative_pass_nr();
    let ready = match ctx.data(|data| data.get_temp::<u64>(installed)) {
        Some(at) => pass > at,
        None => {
            ctx.set_fonts(fonts());
            ctx.data_mut(|data| data.insert_temp(installed, pass));
            false
        }
    };
    BOLD_READY.with(|cell| cell.set(ready));
    let heading = FontId::new(23.0, bold());
    if ctx.style().text_styles.get(&egui::TextStyle::Heading) != Some(&heading) {
        ctx.all_styles_mut(|style| {
            style
                .text_styles
                .insert(egui::TextStyle::Heading, heading.clone());
        });
    }
}

/// Medeo first; the default egui fonts stay behind it for glyphs Medeo lacks (↟ ◷ ◐ …).
pub(super) fn fonts() -> FontDefinitions {
    let mut fonts = FontDefinitions::default();
    for (name, bytes) in [
        (
            SANS,
            &include_bytes!("../../assets/fonts/MedeoSans-Regular.ttf")[..],
        ),
        (
            SANS_BOLD,
            &include_bytes!("../../assets/fonts/MedeoSans-Bold.ttf")[..],
        ),
        (
            MONO,
            &include_bytes!("../../assets/fonts/MedeoMono-Regular.ttf")[..],
        ),
    ] {
        fonts
            .font_data
            .insert(name.into(), Arc::new(FontData::from_static(bytes)));
    }
    let fallback = fonts
        .families
        .get(&FontFamily::Monospace)
        .cloned()
        .unwrap_or_default();
    for (family, first) in [
        (FontFamily::Proportional, SANS),
        (bold_family(), SANS_BOLD),
        (FontFamily::Monospace, MONO),
    ] {
        let mut chain = vec![first.to_owned()];
        chain.extend(fallback.iter().cloned());
        fonts.families.insert(family, chain);
    }
    fonts
}

/// Text sizes of the mock-up.
pub(super) fn text_styles(style: &mut egui::Style) {
    use egui::TextStyle;
    style.override_font_id = None;
    style.text_styles = [
        (TextStyle::Small, FontId::proportional(12.0)),
        (TextStyle::Body, FontId::proportional(15.0)),
        (TextStyle::Button, FontId::proportional(15.0)),
        (TextStyle::Heading, FontId::new(23.0, bold())),
        (TextStyle::Monospace, FontId::monospace(14.0)),
    ]
    .into();
}

/// Resolved colours of the current theme, classic themes included.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(super) struct Pal {
    pub bg: Color32,
    pub panel: Color32,
    pub raised: Color32,
    pub line: Color32,
    pub strong: Color32,
    pub ink: Color32,
    pub dim: Color32,
    pub accent: Color32,
    pub on_accent: Color32,
    pub ok: Color32,
    pub warn: Color32,
    pub error: Color32,
    pub selected: Color32,
}

pub(super) fn pal(ctx: &egui::Context) -> Pal {
    let rgb = Color32::from_rgb;
    if !ctx.style().visuals.dark_mode {
        return Pal {
            bg: rgb(243, 242, 236),
            panel: rgb(252, 251, 247),
            raised: rgb(232, 236, 234),
            line: rgb(201, 211, 211),
            strong: rgb(143, 163, 166),
            ink: rgb(38, 53, 58),
            dim: rgb(85, 102, 107),
            accent: rgb(22, 102, 121),
            on_accent: rgb(252, 251, 247),
            ok: rgb(51, 101, 66),
            warn: rgb(130, 89, 28),
            error: rgb(171, 52, 64),
            selected: rgb(201, 225, 227),
        };
    }
    if let Some(colors) = ctx.data(|data| data.get_temp::<Palette>(palette_id())) {
        return Pal {
            bg: colors.bg,
            panel: colors.panel,
            raised: colors.raised,
            line: colors.line,
            strong: colors.line.lerp_to_gamma(colors.dim, 0.4),
            ink: colors.ink,
            dim: colors.dim,
            accent: colors.accent,
            on_accent: colors.extreme,
            ok: colors.ok,
            warn: colors.warn,
            error: colors.error,
            selected: colors.selected,
        };
    }
    Pal {
        bg: rgb(21, 27, 30),
        panel: rgb(28, 38, 43),
        raised: rgb(38, 50, 56),
        line: rgb(52, 68, 75),
        strong: rgb(82, 99, 106),
        ink: INK,
        dim: DIM,
        accent: CYAN,
        on_accent: rgb(16, 23, 26),
        ok: GREEN,
        warn: AMBER,
        error: RED,
        selected: rgb(38, 59, 66),
    }
}

const BUTTON_HEIGHT: f32 = 40.0;
/// Above this many items lights become a bar and the list gets filters.
pub(super) const LONG_LIST: usize = 8;

/// Main action: accent fill, capital letters.
pub(super) fn primary(text: &str, pal: &Pal) -> egui::Button<'static> {
    filled(&text.to_uppercase(), pal.accent, pal)
}

/// Secondary action: outline only.
pub(super) fn secondary(text: &str, pal: &Pal) -> egui::Button<'static> {
    outline(text, pal.ink, pal.strong)
}

/// Destructive action: outline in the error colour.
pub(super) fn danger(text: &str, pal: &Pal) -> egui::Button<'static> {
    outline(text, pal.error, pal.error)
}

fn outline(text: &str, color: Color32, border: Color32) -> egui::Button<'static> {
    egui::Button::new(RichText::new(text).color(color))
        .fill(Color32::TRANSPARENT)
        .stroke(Stroke::new(1.0_f32, border))
        .corner_radius(4)
        .min_size(Vec2::new(0.0, BUTTON_HEIGHT))
}

/// A bold outline in one colour, for an action that belongs to a coloured block.
pub(super) fn tinted(text: &str, color: Color32) -> egui::Button<'static> {
    egui::Button::new(RichText::new(text).family(bold()).color(color))
        .fill(Color32::TRANSPARENT)
        .stroke(Stroke::new(1.0_f32, color))
        .corner_radius(4)
        .min_size(Vec2::new(0.0, BUTTON_HEIGHT))
}

/// A tab or a choice: filled with the accent when selected.
pub(super) fn choice(text: &str, selected: bool, pal: &Pal) -> egui::Button<'static> {
    if selected {
        filled(text, pal.accent, pal)
    } else {
        outline(text, pal.ink, pal.line)
    }
}

/// Small spaced capitals above a block: «НА УЧАСТКЕ».
pub(super) fn caps(ui: &mut egui::Ui, text: &str, color: Color32) -> egui::Response {
    let mut job = LayoutJob::default();
    job.append(
        &text.to_uppercase(),
        0.0,
        TextFormat {
            font_id: FontId::proportional(12.0),
            color,
            extra_letter_spacing: 1.2,
            ..Default::default()
        },
    );
    ui.label(job)
}

/// A sunken block inside a card: page colour, thin border.
pub(super) fn well(pal: &Pal) -> egui::Frame {
    egui::Frame::new()
        .fill(pal.bg)
        .stroke(Stroke::new(1.0_f32, pal.line))
        .corner_radius(4)
        .inner_margin(Margin::same(14))
}

pub(super) fn card(pal: &Pal) -> egui::Frame {
    egui::Frame::new()
        .fill(pal.panel)
        .stroke(Stroke::new(1.0_f32, pal.line))
        .corner_radius(6)
        .inner_margin(Margin::same(18))
}

/// A framed group of form fields with a title, like a fieldset.
pub(super) fn group<R>(
    ui: &mut egui::Ui,
    title: &str,
    title_color: Color32,
    pal: &Pal,
    add: impl FnOnce(&mut egui::Ui) -> R,
) -> R {
    egui::Frame::new()
        .stroke(Stroke::new(1.0_f32, pal.line))
        .corner_radius(4)
        .inner_margin(Margin::same(14))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.label(RichText::new(title).family(bold()).color(title_color));
            ui.add_space(4.0);
            add(ui)
        })
        .inner
}

/// A labelled single-line text field; addresses and ports use the monospace font.
pub(super) fn field(ui: &mut egui::Ui, label: &str, value: &mut String, pal: &Pal) {
    ui.label(RichText::new(label).size(13.0).color(pal.dim));
    ui.add(
        egui::TextEdit::singleline(value)
            .font(egui::TextStyle::Monospace)
            .margin(Vec2::new(10.0, 9.0))
            .desired_width(f32::INFINITY),
    );
}

/// The lever switch of a tunnel or rule row. `busy` keeps the knob in the middle.
pub(super) fn lever(
    ui: &mut egui::Ui,
    on: bool,
    busy: bool,
    color: Color32,
    pal: &Pal,
    label: &str,
    motion: bool,
) -> egui::Response {
    let (rect, response) = ui.allocate_exact_size(Vec2::new(72.0, 44.0), Sense::click());
    response.widget_info(|| {
        egui::WidgetInfo::selected(egui::WidgetType::Checkbox, ui.is_enabled(), on, label)
    });
    let target = if busy {
        0.5
    } else if on {
        1.0
    } else {
        0.0
    };
    let position = if motion {
        ui.ctx().animate_value_with_time(response.id, target, 0.18)
    } else {
        target
    };
    let track = Rect::from_center_size(rect.center(), Vec2::new(64.0, 32.0));
    let filled = on && !busy;
    ui.painter().rect(
        track,
        6,
        if filled { color } else { pal.bg },
        Stroke::new(2.0_f32, if on || busy { color } else { pal.strong }),
        StrokeKind::Inside,
    );
    let travel = track.width() - 6.0 - 22.0;
    let knob = Rect::from_min_size(
        Pos2::new(track.left() + 3.0 + travel * position, track.top() + 5.0),
        Vec2::splat(22.0),
    );
    ui.painter()
        .rect_filled(knob, 3, if filled { pal.on_accent } else { color });
    if response.has_focus() {
        ui.painter().rect_stroke(
            rect.shrink(1.0),
            4,
            Stroke::new(2.0_f32, pal.ink),
            StrokeKind::Inside,
        );
    }
    response
}

/// One state light of the summary line.
#[derive(Clone)]
pub(super) struct Lamp {
    pub color: Color32,
    pub filled: bool,
    pub blink: bool,
    pub selected: bool,
    pub name: String,
    pub group: super::Group,
}

/// Up to eight round lights; beyond that one bar of equal sectors in list order.
pub(super) fn lamps(ui: &mut egui::Ui, lamps: &[Lamp], blink_on: bool, pal: &Pal) {
    let visible = |lamp: &Lamp| !lamp.blink || blink_on;
    if lamps.len() <= LONG_LIST {
        let size = Vec2::new(lamps.len() as f32 * 26.0, 22.0);
        let (rect, response) = ui.allocate_exact_size(size, Sense::hover());
        for (index, lamp) in lamps.iter().enumerate() {
            let center = Pos2::new(rect.left() + 11.0 + index as f32 * 26.0, rect.center().y);
            let color = if visible(lamp) {
                lamp.color
            } else {
                lamp.color.gamma_multiply(0.3)
            };
            if lamp.filled {
                ui.painter().circle_filled(center, 8.0, color);
            }
            ui.painter()
                .circle_stroke(center, 8.0, Stroke::new(2.0_f32, color));
        }
        hover_lamp(&response, lamps, |pos| {
            ((pos.x - rect.left()) / 26.0).floor() as usize
        });
        return;
    }
    let (rect, response) = ui.allocate_exact_size(Vec2::new(260.0, 22.0), Sense::hover());
    ui.painter().rect(
        rect,
        4,
        pal.bg,
        Stroke::new(1.0_f32, pal.strong),
        StrokeKind::Inside,
    );
    let inner = rect.shrink(3.0);
    let gap = 2.0;
    let width = (inner.width() - gap * (lamps.len() - 1) as f32) / lamps.len() as f32;
    for (index, lamp) in lamps.iter().enumerate() {
        let left = inner.left() + index as f32 * (width + gap);
        let sector = Rect::from_min_size(
            Pos2::new(left, inner.top()),
            Vec2::new(width, inner.height()),
        );
        let color = if !lamp.filled {
            pal.line
        } else if visible(lamp) {
            lamp.color
        } else {
            lamp.color.gamma_multiply(0.3)
        };
        ui.painter().rect_filled(sector, 2, color);
        if lamp.selected {
            ui.painter().rect_stroke(
                sector.expand(1.5),
                2,
                Stroke::new(2.0_f32, pal.ink),
                StrokeKind::Outside,
            );
        }
    }
    hover_lamp(&response, lamps, |pos| {
        ((pos.x - inner.left()) / (width + gap)).floor() as usize
    });
}

fn hover_lamp(response: &egui::Response, lamps: &[Lamp], index: impl Fn(Pos2) -> usize) {
    if let Some(pos) = response.hover_pos()
        && let Some(lamp) = lamps.get(index(pos))
    {
        response.clone().on_hover_text(&lamp.name);
    }
}

/// Wire state between two nodes of the route scheme.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Wire {
    Idle,
    Trying,
    Live,
}

pub(super) struct Node {
    pub title: String,
    pub value: String,
    pub lit: bool,
}

/// Local end, SSH node and far end joined by dashed wires that run while traffic flows.
pub(super) fn route(
    ui: &mut egui::Ui,
    nodes: &[Node; 3],
    wires: [Wire; 2],
    color: Color32,
    time: Option<f64>,
    pal: &Pal,
) {
    egui::Frame::new()
        .fill(pal.bg)
        .stroke(Stroke::new(1.0_f32, pal.line))
        .corner_radius(4)
        .inner_margin(Margin::same(14))
        .show(ui, |ui| {
            let wide = ui.available_width() >= 420.0;
            let wire = 28.0;
            if wide {
                let width =
                    (ui.available_width() - 2.0 * (wire + 2.0 * ui.spacing().item_spacing.x)) / 3.0;
                ui.horizontal(|ui| {
                    for (index, node) in nodes.iter().enumerate() {
                        route_node(ui, node, width, color, pal);
                        if index < 2 {
                            let (rect, _) =
                                ui.allocate_exact_size(Vec2::new(wire, 60.0), Sense::hover());
                            dashes(
                                ui,
                                rect.left_center(),
                                rect.right_center(),
                                wires[index],
                                color,
                                time,
                                pal,
                            );
                        }
                    }
                });
            } else {
                for (index, node) in nodes.iter().enumerate() {
                    route_node(ui, node, ui.available_width(), color, pal);
                    if index < 2 {
                        let (rect, _) = ui.allocate_exact_size(
                            Vec2::new(ui.available_width(), 18.0),
                            Sense::hover(),
                        );
                        let x = rect.left() + 24.0;
                        dashes(
                            ui,
                            Pos2::new(x, rect.top()),
                            Pos2::new(x, rect.bottom()),
                            wires[index],
                            color,
                            time,
                            pal,
                        );
                    }
                }
            }
        });
}

fn route_node(ui: &mut egui::Ui, node: &Node, width: f32, color: Color32, pal: &Pal) {
    egui::Frame::new()
        .stroke(Stroke::new(
            2.0_f32,
            if node.lit { color } else { pal.line },
        ))
        .corner_radius(4)
        .inner_margin(Margin::symmetric(12, 10))
        .show(ui, |ui| {
            ui.set_width(width - 24.0 - 4.0);
            ui.vertical(|ui| {
                ui.spacing_mut().item_spacing.y = 2.0;
                ui.label(RichText::new(&node.title).size(13.0).color(pal.dim));
                ui.add(
                    egui::Label::new(RichText::new(&node.value).monospace().color(pal.ink)).wrap(),
                );
            });
        });
}

fn dashes(
    ui: &egui::Ui,
    from: Pos2,
    to: Pos2,
    wire: Wire,
    color: Color32,
    time: Option<f64>,
    pal: &Pal,
) {
    let (stroke_color, speed) = match wire {
        Wire::Idle => (pal.strong, 0.0),
        Wire::Trying => (color, 10.0),
        Wire::Live => (color, 28.0),
    };
    let length = from.distance(to);
    if length < 1.0 {
        return;
    }
    let direction = (to - from) / length;
    let period = 16.0;
    let offset = time.map_or(0.0, |time| (time * speed) as f32 % period);
    let mut start = offset - period;
    while start < length {
        let a = start.max(0.0);
        let b = (start + period / 2.0).min(length);
        if b > a {
            ui.painter().line_segment(
                [from + direction * a, from + direction * b],
                Stroke::new(3.0_f32, stroke_color),
            );
        }
        start += period;
    }
}

/// What the mole does in a frame of its animation.
#[derive(Clone, Copy, Default)]
pub(super) struct Pose {
    /// -1 left, 0 straight, 1 right.
    pub look: i8,
    pub lamp_dim: bool,
    /// `None` draws no rays; `Some(phase)` alternates the two ray groups.
    pub rays: Option<bool>,
}

impl Pose {
    /// Pupils left, right, centre in turn; a blinking lamp and rays. Still when motion is off.
    pub fn at(milliseconds: Option<u128>, rays: bool) -> Self {
        let Some(ms) = milliseconds else {
            return Self {
                look: 0,
                lamp_dim: false,
                rays: rays.then_some(true),
            };
        };
        Self {
            look: [-1, 1, 0][(ms / 1500 % 3) as usize],
            lamp_dim: matches!(ms % 5000, 4200..=4400 | 4600..=4800),
            rays: rays.then_some(ms / 800 % 2 == 0),
        }
    }
}

const MOLE: [&str; 13] = [
    ".....oooooo.....",
    "....oyyggyyo....",
    "...oyygwwgyyo...",
    "..oyyygwwgyyyo..",
    "..odddggggdddo..",
    "oyyyyyyyyyyyyyyo",
    ".offffffffffffo.",
    ".ofllllffllllfo.",
    "sofllllffllllfos",
    "sofllllffllllfos",
    ".ofllllffllllfo.",
    ".offffffffffffo.",
    "..oooooooooooo..",
];

/// The mole in a miner's helmet, drawn from whole pixels of size `cell`.
pub(super) fn mole(ui: &mut egui::Ui, cell: f32, pose: Pose, pal: &Pal) -> egui::Response {
    let ray_rows = if pose.rays.is_some() { 3.0 } else { 0.0 };
    let size = Vec2::new(16.0 * cell, (MOLE.len() as f32 + ray_rows) * cell);
    let (rect, response) = ui.allocate_exact_size(size, Sense::hover());
    let origin = rect.min + Vec2::new(0.0, ray_rows * cell);
    let pixel = |x: f32, y: f32, color: Color32| {
        ui.painter().rect_filled(
            Rect::from_min_size(origin + Vec2::new(x * cell, y * cell), Vec2::splat(cell)),
            0,
            color,
        );
    };
    let outline = Color32::from_rgb(16, 17, 19);
    let lamp = Color32::from_rgb(255, 246, 208);
    for (y, row) in MOLE.iter().enumerate() {
        for (x, code) in row.chars().enumerate() {
            let color = match code {
                'o' => outline,
                'y' => pal.accent,
                'd' => pal.accent.lerp_to_gamma(Color32::BLACK, 0.22),
                'g' => Color32::from_rgb(58, 61, 66),
                'w' if pose.lamp_dim => lamp.gamma_multiply(0.45),
                'w' => lamp,
                'f' => pal.ink,
                'l' => pal.bg,
                's' => pal.strong,
                _ => continue,
            };
            pixel(x as f32, y as f32, color);
        }
    }
    for lens in [4.0, 10.0] {
        let x = lens + f32::from(pose.look);
        for (dx, dy) in [(0.0, 0.0), (1.0, 0.0), (0.0, 1.0), (1.0, 1.0)] {
            pixel(x + dx, 8.0 + dy, pal.accent);
        }
        pixel(x, 8.0, pal.ink);
    }
    if let Some(phase) = pose.rays {
        for (x, y, group) in [
            (7.0, -3.0, true),
            (8.0, -3.0, true),
            (7.0, -2.0, true),
            (8.0, -2.0, true),
            (4.0, -2.0, false),
            (11.0, -2.0, false),
            (2.0, -1.0, true),
            (13.0, -1.0, true),
        ] {
            let on = group == phase;
            pixel(x, y, if on { lamp } else { lamp.gamma_multiply(0.15) });
        }
    }
    response
}

/// The dialog panel: a frame over a darkened window, with an accent strip on top.
pub(super) fn modal<R>(
    ctx: &egui::Context,
    id: &str,
    strip: Color32,
    content: impl FnOnce(&mut egui::Ui) -> R,
) -> egui::ModalResponse<R> {
    let pal = pal(ctx);
    let margin = Margin {
        left: 24,
        right: 24,
        top: 24,
        bottom: 20,
    };
    egui::Modal::new(egui::Id::new(id))
        .frame(
            egui::Frame::new()
                .fill(pal.panel)
                .stroke(Stroke::new(1.0_f32, pal.line))
                .corner_radius(6)
                .inner_margin(margin),
        )
        .backdrop_color(Color32::from_black_alpha(158))
        .show(ctx, |ui| {
            let inner = content(ui);
            let area = ui.min_rect();
            let strip_rect = Rect::from_min_max(
                Pos2::new(
                    area.left() - f32::from(margin.left),
                    area.top() - f32::from(margin.top),
                ),
                Pos2::new(
                    area.right() + f32::from(margin.right),
                    area.top() - f32::from(margin.top) + 4.0,
                ),
            );
            ui.painter().rect_filled(
                strip_rect,
                CornerRadius {
                    nw: 6,
                    ne: 6,
                    sw: 0,
                    se: 0,
                },
                strip,
            );
            inner
        })
}

/// A filled button for a risky confirmation: replacing a host key, deleting.
pub(super) fn filled(text: &str, fill: Color32, pal: &Pal) -> egui::Button<'static> {
    egui::Button::new(RichText::new(text).family(bold()).color(pal.on_accent))
        .fill(fill)
        .stroke(Stroke::NONE)
        .corner_radius(4)
        .min_size(Vec2::new(0.0, BUTTON_HEIGHT))
}

pub(super) fn alarm(text: &str, pal: &Pal) -> egui::Button<'static> {
    filled(text, pal.warn, pal)
}

/// A theme as a card in its own colours, with samples of the accent, warning and panel.
pub(super) fn theme_card(
    ui: &mut egui::Ui,
    label: &str,
    mark: &str,
    colors: &Palette,
    selected: bool,
) -> egui::Response {
    let (rect, response) = ui.allocate_exact_size(Vec2::new(150.0, 104.0), Sense::click());
    response.widget_info(|| {
        egui::WidgetInfo::selected(
            egui::WidgetType::RadioButton,
            ui.is_enabled(),
            selected,
            label,
        )
    });
    let border = if selected {
        colors.accent
    } else if response.hovered() {
        colors.dim
    } else {
        colors.line
    };
    ui.painter().rect(
        rect,
        6,
        colors.bg,
        Stroke::new(3.0_f32, border),
        StrokeKind::Inside,
    );
    for (index, (fill, stroke)) in [
        (colors.accent, colors.accent),
        (colors.warn, colors.warn),
        (colors.panel, colors.line),
    ]
    .into_iter()
    .enumerate()
    {
        let swatch = Rect::from_min_size(
            rect.min + Vec2::new(14.0 + index as f32 * 26.0, 14.0),
            Vec2::splat(22.0),
        );
        ui.painter().rect(
            swatch,
            3,
            fill,
            Stroke::new(1.0_f32, stroke),
            StrokeKind::Inside,
        );
    }
    ui.painter().text(
        rect.min + Vec2::new(14.0, 50.0),
        egui::Align2::LEFT_TOP,
        label,
        FontId::new(16.0, bold()),
        colors.ink,
    );
    if !mark.is_empty() {
        ui.painter().text(
            rect.min + Vec2::new(14.0, 76.0),
            egui::Align2::LEFT_TOP,
            mark,
            FontId::proportional(13.0),
            colors.dim,
        );
    }
    if response.has_focus() {
        ui.painter().rect_stroke(
            rect.expand(2.0),
            8,
            Stroke::new(2.0_f32, colors.ink),
            StrokeKind::Outside,
        );
    }
    response
}

/// The sign before a request title: a triangle for a host key, a circle for a password.
pub(super) fn sign(ui: &mut egui::Ui, symbol: char, color: Color32) {
    let (rect, _) = ui.allocate_exact_size(Vec2::splat(30.0), Sense::hover());
    let center = rect.center();
    if symbol == '!' {
        let points = vec![
            Pos2::new(center.x, rect.top() + 2.0),
            Pos2::new(rect.right() - 1.0, rect.bottom() - 3.0),
            Pos2::new(rect.left() + 1.0, rect.bottom() - 3.0),
        ];
        ui.painter().add(egui::Shape::convex_polygon(
            points,
            Color32::TRANSPARENT,
            Stroke::new(2.0_f32, color),
        ));
    } else {
        ui.painter()
            .circle_stroke(center, 13.0, Stroke::new(2.0_f32, color));
    }
    ui.painter().text(
        center + Vec2::new(0.0, if symbol == '!' { 3.0 } else { 0.0 }),
        egui::Align2::CENTER_CENTER,
        symbol,
        FontId::new(15.0, bold()),
        color,
    );
}

/// A keyboard key in the help table.
pub(super) fn kbd(ui: &mut egui::Ui, text: &str, pal: &Pal) {
    egui::Frame::new()
        .fill(pal.bg)
        .stroke(Stroke::new(1.0_f32, pal.strong))
        .corner_radius(4)
        .inner_margin(Margin::symmetric(8, 2))
        .show(ui, |ui| {
            ui.label(RichText::new(text).monospace().size(13.0).color(pal.ink));
        });
}

/// Title-and-value pairs in cells of equal width: four in a row when wide, two otherwise.
pub(super) fn facts(ui: &mut egui::Ui, pairs: &[(&str, String)], pal: &Pal) {
    let columns = if ui.available_width() >= 640.0 { 4 } else { 2 };
    let gap = 24.0;
    let width = (ui.available_width() - gap * (columns - 1) as f32) / columns as f32;
    for chunk in pairs.chunks(columns) {
        ui.horizontal_top(|ui| {
            ui.spacing_mut().item_spacing.x = gap;
            for (title, value) in chunk {
                ui.allocate_ui_with_layout(
                    Vec2::new(width, 0.0),
                    egui::Layout::top_down(egui::Align::Min),
                    |ui| {
                        ui.set_width(width);
                        ui.spacing_mut().item_spacing.y = 2.0;
                        ui.label(RichText::new(*title).size(13.0).color(pal.dim));
                        ui.add(egui::Label::new(value.as_str()).wrap());
                    },
                );
            }
        });
    }
}
