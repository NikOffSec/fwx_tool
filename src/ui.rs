use anyhow::Result;

use binwalk::signatures::common::SignatureResult;
use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use ratatui::{
    DefaultTerminal, Frame,
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{
        Bar, BarChart, BarGroup, Block, Cell, List, ListItem, ListState, Paragraph, Row, Table,
        TableState, Wrap,
    },
};

use crate::{disassemble, extract, metadata};

const ENTROPY_BLOCK_SIZE: usize = 1024;

const DEFAULT_STATUS: &str =
    "[Tab] switch pane   [↑/↓] scroll   [e] extract   [m] disasm metadata   [q] quit";

/// Labels for the manual-metadata form, in tab order.
const DISASM_FIELDS: [&str; 4] = [
    "Architecture",
    "Endianness",
    "Base address (hex)",
    "Offset (hex)",
];

#[derive(Clone, Copy, PartialEq, Eq)]
enum Pane {
    Disasm,
    Files,
    Strings,
    Entropy,
}

/// State of the manual-metadata entry form shown in the disassembly pane when
/// automatic detection fails.
struct DisasmForm {
    values: [String; 4],
    active: usize,
    error: Option<String>,
}

impl DisasmForm {
    fn new() -> Self {
        Self {
            // Base address and offset default to 0, which is the right guess for
            // a raw firmware blob loaded at the start of memory.
            values: [String::new(), String::new(), "0".to_string(), "0".to_string()],
            active: 0,
            error: None,
        }
    }
}

pub struct App {
    // Inputs kept around so extraction can run on demand.
    filepath: String,
    firmware: Vec<u8>,

    // Precomputed analysis results.
    disasm: Vec<disassemble::Insn>,
    disasm_err: Option<String>,
    findings: Option<Vec<SignatureResult>>,
    strings: Vec<(String, u64, bool)>,
    strings_err: Option<String>,
    entropy: Vec<(usize, f64)>,

    // UI state.
    status: String,
    focus: Pane,
    disasm_state: TableState,
    files_state: ListState,
    strings_state: ListState,
    // When Some, the disassembly pane is in manual-metadata entry mode and
    // captures keystrokes for the form.
    disasm_input: Option<DisasmForm>,
    should_quit: bool,
}

/// Entry point called from main(): sets up the terminal, runs the loop,
/// and restores the terminal afterwards (init() also installs a panic hook
/// that restores the terminal, so a panic won't wreck your prompt).
pub fn run(firmware: Vec<u8>, filepath: String) -> Result<()> {
    let terminal = ratatui::init();
    let app = App::new(firmware, filepath);
    let result = app.main_loop(terminal);
    ratatui::restore();
    result
}

impl App {
    fn new(firmware: Vec<u8>, filepath: String) -> Self {
        // Run every analysis once, up front.
        let (disasm, disasm_err) = match disassemble::disassembler(&firmware) {
            Ok(d) => (d, None),
            Err(e) => (Vec::new(), Some(e)),
        };
        let findings = extract::scan(&firmware);
        let (strings, strings_err) = match metadata::extract_strings(&firmware) {
            Ok(s) => (metadata::prioritize_strings(s), None),
            Err(e) => (Vec::new(), Some(e.to_string())),
        };
        let entropy = metadata::entropy_scan(&firmware, ENTROPY_BLOCK_SIZE);

        // Seed selections so the highlight has somewhere to sit.
        let mut disasm_state = TableState::default();
        if !disasm.is_empty() {
            disasm_state.select(Some(0));
        }
        let mut files_state = ListState::default();
        if findings.as_ref().is_some_and(|f| !f.is_empty()) {
            files_state.select(Some(0));
        }
        let mut strings_state = ListState::default();
        if !strings.is_empty() {
            strings_state.select(Some(0));
        }

        Self {
            filepath,
            firmware,
            disasm,
            disasm_err,
            findings,
            strings,
            strings_err,
            entropy,
            status: DEFAULT_STATUS.to_string(),
            focus: Pane::Disasm,
            disasm_state,
            files_state,
            strings_state,
            disasm_input: None,
            should_quit: false,
        }
    }

    fn main_loop(mut self, mut terminal: DefaultTerminal) -> Result<()> {
        while !self.should_quit {
            terminal.draw(|frame| self.render(frame))?;
            self.handle_events()?;
        }
        Ok(())
    }

    // ---- events -----------------------------------------------------------

    fn handle_events(&mut self) -> Result<()> {
        if let Event::Key(key) = event::read()? {
            // On Windows a key generates both Press and Release events; ignore
            // everything that isn't a press so actions don't fire twice.
            if key.kind != KeyEventKind::Press {
                return Ok(());
            }
            // While the manual-metadata form is open it owns the keyboard, so
            // typing "q", "j", etc. edits fields instead of driving the UI.
            if self.disasm_input.is_some() {
                self.handle_form_key(key.code);
                return Ok(());
            }
            match key.code {
                KeyCode::Char('q') | KeyCode::Esc => self.should_quit = true,
                KeyCode::Tab => self.cycle_focus(),
                KeyCode::Down | KeyCode::Char('j') => self.scroll(1),
                KeyCode::Up | KeyCode::Char('k') => self.scroll(-1),
                KeyCode::PageDown => self.scroll(10),
                KeyCode::PageUp => self.scroll(-10),
                KeyCode::Char('e') => self.extract(),
                KeyCode::Char('m') => self.open_disasm_form(),
                _ => {}
            }
        }
        Ok(())
    }

    fn cycle_focus(&mut self) {
        self.focus = match self.focus {
            Pane::Disasm => Pane::Files,
            Pane::Files => Pane::Strings,
            Pane::Strings => Pane::Entropy,
            Pane::Entropy => Pane::Disasm,
        };
    }

    fn scroll(&mut self, delta: isize) {
        match self.focus {
            Pane::Disasm => {
                let n = self.disasm.len();
                let sel = step(self.disasm_state.selected(), delta, n);
                self.disasm_state.select(sel);
            }
            Pane::Files => {
                let n = self.findings.as_ref().map_or(0, |f| f.len());
                let sel = step(self.files_state.selected(), delta, n);
                self.files_state.select(sel);
            }
            Pane::Strings => {
                let n = self.strings.len();
                let sel = step(self.strings_state.selected(), delta, n);
                self.strings_state.select(sel);
            }
            Pane::Entropy => {} // static chart, nothing to scroll
        }
    }

    fn extract(&mut self) {
        match self.findings.as_ref() {
            Some(sigs) if !sigs.is_empty() => {
                self.status = match extract::unpack(self.filepath.clone(), &self.firmware, sigs) {
                    Ok(results) if results.is_empty() => {
                        "Extraction ran, but nothing was carved out.".to_string()
                    }
                    Ok(results) => {
                        format!("Extracted {} item(s) into ./extracted", results.len())
                    }
                    Err(e) => format!("Extraction failed: {e}"),
                };
            }
            _ => self.status = "No signatures available to extract.".to_string(),
        }
    }

    // ---- manual disassembly metadata --------------------------------------

    /// Open the manual-metadata form (only meaningful from the disasm pane).
    fn open_disasm_form(&mut self) {
        if self.focus != Pane::Disasm {
            self.status = "Focus the Disassembly pane (Tab) before entering metadata.".to_string();
            return;
        }
        self.disasm_input = Some(DisasmForm::new());
        self.status =
            "Manual metadata: type values · [Tab]/[↑↓] field · [Enter] run · [Esc] cancel"
                .to_string();
    }

    /// Route a keystroke to the open form: edit fields, move between them, or
    /// submit / cancel.
    fn handle_form_key(&mut self, code: KeyCode) {
        match code {
            KeyCode::Esc => {
                self.disasm_input = None;
                self.status = DEFAULT_STATUS.to_string();
            }
            KeyCode::Enter => self.submit_disasm_form(),
            other => {
                if let Some(form) = self.disasm_input.as_mut() {
                    match other {
                        KeyCode::Tab | KeyCode::Down => {
                            form.active = (form.active + 1) % DISASM_FIELDS.len();
                        }
                        KeyCode::Up => {
                            form.active = (form.active + DISASM_FIELDS.len() - 1) % DISASM_FIELDS.len();
                        }
                        KeyCode::Backspace => {
                            form.values[form.active].pop();
                        }
                        KeyCode::Char(c) => form.values[form.active].push(c),
                        _ => {}
                    }
                }
            }
        }
    }

    /// Validate the form and, if it parses, run the disassembler with the
    /// user-supplied metadata. A parse error stays in the form; a disassembly
    /// error closes the form and is surfaced so the user can retry with [m].
    fn submit_disasm_form(&mut self) {
        let Some(form) = self.disasm_input.as_ref() else {
            return;
        };

        let meta = match Self::parse_form(form) {
            Ok(meta) => meta,
            Err(msg) => {
                if let Some(form) = self.disasm_input.as_mut() {
                    form.error = Some(msg);
                }
                return;
            }
        };

        match disassemble::disassemble_manual(&self.firmware, &meta) {
            Ok(disasm) => {
                self.disasm = disasm;
                self.disasm_err = None;
                self.disasm_input = None;
                self.disasm_state = TableState::default();
                self.disasm_state.select(Some(0));
                self.status =
                    format!("Disassembled {} instruction(s) from manual metadata.", self.disasm.len());
            }
            Err(e) => {
                self.disasm_err = Some(e.clone());
                self.disasm_input = None;
                self.status = format!("Disassembly failed: {e}  —  press [m] to try new data");
            }
        }
    }

    /// Turn the raw form strings into a `ManualMeta`, reporting the first bad
    /// field as an error string.
    fn parse_form(form: &DisasmForm) -> Result<disassemble::ManualMeta, String> {
        let arch = disassemble::parse_arch(&form.values[0])
            .ok_or_else(|| format!("unknown architecture: '{}'", form.values[0].trim()))?;
        let endian = disassemble::parse_endian(&form.values[1])
            .ok_or("endianness must be 'little'/'le' or 'big'/'be'")?;
        let base_addr = disassemble::parse_hex(&form.values[2])
            .ok_or("base address must be a hex number (e.g. 0x80000000)")?;
        let offset = if form.values[3].trim().is_empty() {
            0
        } else {
            disassemble::parse_hex(&form.values[3]).ok_or("offset must be a hex number")? as usize
        };
        Ok(disassemble::ManualMeta {
            arch,
            endian,
            base_addr,
            offset,
        })
    }

    // ---- rendering --------------------------------------------------------

    fn render(&mut self, frame: &mut Frame) {
        // Reserve one line at the bottom for status/help, grid takes the rest.
        let [body, status_area] =
            Layout::vertical([Constraint::Fill(1), Constraint::Length(1)]).areas(frame.area());

        // 2x2 grid.
        let [top, bottom] =
            Layout::vertical([Constraint::Percentage(50), Constraint::Percentage(50)]).areas(body);
        let [top_left, top_right] =
            Layout::horizontal([Constraint::Percentage(50), Constraint::Percentage(50)]).areas(top);
        let [bottom_left, bottom_right] =
            Layout::horizontal([Constraint::Percentage(50), Constraint::Percentage(50)])
                .areas(bottom);

        self.render_disasm(frame, top_left);
        self.render_files(frame, top_right);
        self.render_strings(frame, bottom_left);
        self.render_entropy(frame, bottom_right);

        // ---- center logo overlay (render later, once art exists) ----------
        // Widgets drawn later paint over earlier ones, so this sits on top of
        // the grid. Clear wipes the cells underneath first.
        //
        // let logo_area = centered_rect(body, 24, 8);
        // frame.render_widget(ratatui::widgets::Clear, logo_area);
        // frame.render_widget(
        //     Paragraph::new("FWX")
        //         .alignment(ratatui::layout::Alignment::Center)
        //         .block(Block::bordered().title("Logo")),
        //     logo_area,
        // );

        frame.render_widget(
            Paragraph::new(self.status.as_str()).style(Style::new().fg(Color::DarkGray)),
            status_area,
        );
    }

    /// A bordered block whose border lights up when its pane has focus.
    fn pane_block(&self, title: &str, pane: Pane) -> Block<'static> {
        let mut block = Block::bordered().title(title.to_string());
        if self.focus == pane {
            block = block.border_style(Style::new().fg(Color::Cyan));
        }
        block
    }

    fn render_disasm(&mut self, frame: &mut Frame, area: Rect) {
        let block = self.pane_block("Disassembly Listing", Pane::Disasm);

        // Manual-metadata form takes over the pane while it is open.
        if let Some(form) = &self.disasm_input {
            let inner = block.inner(area);
            frame.render_widget(block, area);
            frame.render_widget(
                Paragraph::new(disasm_form_lines(form)).wrap(Wrap { trim: false }),
                inner,
            );
            return;
        }

        if self.disasm.is_empty() {
            let mut lines = vec![
                Line::from("No disassembly available."),
                Line::from(""),
                Line::from(
                    "Automatic architecture detection failed (no object header / base address).",
                ),
            ];
            if let Some(err) = &self.disasm_err {
                lines.push(Line::from(""));
                lines.push(Line::from(Span::styled(
                    format!("reason: {err}"),
                    Style::new().fg(Color::Red),
                )));
            }
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                "Press [m] to enter the binary's metadata manually.",
                Style::new().fg(Color::Cyan),
            )));
            let msg = Paragraph::new(lines).block(block).wrap(Wrap { trim: false });
            frame.render_widget(msg, area);
            return;
        }

        let rows = self.disasm.iter().map(|(addr, bytes, mnem, ops)| {
            Row::new(vec![
                Cell::from(format!("{addr:08x}")),
                Cell::from(bytes.clone()).style(Style::new().fg(Color::DarkGray)),
                Cell::from(mnem.clone()).style(Style::new().fg(Color::Yellow)),
                Cell::from(ops.clone()),
            ])
        });
        let widths = [
            Constraint::Length(10),
            Constraint::Length(18),
            Constraint::Length(8),
            Constraint::Fill(1),
        ];
        let table = Table::new(rows, widths)
            .block(block)
            // NOTE: on ratatui < 0.29 this method is `highlight_style`.
            .row_highlight_style(
                Style::new()
                    .bg(Color::DarkGray)
                    .add_modifier(Modifier::BOLD),
            )
            .highlight_symbol("▶ ");
        frame.render_stateful_widget(table, area, &mut self.disasm_state);
    }

    fn render_files(&mut self, frame: &mut Frame, area: Rect) {
        let block = self.pane_block("Files Found  ([e] to extract)", Pane::Files);

        let items: Vec<ListItem> = match self.findings.as_ref() {
            Some(sigs) if !sigs.is_empty() => sigs
                .iter()
                .map(|s| {
                    ListItem::new(Line::from(format!(
                        "0x{:08x}  {:<14}  {}",
                        s.offset, s.name, s.description
                    )))
                })
                .collect(),
            _ => vec![ListItem::new("(no signatures found)")],
        };

        let list = List::new(items)
            .block(block)
            .highlight_style(
                Style::new()
                    .bg(Color::DarkGray)
                    .add_modifier(Modifier::BOLD),
            )
            .highlight_symbol("▶ ");
        frame.render_stateful_widget(list, area, &mut self.files_state);
    }

    fn render_strings(&mut self, frame: &mut Frame, area: Rect) {
        let important_count = self.strings.iter().filter(|(_, _, imp)| *imp).count();
        let title = if important_count > 0 {
            format!("Strings Found  (★ {important_count} of interest, shown first)")
        } else {
            "Strings Found".to_string()
        };
        let block = self.pane_block(&title, Pane::Strings);

        if let Some(err) = &self.strings_err {
            frame.render_widget(
                Paragraph::new(format!("error extracting strings: {err}"))
                    .block(block)
                    .style(Style::new().fg(Color::Red)),
                area,
            );
            return;
        }

        let items: Vec<ListItem> = if self.strings.is_empty() {
            vec![ListItem::new("(no strings found)")]
        } else {
            self.strings
                .iter()
                .map(|(s, off, important)| {
                    let marker = if *important { "★ " } else { "  " };
                    let item = ListItem::new(Line::from(format!("{marker}0x{off:08x}  {s}")));
                    if *important {
                        item.style(Style::new().fg(Color::Green).add_modifier(Modifier::BOLD))
                    } else {
                        item
                    }
                })
                .collect()
        };

        let list = List::new(items)
            .block(block)
            .highlight_style(
                Style::new()
                    .bg(Color::DarkGray)
                    .add_modifier(Modifier::BOLD),
            )
            .highlight_symbol("▶ ");
        frame.render_stateful_widget(list, area, &mut self.strings_state);
    }

    fn render_entropy(&mut self, frame: &mut Frame, area: Rect) {
        let block = self.pane_block("Entropy Blocks", Pane::Entropy);

        if self.entropy.is_empty() {
            frame.render_widget(Paragraph::new("(no entropy data)").block(block), area);
            return;
        }

        // Paint the border first, then split the interior into an info line and
        // the chart area below it.
        let inner = block.inner(area);
        frame.render_widget(block, area);

        let [info_area, chart_area] =
            Layout::vertical([Constraint::Length(1), Constraint::Fill(1)]).areas(inner);

        // Spell out how one entropy block relates to the whole file so the bar
        // widths mean something: block size, total size, and each block's share.
        let file_size = self.firmware.len();
        let block_pct = if file_size > 0 {
            ENTROPY_BLOCK_SIZE as f64 / file_size as f64 * 100.0
        } else {
            0.0
        };
        let info = format!(
            "block {} · file {} · {} blocks (1 block ≈ {:.3}% of file)",
            human_size(ENTROPY_BLOCK_SIZE),
            human_size(file_size),
            self.entropy.len(),
            block_pct,
        );
        frame.render_widget(
            Paragraph::new(info).style(Style::new().fg(Color::DarkGray)),
            info_area,
        );

        // Fit the number of bars to the available inner width.
        let bar_width = 6u16;
        let bar_gap = 1u16;
        let n_bars = ((chart_area.width + bar_gap) / (bar_width + bar_gap)).max(1) as usize;

        let bars = downsample_entropy(&self.entropy, n_bars);
        let chart = BarChart::default()
            .data(BarGroup::default().bars(&bars))
            .bar_width(bar_width)
            .bar_gap(bar_gap)
            .max(800); // entropy 0.0..8.0 scaled by 100
        frame.render_widget(chart, chart_area);
    }
}

// ---- helpers --------------------------------------------------------------

/// Move a selection index by `delta`, clamped to [0, len-1]. Returns None for
/// an empty list.
fn step(current: Option<usize>, delta: isize, len: usize) -> Option<usize> {
    if len == 0 {
        return None;
    }
    let cur = current.unwrap_or(0) as isize;
    let next = (cur + delta).clamp(0, len as isize - 1) as usize;
    Some(next)
}

/// Build the lines for the manual-metadata form: a header, one row per field
/// (the active one marked and highlighted), input hints, and any parse error.
fn disasm_form_lines(form: &DisasmForm) -> Vec<Line<'static>> {
    let mut lines = vec![
        Line::from(Span::styled(
            "Automatic detection failed — enter metadata manually:",
            Style::new().fg(Color::Cyan),
        )),
        Line::from(""),
    ];

    for (i, label) in DISASM_FIELDS.iter().enumerate() {
        let active = i == form.active;
        let (marker, cursor, label_style) = if active {
            (
                "▶ ",
                "_",
                Style::new().fg(Color::Yellow).add_modifier(Modifier::BOLD),
            )
        } else {
            ("  ", "", Style::new().fg(Color::Gray))
        };
        lines.push(Line::from(vec![
            Span::styled(format!("{marker}{label:<20}"), label_style),
            Span::raw(format!("{}{cursor}", form.values[i])),
        ]));
    }

    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "arch: x86_64 i386 aarch64 arm mips mips64 ppc64 riscv32 riscv64",
        Style::new().fg(Color::DarkGray),
    )));
    lines.push(Line::from(Span::styled(
        "endian: little | big     ·     address & offset are hex",
        Style::new().fg(Color::DarkGray),
    )));

    if let Some(err) = &form.error {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            format!("✗ {err}"),
            Style::new().fg(Color::Red),
        )));
    }

    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "[Tab]/[↑↓] field   [Enter] run   [Esc] cancel",
        Style::new().fg(Color::DarkGray),
    )));

    lines
}

/// Human-readable byte count (B / KiB / MiB) for the entropy info line.
fn human_size(bytes: usize) -> String {
    const KIB: usize = 1024;
    const MIB: usize = 1024 * 1024;
    if bytes >= MIB {
        format!("{:.1} MiB", bytes as f64 / MIB as f64)
    } else if bytes >= KIB {
        format!("{:.1} KiB", bytes as f64 / KIB as f64)
    } else {
        format!("{bytes} B")
    }
}

/// Aggregate the (offset, entropy) blocks into at most `n_bars` averaged bars,
/// coloured by entropy level (red = likely compressed/encrypted, blue = low).
fn downsample_entropy(entropy: &[(usize, f64)], n_bars: usize) -> Vec<Bar<'static>> {
    if entropy.is_empty() || n_bars == 0 {
        return Vec::new();
    }
    let n = n_bars.min(entropy.len());
    let chunk = entropy.len().div_ceil(n);

    entropy
        .chunks(chunk)
        .map(|c| {
            let avg = c.iter().map(|(_, e)| *e).sum::<f64>() / c.len() as f64;
            let color = if avg >= 7.0 {
                Color::Red
            } else if avg >= 5.0 {
                Color::Yellow
            } else {
                Color::Blue
            };
            Bar::default()
                .value((avg * 100.0) as u64)
                .label(Line::from(format!("{avg:.1}")))
                .text_value(String::new()) // hide the raw scaled number inside the bar
                .style(Style::new().fg(color))
        })
        .collect()
}

/// Centered sub-rect for the (future) logo overlay.
#[allow(dead_code)]
fn centered_rect(area: Rect, width: u16, height: u16) -> Rect {
    let x = area.x + area.width.saturating_sub(width) / 2;
    let y = area.y + area.height.saturating_sub(height) / 2;
    Rect {
        x,
        y,
        width: width.min(area.width),
        height: height.min(area.height),
    }
}
