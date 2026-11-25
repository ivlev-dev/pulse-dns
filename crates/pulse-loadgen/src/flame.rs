//! Flamegraph без внешних утилит: `perf script` → folded stacks → SVG.
//!
//! `inferno` на стенде может отсутствовать; тогда `pulse-bench` использует
//! этот модуль. Формат folded — стандартный (`frame;frame;leaf count`),
//! совместим с `inferno-flamegraph`, если он появится.

use std::collections::BTreeMap;
use std::fmt::Write as _;

/// Сворачивает вывод `perf script` в folded-строки.
///
/// Семпл в `perf script` — строка с заголовком и последующими строками
/// callchain с отступом; кадры идут от листа к корню. Для folded порядок
/// обратный (корень → лист), вес — period события.
#[must_use]
pub fn collapse(script: &str) -> String {
    let mut stacks: BTreeMap<String, u64> = BTreeMap::new();
    let mut frames: Vec<String> = Vec::new();
    let mut weight = 1_u64;
    for line in script.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if let Some((period, frame)) = header(trimmed) {
            flush(&mut frames, weight, &mut stacks);
            weight = period;
            frames.push(frame);
            continue;
        }
        let indented = line.starts_with(' ') || line.starts_with('\t');
        if indented && let Some(frame) = frame_from_line(trimmed) {
            frames.push(frame);
        }
    }
    flush(&mut frames, weight, &mut stacks);
    let mut out = String::new();
    for (stack, count) in stacks {
        let _ = writeln!(out, "{stack} {count}");
    }
    out
}

fn flush(frames: &mut Vec<String>, weight: u64, stacks: &mut BTreeMap<String, u64>) {
    if frames.is_empty() {
        return;
    }
    let mut root_first: Vec<&str> = frames.iter().rev().map(String::as_str).collect();
    if root_first.is_empty() {
        root_first.push("[unknown]");
    }
    // Первый кадр — символ из заголовка; пустые кадры не должны рвать стек.
    let key = root_first
        .iter()
        .map(|frame| sanitize(frame))
        .filter(|frame| !frame.is_empty())
        .collect::<Vec<_>>()
        .join(";");
    if !key.is_empty() {
        *stacks.entry(key).or_insert(0) += weight.max(1);
    }
    frames.clear();
}

fn header(line: &str) -> Option<(u64, String)> {
    let tokens: Vec<&str> = line.split_whitespace().collect();
    let event = tokens
        .iter()
        .position(|token| token.ends_with(':') && token.contains("cycles"))?;
    let period = tokens.get(event.checked_sub(1)?)?.parse().ok()?;
    let frame = frame_from_tokens(&tokens[event + 1..]);
    Some((period, frame))
}

fn frame_from_line(line: &str) -> Option<String> {
    let tokens: Vec<&str> = line.split_whitespace().collect();
    let frame = frame_from_tokens(&tokens);
    (!frame.is_empty()).then_some(frame)
}

fn frame_from_tokens(tokens: &[&str]) -> String {
    let mut start = 0;
    if tokens.first().is_some_and(|token| is_address(token)) {
        start = 1;
    }
    tokens[start..].join(" ")
}

fn is_address(token: &str) -> bool {
    token.len() >= 8
        && token.chars().all(|value| value.is_ascii_hexdigit())
        && token.chars().any(|value| value.is_ascii_digit())
}

fn sanitize(frame: &str) -> String {
    frame.trim().replace(';', ":").replace(['\n', '\r'], " ")
}

struct Node {
    name: String,
    count: u64,
    depth: usize,
    children: Vec<usize>,
    x: f64,
    width: f64,
}

/// Рисует простой SVG-flamegraph из folded-строк.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn render_svg(folded: &str, title: &str) -> String {
    let mut nodes = vec![Node {
        name: "all".to_owned(),
        count: 0,
        depth: 0,
        children: Vec::new(),
        x: 0.0,
        width: 0.0,
    }];
    let mut total = 0_u64;
    for line in folded.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Some((stack, count)) = line.rsplit_once(' ') else {
            continue;
        };
        let Ok(count) = count.parse::<u64>() else {
            continue;
        };
        if count == 0 {
            continue;
        }
        total = total.saturating_add(count);
        nodes[0].count = nodes[0].count.saturating_add(count);
        let mut parent = 0_usize;
        for frame in stack.split(';') {
            let frame = frame.trim();
            if frame.is_empty() {
                continue;
            }
            let child = nodes[parent]
                .children
                .iter()
                .copied()
                .find(|index| nodes[*index].name == frame);
            parent = if let Some(child) = child {
                nodes[child].count = nodes[child].count.saturating_add(count);
                child
            } else {
                let index = nodes.len();
                let depth = nodes[parent].depth + 1;
                nodes.push(Node {
                    name: frame.to_owned(),
                    count,
                    depth,
                    children: Vec::new(),
                    x: 0.0,
                    width: 0.0,
                });
                nodes[parent].children.push(index);
                index
            };
        }
    }
    if total == 0 {
        return String::new();
    }
    let width = 1400.0;
    layout(&mut nodes, 0, 0.0, width, total);
    let max_depth = nodes.iter().map(|node| node.depth).max().unwrap_or(0);
    let row = 18.0;
    let height = (max_depth as f64 + 1.0) * row + 40.0;
    let mut svg = String::new();
    let _ = writeln!(
        svg,
        r#"<svg xmlns="http://www.w3.org/2000/svg" width="{width:.0}" height="{height:.0}" viewBox="0 0 {width:.0} {height:.0}">"#
    );
    let _ = writeln!(
        svg,
        r##"<rect width="100%" height="100%" fill="#11151c"/>"##
    );
    let _ = writeln!(
        svg,
        r##"<text x="8" y="16" fill="#e6edf3" font-family="monospace" font-size="12">{}</text>"##,
        escape(title)
    );
    for node in &nodes[1..] {
        if node.depth == 0 || node.width < 1.0 {
            continue;
        }
        let y = 24.0 + (node.depth as f64 - 1.0) * row;
        let color = palette(node.depth);
        let _ = writeln!(
            svg,
            r#"<rect x="{:.1}" y="{y:.1}" width="{:.1}" height="{:.1}" fill="{color}"/>"#,
            node.x,
            node.width,
            row - 1.0
        );
        if node.width > 34.0 {
            let max_chars = (node.width / 6.5) as usize;
            let text = truncate(&node.name, max_chars);
            let _ = writeln!(
                svg,
                r##"<text x="{:.1}" y="{:.1}" fill="#0b0e13" font-family="monospace" font-size="10">{}</text>"##,
                node.x + 2.0,
                y + 12.0,
                escape(&text)
            );
        }
    }
    svg.push_str("</svg>\n");
    svg
}

fn layout(nodes: &mut [Node], index: usize, x: f64, width: f64, total: u64) {
    nodes[index].x = x;
    nodes[index].width = width;
    let children = nodes[index].children.clone();
    let mut cursor = x;
    for child in children {
        let fraction = if total == 0 {
            0.0
        } else {
            nodes[child].count as f64 / nodes[index].count.max(1) as f64
        };
        let child_width = width * fraction;
        layout(nodes, child, cursor, child_width, total);
        cursor += child_width;
    }
}

fn palette(depth: usize) -> &'static str {
    const COLORS: [&str; 10] = [
        "#f6c85f", "#f29e4c", "#ef8354", "#ee6c4d", "#e05d44", "#d1495b", "#b23a48", "#8b2f3a",
        "#6b2430", "#4f1c25",
    ];
    COLORS[depth.min(COLORS.len() - 1)]
}

fn truncate(text: &str, max_chars: usize) -> String {
    if max_chars == 0 {
        return String::new();
    }
    if text.chars().count() <= max_chars {
        return text.to_owned();
    }
    let mut short: String = text.chars().take(max_chars.saturating_sub(1)).collect();
    short.push('…');
    short
}

fn escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

#[cfg(test)]
mod tests {
    use super::*;

    const SCRIPT: &str = "\
            pulsed 100 [001] 1.000000:          100 cycles:u:      7f001234 leaf+0x1 (/bin/pulsed)
            parent+0x2 (/bin/pulsed)
            root+0x3 (/bin/pulsed)

            pulsed 100 [001] 1.000100:          300 cycles:u:      7f001234 leaf+0x1 (/bin/pulsed)
            parent+0x2 (/bin/pulsed)
            root+0x3 (/bin/pulsed)
";

    #[test]
    fn collapse_orders_root_first_and_sums() {
        let folded = collapse(SCRIPT);
        assert!(
            folded.contains(
                "root+0x3 (/bin/pulsed);parent+0x2 (/bin/pulsed);leaf+0x1 (/bin/pulsed) 400"
            ),
            "{folded}"
        );
    }

    #[test]
    fn renders_svg_with_frames() {
        let folded = collapse(SCRIPT);
        let svg = render_svg(&folded, "cycles:u");
        assert!(svg.starts_with("<svg"));
        assert!(svg.contains("leaf+0x1"));
        assert!(svg.contains("<rect"));
        assert!(svg.ends_with("</svg>\n"));
    }

    #[test]
    fn empty_input_is_safe() {
        assert_eq!(collapse("").len(), 0);
        assert_eq!(render_svg("", "empty").len(), 0);
    }

    #[test]
    fn escapes_text() {
        let svg = render_svg("a<b;c&d 1", "t<1");
        assert!(svg.contains("a&lt;b"));
        assert!(svg.contains("c&amp;d"));
        assert!(svg.contains("t&lt;1"));
    }
}
