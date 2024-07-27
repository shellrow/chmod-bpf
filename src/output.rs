use anstream::println;

/// UTF-8 check mark emoji (✅), used to indicate that a step was successful
pub const EMOJI_CHECK_MARK: &str = "\u{2705}";
/// UTF-8 cross mark emoji (❌), used to indicate that a step failed
pub const EMOJI_CROSS_MARK: &str = "\u{274C}";

pub const LOG_LABEL_OK: &str = "OK";
pub const LOG_LABEL_ERROR: &str = "ERROR";
pub const LOG_LABEL_WARN: &str = "WARN";
pub const LOG_LABEL_INFO: &str = "INFO";
pub const LOG_LABEL_FAIL: &str = "FAIL";

pub fn std_ok_log(label: &str, message: &str) {
    let green_style = anstyle::Style::new().fg_color(Some(anstyle::Color::Ansi(anstyle::AnsiColor::Green)));
    let dimmed_style = anstyle::Style::new().dimmed();
    println!("{dimmed_style}[{dimmed_style:#}{green_style}{label}{green_style:#}{dimmed_style}]{dimmed_style:#} {message}");
}

pub fn std_check_ok_log(label: &str, message: &str) {
    println!("{EMOJI_CHECK_MARK} {label} {message}");
}

pub fn std_error_log(label: &str, message: &str) {
    let red_style = anstyle::Style::new().fg_color(Some(anstyle::Color::Ansi(anstyle::AnsiColor::Red)));
    let dimmed_style = anstyle::Style::new().dimmed();
    println!("{dimmed_style}[{dimmed_style:#}{red_style}{label}{red_style:#}{dimmed_style}]{dimmed_style:#} {message}");
}

pub fn std_check_error_log(label: &str, message: &str) {
    let red_style = anstyle::Style::new().fg_color(Some(anstyle::Color::Ansi(anstyle::AnsiColor::Red)));
    println!("{EMOJI_CROSS_MARK} {red_style}{label}{red_style:#} {message}");
}

pub fn get_ok_log(label: &str, message: &str) -> String {
    let green_style = anstyle::Style::new().fg_color(Some(anstyle::Color::Ansi(anstyle::AnsiColor::Green)));
    let dimmed_style = anstyle::Style::new().dimmed();
    format!("{dimmed_style}[{dimmed_style:#}{green_style}{label}{green_style:#}{dimmed_style}]{dimmed_style:#} {message}")
}

pub fn get_check_ok_log(message: &str) -> String {
    format!("{EMOJI_CHECK_MARK} {message}")
}

pub fn get_error_log(label: &str, message: &str) -> String {
    let red_style = anstyle::Style::new().fg_color(Some(anstyle::Color::Ansi(anstyle::AnsiColor::Red)));
    let dimmed_style = anstyle::Style::new().dimmed();
    format!("{dimmed_style}[{dimmed_style:#}{red_style}{label}{red_style:#}{dimmed_style}]{dimmed_style:#} {message}")
}

pub fn get_check_error_log(message: &str) -> String {
    format!("{EMOJI_CROSS_MARK} {message}")
}

pub fn node_label(label: &str, value: Option<&str>, delimiter: Option<&str>) -> String {
    match value {
        Some(value) => {
            let delimiter = match delimiter {
                Some(delimiter) => delimiter,
                None => ":",
            };
            format!("{}{} {}", label, delimiter, value)
        }
        None => {
            label.to_string()
        }
    }
}
