//! Console messages (to standard error, so standard output can carry a CSV or JSON stream), and optionally to a log
//! file with EvtxECmd's `[HH:mm:ss.fff LVL]` template.

use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};

use crate::Level;

pub struct Logger {
    level: Level,
    file: Option<(PathBuf, BufWriter<File>)>,
    prefix: bool,
    stdout: bool,
}

fn code(level: Level) -> &'static str {
    match level {
        Level::Trace => "VRB",
        Level::Debug => "DBG",
        Level::Info => "INF",
        Level::Warning => "WRN",
        Level::Error => "ERR",
    }
}

impl Logger {
    pub fn new(level: Level, _date_format: &str) -> Logger {
        Logger { level, file: None, prefix: level <= Level::Debug, stdout: false }
    }

    /// Messages to standard output instead of standard error (for tools that write no data there)
    pub fn to_stdout(mut self) -> Logger {
        self.stdout = true;
        self
    }

    pub fn open_file(&mut self, path: &Path) -> std::io::Result<()> {
        let f = File::create(path)?;
        self.file = Some((path.to_path_buf(), BufWriter::new(f)));
        Ok(())
    }

    pub fn file_path(&self) -> Option<&Path> {
        self.file.as_ref().map(|(p, _)| p.as_path())
    }

    pub fn log(&mut self, level: Level, message: &str) {
        if level < self.level {
            return;
        }
        let stamp = crate::time::Timestamp::now().format("HH:mm:ss.fff");
        for line in message.split('\n') {
            let text = if self.prefix && !line.is_empty() { format!("[{stamp} {}] {line}", code(level)) } else { line.to_string() };
            if self.stdout {
                println!("{text}");
            } else {
                eprintln!("{text}");
            }
            if let Some((_, f)) = &mut self.file {
                if line.is_empty() {
                    let _ = writeln!(f);
                } else {
                    let _ = writeln!(f, "[{stamp} {}] {line}", code(level));
                }
            }
        }
    }

    pub fn info(&mut self, message: &str) {
        self.log(Level::Info, message);
    }

    pub fn debug(&mut self, message: &str) {
        self.log(Level::Debug, message);
    }

    pub fn warning(&mut self, message: &str) {
        self.log(Level::Warning, message);
    }

    pub fn error(&mut self, message: &str) {
        self.log(Level::Error, message);
    }
}

impl Drop for Logger {
    fn drop(&mut self) {
        if let Some((_, f)) = &mut self.file {
            let _ = f.flush();
        }
    }
}
