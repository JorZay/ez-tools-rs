//! The XHTML report, as .NET's XmlTextWriter writes it (indented by 4), with its styles.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use ez_common::cli::log::Logger;

use crate::{Row, bool_text, io_message};

const NORMALIZE_CSS: &[u8] = include_bytes!("../assets/normalize.css");
const STYLE_CSS: &[u8] = include_bytes!("../assets/style.css");
const DIRECTORIES_PNG: &[u8] = include_bytes!("../assets/directories.png");
const FILES_LOADED_PNG: &[u8] = include_bytes!("../assets/filesloaded.png");

pub struct Document {
    path: PathBuf,
    text: String,
}

/// Text as XmlTextEncoder writes it: characters XML doesn't allow as references, and those beyond the BMP too
fn escape(out: &mut String, s: &str, attribute: bool) {
    for c in s.chars() {
        match c {
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '&' => out.push_str("&amp;"),
            '"' if attribute => out.push_str("&quot;"),
            '\t' => out.push(c),
            '\n' | '\r' if !attribute => out.push(c),
            c if (c as u32) < 0x20 || c as u32 > 0xFFFD => write!(out, "&#x{:X};", c as u32).unwrap(),
            c => out.push(c),
        }
    }
}

impl Document {
    /// The folder, its styles and the start of the document. As in the original, the file is at the --html folder
    /// joined with the report's folder (which starts with --html), so a relative --html fails.
    pub fn create(html: &str, stamp: &str, log: &mut Logger) -> Result<Document, String> {
        let dir = Path::new(html);
        let create = |p: &Path| std::fs::create_dir_all(p).map_err(|e| io_message(p, &e));
        if !dir.is_dir() {
            log.info(&format!("{html} does not exist. Creating..."));
            create(dir)?;
        }
        let safe = html.replace(r":\", "_").replace('\\', "_").replace('/', "_");
        let out_dir = dir.join(format!("{stamp}_PECmd_Output_for_{safe}"));
        create(&out_dir)?;
        let styles = out_dir.join("styles");
        create(&styles)?;
        for (name, bytes) in [
            ("normalize.css", NORMALIZE_CSS),
            ("style.css", STYLE_CSS),
            ("directories.png", DIRECTORIES_PNG),
            ("filesloaded.png", FILES_LOADED_PNG),
        ] {
            let p = styles.join(name);
            std::fs::write(&p, bytes).map_err(|e| io_message(&p, &e))?;
        }
        let path = dir.join(&out_dir).join("index.xhtml");
        log.info(&format!("Saving HTML output to {}", path.display()));
        // created now, so a path that can't be written stops the exports here
        std::fs::File::create(&path).map_err(|e| io_message(&path, &e))?;
        let text = String::from(
            "\u{FEFF}<?xml version=\"1.0\" encoding=\"utf-8\"?>\r\n<?xml-stylesheet href=\"styles/normalize.css\"?>\r\n<?xml-stylesheet href=\"styles/style.css\"?>\r\n<document>",
        );
        Ok(Document { path, text })
    }

    fn element(&mut self, name: &str, title: Option<&str>, value: &str) {
        let out = &mut self.text;
        write!(out, "\r\n        <{name}").unwrap();
        if let Some(t) = title {
            out.push_str(" title=\"");
            escape(out, t, true);
            out.push('"');
        }
        if value.is_empty() {
            out.push_str(" />");
            return;
        }
        out.push('>');
        escape(out, value, false);
        write!(out, "</{name}>").unwrap();
    }

    pub fn container(&mut self, r: &Row) {
        self.text.push_str("\r\n    <Container>");
        self.element("SourceFile", None, &r.source_filename);
        self.element("SourceCreated", None, &r.source_created);
        self.element("SourceModified", None, &r.source_modified);
        self.element("SourceAccessed", None, &r.source_accessed);
        self.element("LastRun", None, &r.last_run);
        for (i, run) in r.previous_runs.iter().enumerate() {
            self.element(&format!("PreviousRun{i}"), None, run.as_deref().unwrap_or(""));
        }
        self.element("ExecutableName", Some("Note: The name of the executable tracked by the pf file"), &r.executable_name);
        self.element("FullPath", None, &r.full_path);
        self.element("PathValidated", None, bool_text(r.path_validated));
        self.element("RunCount", None, &r.run_count);
        self.element("Size", Some("Note: The size of the executable in bytes"), &r.size);
        self.element(
            "Hash",
            Some("Note: The calculated hash for the pf file that should match the hash in the source file name"),
            &r.hash,
        );
        self.element("Version", Some("Note: The operating system that generated the prefetch file"), &r.version);
        self.element("Note", None, r.note.as_deref().unwrap_or(""));
        self.element("Volume0Name", None, &r.volume0_name);
        self.element("Volume0Serial", None, &r.volume0_serial);
        self.element("Volume0Created", None, &r.volume0_created);
        self.element("Volume1Name", None, r.volume1_name.as_deref().unwrap_or(""));
        self.element("Volume1Serial", None, r.volume1_serial.as_deref().unwrap_or(""));
        self.element("Volume1Created", None, r.volume1_created.as_deref().unwrap_or(""));
        self.element(
            "Directories",
            Some("A comma separated list of all directories accessed by the executable"),
            r.directories.as_deref().unwrap_or(""),
        );
        self.element(
            "FilesLoaded",
            Some("A comma separated list of all files that were loaded by the executable"),
            r.files_loaded.as_deref().unwrap_or(""),
        );
        self.text.push_str("\r\n    </Container>");
    }

    pub fn finish(mut self) -> Result<(), String> {
        self.text.push_str("\r\n</document>");
        std::fs::write(&self.path, &self.text).map_err(|e| io_message(&self.path, &e))
    }
}
