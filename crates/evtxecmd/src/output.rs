//! The output files: CSV and JSON lines, UTF-8 with a BOM as EvtxECmd writes them.

use std::io::{self, Write};
use std::path::Path;

use evtx_ez::output::table::{CSV_HEADER, CSV_NEW_LINE, write_csv_row, write_json_row};
use evtx_ez::timeline::{Row, RowSink};

pub use ez_common::cli::{BOM, open, resolve, utc_now};
pub use ez_common::dotnet::n0;

pub struct Writer {
    csv: Option<Box<dyn Write>>,
    json: Option<Box<dyn Write>>,
    date_format: String,
    full_json: bool,
    buf: String,
}

impl Writer {
    pub fn create(csv: Option<&Path>, json: Option<&Path>, date_format: &str, full_json: bool) -> Result<Writer, String> {
        let mut w = Writer { csv: None, json: None, date_format: date_format.to_string(), full_json, buf: String::new() };
        if let Some(p) = csv {
            let mut f = open(p)?;
            let header = format!("{CSV_HEADER}{CSV_NEW_LINE}");
            f.write_all(BOM).and_then(|_| f.write_all(header.as_bytes())).map_err(|e| e.to_string())?;
            w.csv = Some(f);
        }
        if let Some(p) = json {
            let mut f = open(p)?;
            f.write_all(BOM).map_err(|e| e.to_string())?;
            w.json = Some(f);
        }
        Ok(w)
    }

    pub fn finish(&mut self) -> io::Result<()> {
        if let Some(f) = &mut self.csv {
            f.flush()?;
        }
        if let Some(f) = &mut self.json {
            f.flush()?;
        }
        Ok(())
    }
}

impl RowSink for Writer {
    fn write_row(&mut self, row: &Row, sources: &[&Path]) -> io::Result<()> {
        let source = match sources {
            [one] => one.to_string_lossy().into_owned(),
            many => many.iter().map(|p| p.to_string_lossy()).collect::<Vec<_>>().join("|"),
        };
        if let Some(f) = &mut self.csv {
            self.buf.clear();
            write_csv_row(&mut self.buf, row, &source, &self.date_format);
            f.write_all(self.buf.as_bytes())?;
        }
        if let Some(f) = &mut self.json {
            self.buf.clear();
            write_json_row(&mut self.buf, row, &source, self.full_json);
            f.write_all(self.buf.as_bytes())?;
        }
        Ok(())
    }
}
