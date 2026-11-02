//! A row of output: what EvtxECmd writes for a record, plus what merging needs.

use std::io::{self, Read, Write};

use crate::record::EventRecord;
use crate::time::Timestamp;

/// A record as written to CSV or JSON. `sources` is filled in when the row is written: the files the event was in.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Row {
    pub record_number: i64,
    pub event_record_id: Option<String>,
    pub time_created: Timestamp,
    pub event_id: i32,
    pub level: Option<String>,
    pub provider: Option<String>,
    pub channel: Option<String>,
    pub process_id: i32,
    pub thread_id: i32,
    pub computer: Option<String>,
    pub chunk_number: u32,
    pub user_id: Option<String>,
    pub map_description: Option<String>,
    pub user_name: Option<String>,
    pub remote_host: Option<String>,
    pub payload_data: [Option<String>; 6],
    pub executable_info: Option<String>,
    pub hidden_record: bool,
    pub keywords: Option<String>,
    pub extra_data_offset: i64,
    /// The payload as JSON (EvtxECmd's Payload column)
    pub payload: String,
    pub rendering_info: Option<String>,
    /// The whole event as JSON, when it is wanted (--fj)
    pub event_json: Option<String>,

    /// The chunk the row came from (an index into the timeline's chunk table, which lists the files that held it)
    pub chunk: u32,
    /// The order the row was read in: file, then position, for a stable sort
    pub seq: u64,
    /// [`EventRecord::content_hash`], when merging
    pub content_hash: u128,
}

impl Row {
    pub fn from_record(r: &EventRecord, full_json: bool) -> Row {
        Row {
            record_number: r.record_number,
            event_record_id: r.event_record_id.clone(),
            time_created: r.time_created,
            event_id: r.event_id,
            level: r.level.clone(),
            provider: r.provider.clone(),
            channel: r.channel.clone(),
            process_id: r.process_id,
            thread_id: r.thread_id,
            computer: r.computer.clone(),
            chunk_number: r.chunk_number,
            user_id: r.user_id.clone(),
            map_description: r.map_description.clone(),
            user_name: r.user_name.clone(),
            remote_host: r.remote_host.clone(),
            payload_data: r.payload_data.clone(),
            executable_info: r.executable_info.clone(),
            hidden_record: r.hidden_record,
            keywords: r.keywords.clone(),
            extra_data_offset: r.extra_data_offset,
            payload: r.payload_json(),
            rendering_info: r.rendering_info.clone(),
            event_json: full_json.then(|| r.event_json()),
            chunk: 0,
            seq: 0,
            content_hash: 0,
        }
    }

    /// Roughly the memory the row uses
    pub fn heap_size(&self) -> usize {
        let s = |o: &Option<String>| o.as_ref().map_or(0, |s| s.capacity());
        std::mem::size_of::<Row>()
            + s(&self.event_record_id)
            + s(&self.level)
            + s(&self.provider)
            + s(&self.channel)
            + s(&self.computer)
            + s(&self.user_id)
            + s(&self.map_description)
            + s(&self.user_name)
            + s(&self.remote_host)
            + self.payload_data.iter().map(s).sum::<usize>()
            + s(&self.executable_info)
            + s(&self.keywords)
            + self.payload.capacity()
            + s(&self.rendering_info)
            + s(&self.event_json)
    }

    /// The same event: what merging collapses (the content hash covers the whole rendered event)
    pub fn same_event(&self, other: &Row) -> bool {
        self.content_hash == other.content_hash
            && self.time_created == other.time_created
            && self.record_number == other.record_number
            && self.event_record_id == other.event_record_id
            && self.computer == other.computer
            && self.channel == other.channel
            && self.provider == other.provider
            && self.event_id == other.event_id
            && self.payload == other.payload
    }

    pub(crate) fn encode(&self, w: &mut impl Write) -> io::Result<()> {
        fn s(w: &mut impl Write, v: &Option<String>) -> io::Result<()> {
            match v {
                None => w.write_all(&u32::MAX.to_le_bytes()),
                Some(v) => {
                    w.write_all(&(v.len() as u32).to_le_bytes())?;
                    w.write_all(v.as_bytes())
                }
            }
        }
        w.write_all(&self.record_number.to_le_bytes())?;
        s(w, &self.event_record_id)?;
        w.write_all(&self.time_created.0.to_le_bytes())?;
        w.write_all(&self.event_id.to_le_bytes())?;
        s(w, &self.level)?;
        s(w, &self.provider)?;
        s(w, &self.channel)?;
        w.write_all(&self.process_id.to_le_bytes())?;
        w.write_all(&self.thread_id.to_le_bytes())?;
        s(w, &self.computer)?;
        w.write_all(&self.chunk_number.to_le_bytes())?;
        s(w, &self.user_id)?;
        s(w, &self.map_description)?;
        s(w, &self.user_name)?;
        s(w, &self.remote_host)?;
        for p in &self.payload_data {
            s(w, p)?;
        }
        s(w, &self.executable_info)?;
        w.write_all(&[self.hidden_record as u8])?;
        s(w, &self.keywords)?;
        w.write_all(&self.extra_data_offset.to_le_bytes())?;
        w.write_all(&(self.payload.len() as u32).to_le_bytes())?;
        w.write_all(self.payload.as_bytes())?;
        s(w, &self.rendering_info)?;
        s(w, &self.event_json)?;
        w.write_all(&self.chunk.to_le_bytes())?;
        w.write_all(&self.seq.to_le_bytes())?;
        w.write_all(&self.content_hash.to_le_bytes())
    }

    /// The next row, or None at the end of the stream
    pub(crate) fn decode(r: &mut impl Read) -> io::Result<Option<Row>> {
        fn n<const N: usize>(r: &mut impl Read) -> io::Result<[u8; N]> {
            let mut b = [0u8; N];
            r.read_exact(&mut b)?;
            Ok(b)
        }
        fn s(r: &mut impl Read) -> io::Result<Option<String>> {
            let len = u32::from_le_bytes(n::<4>(r)?);
            if len == u32::MAX {
                return Ok(None);
            }
            let mut b = vec![0u8; len as usize];
            r.read_exact(&mut b)?;
            String::from_utf8(b).map(Some).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
        }
        let mut first = [0u8; 8];
        match r.read_exact(&mut first) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => return Err(e),
        }
        Ok(Some(Row {
            record_number: i64::from_le_bytes(first),
            event_record_id: s(r)?,
            time_created: Timestamp(i64::from_le_bytes(n(r)?)),
            event_id: i32::from_le_bytes(n(r)?),
            level: s(r)?,
            provider: s(r)?,
            channel: s(r)?,
            process_id: i32::from_le_bytes(n(r)?),
            thread_id: i32::from_le_bytes(n(r)?),
            computer: s(r)?,
            chunk_number: u32::from_le_bytes(n(r)?),
            user_id: s(r)?,
            map_description: s(r)?,
            user_name: s(r)?,
            remote_host: s(r)?,
            payload_data: [s(r)?, s(r)?, s(r)?, s(r)?, s(r)?, s(r)?],
            executable_info: s(r)?,
            hidden_record: n::<1>(r)?[0] != 0,
            keywords: s(r)?,
            extra_data_offset: i64::from_le_bytes(n(r)?),
            payload: s(r)?.unwrap_or_default(),
            rendering_info: s(r)?,
            event_json: s(r)?,
            chunk: u32::from_le_bytes(n(r)?),
            seq: u64::from_le_bytes(n(r)?),
            content_hash: u128::from_le_bytes(n(r)?),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let row = Row {
            record_number: 5,
            event_record_id: Some("5".into()),
            time_created: Timestamp(123),
            payload_data: [Some("a".into()), None, Some(String::new()), None, None, Some("ü".into())],
            payload: "{}".into(),
            hidden_record: true,
            chunk: 3,
            seq: 99,
            content_hash: u128::MAX - 1,
            ..Default::default()
        };
        let mut buf = Vec::new();
        row.encode(&mut buf).unwrap();
        row.encode(&mut buf).unwrap();
        let mut r = &buf[..];
        assert_eq!(Row::decode(&mut r).unwrap().unwrap(), row);
        assert_eq!(Row::decode(&mut r).unwrap().unwrap(), row);
        assert!(Row::decode(&mut r).unwrap().is_none());
    }
}
