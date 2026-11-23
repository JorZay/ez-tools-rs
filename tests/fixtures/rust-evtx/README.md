# Samples from omerbenamram/evtx

From https://github.com/omerbenamram/EVTX/tree/master/samples (MIT or Apache-2.0), gzipped; the tests decompress them.
The expected record counts are what that parser (evtx_dump 0.12.3, which goes on after damaged data as EvtxECmd
2026.11 does) finds.

- `security.evtx`, `system.evtx`, `sysmon.evtx`, `new-user-security.evtx`, `issue_201.evtx`
- `Archive-ForwardedEvents-test.evtx`: Windows Event Forwarding (records without templates, RenderingInfo); EvtxECmd issue #15
- `MSExchange_Management_wec.evtx`: a Windows Event Collector log
- `sample_with_a_bad_chunk_magic.evtx`, `security_bad_string_cache.evtx`, `sample-with-zero-data-size-event.evtx`,
  `sample-with-irregular-bool-values.evtx`, `Security_with_size_t.evtx`, `Application_no_crc32.evtx`
- `2-system-Security-dirty.evtx`: a dirty log
- `Microsoft-Windows-WorkFolders%4WHC.evtx`: a chunk whose header was reset (a cleared log), with two records left
  in it (forensicmatt/evtx's parse-empty-pages test): what `--rr` recovers as ClearedChunk
