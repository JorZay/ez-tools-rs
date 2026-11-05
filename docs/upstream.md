# Upstream versions

The commits of Eric Zimmerman's repositories each port was built from, so a later update can diff upstream from
there (`git log <commit>..` in the upstream repository) and rerun that tool's parity script. Update this file whenever a
port is brought up to date.

| Port | Upstream repository | Commit | Date | Tool version | Recorded |
|---|---|---|---|---|---|
| `pecmd` | EricZimmerman/PECmd | `6586b8ab2417e4881b3e0166668ed3f1251204e3` | 2026-10-25 | 2026.10.3 | Exact |
| `prefetch-ez` | EricZimmerman/Prefetch | `841212266356a9121a1c34ee538cbce2bb2b9cf3` | 2026-10-16 | PECmd references package 2026.10.1 | Exact |
| `amcacheparser`, `amcache-ez` | EricZimmerman/AmcacheParser | `4706a080461d9506edbd6327bc58fc558978606d` | 2026-10-25 | 2026.10.1 | Exact |
| `appcompatcacheparser`, `appcompatcache-ez` | EricZimmerman/AppCompatCacheParser | `694c0bba98b7a2edc78f8a8fd6975bf94d37cf8c` | 2026-10-25 | 2026.10.1 | Exact |
| `sqlecmd`, `sqlmap-ez`, `maps-sqlecmd/` | EricZimmerman/SQLECmd | `c67634af503bd53777689998f1d9e3c0b4e2fdff` | 2026-10-25 | 2026.10.3 (System.Data.SQLite 1.0.119, SQLite 3.46.1) | Exact |
| `lecmd` | EricZimmerman/LECmd | `b5bbf29e4b58384fe7bd4384cb4851960c31dc83` | | 2026.10.4 | Exact |
| `jlecmd` | EricZimmerman/JLECmd | `256962fcb3690d779faba11726dd63ee500ae2a7` | 2026-10-29 | 2026.10.6 | Exact |
| `jumplist-ez` | EricZimmerman/JumpList | `c125c8e` (tag 2026.10.10) | 2026-10-29 | 2026.10.10 | Exact |
| `olecf-ez` | EricZimmerman/OleCf | `afd5ee9` (tag 2026.10.1, not HEAD) | 2026-10-15 | 2026.10.1 | Exact |
| `lnk-ez` | EricZimmerman/Lnk | `dab1c8ab9c1c18d2cf89a4938ab95794d17d3a44` | | 2026.10.11 | Exact |
| `shellitems-ez` | EricZimmerman/ExtensionBlocks | `897bbe3` (not HEAD) | | 2026.10.9 | Exact |
| `recmd` | EricZimmerman/RECmd | `8d1955910964209500b6f74f169e3e52554838d7` | | 2026.10.3 | Exact |
| `rla` | EricZimmerman/RECmd | `8d1955910964209500b6f74f169e3e52554838d7` | 2026-10-29 | 2026.10.1 | Exact |
| `registry-plugins` | EricZimmerman/RegistryPlugins | `bf564d6c4fcabf67b5ce4428ddf5e4a769b1e9ba` | 2026-10-29 | RegistryPluginBase 2026.10.7 | Exact (all 69 ported) |
| `guidmapping-ez` | EricZimmerman/GuidMapping | `e2c93615a491ca43197b36960a436b559062cb52` | | 2026.10.2 | Exact |
| `registry-ez` | EricZimmerman/Registry | not recorded (NuGet package 2026.10.1) | | 2026.10.1 | Package version only |
| `evtxecmd`, `evtx-ez` | EricZimmerman/evtx | `fbf2f66736669689bfb95f735f7eca86d29d9800` | 2026-10-25 | | Estimate |
| `mftecmd` | EricZimmerman/MFTECmd | `b1f668d870153f9a4c4073845265c0e6071ed09f` | 2026-10-25 | 2026.10.6 | Estimate |
| `ntfs-ez` | EricZimmerman/MFT | `3eecafae50ac8935b239cf3ded690b11af5020f4` | 2026-10-24 | | Estimate |

Exact: the commit that was cloned for the port. Estimate: the commit wasn't written down when the port was made, so
this is upstream's latest commit before the port's first commit (2026-11-02); check it before relying on it.
