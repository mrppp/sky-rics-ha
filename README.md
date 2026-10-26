# sky_rics_ha — Home Assistant integration (research)

Safety-gated HA integration for the **permitted Sky Glass only**. Ruby's
device is always excluded via the shared `sky-rics-exclusions.json`.

## What it provides

| Entity | Type | Purpose | Risk |
|---|---|---|---|
| `binary_sensor.<name>_rics_presence` | binary_sensor | device awake (TCP 8091 reachable, no pairing) | NONE |
| `binary_sensor.<name>_rics_bound` | binary_sensor | pair+bind session ok (no key sent) | none on screen |
| `remote.<name>_remote` | remote | `send_command` service, **gated** | only if enabled |

## Install (live HAOS VM)

The integration is **installed and running** on the live HA instance at
`192.168.0.3` (HAOS). It is deployed as a HACS custom repository
(`mrppp/sky-rics-ha`), which is the current install path:

1. HACS → custom repositories → add `https://github.com/mrppp/sky-rics-ha`
   (category: integration) → download → restart HA.

The repository root is the component, with `sky_rics/` and `certs/` bundled
inside it, so HACS writes a self-contained `custom_components/sky_rics_ha/`.

- Component: `/config/custom_components/sky_rics_ha/`
- Config: `configuration.yaml` gains `binary_sensor:` and `remote:` blocks
  pointing at `/config/sky_rics_config/` (the exclusions/targets JSON, copied
  into the VM).
- Entities live: `binary_sensor.sky_glass_rics_presence`,
  `binary_sensor.sky_glass_rics_bound`, `remote.sky_glass_remote`.

Manual copy equivalent (e.g. on a fresh HAOS instance):
1. Copy `custom_components/sky_rics_ha/` → `~/config/custom_components/sky_rics_ha/`.
2. Copy `config/sky-rics-{exclusions,targets}.json` → `~/config/sky_rics_config/`.
3. Add the `binary_sensor:` and `remote:` blocks (see `configuration.yaml.example`,
   adjust paths to `/config/sky_rics_config/`).
4. Restart HA.

Deployment helper: `tools/push_to_ha_vm.py` pushes files into a local libvirt
VM over the QEMU guest agent (used for the original install, before HA moved to
its own host).

## IP resolution

The hub resolves the target IP from the kernel neighbour table, then falls back
to the static IP recorded for that MAC in the permitted-targets file (the HA
container's neighbour table is usually empty). Policy stays MAC-keyed: the
resolved IP is re-checked before any session.

## Services

- `sky_rics_ha.send_command` — send exactly one key to the permitted device.

When key commands are enabled, the full RICS control set is available:
**Power**, **VolumeUp/Down/Mute**, **ChannelUp/Down**, **Home**, **Info**,
navigation (`ArrowUp/Down/Left/Right`, `Enter`, `Backspace`, `Dismiss`),
menu (`AccessMenu`, `Option`, `Search`, `Settings`), playback
(`MediaPlay`, `MediaRecord`, `MediaRewind`, `MediaFastForward`), `Source`,
`Plus`, digits `Digit0-9`, and colour buttons `Red/Green/Yellow/Blue`.
These are the protocol's real key names.

Device-rejected pseudo-keys (`Standby`, `PowerOff`, `WakeUp`, `STBPower`,
`TVPower`, `AudioVolume*`, `PageUp/Down`, etc.) are always in `FORBIDDEN_KEYS`
and blocked.

## Key commands

Key commands were **enabled** in the example config (authorised 2026-09-12).
Commands are still only sent when a user calls `send_command`; nothing is sent
autonomously. To disable again, set `allow_key_commands: false`.

## Safety

- Target must be a MAC-keyed permitted target (targets file) and not excluded
  (exclusions file). Otherwise every operation fails closed.
- IP is resolved from the neighbour table by MAC at runtime — never hardcoded.
- Authentication material is redacted from logs (default).
- No autonomous key sending: commands are sent only when a user calls the
  service, and only if `allow_key_commands: true`.
- Forbidden keys (device-rejected pseudo-keys such as `Standby`/`PowerOff`/
  `AudioVolume*`) are always blocked even with key commands enabled.

## Tests

`tests/test_ha_integration.py` covers policy enforcement (excluded/permitted/
unknown), IP-by-MAC resolution, presence-without-IP, the key-command gate, and
the forbidden/safe key sets. Run with `python3 -m unittest
tests.test_ha_integration -v`.