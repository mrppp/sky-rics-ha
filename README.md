# Sky RICS HA (research)

Safety-gated Home Assistant integration for the permitted Sky Glass RICS
remote. Research only; Ruby's Sky box stays excluded.

Entities: `binary_sensor.<name>_rics_presence`, `binary_sensor.<name>_rics_bound`,
`remote.<name>_remote` (gated `sky_rics_ha.send_command`).

Configure via `configuration.yaml` — see the main research repo's
`homeassistant/configuration.yaml.example`.
