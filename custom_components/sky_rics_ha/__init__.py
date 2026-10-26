"""Sky RICS HA (research) integration.

Safety-gated Home Assistant integration for the permitted Sky Glass only.
Provides:
  - binary_sensor.<name>_rics_reachable  (TCP 8091 up; no pairing)
  - binary_sensor.<name>_rics_bound      (last session outcome; event-driven)
  - remote.<name>_remote                 (gated send_command service)

Exclusions and permitted-target policy are loaded from the research config
(see docs/sky-rics-*). Ruby's device is always excluded.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from .const import DOMAIN

if TYPE_CHECKING:  # pragma: no cover
    from homeassistant.core import HomeAssistant

_LOGGER = logging.getLogger(__name__)


def setup(hass: HomeAssistant, config) -> bool:
    """Set up via configuration.yaml (config_flow=false)."""
    hass.data.setdefault(DOMAIN, {})
    _LOGGER.info("sky_rics_ha setup")
    return True


async def async_setup(hass: HomeAssistant, config) -> bool:
    from homeassistant.const import EVENT_HOMEASSISTANT_STOP

    hass.data.setdefault(DOMAIN, {})

    async def _close_hubs(_event=None) -> None:
        for hub in list(hass.data.get(DOMAIN, {}).values()):
            try:
                await hass.async_add_executor_job(hub.close)
            except Exception:  # noqa: BLE001
                _LOGGER.debug("sky_rics hub close failed", exc_info=True)

    hass.bus.async_listen_once(EVENT_HOMEASSISTANT_STOP, _close_hubs)
    return True
