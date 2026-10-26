"""Sky RICS HA (research) integration.

Safety-gated Home Assistant integration for the permitted Sky Glass only.
Provides:
  - binary_sensor.sky_glass_rics_presence  (device awake; no pairing)
  - binary_sensor.sky_glass_rics_bound      (pair+bind session ok; no key sent)
  - remote.sky_glass_remote                  (gated send_command service)

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
    hass.data.setdefault(DOMAIN, {})
    return True