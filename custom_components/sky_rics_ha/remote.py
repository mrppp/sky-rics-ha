"""Remote platform exposing a gated send_command service for the permitted device.

Commands are never sent autonomously. A command is sent only when a user calls
the service, and only if the hub is configured with allow_key_commands=true and
the key is on the safe allowlist (never the forbidden set).
"""

from __future__ import annotations

import logging

from homeassistant.components.remote import RemoteEntity
from homeassistant.const import CONF_NAME
from homeassistant.core import HomeAssistant, ServiceCall, SupportsResponse

from .const import (ATTR_KEY, CONF_ALLOW_KEYS, CONF_EXCLUSIONS, CONF_MAC,
                    CONF_PORT, CONF_TARGETS, DOMAIN, ALLOWED_KEYS, FORBIDDEN_KEYS)
from .hub import SkyRicsHub, get_hub

_LOGGER = logging.getLogger(__name__)


async def async_setup_platform(hass, config, async_add_entities, discovery_info=None):
    hub = get_hub(hass, config)
    name = config.get(CONF_NAME, "Sky Glass")
    entity = SkyRicsRemote(hass, hub, name)
    async_add_entities([entity])

    async def handle_send_command(call: ServiceCall):
        key = call.data.get(ATTR_KEY)
        if not key:
            _LOGGER.warning("sky_rics: send_command missing key")
            return {"sent": False, "reason": "missing-key"}
        result = await entity.async_send_key(str(key))
        if not result.get("sent"):
            _LOGGER.warning("sky_rics: key %s not sent: %s", key, result.get("reason"))
        return result

    hass.services.async_register(
        DOMAIN,
        "send_command",
        handle_send_command,
        supports_response=SupportsResponse.OPTIONAL,
    )


class SkyRicsRemote(RemoteEntity):
    _attr_icon = "mdi:remote"

    def __init__(self, hass, hub: SkyRicsHub, name: str):
        self._hub = hub
        self._base_name = name
        self._attr_should_poll = False
        self._attr_is_on = hub.allow_keys
        self._attr_extra_state_attributes = {"mac": hub.mac, "allow_key_commands": hub.allow_keys}

    @property
    def name(self):
        return f"{self._base_name} Remote"

    @property
    def unique_id(self):
        return f"sky_rics_ha_{self._hub.mac.replace(':','')}_remote"

    async def async_send_command(self, command, **kwargs):
        if isinstance(command, str):
            command = [command]
        for key in command:
            await self.async_send_key(key)

    async def async_send_key(self, key: str) -> dict:
        key = key.strip()
        if key in FORBIDDEN_KEYS:
            _LOGGER.warning("sky_rics: forbidden key %s", key)
            return {"sent": False, "reason": "forbidden"}
        if key not in ALLOWED_KEYS:
            _LOGGER.warning("sky_rics: key %s not on allowlist", key)
            return {"sent": False, "reason": "not-allowlisted"}
        return await self.hass.async_add_executor_job(self._hub.send_key, key)