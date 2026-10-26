"""Binary sensors: RICS presence (awake) and RICS bound session."""

from __future__ import annotations

import logging
from datetime import timedelta

from homeassistant.components.binary_sensor import BinarySensorEntity
from homeassistant.const import CONF_NAME
from homeassistant.helpers.event import async_track_time_interval

from .const import (CONF_EXCLUSIONS, CONF_MAC, CONF_PORT, CONF_SCAN_INTERVAL,
                    CONF_TARGETS, DEFAULT_SCAN_INTERVAL)
from .hub import SkyRicsHub

_LOGGER = logging.getLogger(__name__)


async def async_setup_platform(hass, config, async_add_entities, discovery_info=None):
    hub = SkyRicsHub(
        mac=config[CONF_MAC],
        exclusions_path=config.get(CONF_EXCLUSIONS, ""),
        targets_path=config.get(CONF_TARGETS, ""),
        port=config.get(CONF_PORT, 8091),
    )
    name = config.get(CONF_NAME, "Sky Glass")
    interval = config.get(CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL)
    async_add_entities([SkyPresenceSensor(hass, hub, name, interval),
                        SkyBoundSensor(hass, hub, name, interval)])


class _SkySensor(BinarySensorEntity):
    """Polling base: refreshes on its own timer so the interval is per-entity."""

    _attr_should_poll = False

    def __init__(self, hass, hub: SkyRicsHub, base_name: str, interval: int):
        self.hass = hass
        self._hub = hub
        self._base_name = base_name
        self._attr_extra_state_attributes = {}
        self._scan_interval = max(5, int(interval))
        self._attr_is_on = None

    async def async_added_to_hass(self) -> None:
        await self._refresh()
        self.async_on_remove(
            async_track_time_interval(
                self.hass, self._refresh, timedelta(seconds=self._scan_interval)
            )
        )

    async def _refresh(self, _now=None) -> None:
        try:
            await self.async_update()
        except Exception as exc:  # noqa: BLE001 - never kill the timer
            _LOGGER.warning("sky_rics %s update failed: %s", self.unique_id, exc)
        self.async_write_ha_state()

    async def async_update(self) -> None:
        raise NotImplementedError


class SkyPresenceSensor(_SkySensor):
    _attr_icon = "mdi:television"

    @property
    def name(self):
        return f"{self._base_name} RICS presence"

    @property
    def unique_id(self):
        return f"sky_rics_ha_{self._hub.mac.replace(':','')}_presence"

    async def async_update(self):
        self._attr_is_on = await self.hass.async_add_executor_job(self._hub.presence)
        attrs = {"mac": self._hub.mac}
        if self._attr_is_on:
            attrs["ip"] = await self.hass.async_add_executor_job(self._hub.resolve_ip)
        self._attr_extra_state_attributes = attrs


class SkyBoundSensor(_SkySensor):
    _attr_icon = "mdi:shield-check-outline"

    @property
    def name(self):
        return f"{self._base_name} RICS bound"

    @property
    def unique_id(self):
        return f"sky_rics_ha_{self._hub.mac.replace(':','')}_bound"

    async def async_update(self):
        result = await self.hass.async_add_executor_job(self._hub.bind_state)
        self._attr_is_on = result.get("bound") is True
        self._attr_extra_state_attributes = {
            "reason": result.get("reason", ""),
            "device_name": result.get("device_name", ""),
            "bind_id": result.get("bind_id"),
            "mac": self._hub.mac,
        }
