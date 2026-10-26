"""Binary sensors: RICS reachability (TCP only) and last session outcome.

Reachability polls TCP 8091 and never authenticates. The bound sensor is
event-driven: it reflects the outcome of the last real session, so idle time
costs no pair/bind churn.
"""

from __future__ import annotations

import logging
from datetime import timedelta

from homeassistant.components.binary_sensor import BinarySensorEntity
from homeassistant.const import CONF_NAME
from homeassistant.helpers.event import async_track_time_interval

from .const import CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL
from .hub import SkyRicsHub, get_hub

_LOGGER = logging.getLogger(__name__)


async def async_setup_platform(hass, config, async_add_entities, discovery_info=None):
    hub = get_hub(hass, config)
    name = config.get(CONF_NAME, "Sky Glass")
    interval = config.get(CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL)
    async_add_entities([SkyReachableSensor(hass, hub, name, interval),
                        SkyBoundSensor(hass, hub, name)])


class _SkySensor(BinarySensorEntity):
    _attr_should_poll = False

    def __init__(self, hass, hub: SkyRicsHub, base_name: str):
        self.hass = hass
        self._hub = hub
        self._base_name = base_name
        self._attr_extra_state_attributes = {}
        self._attr_is_on = None

    async def async_update(self) -> None:
        raise NotImplementedError


class SkyReachableSensor(_SkySensor):
    """True when TCP 8091 answers. Network reachability, NOT screen state."""

    _attr_icon = "mdi:television"

    def __init__(self, hass, hub: SkyRicsHub, base_name: str, interval: int):
        super().__init__(hass, hub, base_name)
        self._scan_interval = max(5, int(interval))

    @property
    def name(self):
        return f"{self._base_name} RICS reachable"

    @property
    def unique_id(self):
        return f"sky_rics_ha_{self._hub.mac.replace(':','')}_presence"

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
            _LOGGER.warning("sky_rics reachable update failed: %s", exc)
        self.async_write_ha_state()

    async def async_update(self) -> None:
        self._attr_is_on = await self.hass.async_add_executor_job(self._hub.presence)
        attrs = {"mac": self._hub.mac}
        if self._attr_is_on:
            attrs["ip"] = await self.hass.async_add_executor_job(self._hub.resolve_ip)
        self._attr_extra_state_attributes = attrs


class SkyBoundSensor(_SkySensor):
    """Outcome of the last real session. No polling, so no idle auth churn."""

    _attr_icon = "mdi:shield-check-outline"

    @property
    def name(self):
        return f"{self._base_name} RICS bound"

    @property
    def unique_id(self):
        return f"sky_rics_ha_{self._hub.mac.replace(':','')}_bound"

    async def async_added_to_hass(self) -> None:
        self._apply()
        self.async_on_remove(self._hub.add_listener(self._on_hub_change))

    def _on_hub_change(self) -> None:
        """Called from the executor thread; hop to the event loop."""
        self.hass.loop.call_soon_threadsafe(self._write)

    def _write(self) -> None:
        self._apply()
        self.async_write_ha_state()

    def _apply(self) -> None:
        state = self._hub.last_session
        self._attr_is_on = state.get("bound")
        self._attr_extra_state_attributes = {
            "reason": state.get("reason", ""),
            "device_name": state.get("device_name", ""),
            "bind_id": state.get("bind_id"),
            "mac": self._hub.mac,
        }
