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

from .const import (CONF_POWER_ENTITY, CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL)
from .hub import SkyRicsHub, get_hub
from .tv_state import TV_DWELL_S, TV_OFF_W, TV_ON_W, classify

_LOGGER = logging.getLogger(__name__)


def _find_power_entity(hass, base_name: str) -> str | None:
    """Find a power sensor for this device when none is configured.

    Matches a `power` device_class sensor whose friendly name starts with the
    configured device name (e.g. "Sky Glass Power"). Explicit config wins.
    """
    prefix = base_name.lower()
    for state in hass.states.async_all("sensor"):
        if state.attributes.get("device_class") != "power":
            continue
        friendly = str(state.attributes.get("friendly_name", "")).lower()
        if friendly.startswith(prefix):
            return state.entity_id
    return None


async def async_setup_platform(hass, config, async_add_entities, discovery_info=None):
    hub = get_hub(hass, config)
    name = config.get(CONF_NAME, "Sky Glass")
    interval = config.get(CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL)
    entities = [SkyReachableSensor(hass, hub, name, interval),
                SkyBoundSensor(hass, hub, name)]
    power_entity = config.get(CONF_POWER_ENTITY)
    entities.append(SkyTvOnSensor(hass, hub, name, power_entity))
    async_add_entities(entities)


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


class SkyTvOnSensor(_SkySensor):
    """Estimated panel state from a power sensor.

    RICS has no state query, so this is an estimate, not a fact. Hysteresis
    (3 W off / 20 W on) plus a 60s dwell keeps the standby oscillation and
    brief dips from flapping it. Stale or unavailable readings become unknown.
    """

    _attr_icon = "mdi:television"
    _attr_device_class = "power"

    def __init__(self, hass, hub: SkyRicsHub, base_name: str, power_entity: str | None):
        super().__init__(hass, hub, base_name)
        self._base = base_name
        self._power_entity = power_entity
        self._pending = None
        self._cancel = None
        self._last_reading = None

    @property
    def name(self):
        return f"{self._base_name} TV on"

    @property
    def unique_id(self):
        return f"sky_rics_ha_{self._hub.mac.replace(':','')}_tv_on"

    async def async_added_to_hass(self) -> None:
        from homeassistant.helpers.event import async_track_time_interval

        # The power sensor may not exist yet at platform setup, so resolve it
        # lazily and keep retrying until it appears.
        self._resolve()
        if self._power_entity is None:
            self.async_on_remove(
                async_track_time_interval(
                    self.hass, self._retry_resolve, timedelta(seconds=60)
                )
            )

    def _retry_resolve(self, _now=None) -> None:
        if self._power_entity is not None:
            return
        self._resolve()
        if self._power_entity is not None:
            self._evaluate(self.hass.states.get(self._power_entity))

    def _resolve(self) -> None:
        from homeassistant.helpers.event import async_track_state_change_event

        if self._power_entity is None:
            self._power_entity = _find_power_entity(self.hass, self._base)
        if self._power_entity is None:
            return
        self.async_on_remove(
            async_track_state_change_event(
                self.hass, [self._power_entity], self._on_power
            )
        )
        self._evaluate(self.hass.states.get(self._power_entity))

    def _on_power(self, event) -> None:
        self._evaluate(event.data.get("new_state"))

    def _evaluate(self, state) -> None:
        watts = None
        if state is not None and state.state not in ("unavailable", "unknown", None):
            try:
                watts = float(state.state)
            except (TypeError, ValueError):
                watts = None

        if watts is None:
            self._attr_is_on = None
            self._attr_extra_state_attributes = {
                "source": self._power_entity, "watts": None, "reason": "no-reading",
            }
            self.async_write_ha_state()
            return

        self._last_reading = watts
        candidate = classify(watts, self._attr_is_on)

        if candidate is None or candidate == self._attr_is_on:
            self._pending = None
            if self._cancel:
                self._cancel()
                self._cancel = None
            self._publish(watts, "held" if candidate == self._attr_is_on else "init")
            return

        if self._pending is candidate:
            return  # already waiting out the dwell
        self._pending = candidate
        if self._cancel:
            self._cancel()
        from homeassistant.helpers.event import async_call_later

        self._cancel = async_call_later(
            self.hass, TV_DWELL_S, lambda _now: self._commit(candidate)
        )

    def _commit(self, candidate) -> None:
        self._cancel = None
        self._pending = None
        self._attr_is_on = candidate
        self._publish(self._last_reading, "dwell")

    def _publish(self, watts, reason: str) -> None:
        self._attr_extra_state_attributes = {
            "source": self._power_entity,
            "watts": watts,
            "reason": reason,
            "off_threshold_w": TV_OFF_W,
            "on_threshold_w": TV_ON_W,
        }
        self.async_write_ha_state()
