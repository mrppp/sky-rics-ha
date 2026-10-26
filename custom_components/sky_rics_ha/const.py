"""Constants for the sky_rics_ha research integration."""

DOMAIN = "sky_rics_ha"

CONF_MAC = "mac"
CONF_PORT = "port"
CONF_EXCLUSIONS = "exclusions"
CONF_TARGETS = "targets"
CONF_CERT_CHAIN = "cert_chain"
CONF_PRIVATE_KEY = "private_key"
CONF_ALLOW_KEYS = "allow_key_commands"
CONF_SCAN_INTERVAL = "scan_interval_seconds"
CONF_REDACT = "redact_logs"
CONF_WAKE_ON_ANY_KEY = "wake_on_any_key"
CONF_WAKE_SETTLE = "wake_settle_seconds"
CONF_POWER_ENTITY = "power_entity"

DEFAULT_PORT = 8091
DEFAULT_SCAN_INTERVAL = 60
DEFAULT_REDACT = True

# Explicitly permitted safe keys (mirror tools/sky_rics_send_key.py).
# Info is the least disruptive (dismissible overlay).
SAFE_KEYS = ("Info",)

# Keys the RICS protocol actually accepts for control (verified key set).
# These are the protocol's real names; the pseudo-keys (PowerOff, Standby,
# AudioVolume*, etc.) are rejected by the device and are NOT in this set.
CONTROL_KEYS = {
    # Power
    "Power",
    # Volume
    "VolumeUp", "VolumeDown", "VolumeMute",
    # Channel
    "ChannelUp", "ChannelDown",
    # Home / menu / info
    "Home", "AccessMenu", "Option", "Search", "Settings", "Info",
    # Navigation & select
    "ArrowUp", "ArrowDown", "ArrowLeft", "ArrowRight", "Enter",
    "Backspace", "Dismiss",
    # Playback
    "MediaPlay", "MediaRecord", "MediaRewind", "MediaFastForward",
    # Source / Sky+
    "Source", "Plus",
    # Digits
    "Digit0", "Digit1", "Digit2", "Digit3", "Digit4",
    "Digit5", "Digit6", "Digit7", "Digit8", "Digit9",
    # Colour buttons
    "Red", "Green", "Yellow", "Blue",
}

# Never allowed: names the RICS device rejects (verified as unsupported) and
# any placeholder/unknown names. These would only ever return status:false.
FORBIDDEN_KEYS = {
    "Standby", "WakeUp", "PowerOff", "STBPower", "TVPower",
    "AudioVolumeUp", "AudioVolumeDown", "AudioVolumeMute",
    "PageUp", "PageDown", "LiveContent", "OnDemand",
    "Guide", "Help", "Menu", "Back", "Select", "Subtitle", "Teletext", "Exit",
    "Play", "Pause", "PlayPause", "Stop", "Record",
    "MediaPause", "MediaStop", "MediaPlayPause",
    "PlaySpeedUp", "PlaySpeedDown", "PlaySpeedReset",
    "ColorF0Red", "ColorF1Green", "ColorF2Yellow", "ColorF3Blue",
    "ClosedCaptionToggle", "GuideNextDay", "GuidePreviousDay",
}

# Full set that may be sent when allow_key_commands is enabled.
ALLOWED_KEYS = CONTROL_KEYS | set(SAFE_KEYS)

ATTR_DEVICE = "device"
ATTR_KEY = "key"
ATTR_BIND_ID = "bind_id"
ATTR_DEVICE_NAME = "device_name"