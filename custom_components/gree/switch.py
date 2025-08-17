"""Switch platform for Gree climate."""

from __future__ import annotations

import logging

from homeassistant.components.switch import SwitchEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.components.climate import (HVACMode)
from homeassistant.helpers.device_registry import CONNECTION_NETWORK_MAC

from .climate import GreeClimate

# from homeassistant.helpers.entity import async_get_platforms
from .const import DOMAIN

_LOGGER = logging.getLogger(__name__)

SWITCHES = [
    ("lights", "Lig", "Lights"),
    ("xfan", "Blo", "XFan"),
    ("health", "Health", "Health"),
    ("powersave", "SvSt", "Powersave"),
    ("sleep", "SwhSlp", "Sleep"),
    ("eightdegheat", "StHt", "8°C Heat"),
    ("air", "Air", "Air"),
    ("anti_direct_blow", "AntiDirectBlow", "Anti Direct Blow"),
    ("beeper", "Buzzer_ON_OFF", "Beeper"),
    ("auto_light", None, "Auto Light"),
    ("auto_xfan", None, "Auto XFan"),
    ("light_sensor", "LigSen", "Light Sensor"),
]


class GreeOptionSwitch(SwitchEntity):
    """Generic switch for Gree option."""

    _attr_has_entity_name = True

    def __init__(self, climate: GreeClimate, key: str, option: str, name: str) -> None:
        self._climate = climate
        self._key = key
        self._option = option
        # print(f"switch.gree_{climate._mac_addr}_{key}")
        self._attr_unique_id = f"switch.gree_{climate._mac_addr}_{key}"
        # self._attr_name = f"{climate._name} {name}"
        self.entity_id = f"switch.{(climate._name).lower()}_{key}"
        self._attr_translation_key = key
        # self._attr_device_info = {  "identifiers": {(DOMAIN, climate._mac_addr)},
        #                             "connections": {(CONNECTION_NETWORK_MAC, climate._mac_addr)},
        #                             "name": climate._name}
        self._attr_device_info = climate._attr_device_info

    async def async_update(self) -> None:
        """Update the switch state."""
        if self._key == "auto_light":
            self._attr_is_on = self._climate._auto_light
        elif self._key == "auto_xfan":
            self._attr_is_on = self._climate._auto_xfan
        elif self._key == "light_sensor":
            self._attr_is_on = self._climate._enable_light_sensor
            value = self._climate._acOptions.get(self._option)
            self._attr_is_on = bool(value) if value is not None else False
        elif self._key == "beeper":
            self._attr_is_on = self._climate._current_beeper_enabled
        else:
            value = self._climate._acOptions.get(self._option)
            self._attr_is_on = bool(value) if value is not None else False

    async def async_turn_on(self, **kwargs) -> None:
        """Turn the entity on."""
        if self._key == "eightdegheat":
            if (self._climate._hvac_mode == "heat"):  # Ensure that 8°C heat can only be enabled in heat mode
                self._climate.SyncState({self._option: 1})
            else:
                _LOGGER.warning("8°C heat can only be enabled in heat mode")
                return
        elif self._key == "auto_light":
            self._climate._auto_light = True
            self._climate.schedule_update_ha_state(True)
        elif self._key == "auto_xfan":
            self._climate._auto_xfan = True
            if (self._climate.hvac_mode in (HVACMode.COOL, HVACMode.DRY)):      # Ensure that XFan will be enabled right away when in cool or dry mode
                self._climate.SyncState({'Blo': 1})
            self._climate.schedule_update_ha_state(True)
        elif self._key == "light_sensor":
            self._climate._enable_light_sensor = True
            self._climate.SyncState({self._option: 1})
        elif self._key == "beeper":
            self._climate.set_beeper_enabled(True)
        elif self._key == "sleep":
            self._climate.SyncState({"SwhSlp": 1, "SlpMod": 1})
        else:
            self._climate.SyncState({self._option: 1})
        await self._climate.async_update_ha_state(True)

    async def async_turn_off(self, **kwargs) -> None:
        """Turn the entity off."""
        # if self._key == "eightdegheat":
        #     self._climate.SyncState({"StHt": 0})
        if self._key == "auto_light":
            self._climate._auto_light = False
            self._climate.schedule_update_ha_state(True)
        elif self._key == "auto_xfan":
            self._climate._auto_xfan = False
            self._climate.schedule_update_ha_state(True)
        elif self._key == "light_sensor":
            self._climate._enable_light_sensor = False
            self._climate.SyncState({self._option: 0})
        elif self._key == "beeper":
            self._climate.set_beeper_enabled(False)
        elif self._key == "sleep":
            self._climate.SyncState({"SwhSlp": 0, "SlpMod": 0})
        else:
            self._climate.SyncState({self._option: 0})
        await self._climate.async_update_ha_state(True)

    async def async_added_to_hass(self):
        """Update the switch state when added to hass."""
        await self.async_update()

async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry, async_add_entities) -> None:
    """Set up Gree switches from a config entry."""
    climate_entities = (hass.data.get(DOMAIN, {}).get(entry.entry_id, {}).get("climate_entities", []))
    if not climate_entities:
        _LOGGER.debug("No GreeClimate entity found for switch setup")
        return
    climate = climate_entities[0]
    entities = [GreeOptionSwitch(climate, key, option, name) for key, option, name in SWITCHES]
    async_add_entities(entities)
