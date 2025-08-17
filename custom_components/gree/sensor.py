"""Sensor platform for Gree climate."""

from homeassistant.components.sensor import SensorEntity, SensorDeviceClass, SensorStateClass
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.device_registry import CONNECTION_NETWORK_MAC

from .const import DOMAIN, MIN_TEMP_C, MAX_TEMP_C
from .climate import GreeClimate

import logging
_LOGGER = logging.getLogger(__name__)

class GreeCurrentTempSensor(SensorEntity):
    """Sensor entity for current temperature."""

    _attr_has_entity_name = True
    _attr_translation_key = "current_temp"
    _attr_device_class = SensorDeviceClass.TEMPERATURE
    _attr_state_class = SensorStateClass.MEASUREMENT

    def __init__(self, climate: GreeClimate) -> None:
        self._climate = climate
        self._attr_unique_id = f"sensor.gree_{climate._mac_addr}_current_temp"
        # self._attr_name = f"{climate._name} Current Temperature"
        self.entity_id = f"sensor.{(climate._name).lower()}_current_temp"
        self._attr_native_unit_of_measurement = climate._unit_of_measurement
        self.suggested_display_precision = 0
        # self._attr_device_info = {  "identifiers": {(DOMAIN, climate._mac_addr)},
        #                             "connections": {(CONNECTION_NETWORK_MAC, climate._mac_addr)},
        #                             "name": climate._name}
        self._attr_device_info = climate._attr_device_info


    # @property
    # def native_value(self) -> float | None:
    #     return self._climate.current_temperature

    async def async_update(self) -> None:
        """Update entity state."""
        if(self._climate._current_temperature is not None):
            self._attr_native_value = self._climate._current_temperature
            if(self._climate._current_temperature < MIN_TEMP_C or self._climate._current_temperature > MAX_TEMP_C):
                _LOGGER.warning(f"Current temperature {self._climate._current_temperature} is out of bounds for {self._climate._name}. "
                            f"Expected range: {MIN_TEMP_C} - {MAX_TEMP_C}. Consider checking temperature offset in settings.")

    async def async_added_to_hass(self):
        """Update entities state when added to hass."""
        await self.async_update()

async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry, async_add_entities) -> None:
    climate_entities = hass.data.get(DOMAIN, {}).get(entry.entry_id, {}).get("climate_entities", [])
    if not climate_entities:
        return
    climate = climate_entities[0]
    async_add_entities([GreeCurrentTempSensor(climate)])
