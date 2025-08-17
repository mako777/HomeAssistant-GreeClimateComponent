"""Number platform for Gree climate."""

from homeassistant.components.number import NumberEntity, NumberDeviceClass
from homeassistant.components.sensor import SensorStateClass
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.device_registry import CONNECTION_NETWORK_MAC

from .const import DOMAIN, MIN_TEMP_C, MAX_TEMP_C
from .climate import GreeClimate

class GreeTargetTempNumber(NumberEntity):
    """Number entity for target temperature."""

    _attr_has_entity_name = True
    _attr_translation_key = "target_temp"
    _attr_state_class = SensorStateClass.MEASUREMENT
    _attr_device_class = NumberDeviceClass.TEMPERATURE

    def __init__(self, climate: GreeClimate) -> None:
        self._climate = climate
        self._option = "SetTem"
        self._attr_unique_id = f"number.gree_{climate._mac_addr}_target_temp"
        # self._attr_name = f"{climate._name} Target temperature"
        self.entity_id = f"number.{(climate._name).lower()}_target_temp"
        self._attr_native_step = climate._target_temperature_step
        self._attr_native_min_value = MIN_TEMP_C
        self._attr_native_max_value = MAX_TEMP_C
        self.native_unit_of_measurement = climate._unit_of_measurement
        # self._attr_device_info = {  "identifiers": {(DOMAIN, climate._mac_addr)},
        #                             "connections": {(CONNECTION_NETWORK_MAC, climate._mac_addr)},
        #                             "name": climate._name}
        self._attr_device_info = climate._attr_device_info

    async def async_set_native_value(self, value: float) -> None:
        self._climate.set_temperature(temperature=value)
        await self._climate.async_update_ha_state(True)

    async def async_update(self) -> None:
        """Update number state."""
        self._attr_native_value = self._climate._acOptions.get(self._option)

    async def async_added_to_hass(self):
        """Update entities state when added to hass."""
        await self.async_update()

async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry, async_add_entities) -> None:
    climate_entities = hass.data.get(DOMAIN, {}).get(entry.entry_id, {}).get("climate_entities", [])
    if not climate_entities:
        return
    climate = climate_entities[0]
    async_add_entities([GreeTargetTempNumber(climate)])
