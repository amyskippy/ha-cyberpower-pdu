from __future__ import annotations

from homeassistant.components.select import SelectEntity
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from . import CyberPowerPduConfigEntry
from .entity import CyberPowerPduEntity

SOURCE_OPTIONS = {1: "Source A", 2: "Source B", 3: "None"}
SOURCE_OPTION_VALUES = {"Source A": 1, "Source B": 2, "None": 3}


async def async_setup_entry(
    hass,
    entry: CyberPowerPduConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    coordinator = entry.runtime_data
    entities: list[SelectEntity] = []
    if coordinator.data and coordinator.data.source is not None:
        entities.append(CyberPowerPreferredSourceSelect(coordinator))
    async_add_entities(entities)


class CyberPowerPreferredSourceSelect(CyberPowerPduEntity, SelectEntity):
    _attr_current_option = None
    _attr_options = list(SOURCE_OPTIONS.values())
    _attr_translation_key = "preferred_source"
    _attr_has_entity_name = True

    def __init__(self, coordinator) -> None:
        super().__init__(coordinator)
        self._attr_unique_id = f"{coordinator.device_identifier}_preferred_source"

    @property
    def current_option(self) -> str | None:
        if not self.coordinator.data or not self.coordinator.data.source:
            return None
        preferred = self.coordinator.data.source.preferred_source
        return SOURCE_OPTIONS.get(preferred)

    @property
    def available(self) -> bool:
        return (
            super().available
            and self.coordinator.data is not None
            and self.coordinator.data.source is not None
        )

    async def async_select_option(self, option: str) -> None:
        value = SOURCE_OPTION_VALUES.get(option)
        if value is None:
            return
        await self.coordinator.async_set_preferred_source(value)