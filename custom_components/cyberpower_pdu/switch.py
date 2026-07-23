from __future__ import annotations

from typing import Any

from homeassistant.components.switch import SwitchDeviceClass, SwitchEntity
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from . import CyberPowerPduConfigEntry, _get_chained_coordinators
from .const import OUTLET_STATE_OFF, OUTLET_STATE_ON
from .entity import AnyCoordinator, CyberPowerPduEntity


async def async_setup_entry(
    hass: HomeAssistant,
    entry: CyberPowerPduConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    coordinator = entry.runtime_data
    entities: list[SwitchEntity] = []

    # Main coordinator outlets
    if coordinator.data:
        entities.extend(
            CyberPowerOutletSwitch(coordinator, outlet.index, outlet.name)
            for outlet in coordinator.data.outlets
        )

    # Chained PDU outlets
    chained = _get_chained_coordinators(hass, entry)
    for chained_coord in chained:
        if chained_coord.data:
            entities.extend(
                CyberPowerOutletSwitch(chained_coord, outlet.index, outlet.name)
                for outlet in chained_coord.data.outlets
            )

    async_add_entities(entities)


class CyberPowerOutletSwitch(CyberPowerPduEntity, SwitchEntity):
    _attr_device_class = SwitchDeviceClass.OUTLET

    def __init__(self, coordinator: AnyCoordinator, index: int, outlet_name: str) -> None:
        super().__init__(coordinator)
        self._index = index
        self._attr_name = outlet_name
        self._attr_unique_id = f"{coordinator.device_identifier}_outlet_{index}_switch"

    @property
    def is_on(self) -> bool | None:
        outlet = self.coordinator.data.outlet(self._index) if self.coordinator.data else None
        return outlet.is_on if outlet else None

    @property
    def available(self) -> bool:
        outlet = self.coordinator.data.outlet(self._index) if self.coordinator.data else None
        return (
            super().available
            and outlet is not None
            and outlet.state in (OUTLET_STATE_ON, OUTLET_STATE_OFF)
        )

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        outlet = self.coordinator.data.outlet(self._index) if self.coordinator.data else None
        return {
            "outlet_index": self._index,
            "command_pending": outlet.command_pending if outlet else None,
            "bank": outlet.bank if outlet else None,
            "phase": outlet.phase if outlet else None,
            "alarm": outlet.alarm if outlet else None,
        }

    async def async_turn_on(self, **kwargs: Any) -> None:
        await self.coordinator.async_set_outlet_power(self._index, True)

    async def async_turn_off(self, **kwargs: Any) -> None:
        await self.coordinator.async_set_outlet_power(self._index, False)

