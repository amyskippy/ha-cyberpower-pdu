from __future__ import annotations

from homeassistant.components.binary_sensor import (
    BinarySensorDeviceClass,
    BinarySensorEntity,
    BinarySensorEntityDescription,
)
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from . import CyberPowerPduConfigEntry
from .entity import CyberPowerPduEntity
from .snmp import CyberPowerPduEnvContact

ENV_CONTACT_NORMAL = 1


async def async_setup_entry(
    hass,
    entry: CyberPowerPduConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    coordinator = entry.runtime_data
    entities: list[CyberPowerEnvContactBinarySensor] = []
    if coordinator.data and coordinator.data.environment:
        for contact in coordinator.data.environment.contacts:
            entities.append(CyberPowerEnvContactBinarySensor(coordinator, contact))
    async_add_entities(entities)


class CyberPowerEnvContactBinarySensor(CyberPowerPduEntity, BinarySensorEntity):
    entity_description: BinarySensorEntityDescription
    _contact: CyberPowerPduEnvContact

    def __init__(
        self, coordinator, contact: CyberPowerPduEnvContact,
    ) -> None:
        super().__init__(coordinator)
        self._contact = contact
        name = contact.name or f"Contact {contact.index}"
        self._attr_name = name
        self._attr_unique_id = f"{coordinator.device_identifier}_env_contact_{contact.index}"
        self.entity_description = BinarySensorEntityDescription(
            key=f"env_contact_{contact.index}",
            name=name,
            device_class=BinarySensorDeviceClass.PROBLEM,
        )

    @property
    def is_on(self) -> bool | None:
        if not self.coordinator.data or not self.coordinator.data.environment:
            return None
        # Find the current contact data by index
        contact = next(
            (
                c
                for c in self.coordinator.data.environment.contacts
                if c.index == self._contact.index
            ),
            None,
        )
        if contact is None or contact.status is None:
            return None
        # is_on=True means "abnormal" (alarm triggered)
        return contact.status != ENV_CONTACT_NORMAL

    @property
    def available(self) -> bool:
        return (
            super().available
            and self.coordinator.data is not None
            and self.coordinator.data.environment is not None
        )