from __future__ import annotations

from homeassistant.components.binary_sensor import (
    BinarySensorDeviceClass,
    BinarySensorEntity,
    BinarySensorEntityDescription,
)
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from . import CyberPowerPduConfigEntry, _get_environment_coordinator
from .const import DOMAIN
from .coordinator import CyberPowerEnvironmentCoordinator
from .snmp import CyberPowerPduEnvContact

ENV_CONTACT_NORMAL = 1


async def async_setup_entry(
    hass,
    entry: CyberPowerPduConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    entities: list[BinarySensorEntity] = []

    env_coord = _get_environment_coordinator(hass, entry)
    if env_coord is not None and env_coord.data:
        for contact in env_coord.data.contacts:
            entities.append(CyberPowerEnvContactBinarySensor(env_coord, contact))

    async_add_entities(entities)


class CyberPowerEnvContactBinarySensor(
    CoordinatorEntity[CyberPowerEnvironmentCoordinator], BinarySensorEntity
):
    entity_description: BinarySensorEntityDescription
    _contact: CyberPowerPduEnvContact
    _attr_has_entity_name = True

    def __init__(
        self, coordinator: CyberPowerEnvironmentCoordinator, contact: CyberPowerPduEnvContact,
    ) -> None:
        super().__init__(coordinator)
        self._contact = contact
        name = contact.name or f"Contact {contact.index}"
        self._attr_name = name
        self._attr_unique_id = f"{coordinator.device_identifier}_contact_{contact.index}"
        self.entity_description = BinarySensorEntityDescription(
            key=f"contact_{contact.index}",
            name=name,
            device_class=BinarySensorDeviceClass.PROBLEM,
        )

    @property
    def device_info(self) -> DeviceInfo:
        return DeviceInfo(
            identifiers={(DOMAIN, self.coordinator.device_identifier)},
            manufacturer="CyberPower",
            model="Environmental Sensor",
            name=self.coordinator.device_name or "Environmental Sensor",
            serial_number=self.coordinator.env_serial,
        )

    @property
    def is_on(self) -> bool | None:
        if not self.coordinator.data:
            return None
        # Find the current contact data by index
        contact = next(
            (
                c
                for c in self.coordinator.data.contacts
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
        )