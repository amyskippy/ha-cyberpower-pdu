from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from homeassistant.components.sensor import (
    SensorDeviceClass,
    SensorEntity,
    SensorEntityDescription,
    SensorStateClass,
)
from homeassistant.const import (
    UnitOfApparentPower,
    UnitOfElectricCurrent,
    UnitOfElectricPotential,
    UnitOfEnergy,
    UnitOfFrequency,
    UnitOfPower,
    UnitOfTemperature,
)
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers import entity_registry as er

from . import CyberPowerPduConfigEntry, _get_chained_coordinators
from .entity import AnyCoordinator, CyberPowerPduEntity
from .snmp import CyberPowerPduData, CyberPowerPduEnvironment, CyberPowerPduSource

SOURCE_SELECTED_OPTIONS = {1: "Source A", 2: "Source B", 3: "None"}


@dataclass(frozen=True, kw_only=True)
class SourceSensorDescription(SensorEntityDescription):
    value_fn: Callable[[CyberPowerPduSource], int | float | str | None]


SOURCE_SENSORS: tuple[SourceSensorDescription, ...] = (
    SourceSensorDescription(
        key="selected_source",
        name="Selected Source",
        device_class=None,
        value_fn=lambda src: SOURCE_SELECTED_OPTIONS.get(
            src.selected_source, "Unknown"
        )
        if src.selected_source is not None
        else None,
    ),
    SourceSensorDescription(
        key="source_a_voltage",
        name="Source A Voltage",
        device_class=SensorDeviceClass.VOLTAGE,
        native_unit_of_measurement=UnitOfElectricPotential.VOLT,
        state_class=SensorStateClass.MEASUREMENT,
        value_fn=lambda src: src.source_a_voltage,
    ),
    SourceSensorDescription(
        key="source_b_voltage",
        name="Source B Voltage",
        device_class=SensorDeviceClass.VOLTAGE,
        native_unit_of_measurement=UnitOfElectricPotential.VOLT,
        state_class=SensorStateClass.MEASUREMENT,
        value_fn=lambda src: src.source_b_voltage,
    ),
    SourceSensorDescription(
        key="source_a_frequency",
        name="Source A Frequency",
        device_class=SensorDeviceClass.FREQUENCY,
        native_unit_of_measurement=UnitOfFrequency.HERTZ,
        state_class=SensorStateClass.MEASUREMENT,
        value_fn=lambda src: src.source_a_frequency,
    ),
    SourceSensorDescription(
        key="source_b_frequency",
        name="Source B Frequency",
        device_class=SensorDeviceClass.FREQUENCY,
        native_unit_of_measurement=UnitOfFrequency.HERTZ,
        state_class=SensorStateClass.MEASUREMENT,
        value_fn=lambda src: src.source_b_frequency,
    ),
    SourceSensorDescription(
        key="redundancy_state",
        name="Redundancy State",
        device_class=None,
        value_fn=lambda src: (
            "Redundant" if src.redundancy_state == 2 else "Lost"
            if src.redundancy_state == 1
            else None
        ),
    ),
    SourceSensorDescription(
        key="phase_sync",
        name="Phase Sync",
        device_class=None,
        value_fn=lambda src: (
            "In Sync" if src.phase_sync == 1 else "Out of Sync"
            if src.phase_sync == 2
            else None
        ),
    ),
)


@dataclass(frozen=True, kw_only=True)
class EnvironmentSensorDescription(SensorEntityDescription):
    value_fn: Callable[[CyberPowerPduEnvironment], float | None]


ENVIRONMENT_SENSORS: tuple[EnvironmentSensorDescription, ...] = (
    EnvironmentSensorDescription(
        key="temperature",
        name="Temperature",
        device_class=SensorDeviceClass.TEMPERATURE,
        native_unit_of_measurement=UnitOfTemperature.CELSIUS,
        state_class=SensorStateClass.MEASUREMENT,
        value_fn=lambda env: env.temperature,
    ),
    EnvironmentSensorDescription(
        key="humidity",
        name="Humidity",
        device_class=SensorDeviceClass.HUMIDITY,
        native_unit_of_measurement="%",
        state_class=SensorStateClass.MEASUREMENT,
        value_fn=lambda env: env.humidity,
    ),
)


LEGACY_OUTLET_SENSOR_KEYS = (
    "power",
    "apparent_power",
    "current",
    "energy",
    "peak_power",
)


@dataclass(frozen=True, kw_only=True)
class PduSensorDescription(SensorEntityDescription):
    value_fn: Callable[[CyberPowerPduData], int | float | None]


PDU_SENSORS: tuple[PduSensorDescription, ...] = (
    PduSensorDescription(
        key="total_power",
        name="Power",
        device_class=SensorDeviceClass.POWER,
        native_unit_of_measurement=UnitOfPower.WATT,
        state_class=SensorStateClass.MEASUREMENT,
        value_fn=lambda data: data.power,
    ),
    PduSensorDescription(
        key="total_apparent_power",
        name="Apparent Power",
        device_class=SensorDeviceClass.APPARENT_POWER,
        native_unit_of_measurement=UnitOfApparentPower.VOLT_AMPERE,
        state_class=SensorStateClass.MEASUREMENT,
        value_fn=lambda data: data.apparent_power,
    ),
    PduSensorDescription(
        key="total_current",
        name="Current",
        device_class=SensorDeviceClass.CURRENT,
        native_unit_of_measurement=UnitOfElectricCurrent.AMPERE,
        state_class=SensorStateClass.MEASUREMENT,
        value_fn=lambda data: data.current,
    ),
    PduSensorDescription(
        key="voltage",
        name="Voltage",
        device_class=SensorDeviceClass.VOLTAGE,
        native_unit_of_measurement=UnitOfElectricPotential.VOLT,
        state_class=SensorStateClass.MEASUREMENT,
        value_fn=lambda data: data.voltage,
    ),
    PduSensorDescription(
        key="total_energy",
        name="Energy",
        device_class=SensorDeviceClass.ENERGY,
        native_unit_of_measurement=UnitOfEnergy.KILO_WATT_HOUR,
        state_class=SensorStateClass.TOTAL_INCREASING,
        value_fn=lambda data: data.energy,
    ),
)


async def async_setup_entry(
    hass,
    entry: CyberPowerPduConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    coordinator = entry.runtime_data
    _remove_legacy_outlet_sensors(hass, entry)
    entities: list[SensorEntity] = []

    # Main coordinator sensors
    entities.extend(
        CyberPowerPduSensor(coordinator, description) for description in PDU_SENSORS
    )
    if coordinator.data and coordinator.data.source is not None:
        entities.extend(
            CyberPowerPduSourceSensor(coordinator, description)
            for description in SOURCE_SENSORS
        )
    if coordinator.data and coordinator.data.environment is not None:
        entities.extend(
            CyberPowerPduEnvironmentSensor(coordinator, description)
            for description in ENVIRONMENT_SENSORS
        )

    # Chained PDU sensors
    chained = _get_chained_coordinators(hass, entry)
    for chained_coord in chained:
        if chained_coord.data:
            # Only add source sensors for chained PDUs (they have no power/current/voltage)
            if chained_coord.data.source is not None:
                entities.extend(
                    CyberPowerPduSourceSensor(chained_coord, description)
                    for description in SOURCE_SENSORS
                )

    async_add_entities(entities)


class CyberPowerPduSensor(CyberPowerPduEntity, SensorEntity):
    entity_description: PduSensorDescription

    def __init__(self, coordinator: AnyCoordinator, description: PduSensorDescription) -> None:
        super().__init__(coordinator)
        self.entity_description = description
        self._attr_name = description.name
        self._attr_unique_id = f"{coordinator.device_identifier}_{description.key}"

    @property
    def native_value(self) -> int | float | None:
        if not self.coordinator.data:
            return None
        return self.entity_description.value_fn(self.coordinator.data)

    @property
    def available(self) -> bool:
        return super().available and self.native_value is not None


class CyberPowerPduSourceSensor(CyberPowerPduEntity, SensorEntity):
    entity_description: SourceSensorDescription

    def __init__(self, coordinator: AnyCoordinator, description: SourceSensorDescription) -> None:
        super().__init__(coordinator)
        self.entity_description = description
        self._attr_name = description.name
        self._attr_unique_id = f"{coordinator.device_identifier}_source_{description.key}"

    @property
    def native_value(self) -> int | float | str | None:
        if not self.coordinator.data or not self.coordinator.data.source:
            return None
        return self.entity_description.value_fn(self.coordinator.data.source)

    @property
    def available(self) -> bool:
        return (
            super().available
            and self.coordinator.data is not None
            and self.coordinator.data.source is not None
            and self.native_value is not None
        )


class CyberPowerPduEnvironmentSensor(CyberPowerPduEntity, SensorEntity):
    entity_description: EnvironmentSensorDescription

    def __init__(
        self, coordinator: AnyCoordinator, description: EnvironmentSensorDescription
    ) -> None:
        super().__init__(coordinator)
        self.entity_description = description
        self._attr_name = description.name
        self._attr_unique_id = f"{coordinator.device_identifier}_env_{description.key}"

    @property
    def native_value(self) -> float | None:
        if not self.coordinator.data or not self.coordinator.data.environment:
            return None
        return self.entity_description.value_fn(self.coordinator.data.environment)

    @property
    def available(self) -> bool:
        return (
            super().available
            and self.coordinator.data is not None
            and self.coordinator.data.environment is not None
            and self.native_value is not None
        )


def _remove_legacy_outlet_sensors(hass, entry: CyberPowerPduConfigEntry) -> None:
    registry = er.async_get(hass)
    for entity_entry in er.async_entries_for_config_entry(registry, entry.entry_id):
        if entity_entry.entity_id.startswith("sensor.") and _is_legacy_outlet_sensor(
            entity_entry.unique_id
        ):
            registry.async_remove(entity_entry.entity_id)


def _is_legacy_outlet_sensor(unique_id: str | None) -> bool:
    return bool(
        unique_id
        and "_outlet_" in unique_id
        and any(unique_id.endswith(f"_{key}") for key in LEGACY_OUTLET_SENSOR_KEYS)
    )

