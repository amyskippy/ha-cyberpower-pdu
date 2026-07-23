from __future__ import annotations

import asyncio
from collections.abc import Iterable
from dataclasses import dataclass, field
from itertools import islice
import os
from typing import Any

from pysnmp.hlapi.v3arch.asyncio import (
    CommunityData,
    ContextData,
    ObjectIdentity,
    ObjectType,
    SnmpEngine,
    UdpTransportTarget,
    UsmUserData,
    get_cmd,
    set_cmd,
    USM_AUTH_HMAC96_MD5,
    USM_AUTH_HMAC96_SHA,
    USM_AUTH_HMAC128_SHA224,
    USM_AUTH_HMAC192_SHA256,
    USM_AUTH_HMAC256_SHA384,
    USM_AUTH_HMAC384_SHA512,
    USM_AUTH_NONE,
    USM_PRIV_CBC56_DES,
    USM_PRIV_CBC168_3DES,
    USM_PRIV_CFB128_AES,
    USM_PRIV_CFB192_AES,
    USM_PRIV_CFB256_AES,
    USM_PRIV_NONE,
)
from pysnmp.proto.rfc1902 import Integer

from .const import (
    AUTH_MD5,
    AUTH_NONE,
    AUTH_SHA,
    AUTH_SHA224,
    AUTH_SHA256,
    AUTH_SHA384,
    AUTH_SHA512,
    DEFAULT_OUTLET_COUNT,
    OUTLET_COMMAND_OFF,
    OUTLET_COMMAND_ON,
    OUTLET_COMMAND_REBOOT,
    OUTLET_STATE_ON,
    PRIVACY_3DES,
    PRIVACY_AES,
    PRIVACY_AES192,
    PRIVACY_AES256,
    PRIVACY_DES,
    PRIVACY_NONE,
    SNMP_V1,
    SNMP_V2C,
)

MAX_OUTLETS = 64
GET_CHUNK_SIZE = 4

EPDU_IDENT = "1.3.6.1.4.1.3808.1.1.3.1"
EPDU_LOAD_STATUS = "1.3.6.1.4.1.3808.1.1.3.2.3.1.1"
EPDU_OUTLET_DEVICE = "1.3.6.1.4.1.3808.1.1.3.3.1"
EPDU_OUTLET_CONTROL = "1.3.6.1.4.1.3808.1.1.3.3.3.1.1"
EPDU_OUTLET_STATUS = "1.3.6.1.4.1.3808.1.1.3.3.5.1.1"

ATS_IDENT = "1.3.6.1.4.1.3808.1.1.5.1"
ATS_OUTLET_DEVICE = "1.3.6.1.4.1.3808.1.1.5.6.1"
ATS_OUTLET_CONTROL = "1.3.6.1.4.1.3808.1.1.5.6.5.1"
ATS_OUTLET_STATUS = "1.3.6.1.4.1.3808.1.1.5.6.3.1"

# ePDU2 branch — unified MIB tree used by ATS PDUs (PDU44004/44005) and daisy-chains
EPDU2_IDENT = "1.3.6.1.4.1.3808.1.1.6"
EPDU2_ROLE = f"{EPDU2_IDENT}.1.0"
EPDU2_IDENT_TABLE_SIZE = f"{EPDU2_IDENT}.2.1.0"
# ePDU2Ident table columns (indexed by module position):
#   1=index, 2=moduleIndex, 3=name, 4=location, 5=contact,
#   6=hardwareRev, 7=firmwareRev, 8=dateOfManufacture,
#   9=modelName, 10=serialNumber, 11=indicator
EPDU2_IDENT_ENTRY = f"{EPDU2_IDENT}.2.2.1"
EPDU2_DEVICE_CONFIG_ENTRY = f"{EPDU2_IDENT}.3.2.1"
# ePDU2DeviceConfigEntry columns:
#   1=index, 2=moduleIndex, 3=name, 4=location, 5=contact,
#   6=displayOrientation, 7=coldstartDelay,
#   8=currentLowLoadThreshold, 9=currentNearOverloadThreshold,
#   10=currentOverloadThreshold, 11=peakLoadReset, 12=energyReset,
#   13=powerLowLoadThreshold, 14=powerNearOverloadThreshold,
#   15=powerOverloadThreshold
EPDU2_OUTLET_SWITCHED_CONFIG_ENTRY = f"{EPDU2_IDENT}.6.1.2.1"
 # ePDU2OutletSwitchedConfigEntry columns:
#   1=index, 2=moduleIndex, 3=number, 4=name,
#   5=powerOnTime, 6=powerOffTime, 7=rebootDuration
EPDU2_OUTLET_SWITCHED_INFO_ENTRY = f"{EPDU2_IDENT}.6.1.3.1"
# ePDU2OutletSwitchedInfoEntry columns:
#   1=index, 2=moduleIndex, 3=number, 4=name, 5=bank, 6=phaseLayout
EPDU2_OUTLET_SWITCHED_STATUS_ENTRY = f"{EPDU2_IDENT}.6.1.4.1"
# ePDU2OutletSwitchedStatusEntry columns:
#   1=index, 2=moduleIndex, 3=number, 4=name,
#   5=state, 6=commandPending
EPDU2_OUTLET_SWITCHED_CONTROL = f"{EPDU2_IDENT}.6.1.5.1"
# ePDU2OutletSwitchedControlEntry columns:
#   1=index, 2=moduleIndex, 3=number, 4=name, 5=command
EPDU2_SOURCE_CONFIG = f"{EPDU2_IDENT}.9.2.1"
EPDU2_SOURCE_STATUS = f"{EPDU2_IDENT}.9.4.1"
# ePDU2SourceConfigEntry columns:
#   1=index, 2=moduleIndex, 3=preferredSource, ...
# ePDU2SourceStatusEntry columns:
#   1=index, 2=moduleIndex, 3=selectedSource, 4=nominalFrequency,
#   5=sourceAVoltage, 6=sourceBVoltage, 7=sourceAFrequency, 8=sourceBFrequency,
#   9=sourceAVolStatus, 10=sourceBVolStatus, 11=sourceAFreqStatus,
#   12=sourceBFreqStatus, 13=phaseSync, 14=pwrSupplyAStatus,
#   15=pwrSupplyBStatus, 16=redundancyState

# Environment Sensor 2 branch (hardware 8) — table-based env sensor
ENVIR2_BASE = "1.3.6.1.4.1.3808.1.1.8"
ENVIR2_IDENT_TABLE_SIZE = f"{ENVIR2_BASE}.1.1.0"
ENVIR2_TEMP_UNIT = f"{ENVIR2_BASE}.2.2.0"
ENVIR2_TEMP_ENTRY = f"{ENVIR2_BASE}.2.3.1"
ENVIR2_HUMID_ENTRY = f"{ENVIR2_BASE}.3.2.1"
ENVIR2_CONTACT_TABLE_SIZE = f"{ENVIR2_BASE}.4.1.0"
ENVIR2_CONTACT_ENTRY = f"{ENVIR2_BASE}.4.2.1"

DEVICE_OIDS = {
    "name": f"{EPDU_IDENT}.1.0",
    "hardware": f"{EPDU_IDENT}.2.0",
    "firmware": f"{EPDU_IDENT}.3.0",
    "model": f"{EPDU_IDENT}.5.0",
    "serial": f"{EPDU_IDENT}.6.0",
    "outlet_count": f"{EPDU_IDENT}.8.0",
    "controlled_outlets": f"{EPDU_OUTLET_DEVICE}.3.0",
}

ATS_DEVICE_OIDS = {
    "name": f"{ATS_IDENT}.1.0",
    "model": f"{ATS_IDENT}.2.0",
    "hardware": f"{ATS_IDENT}.3.0",
    "firmware": f"{ATS_IDENT}.4.0",
    "serial": f"{ATS_IDENT}.5.0",
    "outlet_count": f"{ATS_IDENT}.9.0",
    "controlled_outlets": f"{ATS_OUTLET_DEVICE}.2.0",
}

TOTAL_OIDS = {
    "current": f"{EPDU_LOAD_STATUS}.2.1",
    "voltage": f"{EPDU_LOAD_STATUS}.6.1",
    "power": f"{EPDU_LOAD_STATUS}.7.1",
    "apparent_power": f"{EPDU_LOAD_STATUS}.8.1",
    "power_factor": f"{EPDU_LOAD_STATUS}.9.1",
    "energy": f"{EPDU_LOAD_STATUS}.10.1",
}

OUTLET_STATUS_COLUMNS = {
    "name": 2,
    "phase": 3,
    "state": 4,
    "command_pending": 5,
    "bank": 6,
    "current": 7,
    "power": 8,
    "alarm": 9,
    "peak_power": 10,
    "energy": 13,
}

ATS_OUTLET_STATUS_COLUMNS = {
    "name": 2,
    "state": 3,
    "command_pending": 4,
    "phase": 5,
    "bank": 6,
}

OUTLET_CONTROL_COMMAND_COLUMN = 4
ATS_OUTLET_CONTROL_COMMAND_COLUMN = 3
MIB_BRANCH_EPDU = "epdu"
MIB_BRANCH_ATS = "ats"

AUTH_PROTOCOL_MAP = {
    AUTH_NONE: USM_AUTH_NONE,
    AUTH_MD5: USM_AUTH_HMAC96_MD5,
    AUTH_SHA: USM_AUTH_HMAC96_SHA,
    AUTH_SHA224: USM_AUTH_HMAC128_SHA224,
    AUTH_SHA256: USM_AUTH_HMAC192_SHA256,
    AUTH_SHA384: USM_AUTH_HMAC256_SHA384,
    AUTH_SHA512: USM_AUTH_HMAC384_SHA512,
}

PRIVACY_PROTOCOL_MAP = {
    PRIVACY_NONE: USM_PRIV_NONE,
    PRIVACY_DES: USM_PRIV_CBC56_DES,
    PRIVACY_3DES: USM_PRIV_CBC168_3DES,
    PRIVACY_AES: USM_PRIV_CFB128_AES,
    PRIVACY_AES192: USM_PRIV_CFB192_AES,
    PRIVACY_AES256: USM_PRIV_CFB256_AES,
}


class CyberPowerPduError(Exception):
    pass


class CyberPowerPduConnectionError(CyberPowerPduError):
    pass


class CyberPowerPduSnmpError(CyberPowerPduError):
    def __init__(self, status: str, oid: str | None = None) -> None:
        self.status = status
        self.oid = oid
        message = status if oid is None else f"{status} at {oid}"
        super().__init__(message)

    @property
    def is_missing_oid(self) -> bool:
        return "nosuch" in self.status.replace(" ", "").lower()


@dataclass(slots=True, frozen=True)
class CyberPowerPduConfig:
    host: str
    port: int
    version: str
    community: str | None
    username: str | None
    auth_protocol: str
    auth_key: str | None
    privacy_protocol: str
    privacy_key: str | None
    context_name: str
    timeout: float
    retries: int


@dataclass(slots=True, frozen=True)
class CyberPowerPduDevice:
    host: str
    mib_branch: str
    name: str | None
    model: str | None
    serial: str | None
    firmware: str | None
    hardware: str | None
    outlet_count: int | None
    controlled_outlets: int | None
    has_source: bool = False
    # For chained modules this holds the module index (2+) or 1 for local
    module_index: int | None = None


@dataclass(slots=True, frozen=True)
class CyberPowerPduOutlet:
    index: int
    name: str
    state: int | None
    command_pending: bool | None
    current: float | None
    power: int | None
    apparent_power: float | None
    peak_power: int | None
    energy: float | None
    phase: int | None
    bank: int | None
    alarm: int | None

    @property
    def is_on(self) -> bool | None:
        if self.state is None:
            return None
        return self.state == OUTLET_STATE_ON


@dataclass(slots=True, frozen=True)
class CyberPowerPduSource:
    selected_source: int | None  # 1=A, 2=B, 3=none
    source_a_voltage: float | None  # Volts (scaled from 0.1V)
    source_b_voltage: float | None
    source_a_frequency: float | None  # Hz (scaled from 0.1Hz)
    source_b_frequency: float | None
    source_a_voltage_status: int | None  # 1=normal, 2=over, 3=under
    source_b_voltage_status: int | None
    source_a_frequency_status: int | None  # 1=normal, 2=over, 3=under
    source_b_frequency_status: int | None
    phase_sync: int | None  # 1=inSync, 2=outOfSync
    power_supply_a_status: int | None  # 1=normal, 2/3/4=failed
    power_supply_b_status: int | None
    redundancy_state: int | None  # 1=lost, 2=fully_redundant
    preferred_source: int | None  # 1=A, 2=B, 3=none (from config)


@dataclass(slots=True, frozen=True)
class CyberPowerPduEnvContact:
    index: int
    name: str | None
    status: int | None  # 1=normal, 2=abnormal
    normal_state: int | None  # 1=normalOpen, 2=normalClose


@dataclass(slots=True, frozen=True)
class CyberPowerPduEnvironment:
    temperature: float | None  # °C or °F (scaled from 0.01)
    humidity: float | None  # % (scaled from 0.01)
    contacts: tuple[CyberPowerPduEnvContact, ...] = ()


@dataclass(slots=True, frozen=True)
class CyberPowerPduData:
    device: CyberPowerPduDevice
    outlets: tuple[CyberPowerPduOutlet, ...]
    current: float | None
    voltage: float | None
    power: int | None
    apparent_power: int | None
    power_factor: float | None
    energy: float | None
    source: CyberPowerPduSource | None = None
    environment: CyberPowerPduEnvironment | None = None

    def outlet(self, index: int) -> CyberPowerPduOutlet | None:
        return next((outlet for outlet in self.outlets if outlet.index == index), None)


@dataclass(slots=True, frozen=True)
class CyberPowerChainedPduInfo:
    """Summary info about a daisy-chained PDU discovered via ePDU2."""
    module_index: int
    name: str | None
    model: str | None
    serial: str | None
    firmware: str | None
    hardware: str | None


class CyberPowerPduClient:
    def __init__(self, config: CyberPowerPduConfig) -> None:
        self._config = config
        self._engine: SnmpEngine | None = None
        self._lock = asyncio.Lock()
        self._mib_branch = MIB_BRANCH_EPDU
        self._has_source = False
        self._has_env = False
        # module_index -> {local_outlet_number: global_table_row}
        self._outlet_index_map: dict[int, dict[int, int]] = {}

    async def async_close(self) -> None:
        if self._engine is not None:
            self._engine.close_dispatcher()

    async def async_fetch_device_info(self) -> CyberPowerPduDevice:
        async with self._lock:
            return await self._fetch_device_info_locked()

    async def async_fetch_environment(self) -> CyberPowerPduEnvironment:
        """Fetch environment data for the attached environmental sensor."""
        async with self._lock:
            env = await self._fetch_environment_locked()
            if env is None:
                raise CyberPowerPduSnmpError("Environmental sensor not found")
            return env

    async def async_detect_environment(self) -> tuple[str | None, str | None]:
        """Probe for an attached environmental sensor and return (name, serial)."""
        try:
            values = await self._get_many_locked((ENVIR2_IDENT_TABLE_SIZE,))
            size = _as_int(values.get(ENVIR2_IDENT_TABLE_SIZE))
            if size is None or size < 1:
                return None, None
            ident_oids = (
                f"{ENVIR2_BASE}.1.2.1.3.1",   # name
                f"{ENVIR2_BASE}.1.2.1.5.1",   # serialNumber
            )
            ident_values = await self._get_many_locked(ident_oids)
            return (
                _as_text(ident_values.get(ident_oids[0])),
                _as_text(ident_values.get(ident_oids[1])),
            )
        except (CyberPowerPduConnectionError, CyberPowerPduSnmpError):
            return None, None

    async def async_fetch(self) -> CyberPowerPduData:
        async with self._lock:
            device = await self._fetch_device_info_locked()
            count = _bounded_outlet_count(
                device.controlled_outlets or device.outlet_count or DEFAULT_OUTLET_COUNT
            )
            if device.mib_branch == MIB_BRANCH_ATS:
                outlet_values = await self._get_many_locked(_ats_outlet_status_oids(count))
                outlets = tuple(
                    _build_ats_outlet(index, outlet_values) for index in range(1, count + 1)
                )
                return CyberPowerPduData(
                    device=device,
                    outlets=outlets,
                    current=None,
                    voltage=None,
                    power=None,
                    apparent_power=None,
                    power_factor=None,
                    energy=None,
                )

            total_values = await self._get_many_locked(TOTAL_OIDS.values())
            voltage = _as_scaled_number(total_values.get(TOTAL_OIDS["voltage"]), 10)
            outlet_values = await self._get_many_locked(_outlet_status_oids(count))
            outlets = tuple(
                _build_epdu_outlet(index, outlet_values, voltage)
                for index in range(1, count + 1)
            )

            source = None
            if self._has_source:
                source = await self._fetch_source_locked()

            environment = None
            if self._has_env:
                environment = await self._fetch_environment_locked()

            return CyberPowerPduData(
                device=device,
                outlets=outlets,
                current=_as_scaled_number(total_values.get(TOTAL_OIDS["current"]), 10),
                voltage=voltage,
                power=_as_int(total_values.get(TOTAL_OIDS["power"])),
                apparent_power=_as_int(total_values.get(TOTAL_OIDS["apparent_power"])),
                power_factor=_as_scaled_number(total_values.get(TOTAL_OIDS["power_factor"]), 100),
                energy=_as_scaled_number(total_values.get(TOTAL_OIDS["energy"]), 10),
                source=source,
                environment=environment,
            )

    async def async_set_outlet_power(self, index: int, on: bool) -> None:
        command = OUTLET_COMMAND_ON if on else OUTLET_COMMAND_OFF
        await self._set_outlet_command(index, command)

    async def async_power_cycle_outlet(self, index: int) -> None:
        await self._set_outlet_command(index, OUTLET_COMMAND_REBOOT)

    async def _set_outlet_command(self, index: int, command: int) -> None:
        async with self._lock:
            if self._mib_branch == MIB_BRANCH_ATS:
                oid = f"{ATS_OUTLET_CONTROL}.{ATS_OUTLET_CONTROL_COMMAND_COLUMN}.{index}"
            else:
                oid = f"{EPDU_OUTLET_CONTROL}.{OUTLET_CONTROL_COMMAND_COLUMN}.{index}"
            await self._set_int_locked(oid, command)

    async def async_set_preferred_source(self, source: int) -> None:
        """Set preferred power source (1=A, 2=B, 3=none)."""
        async with self._lock:
            # Module 1 is the local PDU; preferred source config column is 3
            oid = f"{EPDU2_SOURCE_CONFIG}.3.1"
            await self._set_int_locked(oid, source)

    async def async_detect_chained_pdus(self) -> list[CyberPowerChainedPduInfo]:
        """Detect daisy-chained PDUs via ePDU2 ident table.

        Returns a list of CyberPowerChainedPduInfo for each chained PDU (module index >= 2).
        Module 1 is always the local/host PDU and is excluded.
        """
        async with self._lock:
            return await self._detect_chained_pdus_locked()

    async def async_fetch_chained_pdu_data(
        self, module_index: int
    ) -> CyberPowerPduData:
        """Fetch data for a specific chained PDU module.

        Reads device info, outlets, and source data from ePDU2 tables
        filtered to the given module index.
        """
        async with self._lock:
            return await self._fetch_chained_pdu_data_locked(module_index)

    async def async_set_chained_outlet_power(
        self, module_index: int, local_outlet_index: int, on: bool
    ) -> None:
        """Control an outlet on a chained PDU.

        Writes ePDU2OutletSwitchedControlCommand (column 5 of the control table)
        using the sequential row index from the unified ePDU2 switched outlet table.
        For the chained PDU (module 2), rows are offset (e.g., 13..22).
        """
        command = OUTLET_COMMAND_ON if on else OUTLET_COMMAND_OFF
        # Resolve local outlet index to its sequential row index (gi) in the unified table
        row_index = self._outlet_index_map.get(
            module_index, {}
        ).get(local_outlet_index, local_outlet_index)
        async with self._lock:
            oid = f"{EPDU2_OUTLET_SWITCHED_CONTROL}.5.{row_index}"
            await self._set_int_locked(oid, command)

    async def async_set_chained_preferred_source(
        self, module_index: int, source: int
    ) -> None:
        """Set preferred power source for a chained PDU."""
        async with self._lock:
            oid = f"{EPDU2_SOURCE_CONFIG}.3.{module_index}"
            await self._set_int_locked(oid, source)

    async def _fetch_source_locked(self) -> CyberPowerPduSource | None:
        """Fetch ATS source status from ePDU2 branch (module 1 = local PDU)."""
        try:
            oids = _source_status_oids(1)
            values = await self._get_many_locked(oids)
            return _build_source(values, 1)
        except CyberPowerPduSnmpError as err:
            if err.is_missing_oid:
                self._has_source = False
            return None

    async def _fetch_device_info_locked(self) -> CyberPowerPduDevice:
        values = await self._get_many_locked(DEVICE_OIDS.values())
        epdu_device = _build_device(self._config.host, MIB_BRANCH_EPDU, DEVICE_OIDS, values)
        if epdu_device.outlet_count or epdu_device.controlled_outlets:
            self._mib_branch = MIB_BRANCH_EPDU
            # Check for ePDU2 source capability (ATS PDUs like PDU44004/44005)
            await self._detect_source_capability()
            await self._detect_env_capability()
            return epdu_device

        values = await self._get_many_locked(ATS_DEVICE_OIDS.values())
        ats_device = _build_device(self._config.host, MIB_BRANCH_ATS, ATS_DEVICE_OIDS, values)
        if _device_has_data(ats_device):
            self._mib_branch = MIB_BRANCH_ATS
            return ats_device

        if _device_has_data(epdu_device):
            self._mib_branch = MIB_BRANCH_EPDU
            return epdu_device
        return ats_device

    async def _detect_source_capability(self) -> None:
        """Probe ePDU2Role OID to check if this device has ATS source info."""
        try:
            values = await self._get_many_locked((EPDU2_ROLE,))
            role_value = values.get(EPDU2_ROLE)
            role_int = _as_int(role_value)
            if role_int is not None and role_int >= 1:
                self._has_source = True
        except (CyberPowerPduConnectionError, CyberPowerPduSnmpError):
            pass

    async def _detect_env_capability(self) -> None:
        """Probe envir2IdentTableSize to check for an attached environmental sensor."""
        try:
            values = await self._get_many_locked((ENVIR2_IDENT_TABLE_SIZE,))
            size = _as_int(values.get(ENVIR2_IDENT_TABLE_SIZE))
            if size is not None and size >= 1:
                self._has_env = True
        except (CyberPowerPduConnectionError, CyberPowerPduSnmpError):
            pass

    async def _fetch_environment_locked(self) -> CyberPowerPduEnvironment | None:
        """Fetch temperature, humidity, and contacts from envir2 branch."""
        try:
            oids = _env_status_oids()
            values = await self._get_many_locked(oids)
            contact_count = _env_contact_count(values)
            if contact_count > 0:
                values.update(await self._get_many_locked(_env_contact_oids(contact_count)))
            return _build_environment(values)
        except CyberPowerPduSnmpError as err:
            if err.is_missing_oid:
                self._has_env = False
            return None

    async def _detect_chained_pdus_locked(self) -> list[CyberPowerChainedPduInfo]:
        """Read ePDU2IdentTableSize and ePDU2Ident entries to find chained PDUs."""
        try:
            values = await self._get_many_locked((EPDU2_IDENT_TABLE_SIZE,))
            table_size = _as_int(values.get(EPDU2_IDENT_TABLE_SIZE))
            if table_size is None or table_size <= 1:
                return []
        except (CyberPowerPduConnectionError, CyberPowerPduSnmpError):
            return []

        # Fetch ident entries for all modules
        ident_oids: list[str] = []
        for idx in range(1, table_size + 1):
            # Columns: 3=name, 6=hardwareRev, 7=firmwareRev, 9=modelName, 10=serialNumber
            ident_oids.extend([
                f"{EPDU2_IDENT_ENTRY}.3.{idx}",   # name
                f"{EPDU2_IDENT_ENTRY}.6.{idx}",   # hardwareRev
                f"{EPDU2_IDENT_ENTRY}.7.{idx}",   # firmwareRev
                f"{EPDU2_IDENT_ENTRY}.9.{idx}",   # modelName
                f"{EPDU2_IDENT_ENTRY}.10.{idx}",  # serialNumber
            ])

        try:
            ident_values = await self._get_many_locked(ident_oids)
        except (CyberPowerPduConnectionError, CyberPowerPduSnmpError):
            return []

        # Now fetch outlet counts per module from device config
        # Column 8=currentLowLoadThreshold gives us a proxy but we need actual outlet counts
        # Instead, use ePDU2OutletSwitchedConfig which has moduleIndex
        # We'll determine outlet counts later when fetching data
        # For now just build basic info
        chained: list[CyberPowerChainedPduInfo] = []
        for idx in range(2, table_size + 1):
            base = f"{EPDU2_IDENT_ENTRY}"
            chained.append(CyberPowerChainedPduInfo(
                module_index=idx,
                name=_as_text(ident_values.get(f"{base}.3.{idx}")),
                model=_as_text(ident_values.get(f"{base}.9.{idx}")),
                serial=_as_text(ident_values.get(f"{base}.10.{idx}")),
                firmware=_as_text(ident_values.get(f"{base}.7.{idx}")),
                hardware=_as_text(ident_values.get(f"{base}.6.{idx}")),
            ))

        return chained

    async def _fetch_chained_pdu_data_locked(
        self, module_index: int
    ) -> CyberPowerPduData:
        """Fetch full data for a specific chained PDU module from ePDU2 tables."""

        # Build a mapping of global_outlet_index -> local_outlet_number for this module
        # by reading the switched outlet status table's moduleIndex and number columns
        # First get the total switched outlet table size
        try:
            size_values = await self._get_many_locked((f"{EPDU2_IDENT}.6.1.1.0",))
            total_switched = _as_int(size_values.get(f"{EPDU2_IDENT}.6.1.1.0"))
            if total_switched is None or total_switched == 0:
                total_switched = 0
        except (CyberPowerPduConnectionError, CyberPowerPduSnmpError):
            total_switched = 0

        # Read moduleIndex, number, and index columns for all outlets
        module_map_oids: list[str] = []
        for gi in range(1, total_switched + 1):
            module_map_oids.append(f"{EPDU2_OUTLET_SWITCHED_STATUS_ENTRY}.1.{gi}")  # index (SNMP row key)
            module_map_oids.append(f"{EPDU2_OUTLET_SWITCHED_STATUS_ENTRY}.2.{gi}")  # moduleIndex
            module_map_oids.append(f"{EPDU2_OUTLET_SWITCHED_STATUS_ENTRY}.3.{gi}")  # number

        try:
            module_map_values = await self._get_many_locked(module_map_oids)
        except (CyberPowerPduConnectionError, CyberPowerPduSnmpError):
            module_map_values = {}

        # Build mapping: local_outlet_number -> snmp_row_index for this module
        # The SNMP row index (column 1 "index") is used by the control table
        local_to_global: dict[int, int] = {}
        for gi in range(1, total_switched + 1):
            mi = _as_int(module_map_values.get(f"{EPDU2_OUTLET_SWITCHED_STATUS_ENTRY}.2.{gi}"))
            num = _as_int(module_map_values.get(f"{EPDU2_OUTLET_SWITCHED_STATUS_ENTRY}.3.{gi}"))
            if mi == module_index and num is not None:
                row_index = _as_int(module_map_values.get(
                    f"{EPDU2_OUTLET_SWITCHED_STATUS_ENTRY}.1.{gi}"
                ))
                local_to_global[num] = row_index if row_index is not None else gi

        outlet_count = len(local_to_global)
        if not outlet_count:
            outlet_count = DEFAULT_OUTLET_COUNT

        # Cache the mapping for control operations
        self._outlet_index_map[module_index] = local_to_global

        # Fetch outlet status data for all outlets belonging to this module
        # Columns: 4=name, 5=state, 6=commandPending
        outlet_oids: list[str] = []
        for local_num, gi in local_to_global.items():
            outlet_oids.append(f"{EPDU2_OUTLET_SWITCHED_STATUS_ENTRY}.4.{gi}")   # name
            outlet_oids.append(f"{EPDU2_OUTLET_SWITCHED_STATUS_ENTRY}.5.{gi}")   # state
            outlet_oids.append(f"{EPDU2_OUTLET_SWITCHED_STATUS_ENTRY}.6.{gi}")   # commandPending

        try:
            outlet_values = await self._get_many_locked(outlet_oids)
        except (CyberPowerPduConnectionError, CyberPowerPduSnmpError):
            outlet_values = {}

        # Build outlets
        outlets: list[CyberPowerPduOutlet] = []
        for local_num, gi in sorted(local_to_global.items()):
            name_raw = outlet_values.get(f"{EPDU2_OUTLET_SWITCHED_STATUS_ENTRY}.4.{gi}")
            name = _as_text(name_raw) or f"Outlet {local_num}"
            state_raw = outlet_values.get(f"{EPDU2_OUTLET_SWITCHED_STATUS_ENTRY}.5.{gi}")
            pending_raw = outlet_values.get(f"{EPDU2_OUTLET_SWITCHED_STATUS_ENTRY}.6.{gi}")

            outlets.append(CyberPowerPduOutlet(
                index=local_num,
                name=name,
                state=_as_int(state_raw),
                command_pending=_as_pending(pending_raw),
                current=None,
                power=None,
                apparent_power=None,
                peak_power=None,
                energy=None,
                phase=None,
                bank=None,
                alarm=None,
            ))

        # Fetch device info from ePDU2Ident entry
        ident_base = f"{EPDU2_IDENT_ENTRY}"
        dev_values = await self._get_many_locked((
            f"{ident_base}.3.{module_index}",   # name
            f"{ident_base}.6.{module_index}",   # hardwareRev
            f"{ident_base}.7.{module_index}",   # firmwareRev
            f"{ident_base}.9.{module_index}",   # modelName
            f"{ident_base}.10.{module_index}",  # serialNumber
        ))

        device = CyberPowerPduDevice(
            host=self._config.host,
            mib_branch=MIB_BRANCH_ATS,
            name=_as_text(dev_values.get(f"{ident_base}.3.{module_index}")),
            model=_as_text(dev_values.get(f"{ident_base}.9.{module_index}")),
            serial=_as_text(dev_values.get(f"{ident_base}.10.{module_index}")),
            firmware=_as_text(dev_values.get(f"{ident_base}.7.{module_index}")),
            hardware=_as_text(dev_values.get(f"{ident_base}.6.{module_index}")),
            outlet_count=outlet_count,
            controlled_outlets=outlet_count,
            has_source=True,
            module_index=module_index,
        )

        # Fetch source data for this module
        source = None
        try:
            source_oids = _source_status_oids(module_index)
            source_values = await self._get_many_locked(source_oids)
            source = _build_source(source_values, module_index)
        except (CyberPowerPduConnectionError, CyberPowerPduSnmpError):
            pass

        return CyberPowerPduData(
            device=device,
            outlets=tuple(outlets),
            current=None,
            voltage=None,
            power=None,
            apparent_power=None,
            power_factor=None,
            energy=None,
            source=source,
            environment=None,
        )

    async def _get_many_locked(self, oids: Iterable[str]) -> dict[str, Any | None]:
        results: dict[str, Any | None] = {}
        for chunk in _chunks(oids, GET_CHUNK_SIZE):
            try:
                results.update(await self._get_chunk_locked(chunk))
            except CyberPowerPduSnmpError as err:
                if err.is_missing_oid and len(chunk) == 1:
                    results[chunk[0]] = None
                    continue
                if not err.is_missing_oid:
                    raise
                for oid in chunk:
                    try:
                        results.update(await self._get_chunk_locked((oid,)))
                    except CyberPowerPduSnmpError as single_err:
                        if single_err.is_missing_oid:
                            results[oid] = None
                        else:
                            raise
        return results

    async def _get_chunk_locked(self, oids: tuple[str, ...]) -> dict[str, Any | None]:
        error_indication, error_status, error_index, var_binds = await get_cmd(
            await self._async_engine(),
            self._auth_data(),
            await self._transport(),
            self._context_data(),
            *(ObjectType(ObjectIdentity(oid)) for oid in oids),
            lookupMib=False,
        )
        _raise_on_error(error_indication, error_status, error_index, var_binds)
        return {
            oid: _normalise_snmp_value(value)
            for oid, (_, value) in zip(oids, var_binds, strict=False)
        }

    async def _set_int_locked(self, oid: str, value: int) -> None:
        error_indication, error_status, error_index, var_binds = await set_cmd(
            await self._async_engine(),
            self._auth_data(),
            await self._transport(),
            self._context_data(),
            ObjectType(ObjectIdentity(oid), Integer(value)),
            lookupMib=False,
        )
        _raise_on_error(error_indication, error_status, error_index, var_binds)

    async def _async_engine(self) -> SnmpEngine:
        if self._engine is None:
            loop = asyncio.get_running_loop()
            self._engine = await loop.run_in_executor(None, _create_snmp_engine)
        return self._engine

    async def _transport(self) -> UdpTransportTarget:
        return await UdpTransportTarget.create(
            (self._config.host, self._config.port),
            timeout=self._config.timeout,
            retries=self._config.retries,
        )

    def _context_data(self) -> ContextData:
        return ContextData(contextName=self._config.context_name or "")

    def _auth_data(self) -> CommunityData | UsmUserData:
        if self._config.version == SNMP_V1:
            return CommunityData(self._config.community or "", mpModel=0)
        if self._config.version == SNMP_V2C:
            return CommunityData(self._config.community or "", mpModel=1)
        return UsmUserData(
            self._config.username or "",
            authKey=self._config.auth_key or None,
            privKey=self._config.privacy_key or None,
            authProtocol=AUTH_PROTOCOL_MAP[self._config.auth_protocol],
            privProtocol=PRIVACY_PROTOCOL_MAP[self._config.privacy_protocol],
        )


def _raise_on_error(
    error_indication: Any,
    error_status: Any,
    error_index: Any,
    var_binds: Any,
) -> None:
    if error_indication:
        raise CyberPowerPduConnectionError(str(error_indication))
    if error_status:
        status = error_status.prettyPrint()
        oid = None
        if error_index:
            try:
                oid = var_binds[int(error_index) - 1][0].prettyPrint()
            except (IndexError, TypeError, ValueError):
                oid = None
        raise CyberPowerPduSnmpError(status, oid)


def _create_snmp_engine() -> SnmpEngine:
    engine = SnmpEngine()
    mib_builder = engine.message_dispatcher.mib_instrum_controller.get_mib_builder()
    import pysnmp.smi.mibs as mibs
    import pysnmp.smi.mibs.instances as mib_instances

    mib_builder.load_modules(
        *_mib_module_names(mibs.__path__[0]),
        *_mib_module_names(mib_instances.__path__[0]),
    )
    return engine


def _mib_module_names(path: str) -> tuple[str, ...]:
    return tuple(
        filename[:-3]
        for filename in os.listdir(path)
        if filename.endswith(".py") and filename != "__init__.py"
    )


def _outlet_status_oids(count: int) -> tuple[str, ...]:
    return tuple(
        f"{EPDU_OUTLET_STATUS}.{column}.{index}"
        for index in range(1, count + 1)
        for column in OUTLET_STATUS_COLUMNS.values()
    )


def _ats_outlet_status_oids(count: int) -> tuple[str, ...]:
    return tuple(
        f"{ATS_OUTLET_STATUS}.{column}.{index}"
        for index in range(1, count + 1)
        for column in ATS_OUTLET_STATUS_COLUMNS.values()
    )


def _build_device(
    host: str,
    mib_branch: str,
    oids: dict[str, str],
    values: dict[str, Any | None],
) -> CyberPowerPduDevice:
    return CyberPowerPduDevice(
        host=host,
        mib_branch=mib_branch,
        name=_as_text(values.get(oids["name"])),
        model=_as_text(values.get(oids["model"])),
        serial=_as_text(values.get(oids["serial"])),
        firmware=_as_text(values.get(oids["firmware"])),
        hardware=_as_text(values.get(oids["hardware"])),
        outlet_count=_as_int(values.get(oids["outlet_count"])),
        controlled_outlets=_as_int(values.get(oids["controlled_outlets"])),
    )


def _device_has_data(device: CyberPowerPduDevice) -> bool:
    return any(
        (
            device.name,
            device.model,
            device.serial,
            device.outlet_count,
            device.controlled_outlets,
        )
    )


def _build_epdu_outlet(
    index: int,
    values: dict[str, Any | None],
    voltage: float | None,
) -> CyberPowerPduOutlet:
    def value(name: str) -> Any | None:
        return values.get(f"{EPDU_OUTLET_STATUS}.{OUTLET_STATUS_COLUMNS[name]}.{index}")

    name = _as_text(value("name")) or f"Outlet {index}"
    current = _as_scaled_number(value("current"), 100)
    power = _as_int(value("power"))
    apparent_power = _apparent_power(current, voltage)
    return CyberPowerPduOutlet(
        index=index,
        name=name,
        state=_as_int(value("state")),
        command_pending=_as_pending(value("command_pending")),
        current=current,
        power=_normalise_outlet_power(power, current),
        apparent_power=apparent_power,
        peak_power=_as_int(value("peak_power")),
        energy=_as_scaled_number(value("energy"), 10),
        phase=_as_int(value("phase")),
        bank=_as_int(value("bank")),
        alarm=_as_int(value("alarm")),
    )


def _build_ats_outlet(index: int, values: dict[str, Any | None]) -> CyberPowerPduOutlet:
    def value(name: str) -> Any | None:
        return values.get(f"{ATS_OUTLET_STATUS}.{ATS_OUTLET_STATUS_COLUMNS[name]}.{index}")

    name = _as_text(value("name")) or f"Outlet {index}"
    return CyberPowerPduOutlet(
        index=index,
        name=name,
        state=_as_int(value("state")),
        command_pending=_as_pending(value("command_pending")),
        current=None,
        power=None,
        apparent_power=None,
        peak_power=None,
        energy=None,
        phase=_as_int(value("phase")),
        bank=_as_int(value("bank")),
        alarm=None,
    )


def _normalise_snmp_value(value: Any) -> Any | None:
    if value is None or value.__class__.__name__ in {
        "NoSuchObject",
        "NoSuchInstance",
        "EndOfMibView",
    }:
        return None
    return value


def _as_text(value: Any | None) -> str | None:
    if value is None:
        return None
    try:
        octets = bytes(value.asOctets())
    except AttributeError:
        text = value.prettyPrint() if hasattr(value, "prettyPrint") else str(value)
    else:
        try:
            text = octets.decode("utf-8")
        except UnicodeDecodeError:
            text = value.prettyPrint()
    text = text.replace("\x00", "").strip()
    return text or None


def _as_int(value: Any | None) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        text = _as_text(value)
        if text is None:
            return None
        try:
            return int(text)
        except ValueError:
            return None


def _as_scaled_number(value: Any | None, divisor: int) -> float | None:
    raw = _as_int(value)
    if raw is None:
        return None
    return raw / divisor


def _as_pending(value: Any | None) -> bool | None:
    raw = _as_int(value)
    if raw is None:
        return None
    return raw == 1


def _apparent_power(current: float | None, voltage: float | None) -> float | None:
    if current is None or voltage is None:
        return None
    return round(current * voltage, 1)


def _normalise_outlet_power(power: int | None, current: float | None) -> int | None:
    if power == 0 and current is not None and current > 0:
        return None
    return power


def _source_status_oids(module_index: int = 1) -> tuple[str, ...]:
    """Build OIDs for source status table for a given module.

    ePDU2SourceStatusEntry columns:
      1=index, 2=moduleIndex, 3=selectedSource, 4=nominalFrequency,
      5=sourceAVoltage, 6=sourceBVoltage, 7=sourceAFrequency, 8=sourceBFrequency,
      9=sourceAVolStatus, 10=sourceBVolStatus, 11=sourceAFreqStatus,
      12=sourceBFreqStatus, 13=phaseSync, 14=pwrSupplyAStatus,
      15=pwrSupplyBStatus, 16=redundancyState
    ePDU2SourceConfigEntry column 3 = preferredSource
    """
    return (
        f"{EPDU2_SOURCE_STATUS}.3.{module_index}",   # selectedSource
        f"{EPDU2_SOURCE_STATUS}.5.{module_index}",   # sourceAVoltage
        f"{EPDU2_SOURCE_STATUS}.6.{module_index}",   # sourceBVoltage
        f"{EPDU2_SOURCE_STATUS}.7.{module_index}",   # sourceAFrequency
        f"{EPDU2_SOURCE_STATUS}.8.{module_index}",   # sourceBFrequency
        f"{EPDU2_SOURCE_STATUS}.9.{module_index}",   # sourceAVolStatus
        f"{EPDU2_SOURCE_STATUS}.10.{module_index}",  # sourceBVolStatus
        f"{EPDU2_SOURCE_STATUS}.11.{module_index}",  # sourceAFreqStatus
        f"{EPDU2_SOURCE_STATUS}.12.{module_index}",  # sourceBFreqStatus
        f"{EPDU2_SOURCE_STATUS}.13.{module_index}",  # phaseSync
        f"{EPDU2_SOURCE_STATUS}.14.{module_index}",  # pwrSupplyAStatus
        f"{EPDU2_SOURCE_STATUS}.15.{module_index}",  # pwrSupplyBStatus
        f"{EPDU2_SOURCE_STATUS}.16.{module_index}",  # redundancyState
        f"{EPDU2_SOURCE_CONFIG}.3.{module_index}",   # preferredSource
    )


def _build_source(
    values: dict[str, Any | None],
    module_index: int = 1,
) -> CyberPowerPduSource:
    status_base = EPDU2_SOURCE_STATUS
    cfg_base = EPDU2_SOURCE_CONFIG

    return CyberPowerPduSource(
        selected_source=_as_int(values.get(f"{status_base}.3.{module_index}")),
        source_a_voltage=_as_scaled_number(values.get(f"{status_base}.5.{module_index}"), 10),
        source_b_voltage=_as_scaled_number(values.get(f"{status_base}.6.{module_index}"), 10),
        source_a_frequency=_as_scaled_number(values.get(f"{status_base}.7.{module_index}"), 10),
        source_b_frequency=_as_scaled_number(values.get(f"{status_base}.8.{module_index}"), 10),
        source_a_voltage_status=_as_int(values.get(f"{status_base}.9.{module_index}")),
        source_b_voltage_status=_as_int(values.get(f"{status_base}.10.{module_index}")),
        source_a_frequency_status=_as_int(values.get(f"{status_base}.11.{module_index}")),
        source_b_frequency_status=_as_int(values.get(f"{status_base}.12.{module_index}")),
        phase_sync=_as_int(values.get(f"{status_base}.13.{module_index}")),
        power_supply_a_status=_as_int(values.get(f"{status_base}.14.{module_index}")),
        power_supply_b_status=_as_int(values.get(f"{status_base}.15.{module_index}")),
        redundancy_state=_as_int(values.get(f"{status_base}.16.{module_index}")),
        preferred_source=_as_int(values.get(f"{cfg_base}.3.{module_index}")),
    )


def _env_contact_count(values: dict[str, Any | None]) -> int:
    raw = values.get(f"{ENVIR2_CONTACT_TABLE_SIZE}")
    count = _as_int(raw)
    return count if count is not None else 0


def _env_status_oids() -> tuple[str, ...]:
    """Build OIDs for envir2 temp, humidity, and contact table size."""
    return (
        f"{ENVIR2_TEMP_ENTRY}.3.1",     # temperature
        f"{ENVIR2_HUMID_ENTRY}.3.1",    # humidity
        ENVIR2_CONTACT_TABLE_SIZE,       # contact table size
    )


_ENV_OID_MAP = {
    "temperature": f"{ENVIR2_TEMP_ENTRY}.3.1",
    "humidity": f"{ENVIR2_HUMID_ENTRY}.3.1",
}


def _env_contact_oids(count: int) -> tuple[str, ...]:
    """Build OIDs for all env contacts (name, status, normalState per contact)."""
    oids: list[str] = []
    for index in range(1, count + 1):
        oids.append(f"{ENVIR2_CONTACT_ENTRY}.4.{index}")   # name
        oids.append(f"{ENVIR2_CONTACT_ENTRY}.5.{index}")   # status
        oids.append(f"{ENVIR2_CONTACT_ENTRY}.6.{index}")   # normalState
    return tuple(oids)


def _build_environment(values: dict[str, Any | None]) -> CyberPowerPduEnvironment:
    temperature = _as_scaled_number(values.get(_ENV_OID_MAP["temperature"]), 100)
    humidity = _as_scaled_number(values.get(_ENV_OID_MAP["humidity"]), 100)
    contact_count = _env_contact_count(values)

    contacts: list[CyberPowerPduEnvContact] = []
    for index in range(1, contact_count + 1):
        contacts.append(CyberPowerPduEnvContact(
            index=index,
            name=_as_text(values.get(f"{ENVIR2_CONTACT_ENTRY}.4.{index}")),
            status=_as_int(values.get(f"{ENVIR2_CONTACT_ENTRY}.5.{index}")),
            normal_state=_as_int(values.get(f"{ENVIR2_CONTACT_ENTRY}.6.{index}")),
        ))

    return CyberPowerPduEnvironment(
        temperature=temperature,
        humidity=humidity,
        contacts=tuple(contacts),
    )


def _bounded_outlet_count(value: int) -> int:
    return max(1, min(value, MAX_OUTLETS))


def _chunks(values: Iterable[str], size: int) -> Iterable[tuple[str, ...]]:
    iterator = iter(values)
    while chunk := tuple(islice(iterator, size)):
        yield chunk
