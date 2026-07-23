from __future__ import annotations

import asyncio
from datetime import timedelta
import logging

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import (
    CONF_HOST,
    CONF_PORT,
    CONF_SCAN_INTERVAL,
    CONF_TIMEOUT,
    CONF_USERNAME,
)
from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .const import (
    CONF_AUTH_KEY,
    CONF_AUTH_PROTOCOL,
    CONF_COMMUNITY,
    CONF_CONTEXT_NAME,
    CONF_PRIVACY_KEY,
    CONF_PRIVACY_PROTOCOL,
    CONF_RETRIES,
    CONF_SNMP_VERSION,
    DEFAULT_AUTH_PROTOCOL,
    DEFAULT_COMMUNITY,
    DEFAULT_PORT,
    DEFAULT_PRIVACY_PROTOCOL,
    DEFAULT_RETRIES,
    DEFAULT_SCAN_INTERVAL,
    DEFAULT_SNMP_VERSION,
    DEFAULT_TIMEOUT,
    DOMAIN,
    OUTLET_COMMAND_REBOOT,
)
from .snmp import (
    CyberPowerChainedPduInfo,
    CyberPowerPduClient,
    CyberPowerPduConfig,
    CyberPowerPduData,
    CyberPowerPduError,
)

_LOGGER = logging.getLogger(__name__)


class CyberPowerPduCoordinator(DataUpdateCoordinator[CyberPowerPduData]):
    """Coordinator for the local/host PDU."""

    config_entry: ConfigEntry

    def __init__(self, hass: HomeAssistant, entry: ConfigEntry) -> None:
        self.config_entry = entry
        self.client = CyberPowerPduClient(_client_config(entry))
        scan_interval = entry.options.get(
            CONF_SCAN_INTERVAL,
            entry.data.get(CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL),
        )
        super().__init__(
            hass,
            _LOGGER,
            name=DOMAIN,
            update_interval=timedelta(seconds=scan_interval),
        )

    async def _async_update_data(self) -> CyberPowerPduData:
        try:
            return await self.client.async_fetch()
        except CyberPowerPduError as err:
            raise UpdateFailed(str(err)) from err

    async def async_set_outlet_power(self, index: int, on: bool) -> None:
        await self.client.async_set_outlet_power(index, on)
        await asyncio.sleep(1)
        await self.async_request_refresh()

    async def async_power_cycle_outlet(self, index: int) -> None:
        await self.client.async_power_cycle_outlet(index)
        await asyncio.sleep(1)
        await self.async_request_refresh()
        _delayed_refresh(self, 10)

    async def async_set_preferred_source(self, source: int) -> None:
        await self.client.async_set_preferred_source(source)
        await asyncio.sleep(1)
        await self.async_request_refresh()

    async def async_close(self) -> None:
        await self.client.async_close()

    async def async_detect_chained_pdus(self) -> list[CyberPowerChainedPduInfo]:
        """Detect daisy-chained PDUs behind this host."""
        return await self.client.async_detect_chained_pdus()

    @property
    def device_identifier(self) -> str:
        if self.config_entry.unique_id:
            return self.config_entry.unique_id
        if self.data and self.data.device.serial:
            return self.data.device.serial
        return self.config_entry.entry_id


class CyberPowerChainedPduCoordinator(DataUpdateCoordinator[CyberPowerPduData]):
    """Coordinator for a daisy-chained PDU module.

    Shares the same SNMP client as the host coordinator but reads
    data exclusively for its own module index from ePDU2 tables.
    """

    def __init__(
        self,
        hass: HomeAssistant,
        entry: ConfigEntry,
        info: CyberPowerChainedPduInfo,
        parent_client: CyberPowerPduClient,
    ) -> None:
        self.config_entry = entry
        self.info = info
        self.client = parent_client
        scan_interval = entry.options.get(
            CONF_SCAN_INTERVAL,
            entry.data.get(CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL),
        )
        super().__init__(
            hass,
            _LOGGER,
            name=f"{DOMAIN}_chained_{info.module_index}",
            update_interval=timedelta(seconds=scan_interval),
        )

    async def _async_update_data(self) -> CyberPowerPduData:
        try:
            return await self.client.async_fetch_chained_pdu_data(self.info.module_index)
        except CyberPowerPduError as err:
            raise UpdateFailed(str(err)) from err

    async def async_set_outlet_power(self, index: int, on: bool) -> None:
        await self.client.async_set_chained_outlet_power(
            self.info.module_index, index, on
        )
        await asyncio.sleep(1)
        await self.async_request_refresh()

    async def async_power_cycle_outlet(self, index: int) -> None:
        await self.client.async_set_chained_outlet_power(
            self.info.module_index, index, OUTLET_COMMAND_REBOOT
        )
        await asyncio.sleep(1)
        await self.async_request_refresh()
        _delayed_refresh(self, 10)

    async def async_set_preferred_source(self, source: int) -> None:
        await self.client.async_set_chained_preferred_source(
            self.info.module_index, source
        )
        await asyncio.sleep(1)
        await self.async_request_refresh()

    @property
    def device_identifier(self) -> str:
        serial = self.info.serial
        if serial:
            return f"{serial}_module{self.info.module_index}"
        return f"chained_module{self.info.module_index}_{self.config_entry.entry_id}"


def _delayed_refresh(
    coordinator: DataUpdateCoordinator,
    delay: int,
) -> asyncio.Task:
    """Create a task that sleeps then requests a coordinator refresh."""
    async def _refresh() -> None:
        await asyncio.sleep(delay)
        await coordinator.async_request_refresh()

    return coordinator.hass.async_create_task(_refresh())


def _client_config(entry: ConfigEntry) -> CyberPowerPduConfig:
    data = entry.data
    return CyberPowerPduConfig(
        host=data[CONF_HOST],
        port=data.get(CONF_PORT, DEFAULT_PORT),
        version=data.get(CONF_SNMP_VERSION, DEFAULT_SNMP_VERSION),
        community=data.get(CONF_COMMUNITY, DEFAULT_COMMUNITY),
        username=data.get(CONF_USERNAME),
        auth_protocol=data.get(CONF_AUTH_PROTOCOL, DEFAULT_AUTH_PROTOCOL),
        auth_key=data.get(CONF_AUTH_KEY),
        privacy_protocol=data.get(CONF_PRIVACY_PROTOCOL, DEFAULT_PRIVACY_PROTOCOL),
        privacy_key=data.get(CONF_PRIVACY_KEY),
        context_name=data.get(CONF_CONTEXT_NAME, ""),
        timeout=float(data.get(CONF_TIMEOUT, DEFAULT_TIMEOUT)),
        retries=int(data.get(CONF_RETRIES, DEFAULT_RETRIES)),
    )
