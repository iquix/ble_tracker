"""Tracking for bluetooth devices."""
import asyncio
import logging
import threading
import aioblescan as aiobs
import voluptuous as vol
from typing import List, Optional, Set, Tuple

from homeassistant.components.device_tracker import PLATFORM_SCHEMA
from homeassistant.components.device_tracker.const import (
    CONF_TRACK_NEW,
    DEFAULT_TRACK_NEW,
    SOURCE_TYPE_BLUETOOTH_LE,
)
from homeassistant.components.device_tracker.legacy import (
    YAML_DEVICES,
    async_load_config,
)
import homeassistant.helpers.config_validation as cv
from homeassistant.helpers.event import async_track_time_interval
from homeassistant.helpers.typing import HomeAssistantType

_LOGGER = logging.getLogger(__name__)

BLE_PREFIX = "BLE_"

CONF_DEVICE_ID = "device_id"
DEFAULT_DEVICE_ID = 0

PLATFORM_SCHEMA = PLATFORM_SCHEMA.extend(
    {
        vol.Optional(CONF_DEVICE_ID, default=DEFAULT_DEVICE_ID): vol.All(
            vol.Coerce(int), vol.Range(min=0)
        ),
    }
)


def is_bluetooth_device(device):
    """Check whether a device is a bluetooth device by its mac."""
    return device.mac and device.mac[:len(BLE_PREFIX)].upper() == BLE_PREFIX


def see_device(hass, see, mac, device_name):
    """Mark a device as seen."""
    see(
        mac=BLE_PREFIX+mac,
        host_name=device_name,
        source_type=SOURCE_TYPE_BLUETOOTH_LE,
    )

def get_tracking_devices(hass: HomeAssistantType) -> Tuple[Set[str], Set[str]]:
    """
    Load all known devices.

    We just need the devices so set consider_home and home range to 0
    """
    yaml_path: str = hass.config.path(YAML_DEVICES)

    devices = asyncio.run_coroutine_threadsafe(
        async_load_config(yaml_path, hass, 0), hass.loop
    ).result()
    bluetooth_devices = [device for device in devices if is_bluetooth_device(device)]

    devices_to_track: Set[str] = {
        device.mac[len(BLE_PREFIX):] for device in bluetooth_devices if device.track
    }
    devices_to_not_track: Set[str] = {
        device.mac[len(BLE_PREFIX):] for device in bluetooth_devices if not device.track
    }
    return devices_to_track, devices_to_not_track


def setup_scanner(hass, config, see, discovery_info=None):
    """Set up the Bluetooth LE Scanner."""
    device_id: int = config[CONF_DEVICE_ID]
    # If track new devices is true discover new devices on startup.
    track_new: bool = config.get(CONF_TRACK_NEW, DEFAULT_TRACK_NEW)
    _LOGGER.debug("Tracking new devices is set to %s", track_new)

    devices_to_track, devices_to_not_track = get_tracking_devices(hass)

    def perform_bluetooth_update(data):
        """Discover Bluetooth devices and update status."""
        _LOGGER.debug("Performing Bluetooth devices discovery and update ")
        tasks = []

        device_name = None
        mac = parse_hci(data)
        if mac == None:
            return

        if track_new:
            if mac not in devices_to_track and mac not in devices_to_not_track:
                devices_to_track.add(mac)

        if mac in devices_to_track:
            device_name = BLE_PREFIX + mac.replace(":","")
            see_device(hass, see, mac, device_name)


    def parse_hci(data):
        try:
            ev = aiobs.HCI_Event()
            ev.decode(data)
            mac = ev.retrieve("peer")
            for x in mac:
                return x.val.upper()
        except:
            return None
        return None

    def start_thread():
        try:
            mysocket = aiobs.create_bt_socket(device_id)
        except OSError as error:
            _LOGGER.error("HCIdump thread: OS error: %s", error)
        else:
            try:
                event_loop = asyncio.get_event_loop()
                event_loop.close()
            except:
                _LOGGER.debug('no event loop to close')

            event_loop = asyncio.new_event_loop()
            asyncio.set_event_loop(event_loop)
            fac=event_loop._create_connection_transport(mysocket,aiobs.BLEScanRequester,None,None)
            _LOGGER.debug('event loop connection') 
            conn,btctrl = event_loop.run_until_complete(fac)
            _LOGGER.debug('event loop connected') 
            
            btctrl.process=perform_bluetooth_update
            btctrl.send_scan_request()
            _LOGGER.debug('event loop starting') 

            try:
                event_loop.run_forever()
            except:
                _LOGGER.warn('exception in ble tracker custom component')
            finally:
                _LOGGER.warn('closing event loop')
                btctrl.stop_scan_request()
                command = aiobs.HCI_Cmd_LE_Advertise(enable=False)
                btctrl.send_command(command)
                conn.close()
                event_loop.close()
        return True

    if not devices_to_track and not track_new:
        _LOGGER.warn("No Bluetooth LE devices to track and not tracking new devices")
    else:
        th = threading.Thread(target=start_thread, name='start_thread')
        th.start()

    return True