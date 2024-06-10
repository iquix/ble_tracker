"""Tracking for bluetooth devices."""
import asyncio
import logging
import threading
import aioblescan as aiobs
import voluptuous as vol
from aioblescan.plugins import EddyStone
from typing import Optional, Set, Tuple

from homeassistant.components.device_tracker import (
    PLATFORM_SCHEMA,
    SourceType,
)
from homeassistant.components.device_tracker.const import (
    CONF_TRACK_NEW,
    DEFAULT_TRACK_NEW,
)
from homeassistant.components.device_tracker.legacy import (
    YAML_DEVICES,
    async_load_config,
)
import homeassistant.helpers.config_validation as cv
from homeassistant.helpers.event import async_track_time_interval
from homeassistant.core import HomeAssistant

_LOGGER = logging.getLogger(__name__)

BLE_PREFIX = "BLE_"

CONF_DEVICE_ID = "device_id"
CONF_REQUEST_RSSI = "request_rssi"
DEFAULT_DEVICE_ID = 0
DEFAULT_REQUEST_RSSI = False

IBC_PACKET_HEADER = b"\x1a\xff\x4c\x00\x02\x15"

PLATFORM_SCHEMA = PLATFORM_SCHEMA.extend(
    {
        vol.Optional(CONF_TRACK_NEW): cv.boolean,
        vol.Optional(CONF_REQUEST_RSSI, default=DEFAULT_REQUEST_RSSI): cv.boolean,
        vol.Optional(CONF_DEVICE_ID, default=DEFAULT_DEVICE_ID): vol.All(
            vol.Coerce(int), vol.Range(min=0)
        ),
    }
)


def is_ble_device(device):
    """Check whether a device is a BLE device by its mac."""
    return device.mac and device.mac[:len(BLE_PREFIX)].upper() == BLE_PREFIX


async def see_device(hass, async_see, mac, device_name, rssi=None):
    """Mark a device as seen."""
    attributes = {}
    if rssi is not None:
        attributes["rssi"] = rssi
    await async_see(
        mac=BLE_PREFIX+mac,
        host_name=device_name,
        attributes=attributes,
        source_type=SourceType.BLUETOOTH_LE,
    )


async def get_tracking_devices(hass: HomeAssistant) -> Tuple[Set[str], Set[str]]:
    """
    Load all known devices.

    We just need the devices so set consider_home and home range to 0
    """
    yaml_path: str = hass.config.path(YAML_DEVICES)

    devices = await async_load_config(yaml_path, hass, 0)
    bluetooth_devices = [device for device in devices if is_ble_device(device)]

    devices_to_track: Set[str] = {
        device.mac[len(BLE_PREFIX):] for device in bluetooth_devices if device.track
    }
    devices_to_not_track: Set[str] = {
        device.mac[len(BLE_PREFIX):] for device in bluetooth_devices if not device.track
    }
    return devices_to_track, devices_to_not_track


async def async_setup_scanner(hass, config, async_see, discovery_info=None):
    """Set up the Bluetooth LE Scanner."""
    device_id: int = config[CONF_DEVICE_ID]
    request_rssi: bool = config.get(CONF_REQUEST_RSSI)
    # If track new devices is true discover new devices on startup.
    track_new: bool = config.get(CONF_TRACK_NEW, DEFAULT_TRACK_NEW)

    devices_to_track, devices_to_not_track = await get_tracking_devices(hass)

    #_LOGGER.debug("device to track {}".format(devices_to_track))
    #_LOGGER.debug("device to not track {}".format(devices_to_not_track))


    def perform_bluetooth_update(data):
        """Discover Bluetooth devices and update status."""
        device_name = None
        p = parse_hci(data)
        if p["mac"] == None:
            return

        if track_new:
            if p["mac"] not in devices_to_track and p["mac"] not in devices_to_not_track:
                devices_to_track.add(p["mac"])

        if p["mac"] in devices_to_track:
            device_name = BLE_PREFIX + p["mac"].replace(":","")
            asyncio.ensure_future(see_device(hass, async_see, p["mac"], device_name, p["rssi"]))


    def parse_hci(data):
        ret = {}
        ret["mac"]=None
        ret["rssi"]=None
        try:
            ev = aiobs.HCI_Event()
            ev.decode(data)
            eds = EddyStone().decode(ev)
            if ret["mac"] == None and eds and eds.get('name space')!=None:
                ret["mac"] = "EDS_" + eds.get('name space').hex().upper()
            elif IBC_PACKET_HEADER in data:
                startpos = data.find(IBC_PACKET_HEADER) + len(IBC_PACKET_HEADER)
                ret["mac"] = "IBC_" + data[startpos:startpos+18].hex().upper()
            else:
                mac = ev.retrieve("peer")
                for x in mac:
                    ret["mac"] = x.val.upper()
                    break
            if request_rssi:
                rssi = ev.retrieve("rssi")
                for x in rssi:
                    ret["rssi"] = x.val
                    break
        except Exception as ex:
            pass
        return ret


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
                pass
                #_LOGGER.debug('no event loop to close')

            event_loop = asyncio.new_event_loop()
            asyncio.set_event_loop(event_loop)
            fac=event_loop._create_connection_transport(mysocket,aiobs.BLEScanRequester,None,None)
            #_LOGGER.debug('event loop connection') 
            conn,btctrl = event_loop.run_until_complete(fac)
            #_LOGGER.debug('event loop connected') 
            
            btctrl.process=perform_bluetooth_update
            btctrl.send_scan_request()
            #_LOGGER.debug('event loop starting') 

            try:
                event_loop.run_forever()
            except:
                _LOGGER.debug('exception in ble tracker custom component')
            finally:
                _LOGGER.debug('closing event loop')
                btctrl.stop_scan_request()
                command = aiobs.HCI_Cmd_LE_Advertise(enable=False)
                btctrl.send_command(command)
                conn.close()
                event_loop.close()
        return True

    if not devices_to_track and not track_new:
        _LOGGER.debug("No Bluetooth LE devices to track and not tracking new devices")
    else:
        th = threading.Thread(target=start_thread, name='start_thread')
        th.start()

    return True
