#!/usr/bin/python
# Do basic imports
import socket
import base64

import logging
import voluptuous as vol
import homeassistant.helpers.config_validation as cv

from homeassistant.components.climate import (ClimateEntity, ClimateEntityFeature, HVACMode, PLATFORM_SCHEMA)

from homeassistant.const import (ATTR_TEMPERATURE, ATTR_UNIT_OF_MEASUREMENT, CONF_HOST, CONF_MAC, CONF_NAME, CONF_PORT, CONF_TIMEOUT, STATE_OFF, STATE_ON, STATE_UNKNOWN)

from homeassistant.core import (CALLBACK_TYPE, Event, EventStateChangedData, callback, HomeAssistant)
from homeassistant.helpers.event import async_track_state_change_event
from homeassistant.helpers.device_registry import CONNECTION_NETWORK_MAC
from Crypto.Cipher import AES
import json as simplejson
from datetime import timedelta

from .const import *
del PLATFORMS       # This is not used in this file, so we can remove it to avoid confusion

REQUIREMENTS = ['pycryptodome']

_LOGGER = logging.getLogger(__name__)

SUPPORT_FLAGS = ClimateEntityFeature.TARGET_TEMPERATURE | ClimateEntityFeature.FAN_MODE | ClimateEntityFeature.TURN_ON | ClimateEntityFeature.TURN_OFF

# from the remote control and gree app

# update() interval
SCAN_INTERVAL = timedelta(seconds=60)

GCM_IV = b'\x54\x40\x78\x44\x49\x67\x5a\x51\x6c\x5e\x63\x13'
GCM_ADD = b'qualcomm-test'

PLATFORM_SCHEMA = PLATFORM_SCHEMA.extend({
    vol.Optional(CONF_NAME, default='Gree Climate'): cv.string,
    vol.Required(CONF_HOST): cv.string,
    vol.Required(CONF_PORT, default=DEFAULT_PORT): cv.positive_int,
    vol.Required(CONF_MAC): cv.string,
    vol.Optional(CONF_TIMEOUT, default=DEFAULT_TIMEOUT): cv.positive_int,
    vol.Optional(CONF_HVAC_MODES, default=DEFAULT_HVAC_MODES): cv.ensure_list,
    vol.Optional(CONF_TARGET_TEMP_STEP, default=DEFAULT_TARGET_TEMP_STEP): vol.Coerce(float),
    vol.Optional(CONF_TEMP_SENSOR): cv.entity_id,
    vol.Optional(CONF_LIGHTS): cv.entity_id,
    vol.Optional(CONF_XFAN): cv.entity_id,
    vol.Optional(CONF_HEALTH): cv.entity_id,
    vol.Optional(CONF_POWERSAVE): cv.entity_id,
    vol.Optional(CONF_SLEEP): cv.entity_id,
    vol.Optional(CONF_EIGHTDEGHEAT): cv.entity_id,
    vol.Optional(CONF_AIR): cv.entity_id,
    vol.Optional(CONF_ENCRYPTION_KEY): cv.string,
    vol.Optional(CONF_UID): cv.positive_int,
    vol.Optional(CONF_AUTO_XFAN): cv.entity_id,
    vol.Optional(CONF_AUTO_LIGHT): cv.entity_id,
    vol.Optional(CONF_TARGET_TEMP): cv.entity_id,
    vol.Optional(CONF_ENCRYPTION_VERSION, default=1): cv.positive_int,
    vol.Optional(CONF_FAN_MODES, default=DEFAULT_FAN_MODES): cv.ensure_list,
    vol.Optional(CONF_SWING_MODES, default=DEFAULT_SWING_MODES): cv.ensure_list,
    vol.Optional(CONF_SWING_HORIZONTAL_MODES, default=DEFAULT_SWING_HORIZONTAL_MODES): cv.ensure_list,
    vol.Optional(CONF_ANTI_DIRECT_BLOW): cv.entity_id,
    vol.Optional(CONF_DISABLE_AVAILABLE_CHECK, default=False): cv.boolean,
    vol.Optional(CONF_MAX_ONLINE_ATTEMPTS, default=3): cv.positive_int,
    vol.Optional(CONF_LIGHT_SENSOR): cv.entity_id,
    vol.Optional(CONF_BEEPER): cv.entity_id,
    vol.Optional(CONF_TEMP_SENSOR_OFFSET): cv.boolean,
})

async def async_setup_platform(hass: HomeAssistant, config, async_add_devices, discovery_info=None):
    _LOGGER.info('Setting up Gree climate platform')

    name = config.get(CONF_NAME)
    ip_addr = config.get(CONF_HOST)
    port = config.get(CONF_PORT)
    mac_addr = config.get(CONF_MAC).encode().replace(b':', b'')
    timeout = config.get(CONF_TIMEOUT)

    ctts = config.get(CONF_TARGET_TEMP_STEP)
    target_temp_step = ctts if ctts is not None else DEFAULT_TARGET_TEMP_STEP

    chm = config.get(CONF_HVAC_MODES)
    hvac_modes = [getattr(HVACMode, mode.upper()) for mode in (chm if chm is not None else DEFAULT_HVAC_MODES)]

    cfm = config.get(CONF_FAN_MODES)
    fan_modes = cfm if cfm is not None else DEFAULT_FAN_MODES
    csm = config.get(CONF_SWING_MODES)
    swing_modes = csm if csm is not None else DEFAULT_SWING_MODES
    cshm = config.get(CONF_SWING_HORIZONTAL_MODES)
    swing_horizontal_modes = cshm if cshm is not None else DEFAULT_SWING_HORIZONTAL_MODES
    encryption_key = config.get(CONF_ENCRYPTION_KEY)
    uid = config.get(CONF_UID)
    encryption_version = config.get(CONF_ENCRYPTION_VERSION)
    disable_available_check = config.get(CONF_DISABLE_AVAILABLE_CHECK)
    max_online_attempts = config.get(CONF_MAX_ONLINE_ATTEMPTS)
    temp_sensor_offset = config.get(CONF_TEMP_SENSOR_OFFSET)

    _LOGGER.info('Adding Gree climate device to hass')

    async_add_devices([
        GreeClimate(
            hass,
            name,
            ip_addr,
            port,
            mac_addr,
            timeout,
            target_temp_step,
            hvac_modes,
            fan_modes,
            swing_modes,
            swing_horizontal_modes,
            encryption_version,
            disable_available_check,
            max_online_attempts,
            encryption_key,
            uid,
            temp_sensor_offset,
        )
    ])


async def async_setup_entry(hass: HomeAssistant, entry, async_add_devices):
    """Set up Gree climate from a config entry."""
    config = {**entry.data}
    for key, value in entry.options.items():
        if key in OPTION_KEYS and value is not None:
            config[key] = value

    # Create the GreeClimate entity with the provided configuration
    climate_entity = GreeClimate(
        hass,
        config.get(CONF_NAME),
        config.get(CONF_HOST),
        config.get(CONF_PORT),
        (config.get(CONF_MAC) or "").encode().replace(b':', b''),
        config.get(CONF_TIMEOUT),
        config.get(CONF_TARGET_TEMP_STEP, DEFAULT_TARGET_TEMP_STEP),
        config.get(CONF_HVAC_MODES, DEFAULT_HVAC_MODES),
        config.get(CONF_FAN_MODES, DEFAULT_FAN_MODES),
        config.get(CONF_SWING_MODES, DEFAULT_SWING_MODES),
        config.get(CONF_SWING_HORIZONTAL_MODES, DEFAULT_SWING_HORIZONTAL_MODES),
        config.get(CONF_ENCRYPTION_VERSION, 1),
        config.get(CONF_DISABLE_AVAILABLE_CHECK, False),
        config.get(CONF_MAX_ONLINE_ATTEMPTS, 3),
        config.get(CONF_ENCRYPTION_KEY),
        config.get(CONF_UID),
        config.get(CONF_TEMP_SENSOR_OFFSET),
    )
    async_add_devices([climate_entity])

    # Save the climate entity in hass.data for use in other parts of the integration
    if DOMAIN not in hass.data:
        hass.data[DOMAIN] = {}
    if entry.entry_id not in hass.data[DOMAIN]:
        hass.data[DOMAIN][entry.entry_id] = {}
    hass.data[DOMAIN][entry.entry_id]["climate_entities"] = [climate_entity]

async def async_unload_entry(hass: HomeAssistant, entry):
    """Unload a config entry."""
    return True


class GreeClimate(ClimateEntity):
    # Language is retrieved from translation key
    _attr_translation_key = "gree"

    def __init__(self, hass: HomeAssistant, name, ip_addr, port, mac_addr, timeout, target_temp_step, hvac_modes, fan_modes, swing_modes, swing_horizontal_modes, encryption_version, disable_available_check, max_online_attempts, encryption_key=None, uid=None, temp_sensor_offset=None) -> None:
        _LOGGER.info('Initialize the GREE climate device')
        self.hass = hass
        self._name = name
        self._ip_addr = ip_addr
        self._port = port
        self._mac_addr = mac_addr.decode('utf-8').lower()
        self._timeout = timeout
        self._unique_id = 'climate.gree_' + mac_addr.decode('utf-8').lower()
        self._device_online = None
        self._online_attempts = 0
        self._max_online_attempts = max_online_attempts
        self._disable_available_check = disable_available_check
        self._attr_device_info = {  "identifiers": {(DOMAIN, self._mac_addr)},
                                    "connections": {(CONNECTION_NETWORK_MAC, self._mac_addr)},
                                    "name": self._name}

        self._target_temperature = None
        self._target_temperature_step = target_temp_step
        # Device uses a combination of Celsius + a set bit for Fahrenheit, so the integration needs to be aware of the units.
        self._unit_of_measurement = hass.config.units.temperature_unit
        _LOGGER.info("Unit of measurement: %s", self._unit_of_measurement)

        self._hvac_modes = DEFAULT_HVAC_MODES if not CONF_HVAC_MODES else hvac_modes
        self._hvac_mode = HVACMode.OFF
        self._fan_modes = DEFAULT_FAN_MODES if not CONF_FAN_MODES else fan_modes
        self._fan_mode = None
        self._swing_modes = DEFAULT_SWING_MODES if not CONF_SWING_MODES else swing_modes
        self._swing_mode = None
        self._swing_horizontal_modes = DEFAULT_SWING_HORIZONTAL_MODES if not CONF_SWING_HORIZONTAL_MODES else swing_horizontal_modes
        self._swing_horizontal_mode = None

        if temp_sensor_offset not in TEMP_SENSOR_OFFSET_OPTIONS:
            self._temp_sensor_offset = TEMP_SENSOR_OFFSET_OPTIONS[0]  # Default auto
        else:
            self._temp_sensor_offset = temp_sensor_offset

        # Keep unsub callbacks for deregistering listeners
        self._listeners: list[tuple[str, str, CALLBACK_TYPE]] = []

        self._has_temp_sensor = None
        self._has_anti_direct_blow = None
        self._has_light_sensor = None

        self._auto_light = False
        self._auto_xfan = False
        self._enable_light_sensor = False

        self._current_temperature = None
        self._current_lights = None
        self._current_xfan = None
        self._current_health = None
        self._current_powersave = None
        self._current_sleep = None
        self._current_eightdegheat = None
        self._current_air = None
        self._current_anti_direct_blow = None
        self._current_light_sensor = None

        self._firstTimeRun = True

        self._enable_turn_on_off_backwards_compatibility = False

        self.encryption_version = encryption_version
        self.CIPHER = None

        if encryption_key:
            _LOGGER.info('Using configured encryption key: {}'.format(encryption_key))
            self._encryption_key = encryption_key.encode("utf8")
            if encryption_version == 1:
                # Cipher to use to encrypt/decrypt
                self.CIPHER = AES.new(self._encryption_key, AES.MODE_ECB)
            elif encryption_version != 2:
                _LOGGER.error('Encryption version %s is not implemented.' % self.encryption_version)
        else:
            self._encryption_key = None

        if uid:
            self._uid = uid
        else:
            self._uid = 0

        self._acOptions = { 'Pow': None, 'Mod': None, 'SetTem': None, 'WdSpd': None, 'Air': None, 'Blo': None, 'Health': None, 'SwhSlp': None, 'Lig': None, 'SwingLfRig': None, 'SwUpDn': None, 'Quiet': None, 'Tur': None, 'StHt': None, 'TemUn': None, 'HeatCoolType': None, 'TemRec': None, 'SvSt': None, 'SlpMod': None }
        self._optionsToFetch = ["Pow","Mod","SetTem","WdSpd","Air","Blo","Health","SwhSlp","Lig","SwingLfRig","SwUpDn","Quiet","Tur","StHt","TemUn","HeatCoolType","TemRec","SvSt","SlpMod"]

        # helper method to determine TemSen offset
        self._process_temp_sensor = self.TempOffsetResolver()

        self._current_beeper_enabled = True # Default to beeper ON (silent mode OFF)

    # Pad helper method to help us get the right string for encrypting
    def Pad(self, s):
        aesBlockSize = 16
        return s + (aesBlockSize - len(s) % aesBlockSize) * chr(aesBlockSize - len(s) % aesBlockSize)

    def FetchResult(self, cipher, ip_addr, port, timeout, json):
        _LOGGER.debug('Fetching(%s, %s, %s, %s)' % (ip_addr, port, timeout, json))
        clientSock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        clientSock.settimeout(timeout)
        clientSock.sendto(bytes(json, "utf-8"), (ip_addr, port))
        data, addr = clientSock.recvfrom(64000)
        receivedJson = simplejson.loads(data)
        clientSock.close()
        pack = receivedJson['pack']
        base64decodedPack = base64.b64decode(pack)
        decryptedPack = cipher.decrypt(base64decodedPack)
        if self.encryption_version == 2:
            tag = receivedJson['tag']
            cipher.verify(base64.b64decode(tag))
        decodedPack = decryptedPack.decode("utf-8")
        replacedPack = decodedPack.replace('\x0f', '').replace(decodedPack[decodedPack.rindex('}')+1:], '')
        loadedJsonPack = simplejson.loads(replacedPack)
        return loadedJsonPack

    def GetDeviceKey(self):
        _LOGGER.info('Retrieving HVAC encryption key')
        GENERIC_GREE_DEVICE_KEY = "a3K8Bx%2r8Y7#xDh"
        cipher = AES.new(GENERIC_GREE_DEVICE_KEY.encode("utf8"), AES.MODE_ECB)
        pack = base64.b64encode(cipher.encrypt(self.Pad('{"mac":"' + str(self._mac_addr) + '","t":"bind","uid":0}').encode("utf8"))).decode('utf-8')
        jsonPayloadToSend = '{"cid": "app","i": 1,"pack": "' + pack + '","t":"pack","tcid":"' + str(self._mac_addr) + '","uid": 0}'
        try:
            self._encryption_key = self.FetchResult(cipher, self._ip_addr, self._port, self._timeout, jsonPayloadToSend)['key'].encode("utf8")
        except:
            _LOGGER.info('Error getting device encryption key!')
            self._device_online = False
            self._online_attempts = 0
            return False
        else:
            _LOGGER.info('Fetched device encrytion key: %s' % str(self._encryption_key))
            self.CIPHER = AES.new(self._encryption_key, AES.MODE_ECB)
            self._device_online = True
            self._online_attempts = 0
            return True

    def GetGCMCipher(self, key):
        cipher = AES.new(key, AES.MODE_GCM, nonce=GCM_IV)
        cipher.update(GCM_ADD)
        return cipher

    def EncryptGCM(self, key, plaintext):
        encrypted_data, tag = self.GetGCMCipher(key).encrypt_and_digest(plaintext.encode("utf8"))
        pack = base64.b64encode(encrypted_data).decode('utf-8')
        tag = base64.b64encode(tag).decode('utf-8')
        return (pack, tag)

    def GetDeviceKeyGCM(self):
        _LOGGER.info('Retrieving HVAC encryption key')
        GENERIC_GREE_DEVICE_KEY = b'{yxAHAY_Lm6pbC/<'
        plaintext = '{"cid":"' + str(self._mac_addr) + '", "mac":"' + str(self._mac_addr) + '","t":"bind","uid":0}'
        pack, tag = self.EncryptGCM(GENERIC_GREE_DEVICE_KEY, plaintext)
        jsonPayloadToSend = '{"cid": "app","i": 1,"pack": "' + pack + '","t":"pack","tcid":"' + str(self._mac_addr) + '","uid": 0, "tag" : "' + tag + '"}'
        try:
            self._encryption_key = self.FetchResult(self.GetGCMCipher(GENERIC_GREE_DEVICE_KEY), self._ip_addr, self._port, self._timeout, jsonPayloadToSend)['key'].encode("utf8")
        except:
            _LOGGER.info('Error getting device encryption key!')
            self._device_online = False
            self._online_attempts = 0
            return False
        else:
            _LOGGER.info('Fetched device encrytion key: %s' % str(self._encryption_key))
            self._device_online = True
            self._online_attempts = 0
            return True

    def GreeGetValues(self, propertyNames):
        plaintext = '{"cols":' + simplejson.dumps(propertyNames) + ',"mac":"' + str(self._mac_addr) + '","t":"status"}'
        if self.encryption_version == 1:
            cipher = self.CIPHER
            if cipher is None:
                raise ValueError("Encryption cipher is not initialized. Cannot send state to AC.")
            jsonPayloadToSend = '{"cid":"app","i":0,"pack":"' + base64.b64encode(cipher.encrypt(self.Pad(plaintext).encode("utf8"))).decode('utf-8') + '","t":"pack","tcid":"' + str(self._mac_addr) + '","uid":{}'.format(self._uid) + '}'
        elif self.encryption_version == 2:
            pack, tag = self.EncryptGCM(self._encryption_key, plaintext)
            jsonPayloadToSend = '{"cid":"app","i":0,"pack":"' + pack + '","t":"pack","tcid":"' + str(self._mac_addr) + '","uid":{}'.format(self._uid) + ',"tag" : "' + tag + '"}'
            cipher = self.GetGCMCipher(self._encryption_key)
        else:
            raise ValueError(f"Unsupported encryption_version: {self.encryption_version}")
        return self.FetchResult(cipher, self._ip_addr, self._port, self._timeout, jsonPayloadToSend)['dat']

    def SetAcOptions(self, acOptions, newOptionsToOverride, optionValuesToOverride = None):
        if not (optionValuesToOverride is None):
            _LOGGER.debug('Setting acOptions with retrieved HVAC values')
            for key in newOptionsToOverride:
                _LOGGER.debug('Setting %s: %s' % (key, optionValuesToOverride[newOptionsToOverride.index(key)]))
                acOptions[key] = optionValuesToOverride[newOptionsToOverride.index(key)]
            _LOGGER.debug('Done setting acOptions')
        else:
            _LOGGER.debug('Overwriting acOptions with new settings')
            for key, value in newOptionsToOverride.items():
                _LOGGER.debug('Overwriting %s: %s' % (key, value))
                acOptions[key] = value
            _LOGGER.debug('Done overwriting acOptions')
        return acOptions

    def set_beeper_enabled(self, enabled: bool) -> None:
        self._current_beeper_enabled = enabled
        self.SyncState()

    def SendStateToAc(self, timeout):
        opt = '"Pow","Mod","SetTem","WdSpd","Air","Blo","Health","SwhSlp","Lig","SwingLfRig","SwUpDn","Quiet","Tur","StHt","TemUn","HeatCoolType","TemRec","SvSt","SlpMod"'
        p = '{Pow},{Mod},{SetTem},{WdSpd},{Air},{Blo},{Health},{SwhSlp},{Lig},{SwingLfRig},{SwUpDn},{Quiet},{Tur},{StHt},{TemUn},{HeatCoolType},{TemRec},{SvSt},{SlpMod}'.format(**self._acOptions)

        buzzer_command_value = 0 if self._current_beeper_enabled else 1

        opt += ',"Buzzer_ON_OFF"'
        p += ',' + str(buzzer_command_value)
        _LOGGER.debug(f"Sending with Buzzer_ON_OFF={buzzer_command_value} (Silent mode HA toggle is ON: {self._current_beeper_enabled})")

        if self._has_anti_direct_blow:
            opt += ',"AntiDirectBlow"'
            p += ',' + str(self._acOptions['AntiDirectBlow'])
        if self._has_light_sensor:
            opt += ',"LigSen"'
            p += ',' + str(self._acOptions['LigSen'])
        statePackJson = '{"opt":[' + opt + '],"p":[' + p + '],"t":"cmd"}'
        if self.encryption_version == 1:
            cipher = self.CIPHER
            if cipher is None:
                raise ValueError("Encryption cipher is not initialized. Cannot send state to AC.")
            sentJsonPayload = '{"cid":"app","i":0,"pack":"' + base64.b64encode(cipher.encrypt(self.Pad(statePackJson).encode("utf8"))).decode('utf-8') + '","t":"pack","tcid":"' + str(self._mac_addr) + '","uid":{}'.format(self._uid) + '}'
        elif self.encryption_version == 2:
            pack, tag = self.EncryptGCM(self._encryption_key, statePackJson)
            sentJsonPayload = '{"cid":"app","i":0,"pack":"' + pack + '","t":"pack","tcid":"' + str(self._mac_addr) + '","uid":{}'.format(self._uid) + ',"tag":"' + tag +'"}'
            cipher = self.GetGCMCipher(self._encryption_key)
        else:
            raise NotImplementedError("Encryption version %s is not implemented." % self.encryption_version)
        receivedJsonPayload = self.FetchResult(cipher, self._ip_addr, self._port, timeout, sentJsonPayload)
        _LOGGER.debug('Done sending state to HVAC: ' + str(receivedJsonPayload))

    def UpdateHATargetTemperature(self):
        # Sync set temperature to HA. If 8℃ heating is active we set the temp in HA to 8℃ so that it shows the same as the AC display.
        st_ht = self._acOptions.get('StHt')
        if st_ht is not None and int(st_ht) == 1:
            self._target_temperature = 8
            _LOGGER.info(f'{self._name} HA target temp set according to HVAC state to 8℃ since 8℃ heating mode is active')
        else:
            set_tem = self._acOptions.get('SetTem')
            tem_rec = self._acOptions.get('TemRec')
            if set_tem is not None and tem_rec is not None:
                temp_c = self.decode_temp_c(SetTem=set_tem, TemRec=tem_rec) # takes care of 1/2 degrees
                if (self._unit_of_measurement == "°C"):
                    display_temp = temp_c
                elif(self._unit_of_measurement == "°F"):
                    display_temp = self.gree_c_to_f(SetTem=set_tem, TemRec=tem_rec)
                else:
                    display_temp = temp_c # default to deg c
                    _LOGGER.error('Unknown unit of measurement: %s' % self._unit_of_measurement)
                self._target_temperature = display_temp
            else:
                self._target_temperature = None
                _LOGGER.warning("SetTem or TemRec is None, cannot decode target temperature")

            _LOGGER.info(
                f"UpdateHATargetTemperature: {self._name} HA target temp set to: {self._target_temperature} {self._unit_of_measurement}. "
                f"Device commands: SetTem: {self._acOptions['SetTem']}, TemRec: {self._acOptions['TemRec']}"
            )

    def UpdateHAOptions(self):
        # Sync HA with retreived HVAC options
        # WdSpd = fanspeed (0=auto), SvSt = powersave, Air = Air in/out (1=air in, 2=air out), Health = health
        # SwhSlp,SlpMod = sleep (both needed for sleep deactivation), StHt = 8℃ deg heating, Lig = lights, Blo = xfan
        # Sync current HVAC lights option to HA
        if (self._acOptions['Lig'] == 1):
            self._current_lights = STATE_ON
        elif (self._acOptions['Lig'] == 0):
            self._current_lights = STATE_OFF
        else:
            self._current_lights = STATE_UNKNOWN
        _LOGGER.debug('HA lights option set according to HVAC state to: ' + str(self._current_lights))
        # Sync current HVAC xfan option to HA
        if (self._acOptions['Blo'] == 1):
            self._current_xfan = STATE_ON
        elif (self._acOptions['Blo'] == 0):
            self._current_xfan = STATE_OFF
        else:
            self._current_xfan = STATE_UNKNOWN
        _LOGGER.debug('HA xfan option set according to HVAC state to: ' + str(self._current_xfan))
        # Sync current HVAC health option to HA
        if (self._acOptions['Health'] == 1):
            self._current_health = STATE_ON
        elif (self._acOptions['Health'] == 0):
            self._current_health = STATE_OFF
        else:
            self._current_health = STATE_UNKNOWN
        _LOGGER.debug('HA health option set according to HVAC state to: ' + str(self._current_health))
        # Sync current HVAC powersave option to HA
        if (self._acOptions['SvSt'] == 1):
            self._current_powersave = STATE_ON
        elif (self._acOptions['SvSt'] == 0):
            self._current_powersave = STATE_OFF
        else:
            self._current_powersave = STATE_UNKNOWN
        _LOGGER.debug('HA powersave option set according to HVAC state to: ' + str(self._current_powersave))
        # Sync current HVAC sleep option to HA
        if (self._acOptions['SwhSlp'] == 1) and (self._acOptions['SlpMod'] == 1):
            self._current_sleep = STATE_ON
        elif (self._acOptions['SwhSlp'] == 0) and (self._acOptions['SlpMod'] == 0):
            self._current_sleep = STATE_OFF
        else:
            self._current_sleep = STATE_UNKNOWN
        _LOGGER.debug('HA sleep option set according to HVAC state to: ' + str(self._current_sleep))
        # Sync current HVAC 8℃ heat option to HA
        if (self._acOptions['StHt'] == 1):
            self._current_eightdegheat = STATE_ON
        elif (self._acOptions['StHt'] == 0):
            self._current_eightdegheat = STATE_OFF
        else:
            self._current_eightdegheat = STATE_UNKNOWN
        _LOGGER.debug('HA 8℃ heat option set according to HVAC state to: ' + str(self._current_eightdegheat))
        # Sync current HVAC air option to HA
        if (self._acOptions['Air'] == 1):
            self._current_air = STATE_ON
        elif (self._acOptions['Air'] == 0):
            self._current_air = STATE_OFF
        else:
            self._current_air = STATE_UNKNOWN
        _LOGGER.debug('HA air option set according to HVAC state to: ' + str(self._current_air))
        # Sync current HVAC anti direct blow option to HA
        if self._has_anti_direct_blow:
            if (self._acOptions['AntiDirectBlow'] == 1):
                self._current_anti_direct_blow = STATE_ON
            elif (self._acOptions['AntiDirectBlow'] == 0):
                self._current_anti_direct_blow = STATE_OFF
            else:
                self._current_anti_direct_blow = STATE_UNKNOWN
            _LOGGER.debug('HA anti direct blow option set according to HVAC state to: ' + str(self._current_anti_direct_blow))

    def UpdateHAHvacMode(self):
        # Sync current HVAC operation mode to HA
        if (self._acOptions['Pow'] == 0):
            self._hvac_mode = HVACMode.OFF
        else:
            mod_mapping = MODES_MAPPING.get('Mod')
            if mod_mapping is not None:
                for key, value in mod_mapping.items():
                    if value == (self._acOptions['Mod']):
                        self._hvac_mode = key
        _LOGGER.debug('HA operation mode set according to HVAC state to: ' + str(self._hvac_mode))

    def UpdateHACurrentSwingMode(self):
        # Sync current HVAC Swing mode state to HA
        mod_mapping = MODES_MAPPING.get('SwUpDn')
        if mod_mapping is not None:
            for key, value in mod_mapping.items():
                if value == (self._acOptions['SwUpDn']):
                    self._swing_mode = key
        _LOGGER.debug('HA swing mode set according to HVAC state to: ' + str(self._swing_mode))

    def UpdateHACurrentSwingHorizontalMode(self):
        # Sync current HVAC Horizontal Swing mode state to HA
        mod_mapping = MODES_MAPPING.get('SwingLfRig')
        if mod_mapping is not None:
            for key, value in mod_mapping.items():
                if value == (self._acOptions['SwingLfRig']):
                    self._swing_horizontal_mode = key
        _LOGGER.debug('HA horizontal swing mode set according to HVAC state to: ' + str(self._swing_horizontal_mode))

    def UpdateHAFanMode(self):
        # Sync current HVAC Fan mode state to HA
        tur_value = self._acOptions.get('Tur')
        quiet_value = self._acOptions.get('Quiet')
        if tur_value is not None and int(tur_value) == 1:
            turbo_index = self._fan_modes.index('turbo')
            self._fan_mode = self._fan_modes[turbo_index]
        elif quiet_value is not None and int(quiet_value) >= 1:
            quiet_index = self._fan_modes.index('quiet')
            self._fan_mode = self._fan_modes[quiet_index]
        else:
            mod_mapping = MODES_MAPPING.get('WdSpd')
            if mod_mapping is not None:
                for key, value in mod_mapping.items():
                    if value == (self._acOptions['WdSpd']):
                        self._fan_mode = key
        _LOGGER.debug('HA fan mode set according to HVAC state to: ' + str(self._fan_mode))

    def UpdateHACurrentTemperature(self):
        temsen = self._acOptions['TemSen']
        if self._has_temp_sensor and temsen is not None:
            _LOGGER.debug("UpdateHACurrentTemperature: TemSen: " + str(self._acOptions['TemSen']))
            # print(f"UpdateHACurrentTemperature {self._temp_sensor_offset} {TEMP_SENSOR_OFFSET_OPTIONS[0]}")
            if self._temp_sensor_offset == TEMP_SENSOR_OFFSET_OPTIONS[1]:           # Offest on
                temp_c = temsen - TEMP_SENSOR_OFFSET
                _LOGGER.debug(f"method UpdateHACurrentTemperature: User has chosen an offset ({self._temp_sensor_offset})")
            elif self._temp_sensor_offset == TEMP_SENSOR_OFFSET_OPTIONS[2]:         # Offest off
                temp_c = temsen
                _LOGGER.debug(f"UpdateHACurrentTemperature: User has chosen an offset ({self._temp_sensor_offset})")
            else:                                                                   # Default option "Auto"
                temp_c = self._process_temp_sensor(temsen)
                _LOGGER.debug("UpdateHACurrentTemperature: Auto offset, using process_temp_sensor() to automatically determine offset")

            temp_f = self.gree_c_to_f(SetTem=temp_c, TemRec=0) # Convert to Fahrenheit using TemRec bit

            if (self._unit_of_measurement == "°C"):
                self._current_temperature = temp_c
            elif(self._unit_of_measurement == "°F"):
                self._current_temperature = temp_f
            else:
                _LOGGER.error("Unknown unit of measurement: %s" % self._unit_of_measurement)
            _LOGGER.debug('UpdateHACurrentTemperature: HA current temperature set with device built-in temperature sensor state : ' + str(self._current_temperature) + str(self._unit_of_measurement))

    def UpdateHAStateToCurrentACState(self):
        self.UpdateHATargetTemperature()
        self.UpdateHAOptions()
        self.UpdateHAHvacMode()
        if self._swing_modes:
            self.UpdateHACurrentSwingMode()
        if self._swing_horizontal_modes:
            self.UpdateHACurrentSwingHorizontalMode()
        self.UpdateHAFanMode()
        self.UpdateHACurrentTemperature()

    def SyncState(self, acOptions=None):
        #Fetch current settings from HVAC
        _LOGGER.debug('Starting SyncState')
        if acOptions is None:
            acOptions = {}

        if self._has_temp_sensor is None:
            _LOGGER.debug('Attempt to check whether device has an built-in temperature sensor')
            try:
                temp_sensor = self.GreeGetValues(["TemSen"])
            except:
                _LOGGER.debug('Could not determine whether device has an built-in temperature sensor. Retrying at next update()')
            else:
                if temp_sensor:
                    self._has_temp_sensor = True
                    self._acOptions.update({'TemSen': None})
                    self._optionsToFetch.append("TemSen")
                    _LOGGER.debug('Device has an built-in temperature sensor')
                else:
                    self._has_temp_sensor = False
                    _LOGGER.debug('Device has no built-in temperature sensor')

        if self._has_anti_direct_blow is None:
            _LOGGER.debug('Attempt to check whether device has an anti direct blow feature')
            try:
                anti_direct_blow = self.GreeGetValues(["AntiDirectBlow"])
            except:
                _LOGGER.debug('Could not determine whether device has an anti direct blow feature. Retrying at next update()')
            else:
                if anti_direct_blow:
                    self._has_anti_direct_blow = True
                    self._acOptions.update({'AntiDirectBlow': None})
                    self._optionsToFetch.append("AntiDirectBlow")
                    _LOGGER.debug('Device has an anti direct blow feature')
                else:
                    self._has_anti_direct_blow = False
                    _LOGGER.debug('Device has no anti direct blow feature')
        if self._has_light_sensor is None:
            _LOGGER.debug('Attempt to check whether device has an built-in light sensor')
            try:
                light_sensor = self.GreeGetValues(["LigSen"])
            except:
                _LOGGER.debug('Could not determine whether device has an built-in light sensor. Retrying at next update()')
            else:
                if light_sensor:
                    self._has_light_sensor = True
                    self._acOptions.update({'LigSen': None})
                    self._optionsToFetch.append("LigSen")
                    _LOGGER.debug('Device has an built-in light sensor')
                else:
                    self._has_light_sensor = False
                    _LOGGER.debug('Device has no built-in light sensor')

        optionsToFetch = self._optionsToFetch

        try:
            currentValues = self.GreeGetValues(optionsToFetch)
        except:
            _LOGGER.info('Could not connect with device. ')
            if not self._disable_available_check:
                self._online_attempts +=1
                if (self._online_attempts == self._max_online_attempts):
                    _LOGGER.info('Could not connect with device %s times. Set it as offline.' % self._max_online_attempts)
                    self._device_online = False
                    self._online_attempts = 0
        else:
            if not self._disable_available_check:
                if not self._device_online:
                    self._device_online = True
                    self._online_attempts = 0
            # Set latest status from device
            self._acOptions = self.SetAcOptions(self._acOptions, optionsToFetch, currentValues)

            # Overwrite status with our choices
            if not(acOptions == {}):
                self._acOptions = self.SetAcOptions(self._acOptions, acOptions)

            # Initialize the receivedJsonPayload variable (for return)
            receivedJsonPayload = ''

            # If not the first (boot) run, update state towards the HVAC
            if not (self._firstTimeRun):
                if not(acOptions == {}):
                    # loop used to send changed settings from HA to HVAC
                    self.SendStateToAc(self._timeout)
            else:
                # loop used once for Gree Climate initialisation only
                self._firstTimeRun = False

            # Update HA state to current HVAC state
            self.UpdateHAStateToCurrentACState()

            _LOGGER.debug('Finished SyncState')
            return receivedJsonPayload

    async def _async_temp_sensor_changed(self, event: Event[EventStateChangedData]) -> None:
        entity_id = event.data["entity_id"]
        old_state = event.data["old_state"]
        new_state = event.data["new_state"]
        s = str(old_state.state) if hasattr(old_state,'state') else "None"
        _LOGGER.info('temp_sensor state changed | ' + str(entity_id) + ' from ' + s + ' to ' + str(new_state.state))
        # Handle temperature changes.
        if new_state is None:
            return
        self._async_update_current_temp(new_state)
        return self.schedule_update_ha_state(True)

    @callback
    def _async_update_current_temp(self, state):
        _LOGGER.debug('method _async_update_current_temp Thermostat updated with changed temp_sensor state | ' + str(state.state))
        # Set unit = unit of measurement in the climate entity
        unit = state.attributes.get(ATTR_UNIT_OF_MEASUREMENT)
        _LOGGER.debug('method _async_update_current_temp Unit updated with changed temp_sensor unit | ' + str(unit))
        try:
            _state = state.state
            if self.represents_float(_state):
                self._current_temperature = self.hass.config.units.temperature(float(_state), unit)
                _LOGGER.info('method _async_update_current_temp: Current temp: ' + str(self._current_temperature))
        except ValueError as ex:
            _LOGGER.error('method _async_update_current_temp: Unable to update from temp_sensor: %s' % ex)

    def represents_float(self, s):
        _LOGGER.debug('temp_sensor state represents_float |' + str(s))
        try:
            float(s)
            return True
        except ValueError:
            return False

    @property
    def available(self):
        if self._disable_available_check:
            return True
        else:
            if self._device_online:
                _LOGGER.info(f'Available: Device {self._name} is online')
                return True
            else:
                _LOGGER.info(f'Available: Device {self._name} is offline')
                return False

    def update(self):
        _LOGGER.debug('update()')
        if not self._encryption_key:
            if self.encryption_version == 1:
                if self.GetDeviceKey():
                    self.SyncState()
            elif self.encryption_version == 2:
                if self.GetDeviceKeyGCM():
                    self.SyncState()
            else:
                _LOGGER.error('Encryption version %s is not implemented.' % self.encryption_version)
        else:
            self.SyncState()

    @property
    def name(self):
        _LOGGER.debug('name(): ' + str(self._name))
        # Return the name of the climate device.
        return self._name

    @property
    def temperature_unit(self):
        _LOGGER.debug('temperature_unit(): ' + str(self._unit_of_measurement))
        # Return the unit of measurement.
        return self._unit_of_measurement

    @property
    def current_temperature(self):
        _LOGGER.debug('current_temperature(): ' + str(self._current_temperature))
        # Return the current temperature.
        return self._current_temperature

    @property
    def min_temp(self):
        if (self._unit_of_measurement == "°C"):
            MIN_TEMP = MIN_TEMP_C
        else:
            MIN_TEMP = MIN_TEMP_F

        _LOGGER.debug('min_temp(): ' + str(MIN_TEMP))
        # Return the minimum temperature.
        return MIN_TEMP

    @property
    def max_temp(self):
        if (self._unit_of_measurement == "°C"):
            MAX_TEMP = MAX_TEMP_C
        else:
            MAX_TEMP = MAX_TEMP_F

        _LOGGER.debug('max_temp(): ' + str(MAX_TEMP))
        # Return the maximum temperature.
        return MAX_TEMP

    @property
    def target_temperature(self):
        _LOGGER.debug('target_temperature(): ' + str(self._target_temperature))
        # Return the temperature we try to reach.
        return self._target_temperature

    @property
    def target_temperature_step(self):
        _LOGGER.debug('target_temperature_step(): ' + str(self._target_temperature_step))
        # Return the supported step of target temperature.
        return self._target_temperature_step

    @property
    def hvac_mode(self):
        _LOGGER.debug('hvac_mode(): ' + str(self._hvac_mode))
        # Return current operation mode ie. heat, cool, idle.
        return self._hvac_mode

    @property
    def swing_mode(self):
        if self._swing_modes:
            _LOGGER.debug('swing_mode(): ' + str(self._swing_mode))
            # get the current swing mode
            return self._swing_mode
        else:
            return None

    @property
    def swing_modes(self):
        _LOGGER.debug('swing_modes(): ' + str(self._swing_modes))
        # get the list of available swing modes
        return self._swing_modes

    @property
    def swing_horizontal_mode(self):
        if self._swing_horizontal_modes:
            _LOGGER.debug('swing_horizontal_mode(): ' + str(self._swing_horizontal_mode))
            # get the current preset mode
            return self._swing_horizontal_mode
        else:
            return None

    @property
    def swing_horizontal_modes(self):
        _LOGGER.debug('swing_horizontal_modes(): ' + str(self._swing_horizontal_modes))
        # get the list of available preset modes
        return self._swing_horizontal_modes

    @property
    def hvac_modes(self):
        _LOGGER.debug('hvac_modes(): ' + str(self._hvac_modes))
        # Return the list of available operation modes.
        return self._hvac_modes

    @property
    def fan_mode(self):
        _LOGGER.debug('fan_mode(): ' + str(self._fan_mode))
        # Return the fan mode.
        return self._fan_mode

    @property
    def fan_modes(self):
        _LOGGER.debug('fan_list(): ' + str(self._fan_modes))
        # Return the list of available fan modes.
        return self._fan_modes

    @property
    def supported_features(self):
        sf = SUPPORT_FLAGS
        if self._swing_modes:
            sf = sf | ClimateEntityFeature.SWING_MODE
        if self._swing_horizontal_modes:
            sf = sf | ClimateEntityFeature.SWING_HORIZONTAL_MODE
        _LOGGER.debug('supported_features(): ' + str(sf))
        # Return the list of supported features.
        return sf

    @property
    def unique_id(self):
        # Return unique_id
        return self._unique_id

    def set_temperature(self, **kwargs):
        s = kwargs.get(ATTR_TEMPERATURE)

        _LOGGER.info('set_temperature(): ' + str(s) + str(self._unit_of_measurement))
        # Set new target temperatures.
        if s is not None:
            # do nothing if temperature is none
            if not (self._acOptions['Pow'] == 0):
                # do nothing if HVAC is switched off

                if (self._unit_of_measurement == "°C"):
                    SetTem, TemRec = self.encode_temp_c(T=s) # takes care of 1/2 degrees
                elif (self._unit_of_measurement == "°F"):
                    SetTem, TemRec = self.gree_f_to_c(desired_temp_f=s)
                else:
                    _LOGGER.error('Unable to set temperature. Units not set to °C or °F')
                    return

                self.SyncState({'SetTem': int(SetTem), 'TemRec': int(TemRec)})
                _LOGGER.debug('method set_temperature: Set Temp to ' + str(s) + str(self._unit_of_measurement)
                             + ' ->  SyncState with SetTem=' + str(SetTem) + ', SyncState with TemRec=' + str(TemRec))

                self.schedule_update_ha_state()

    def set_swing_mode(self, swing_mode):
        _LOGGER.info('Set swing mode(): ' + str(swing_mode))
        # set the swing mode
        if not (self._acOptions['Pow'] == 0):
            # do nothing if HVAC is switched off
            try:
                sw_up_dn = MODES_MAPPING.get("SwUpDn").get(swing_mode)
                _LOGGER.info('SyncState with SwUpDn=' + str(sw_up_dn))
                self.SyncState({'SwUpDn': sw_up_dn})
                self.schedule_update_ha_state()
            except ValueError:
                _LOGGER.error(f'Unknown swing mode: {swing_mode}')
                return

    def set_swing_horizontal_mode(self, swing_horizontal_mode):
        if not (self._acOptions['Pow'] == 0):
            # do nothing if HVAC is switched off
            try:
                swing_lf_rig= MODES_MAPPING.get("SwingLfRig").get(swing_horizontal_mode)
                _LOGGER.info('SyncState with SwingLfRig=' + str(swing_lf_rig))
                self.SyncState({'SwingLfRig': swing_lf_rig})
                self.schedule_update_ha_state()
            except ValueError:
                _LOGGER.error(f'Unknown preset mode: {swing_horizontal_mode}')
                return

    def set_fan_mode(self, fan):
        _LOGGER.info('set_fan_mode(): ' + str(fan))
        # Set the fan mode.
        if not (self._acOptions['Pow'] == 0):
            try:
                wd_spd = MODES_MAPPING.get("WdSpd").get(fan)

                # Check if this is turbo mode
                if fan == 'turbo':
                    _LOGGER.info('Enabling turbo mode')
                    self.SyncState({'Tur': 1, 'Quiet': 0})
                # Check if this is quiet mode
                elif fan == 'quiet':
                    _LOGGER.info('Enabling quiet mode')
                    self.SyncState({'Tur': 0, 'Quiet': 1})
                else:
                    _LOGGER.info('Setting normal fan mode to ' + str(wd_spd))
                    self.SyncState({'WdSpd': str(wd_spd), 'Tur': 0, 'Quiet': 0})

                self.schedule_update_ha_state()
            except ValueError:
                _LOGGER.error(f'Unknown fan mode: {fan}')
                return

    def set_hvac_mode(self, hvac_mode):
        _LOGGER.info('set_hvac_mode(): ' + str(hvac_mode))
        # Set new operation mode.
        c = {}
        if (hvac_mode == HVACMode.OFF):
            c.update({'Pow': 0})
            if hasattr(self, "_auto_light") and self._auto_light:
                c.update({'Lig': 0})
                if hasattr(self, "_has_light_sensor") and self._has_light_sensor and hasattr(self, "_enable_light_sensor") and self._enable_light_sensor:
                    c.update({'LigSen': 1})
        else:
            mod = MODES_MAPPING.get("Mod").get(hvac_mode)
            c.update({'Pow': 1, 'Mod': mod})
            if hasattr(self, "_auto_light") and self._auto_light:
                c.update({'Lig': 1})
                if hasattr(self, "_has_light_sensor") and self._has_light_sensor and hasattr(self, "_enable_light_sensor") and self._enable_light_sensor:
                    c.update({'LigSen': 0})
            if hasattr(self, "_auto_xfan") and self._auto_xfan:
                if (hvac_mode == HVACMode.COOL) or (hvac_mode == HVACMode.DRY):
                    c.update({'Blo': 1})
        self.SyncState(c)
        self.schedule_update_ha_state()

    def turn_on(self):
        _LOGGER.info('turn_on(): ')
        # Turn on.
        c = {'Pow': 1}
        if hasattr(self, "_auto_light") and self._auto_light:
            c.update({'Lig': 1})
            if hasattr(self, "_has_light_sensor") and self._has_light_sensor and hasattr(self, "_enable_light_sensor") and self._enable_light_sensor:
                c.update({'LigSen': 0})
        self.SyncState(c)
        self.schedule_update_ha_state()

    def turn_off(self):
        _LOGGER.info('turn_off(): ')
        # Turn off.
        c = {'Pow': 0}
        if hasattr(self, "_auto_light") and self._auto_light:
            c.update({'Lig': 0})
            if hasattr(self, "_has_light_sensor") and self._has_light_sensor and hasattr(self, "_enable_light_sensor") and self._enable_light_sensor:
                c.update({'LigSen': 1})
        self.SyncState(c)
        self.schedule_update_ha_state()

    async def async_added_to_hass(self):
        _LOGGER.info('Gree climate device added to hass()')
        self.update()

    async def async_will_remove_from_hass(self) -> None:
        """Clean up when entity is removed."""
        for name, entity_id, unsub in self._listeners:
            _LOGGER.debug('Deregistering %s listener for %s', name, entity_id)
            unsub()
        self._listeners.clear()



    def gree_f_to_c(self, desired_temp_f):
        # Convert to fractional C values for AC
        # See: https://github.com/tomikaa87/gree-remote
        SetTem = round((desired_temp_f - 32.0) * 5.0 / 9.0)
        TemRec = (int)((((desired_temp_f - 32.0) * 5.0 / 9.0) - SetTem) > -0.001)

        return SetTem, TemRec

    def gree_c_to_f(self, SetTem, TemRec):
        # Convert SetTem back to the minimum and maximum Fahrenheit before rounding
        # We consider the worst case scenario: SetTem could be the result of rounding from any value in a range
        # If TemRec is 1, it indicates the value was closer to the upper range of the rounding
        # If TemRec is 0, it indicates the value was closer to the lower range

        if TemRec == 1:
            # SetTem is closer to its higher bound, so we consider SetTem as the lower limit
            min_celsius = SetTem
            max_celsius = SetTem + 0.4999  # Just below the next rounding threshold
        else:
            # SetTem is closer to its lower bound, so we consider SetTem-1 as the potential lower limit
            min_celsius = SetTem - 0.4999  # Just above the previous rounding threshold
            max_celsius = SetTem

        # Convert these Celsius values back to Fahrenheit
        min_fahrenheit = (min_celsius * 9.0 / 5.0) + 32.0
        max_fahrenheit = (max_celsius * 9.0 / 5.0) + 32.0

        int_fahrenheit = round((min_fahrenheit + max_fahrenheit) / 2.0)

        return int_fahrenheit

    def encode_temp_c(self, T):
        """
        Used for encoding 1/2 degree Celsius values.
        Encode any floating‐point temperature T into:
          ‣ temp_int: the integer (°C) portion of the nearest 0.0/0.5 step,
          ‣ half_bit: 1 if the nearest step has a ".5", else 0.

        This "finds the closest multiple of 0.5" to T, then:
          n = round(T * 2)
          temp_int = n >> 1      (i.e. floor(n/2))
          half_bit = n & 1       (1 if it's an odd half‐step)
        """
        # 1) Compute "twice T" and round to nearest integer:
        #    math.floor(T * 2 + 0.5) is equivalent to rounding ties upward.
        n = int(round(T * 2))

        # 2) The low bit of n says ".5" (odd) versus ".0" (even):
        TemRec = n & 1

        # 3) Shifting right by 1 gives floor(n/2), i.e. the integer °C of that nearest half‐step:
        SetTem = n >> 1

        return SetTem, TemRec

    def decode_temp_c(self, SetTem: int, TemRec: int) -> float:
        """
        Given:
          SetTem = the "rounded-down" integer (⌊T⌋ or for negatives, floor(T))
          TemRec = 0 or 1, where 1 means "there was a 0.5"
        Returns the original temperature as a float.
        """
        return SetTem + (0.5 if TemRec else 0.0)

    class TempOffsetResolver:
        """
        Detect whether this sensor reports temperatures in °C
        or in (°C + 40).  Continues to check, and bases decision
        on historical min and max raw values, since there are extreme
        cases which would result in a switch. Two running values are
        stored (min & max raw).

        Note: This could be simplified by just using 40C as a max point
        for the unoffset case and a min point for the offset case. But
        this doesn't account for the marginal cases around 40C as well.

        Example:

        if raw < 40:
            return raw
        else:
            return raw - 40

        """


        def __init__(self,
                     indoor_min: float = -15.0,  # coldest plausible indoor °C
                     indoor_max: float = 40.0,  # hottest plausible indoor °C
                     offset:     float = TEMP_SENSOR_OFFSET,  # device's fixed offset
                     margin:     float = 2.0):  # tolerance before "impossible":
            self._lo_lim      = indoor_min - margin
            self._hi_lim      = indoor_max + margin
            self._offset      = offset

            self._min_raw: float | None = None
            self._max_raw: float | None = None
            self._has_offset: bool | None = None   # undecided until True/False

        def __call__(self, raw: float) -> float:


            # ---- original path (still undecided) ------------------------------
            if self._min_raw is None or raw < self._min_raw:
                self._min_raw = raw
            if self._max_raw is None or raw > self._max_raw:
                self._max_raw = raw

            self._evaluate()  # evaluate every time, so it can change it's mind as needed

            return raw - self._offset if self._has_offset else raw

        def _evaluate(self) -> None:
            """
            Compare the raw range and (raw-offset) range against the
            plausible indoor envelope.  Whichever fits strictly better wins.
            """
            lo, hi = self._min_raw, self._max_raw

            penalty_no  = self._penalty(lo,             hi)
            penalty_off = self._penalty(lo - self._offset,
                                        hi - self._offset)

            if penalty_no == penalty_off:
                return # still ambiguous – keep collecting data

            self._has_offset = penalty_off < penalty_no

        def _penalty(self, lo: float, hi: float) -> float:
            """
            Distance (°C) by which the [lo, hi] interval lies outside
            the indoor envelope.  Zero means entirely plausible.
            """
            pen = 0.0
            if lo < self._lo_lim:
                pen += self._lo_lim - lo
            if hi > self._hi_lim:
                pen += hi - self._hi_lim
            return pen
