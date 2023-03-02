"""
    N4D Wifi Edu GVA

    Copyright (C) 2023  Enrique Medina Gremaldos <quiqueiii@gmail.com>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""

import n4d.responses
import n4d.server.core

import NetworkManager as nm

import codecs
import threading
import time
import dbus
import sys
import hashlib
import binascii
import os
import dbus

def _wpa_psk(ssid,password):
	dk = hashlib.pbkdf2_hmac('sha1', str.encode(password), str.encode(ssid), 4096, 32)
	return binascii.hexlify(dk).decode('utf-8')

class WifiEduGva:

	ERROR_NO_WIFI_DEV = -1
	ERROR_WAITING_FOR_DOMAIN = -2

	def __init__(self):
		self.semaphore = threading.Semaphore(1)

	def get_devices(self):
	# This is a workaround because current python3-networkmanager version (2.1)
	# does not support device types bigger than 26 and crash
		devices = []

		for n in range(1,32):
			try:
				dev = nm.Device("/org/freedesktop/NetworkManager/Devices/{0}".format(n))
				devices.append(dev)
			except dbus.DBusException:
				break
			except KeyError:
				#catch bug and ignore device, any way is not a wifi device we are interested in
				continue


		return devices

	def scan_network(self):
		with self.semaphore:
			wifi = None
			for device in self.get_devices():
				if (device.DeviceType == nm.NM_DEVICE_TYPE_WIFI):
					wifi = device
					break

			if (not wifi):
				return n4d.responses.build_failed_call_response(EscolesConectades.ERROR_NO_WIFI_DEV,"No wireless device available")
			try:
				last = wifi.LastScan
				wifi.RequestScan([])
				while wifi.LastScan<=last:
					time.sleep(0.5)

			except Exception as e:
				#perhaps a scan is going on...
				time.sleep(2.0)

			aps = []
			for ap in wifi.AccessPoints:
				aps.append([ap.Ssid,ap.Strength])

			return n4d.responses.build_successful_call_response(aps)

	def create_connection(self,name,ssid,user,password,wpa_mode):
		with self.semaphore:

			ec = None

			for c in nm.Settings.Connections:
				if c.GetSettings()["connection"]["id"] == name:
					ec = c
					break
			if ec:
				ec.Delete()

			connection = {}
			connection["connection"] = {}
			connection["connection"]["id"] = name
			connection["connection"]["type"] = "802-11-wireless"
			#connection["connection"]["permissions"] = ["user:{0}:".format(user)]
			#connection["connection"]["permissions"] = ["user:root:"]

			connection["802-11-wireless"] = {}
			connection["802-11-wireless"]["ssid"] = dbus.ByteArray(bytes(ssid,'utf-8'))
			connection["802-11-wireless"]["mode"] = "infrastructure"

			connection["802-11-wireless-security"] = {}
			if wpa_mode=="personal":
				connection["802-11-wireless-security"]["key-mgmt"] = "wpa-psk"
				connection["802-11-wireless-security"]["psk"] = _wpa_psk(ssid,password)
			else:
				connection["802-11-wireless-security"]["key-mgmt"] = "wpa-eap"
				connection["802-1x"] = {}
				connection["802-1x"]["eap"] = ["peap"]
				connection["802-1x"]["identity"] = user
				connection["802-1x"]["password"] = password
				connection["802-1x"]["phase2-auth"] = "mschapv2"

			connection["ipv4"] = {}
			connection["ipv4"]["method"] = "auto"

			# This magic flag 0x02 renders connection volatile, so it will be destroyed on next boot
			tmp = nm.Settings.AddConnection2(connection,0x02,[])

			nm.NetworkManager.ActivateConnection(dbus.types.String(tmp[0].object_path),dbus.types.String("/"),dbus.types.String("/"))

			return n4d.responses.build_successful_call_response()

	def get_active_connections(self):
		with self.semaphore:
			connections=[]
			for connection in nm.NetworkManager.ActiveConnections:
				connections.append([connection.Id,connection.Type])

			return n4d.responses.build_successful_call_response(connections)

	def check_wired_connection(self):
		connections = self.get_active_connections()
		for connection in connections["return"]:
			if connection[1] == "802-3-ethernet":
				return n4d.responses.build_successful_call_response(True)

		return n4d.responses.build_successful_call_response(False)

	def disconnect_all(self):
		with self.semaphore:

			for connection in nm.NetworkManager.ActiveConnections:
				if (connection.Type=="802-11-wireless"):
					nm.NetworkManager.DeactivateConnection(connection)

			return n4d.responses.build_successful_call_response()

	def disconnect(self,name,user):
		with self.semaphore:

			for connection in nm.NetworkManager.ActiveConnections:
				if connection.Id == name:
					settings = connection.Connection.GetSettings()
					tmp = settings.get("802-1x")

					if (not tmp == None) and tmp["identity"] == user:
						nm.NetworkManager.DeactivateConnection(connection.object_path)
						return n4d.responses.build_successful_call_response(True)

			return n4d.responses.build_successful_call_response(False)

	def get_settings(self):
		var = n4d.server.core.Core.get_core().get_variable("SDDM_WIFIEDUGVA_SETTINGS")
		return n4d.responses.build_successful_call_response(var["return"])

	def set_settings(self,value):
		n4d.server.core.Core.get_core().set_variable("SDDM_WIFIEDUGVA_SETTINGS",value)
		return n4d.responses.build_successful_call_response()

	def get_autologin(self):
		var = n4d.server.core.Core.get_core().get_variable("SDDM_WIFIEDUGVA_AUTOLOGIN")
		value = codecs.decode(var["return"],"rot13")
		return n4d.responses.build_successful_call_response(value)

	def set_autologin(self,value):
		value = codecs.encode(value,"rot13")
		n4d.server.core.Core.get_core().set_variable("SDDM_WIFIEDUGVA_AUTOLOGIN",value)
		return n4d.responses.build_successful_call_response()

	def wait_for_domain(self):
		try:
			bus = dbus.SystemBus()
			proxy = bus.get_object("org.freedesktop.sssd.infopipe",
				"/org/freedesktop/sssd/infopipe/Domains/EDU_2eGVA_2eES")

			IsOnline = proxy.get_dbus_method("IsOnline","org.freedesktop.sssd.infopipe.Domains.Domain")

			retries = 10

			while IsOnline()==False and retries>0:
				time.sleep(1)
				retries = retries - 1

			return n4d.responses.build_successful_call_response(retries>0)
		except Exception as e:
			return n4d.responses.build_failed_call_response(EscolesConectades.ERROR_WAITING_FOR_DOMAIN,"Error waiting for domain.")
