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

import gi
gi.require_version("NM", "1.0")
from gi.repository import NM
from gi.repository import GLib

import codecs
import threading
import time
import dbus
import sys
import hashlib
import binascii
import os
import dbus
import uuid
import os

from pathlib import Path
import subprocess

def _wpa_psk(ssid,password):
	dk = hashlib.pbkdf2_hmac('sha1', str.encode(password), str.encode(ssid), 4096, 32)
	return binascii.hexlify(dk).decode('utf-8')

class WifiEduGva:

	ERROR_NO_WIFI_DEV = -1
	ERROR_WAITING_FOR_DOMAIN = -2

	def __init__(self):
		self.semaphore = threading.Semaphore(1)
		self.ready = False

	def nm_cb(self, dev, res, data):
		self.ready = True

	def wait_sync(self,client):
		self.ready = False
		context = client.get_main_context()
		while not self.ready:
			context.iteration(False)
			time.sleep(0.250)

	def flush(self,client):
		context = client.get_main_context()
		while context.iteration(False):
			pass

	def scan_network(self):
		with self.semaphore:
			client = NM.Client.new(None)
			self.flush(client)

			wifi = None
			for device in client.get_devices():
				if (device.get_device_type() == NM.DeviceType.WIFI):
					wifi = device
					break

			if (not wifi):
				return n4d.responses.build_failed_call_response(WifiEduGva.ERROR_NO_WIFI_DEV,"No wireless device available")
			try:
				t0 = time.time()
				last = wifi.get_last_scan()
				wifi.request_scan_async(None,None,None)

				while (wifi.get_last_scan() <= last):
					self.flush(client)
					time.sleep(0.250)
					t1 = time.time()
					if ((t1 - t0) > 30.0):
						break
						#just time out after 30s

			except Exception as e:
				#perhaps a scan is going on...
				time.sleep(2.0)

			aps = []
			for ap in wifi.get_access_points():
				ssid = ap.get_ssid()
				if (ssid):
					ssid = ssid.get_data().decode("utf-8")
				else:
					ssid = ""
				
				aps.append([ssid,ap.get_strength()])

			self.flush(client)
			return n4d.responses.build_successful_call_response(aps)

	def create_connection(self,name,ssid,user,password,wpa_mode):
		with self.semaphore:
			client = NM.Client.new(None)
			self.flush(client)

			found = None
			for connection in client.get_connections():
				if (connection.get_id() == name):
					found = connection
					break

			if (found):
				connection.delete_async(None,self.nm_cb,None)
				self.wait_sync(client)

			profile = NM.SimpleConnection.new()

			settings = NM.SettingConnection.new()
			settings.set_property(NM.SETTING_CONNECTION_ID, name)
			settings.set_property(NM.SETTING_CONNECTION_UUID, str(uuid.uuid4()))
			settings.set_property(NM.SETTING_CONNECTION_TYPE, "802-11-wireless")
			profile.add_setting(settings)

			settings = NM.SettingWireless.new()
			settings.set_property(NM.SETTING_WIRELESS_SSID, GLib.Bytes(bytes(ssid.encode("utf-8"))))
			settings.set_property(NM.SETTING_WIRELESS_MODE, "infrastructure")
			profile.add_setting(settings)

			if (wpa_mode == "personal"):
				settings = NM.SettingWirelessSecurity.new()
				settings.set_property(NM.SETTING_WIRELESS_SECURITY_KEY_MGMT, "wpa-psk")
				settings.set_property(NM.SETTING_WIRELESS_SECURITY_PSK, _wpa_psk(ssid,password))
				profile.add_setting(settings)
			else:
				settings = NM.SettingWirelessSecurity.new()
				settings.set_property(NM.SETTING_WIRELESS_SECURITY_KEY_MGMT, "wpa-eap")
				profile.add_setting(settings)

				settings = NM.Setting8021x.new()
				settings.set_property(NM.SETTING_802_1X_EAP, ["peap"])
				settings.set_property(NM.SETTING_802_1X_IDENTITY, user)
				settings.set_property(NM.SETTING_802_1X_PASSWORD, password)
				settings.set_property(NM.SETTING_802_1X_PHASE2_AUTH, "mschapv2")
				profile.add_setting(settings)

				settings = NM.SettingIP4Config.new()
				settings.set_property(NM.SETTING_IP_CONFIG_METHOD, "auto")
				profile.add_setting(settings)

			client.add_connection_async(profile,False,None,self.nm_cb,None)
			self.wait_sync(client)

			#print("Activating connection...")
			#client.activate_connection_async(profile,None,None,None,self.nm_cb,None)
			#self.wait_sync(client)

			self.flush(client)
			return n4d.responses.build_successful_call_response()

	def get_active_connections(self):
		with self.semaphore:
			client = NM.Client.new(None)
			self.flush(client)

			connections=[]
			for connection in client.get_active_connections():
				connections.append([connection.get_id(),connection.get_connection_type()])

			self.flush(client)
			return n4d.responses.build_successful_call_response(connections)

	def check_wired_connection(self):
		# Force additional gateway check
		check_gateway = True
		with self.semaphore:
			client = NM.Client.new(None)
			self.flush(client)

			found = False
			for connection in client.get_active_connections():
				gw_ok = ( (not check_gateway) or bool(connection.get_ip4_config().get_gateway()))
				if (connection.get_connection_type() == "802-3-ethernet" and gw_ok):
					found = True
					break

			self.flush(client)
			return n4d.responses.build_successful_call_response(found)

	def disconnect_all(self):
		with self.semaphore:
			client = NM.Client.new(None)
			self.flush(client)

			found = False
			for connection in client.get_active_connections():
				if (connection.get_connection_type() == "802-11-wireless"):
					client.deactivate_connection_async(connection,None,self.nm_cb,None)
					self.wait_sync(client)

			self.flush(client)
			return n4d.responses.build_successful_call_response()

	def disconnect(self,name,user):
		with self.semaphore:
			client = NM.Client.new(None)
			self.flush(client)

			found = False
			for connection in client.get_active_connections():
				if (connection.get_id() == name):
					conn = connection.get_connection()
					settings = conn.get_setting_802_1x()

					if (settings and settings.get_identity() == user):
						found = True
						client.deactivate_connection_async(connection,None,self.nm_cb,None)
						self.wait_sync(client)

						# NM Api doesn't seem to provide a way to do this
						os.system("nmcli connection delete {0}".format(name))

			self.flush(client)
			return n4d.responses.build_successful_call_response(found)

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

	def is_cdc_enabled(self):
		sssd_conf = Path("/etc/sssd/sssd.conf")
		return n4d.responses.build_successful_call_response(sssd_conf.exists())

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
			return n4d.responses.build_failed_call_response(WifiEduGva.ERROR_WAITING_FOR_DOMAIN,"Error waiting for domain.")

	def check_connectivity(self):
		with self.semaphore:
			client = NM.Client.new(None)
			retries = 30
			while retries > 0:
				client.check_connectivity_async(None,self.nm_cb,None)
				self.wait_sync(client)
				status = client.get_connectivity()
				print("connectivity status:{0}".format(status))

				if (status == NM.ConnectivityState.FULL):
					return n4d.responses.build_successful_call_response(True)
				else:
					active = client.get_active_connections()
					if (len(active) == 0):
						# no active connections found
						break

					time.sleep(1)
					retries = retries - 1

			return n4d.responses.build_successful_call_response(False)

	def guess_mode(self):

		with self.semaphore:
			guessed = 0
			ceip = ["lliurex-meta-gva-desktop-ceip"]
			ies = ["lliurex-meta-gva-desktop-ies, lliurex-meta-gva-desktop-fp"]
			adi = ["lliurex-meta-gva-adi-ceip","lliurex-meta-gva-adi-ies, lliurex-meta-gva-adi-fp"]

			try:
				p = subprocess.Popen(["/usr/bin/dpkg","-l","--no-pager"],stdout=subprocess.PIPE)
				sout,serr = p.communicate(timeout = 5)

				lines = sout.decode("utf-8").split("\n")
				packages = []

				for line in lines:

					tmp = line.split()

					if len(tmp)>2:
						if (tmp[0] == "ii"):
							package = tmp[1].split(":")[0]
							packages.append(package)

				is_ceip = False
				is_ies = False
				is_adi = False

				for package in packages:
					is_ceip = is_ceip or (package in ceip)
					is_ies = is_ies or (package in ies)
					is_adi = is_adi or (package in adi)

			except Exception as e:
				pass

			if is_ceip:
				guessed = guessed | 1

			if is_ies:
				guessed = guessed | 2

			if is_adi:
				guessed = guessed | 4

			return n4d.responses.build_successful_call_response(guessed)

if __name__=="__main__":
	w = WifiEduGva()
	print(w.scan_network())
