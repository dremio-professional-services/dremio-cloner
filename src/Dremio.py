########
# Copyright (C) 2019-2020 Dremio Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
########

import requests
import logging
import json
import time
import sys
import urllib

###
# Dremio API wrapper.
#
###
class Dremio:
	# API URLs
	_catalog_url = 'api/v3/catalog/'
	_reflection_url = 'api/v3/reflection/'
	_catalog_url_by_path = 'api/v3/catalog/by-path/'
	_login_url = 'apiv2/login'
	_eula_url = 'apiv2/eula/accept'
	_reflections_url = "api/v3/reflection/"
	_wlm_queue_url = "api/v3/wlm/queue/"
	_wlm_rule_url = "api/v3/wlm/rule"
	_user_url = "api/v3/user/"
	_user_by_name_url = "api/v3/user/by-name/"
	_role_url = "api/v3/role/"
	_role_by_name_url = "api/v3/role/by-name/"
	_post_sql_url = "api/v3/sql"
	_get_job_url = "api/v3/job/"
	_graph_url_postfix = "graph"
	_refresh_reflections_postfix = "refresh"
	_endpoint = ""
	_username = ""					# Need to keep for expired token processing
	_password = ""
	_authtoken = ""
	_headers = ""
	_verify_ssl = None
	# Dremio Config
	_api_timeout = None 			# Default 10 seconds
	_retry_timedout_source = None 	# Do not retry SOURCE that has timed out in previous API calls. Default False
	errors_encountered = 0
	# Misc
	_timed_out_sources = []

	def __init__(self, endpoint, username, password, accept_eula, api_timeout=10, retry_timedout_source=False, verify_ssl=True):
		self._session = requests.Session()
		if not verify_ssl:
			logging.warning("Unverified HTTPS requests will be made as per configuration.")
			requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)
		self._endpoint = endpoint
		self._verify_ssl = verify_ssl
		self._api_timeout = api_timeout
		self._retry_timedout_source = retry_timedout_source
		self._username = username
		self._password = password
		if accept_eula:
			self._accept_eula()
		self._authenticate()

	def _accept_eula(self):
		headers = {"Content-Type": "application/json"}
		response = self._session.request("POST", self._endpoint + self._eula_url, headers=headers,
									timeout=self._api_timeout, verify=self._verify_ssl)
		if response.status_code != 204 and response.status_code != 200:
			logging.critical("EULA Accept Error " + str(response.status_code))
			raise RuntimeError("EULA Accept error.")

	def _authenticate(self):
		headers = {"Content-Type": "application/json"}
		payload = '{"userName": "' + self._username + '","password": "' + self._password + '"}'
		payload = payload.encode(encoding='utf-8')
		response = self._session.request("POST", self._endpoint + self._login_url, data=payload, headers=headers, timeout=self._api_timeout, verify=self._verify_ssl)
		if response.status_code != 200:
			logging.critical("Authentication Error " + str(response.status_code))
			raise RuntimeError("Authentication error.")
		self._authtoken = '_dremio' + response.json()['token']
		# print(self._authtoken)
		self._headers = {"Content-Type": "application/json", "Authorization": self._authtoken}

	def _build_url(self, url):
		return self._endpoint + url

	def list_catalog(self):
		return self._api_get_json(self._catalog_url, source="list_catalog")

	def get_catalog_entity_by_path(self, path, report_error=True):
		if path[0] == '/':
			path = path[1:]
		if '#' in path:
			path = path.replace("#", "%23")
		return self._api_get_json(self._catalog_url_by_path + path, source="get_catalog_entity_by_path", report_error=report_error)

	def get_catalog_entity_by_id(self, entity_id):
		if entity_id[:7] == 'dremio:':
			return self.get_catalog_entity_by_path(entity_id[8:])
		else:
			return self._api_get_json(self._catalog_url + entity_id, source="get_catalog_entity_by_id")

	def get_catalog_entity_graph_by_id(self, entity_id, report_error=True):
		return self._api_get_json(self._catalog_url + entity_id + '/' + self._graph_url_postfix, source="get_catalog_entity_graph", report_error=report_error)

	def get_user(self, user_id):
		return self._api_get_json(self._user_url + user_id, source="get_user")

	def get_user_by_name(self, username):
		return self._api_get_json(self._user_by_name_url + username, source="get_user_by_name")

	def get_role(self, role_id):
		return self._api_get_json(self._role_url + role_id, source="get_role")

	def get_role_by_name(self, rolename):
		return self._api_get_json(self._role_by_name_url + rolename, source="get_role_by_name")

	def get_catalog_tags(self, entity_id):
		return self._api_get_json(self._catalog_url + entity_id + "/collaboration/tag", source="get_catalog_tags", report_error=False)

	def get_catalog_wiki(self, entity_id):
		return self._api_get_json(self._catalog_url + entity_id + "/collaboration/wiki", source="get_catalog_wiki", report_error=False)

	def get_reflection(self, reflection_id):
		return self._api_get_json(self._reflections_url + reflection_id, source="get_reflection")

	def list_reflections(self):
		return self._api_get_json(self._reflections_url, source="list_reflections")

	def list_queues(self):
		return self._api_get_json(self._wlm_queue_url, source="list_queues")

	def list_rules(self):
		return self._api_get_json(self._wlm_rule_url, source="list_rules")

	_cached_schemas = {}
	def _normalize_schema(self, schema):
		if schema in self._cached_schemas:
			return self._cached_schemas[schema]
		path = schema.split('.')
		normalized_path = ""
		for i in range(0, len(path)):
			normalized_path = normalized_path + path[i]
			entity = self.get_catalog_entity_by_path(normalized_path, report_error=False)
			if entity is not None:
				normalized_path = normalized_path + '/'
			else:
				normalized_path = normalized_path + '.'
		self._cached_schemas[schema] = normalized_path
		return normalized_path

	def create_catalog_entity(self, entity, dry_run=True):
		if dry_run:
			logging.warning("create_catalog_entity: Dry Run. Not submitting changes to API.")
			return
		return self._api_post_json(self._catalog_url, entity, source="create_catalog_entity")

	def update_catalog_entity(self, entity_id, entity, dry_run=True, report_error=True):
		if dry_run:
			logging.warning("update_catalog_entity: Dry Run. Not submitting changes to API.")
			return
		return self._api_put_json(self._catalog_url + entity_id, entity, source="update_catalog_entity", report_error = report_error)

	def create_reflection(self, reflection, dry_run=True):
		if dry_run:
			logging.warning("create_reflection: Dry Run. Not submitting changes to API.")
			return
		return self._api_post_json(self._reflections_url, reflection, source="create_reflection")

	def update_reflection(self, reflection_id, reflection, dry_run=True):
		if dry_run:
			logging.warning("update_reflection: Dry Run. Not submitting changes to API.")
			return
		return self._api_put_json(self._reflections_url + reflection_id, reflection, source="update_reflection")

	def refresh_reflections_by_pds_id(self, pds_entity_id, dry_run=True):
		if dry_run:
			logging.warning("refresh_reflections_by_pds_id: Dry Run. Not submitting request to API.")
			return
		return self._api_post_json(self._catalog_url + pds_entity_id + "/" + self._refresh_reflections_postfix, "", source="refresh_reflections_by_pds_id")

	def refresh_reflections_by_pds_path(self, pds_entity_path, dry_run=True):
		if dry_run:
			logging.warning("refresh_reflections_by_pds_path: Dry Run. Not submitting request to API.")
			return
		pds = self.get_catalog_entity_by_path(pds_entity_path)
		if pds is None:
			logging.error("refresh_reflections_by_pds_path: Could not locate entity for path: " + str(pds_entity_path))
			return None
		pds_entity_id = pds['id']
		result = self._api_post_json(self._catalog_url + pds_entity_id + "/" + self._refresh_reflections_postfix, None, source="refresh_reflections_by_pds_path")
		return result

	def update_wiki(self, catalog_id, wiki, dry_run=True):
		if dry_run:
			logging.warning("update_wiki: Dry Run. Not submitting changes to API.")
			return
		return self._api_post_json(self._catalog_url + catalog_id + "/collaboration/wiki", wiki, source="update_wiki")

	def update_tag(self, catalog_id, tag, dry_run=True):
		if dry_run:
			logging.warning("update_tag: Dry Run. Not submitting changes to API.")
			return
		return self._api_post_json(self._catalog_url + catalog_id + "/collaboration/tag", tag, source="update_tag")

	def promote_pds(self, pds_entity, dry_run=True):
		if dry_run:
			logging.warning("promote_pds: Dry Run. Not submitting changes to API.")
			return
		return self._api_post_json(self._catalog_url + self._encode_http_param(pds_entity['id']), pds_entity,
								   source="promote_pds")

	# Returns Job ID or None
	def submit_sql(self, sql, context=None):
		payload = '{ "sql":"' + sql + '"' + ("" if context is None else ',{"context":"' + context + '"') + ' }'
		logging.debug("submit_sql: sql: " + str(sql))
		logging.debug("submit_sql: payload: " + str(payload))
		jsn = self._api_post_json(self._post_sql_url, payload, source="submit_sql", as_json=False)
		if jsn is not None:
			return jsn["id"]
		else:
			return None

	def get_job_info(self, jobid):
		return self._api_get_json(self._get_job_url + jobid, source="get_job_info")

	def get_job_result(self, jobid, offset=0, limit=100):
		return self._api_get_json(self._get_job_url + jobid + '/results?offset=' + str(offset) + '&limit=' + str(limit),
								  source="get_job_info")

	def delete_reflection(self, reflection_id, dry_run=True, report_error=True):
		if dry_run:
			logging.warning("delete_reflection: Dry Run. Not submitting changes to API for delete reflection: " + reflection_id)
			return
		return self._api_delete(self._reflection_url + reflection_id, source="delete_reflection", report_error = report_error)


	def delete_catalog_entity(self, entity_id, dry_run=True, report_error=True):
		if dry_run:
			logging.warning("delete_catalog_entity: Dry Run. Not submitting changes to API for delete entity: " + entity_id)
			return
		return self._api_delete(self._catalog_url + entity_id, source="delete_catalog_entity", report_error = report_error)

	# Returns JSON if success or None
	def _api_get_json(self, url, source="", report_error=True, reauthenticate=False):
		if reauthenticate:
			self._authenticate()
		# Extract source
		source_name = None
		pos = url.find(self._catalog_url_by_path)
		if pos >= 0:
			source_name = url[pos + 23:]
			source_name = source_name[0:source_name.find("/")]
		else:
			pos = url.find(self._catalog_url)
			if pos >= 0:
				source_name = url[pos + 23:]
				source_name = source_name[0:source_name.find("/")]

		try:
			if source_name in self._timed_out_sources and not self._retry_timedout_source:
				raise requests.exceptions.Timeout()
			response = self._session.request("GET", self._endpoint + url, headers=self._headers, timeout=self._api_timeout, verify=self._verify_ssl)
			if response.status_code == 200:
				return response.json()
			elif response.status_code == 400:  # Bad Request
				if report_error:
					logging.info(source + ": received HTTP Response Code " + str(response.status_code) +
									" for : <" + str(url) + ">" + self._get_error_message(response))
			elif response.status_code == 404:  # Not found
				if report_error:
					logging.info(source + ": received HTTP Response Code " + str(response.status_code) +
									" for : <" + str(url) + ">" + self._get_error_message(response))
			elif response.status_code == 401 or response.status_code == 403:
				# Try to reauthenticate since the token might expire
				if not reauthenticate:
					return self._api_get_json(url, source, report_error, True)
				logging.critical(source + ": received HTTP Response Code " + str(response.status_code) +
								 " for : <" + str(url) + ">" + self._get_error_message(response))
				raise RuntimeError(
					"Specified user does not have sufficient privileges to create objects in the target Dremio Environment.")
			else:
				if report_error:
					logging.error(source + ": received HTTP Response Code " + str(response.status_code) +
								" for : <" + str(url) + ">" + self._get_error_message(response))
					self.errors_encountered = self.errors_encountered + 1
			return None
		except requests.exceptions.Timeout:
			if source_name is None or source_name not in self._timed_out_sources:
				# This situation might happen when an underlying object (file system eg) is not responding
				if report_error:
					logging.error(source + ": HTTP Request Timed-out: " + " <" + str(url) + ">")
					self.errors_encountered = self.errors_encountered + 1
				else:
					logging.info(source + ": HTTP Request Timed-out: " + " <" + str(url) + ">")
			if source_name is not None and source_name not in self._timed_out_sources:
				self._timed_out_sources.append(source_name)
			return None

	# Returns JSON if success or None
	def _api_post_json(self, url, json_data, source="", as_json=True, reauthenticate=False):
		if reauthenticate:
			self._authenticate()
		try:
			try:
				if json_data and isinstance(json_data, str):
					json_data = json_data.encode("utf-8")
			except UnicodeEncodeError as e:
				logging.error(e)
				logging.error(f"Data: {json_data}")
			if json_data is None:
				response = self._session.request("POST", self._endpoint + url, headers=self._headers, timeout=self._api_timeout, verify=self._verify_ssl)
			elif as_json:
				response = self._session.request("POST", self._endpoint + url, json=json_data, headers=self._headers, timeout=self._api_timeout, verify=self._verify_ssl)
			else:
				response = self._session.request("POST", self._endpoint + url, data=json_data, headers=self._headers, timeout=self._api_timeout, verify=self._verify_ssl)
			if response.status_code == 200:
				return response.json()
			# Success, but no response
			elif response.status_code == 204:
				return None
			elif response.status_code == 400:
				logging.error(source + ": received HTTP Response Code " + str(response.status_code) +
							  " for : <" + str(url) + ">" + self._get_error_message(response))
			elif response.status_code == 401 or response.status_code == 403:
				# Try to reauthenticate since the token might expire
				if not reauthenticate:
					return self._api_post_json(url, json_data, source, as_json, False)
				logging.critical(source + ": received HTTP Response Code " + str(response.status_code) +
								 " for : <" + str(url) + ">" + self._get_error_message(response))
				raise RuntimeError(
					"Specified user does not have sufficient priviliges to create objects in the target Dremio Environment.")
			elif response.status_code == 409:  # Already exists.
				logging.error(source + ": received HTTP Response Code " + str(response.status_code) +
							  " for : <" + str(url) + ">" + self._get_error_message(response))
			elif response.status_code == 404:  # Not found
				logging.info(source + ": received HTTP Response Code " + str(response.status_code) +
							 " for : <" + str(url) + ">" + self._get_error_message(response))
			else:
				logging.error(source + ": received HTTP Response Code " + str(response.status_code) +
							  " for : <" + str(url) + ">" + self._get_error_message(response))
			self.errors_encountered = self.errors_encountered + 1
			return None
		except requests.exceptions.Timeout:
			# This situation might happen when an underlying object (file system eg) is not responding
			logging.error(source + ": HTTP Request Timed-out: " + " <" + str(url) + ">")
			self.errors_encountered = self.errors_encountered + 1
			return None

	# Returns JSON if success or None
	def _api_put_json(self, url, json_data, source="", report_error = True, reauthenticate=False):
		if reauthenticate:
			self._authenticate()
		try:
			response = self._session.request("PUT", self._endpoint + url, json=json_data, headers=self._headers, timeout=self._api_timeout, verify=self._verify_ssl)
			if response.status_code == 200:
				return response.json()
			elif response.status_code == 400:  # The supplied CatalogEntity object is invalid.
				if report_error:
					logging.error(source + ": received HTTP Response Code 400 for : <" + str(url) + ">" +
							  self._get_error_message(response))
				else:
					logging.debug(source + ": received HTTP Response Code 400 for : <" + str(url) + ">" +
								  self._get_error_message(response))
			elif response.status_code == 401 or response.status_code == 403:
				# Try to reauthenticate since the token might expire
				if reauthenticate:
					return self._api_put_json(url, json_data, source, report_error, False)
				logging.critical(source + ": received HTTP Response Code " + str(response.status_code) +
								 " for : <" + str(url) + ">" + self._get_error_message(response))
				raise RuntimeError(
					"Specified user does not have sufficient priviliges to create objects in the target Dremio Environment.")
			elif response.status_code == 409:  # A catalog entity with the specified path already exists.
				if report_error:
					logging.error(source + ": received HTTP Response Code 409 for : <" + str(url) + ">" +
							  self._get_error_message(response))
				else:
					logging.debug(source + ": received HTTP Response Code 409 for : <" + str(url) + ">" +
								  self._get_error_message(response))
			elif response.status_code == 404:  # Not found
				logging.info(source + ": received HTTP Response Code 404 for : <" + str(url) + ">" +
							 self._get_error_message(response))
			else:
				if report_error:
					logging.error(source + ": received HTTP Response Code " + str(response.status_code) +
							  " for : <" + str(url) + ">" + self._get_error_message(response))
				else:
					logging.debug(source + ": received HTTP Response Code " + str(response.status_code) +
								  " for : <" + str(url) + ">" + self._get_error_message(response))
			self.errors_encountered = self.errors_encountered + 1
			return None
		except requests.exceptions.Timeout:
			# This situation might happen when an underlying object (file system eg) is not responding
			logging.error(source + ": HTTP Request Timed-out: " + " <" + str(url) + ">")
			self.errors_encountered = self.errors_encountered + 1
			return None

	# Returns JSON if success or None
	def _api_delete(self, url, source="", report_error = True, reauthenticate=False):
		if reauthenticate:
			self._authenticate()
		try:
			response = self._session.request("DELETE", self._endpoint + url, headers=self._headers, timeout=self._api_timeout, verify=self._verify_ssl)
			if response.status_code == 200:
				if response.text == '':
					# if text is empty then response.json() fails, e.g. delete reflections return 200 and empty text.
					return None
				return response.json()
			elif response.status_code == 204:
				return None
			elif response.status_code == 400:  # The supplied CatalogEntity object is invalid.
				if report_error:
					logging.error(source + ": received HTTP Response Code 400 for : <" + str(url) + ">" +
								  self._get_error_message(response))
				else:
					logging.debug(source + ": received HTTP Response Code 400 for : <" + str(url) + ">" +
								  self._get_error_message(response))
			elif response.status_code == 401 or response.status_code == 403:
				# Try to reauthenticate since the token might expire
				if not reauthenticate:
					return self._api_delete(url, source, report_error, False)
				logging.critical(source + ": received HTTP Response Code " + str(response.status_code) +
								 " for : <" + str(url) + ">" + self._get_error_message(response))
				raise RuntimeError(
					"Specified user does not have sufficient priviliges to create objects in the target Dremio Environment.")
			elif response.status_code == 409:  # A catalog entity with the specified path already exists.
				if report_error:
					logging.error(source + ": received HTTP Response Code 409 for : <" + str(url) + ">" +
								  self._get_error_message(response))
				else:
					logging.debug(source + ": received HTTP Response Code 409 for : <" + str(url) + ">" +
								  self._get_error_message(response))
			elif response.status_code == 404:  # Not found
				logging.info(source + ": received HTTP Response Code 404 for : <" + str(url) + ">" +
							 self._get_error_message(response))
			else:
				if report_error:
					logging.error(source + ": received HTTP Response Code " + str(response.status_code) +
								  " for : <" + str(url) + ">" + self._get_error_message(response))
				else:
					logging.debug(source + ": received HTTP Response Code " + str(response.status_code) +
								  " for : <" + str(url) + ">" + self._get_error_message(response))
			self.errors_encountered = self.errors_encountered + 1
			return None
		except requests.exceptions.Timeout:
			# This situation might happen when an underlying object (file system eg) is not responding
			logging.error(source + ": HTTP Request Timed-out: " + " <" + str(url) + ">")
			self.errors_encountered = self.errors_encountered + 1
			return None

	def _get_error_message(self, response):
		message = ""
		try:
			if 'errorMessage' in response.json():
				message = message + " errorMessage: " + str(response.json()['errorMessage'])
			if 'moreInfo' in response.json():
				message = message + " moreInfo: " + str(response.json()['moreInfo'])
		except:
			message = message + " content: " + str(response.content)
		return message

	def _encode_http_param(self, path):
		if sys.version_info.major > 2:
			# handle spaces in non-promoted source or folder paths (want %20 for Dremio URLs rather than +)
			return urllib.parse.quote_plus(urllib.parse.quote(path), safe='%')
		else:
			return urllib.quote_plus(path)
