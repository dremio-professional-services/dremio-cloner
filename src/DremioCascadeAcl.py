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


from Dremio import Dremio
from DremioData import DremioData
from DremioClonerConfig import DremioClonerConfig
from DremioClonerUtils import DremioClonerUtils
from DremioClonerLogger import DremioClonerLogger
from DremioClonerFilter import DremioClonerFilter
import json


class DremioCascadeAcl:

	# Dremio Cloner Config, Logger, Utils
	_config = None
	_logger = None
	_utils = None
	_filter = None

	# Dremio Environment to write to
	_dremio_env = None

	# List of PDS for processing
	_pds_list = None

	_source_list = []

	def __init__(self, dremio, config):
		self._config = config
		self._dremio_env = dremio
		self._logger = DremioClonerLogger(self._config.max_errors, self._config.logging_verbose)
		self._utils = DremioClonerUtils(config)
		self._filter = DremioClonerFilter(config)

	def cascade_acl(self):
		if not self._config.pds_list_useapi:
			# Retrieve list of filtered sources first as it is required for pds_list
			containers = self._dremio_env.list_catalog()['data']
			for container in containers:
				if container['containerType'] == "SOURCE":
					if self._filter.match_source_filter(container):
						if 'id' not in container:
							self._logger.error("cascade_acl: bad data, skipping entity: " + self._utils.get_entity_desc(container))
							continue
						entity = self._dremio_env.get_catalog_entity_by_id(container['id'])
						if entity is None:
							self._logger.error("cascade_acl: error reading entity for container: " + self._utils.get_entity_desc(container))
							continue
						# Re-validate the filter with entity since there is more details in entity
						if self._filter.match_source_filter(entity):
							self._source_list.append(entity)
			# Retrieve list of filtered PDS
			self._pds_list = self._dremio_env.list_pds(self._source_list, self._config.source_folder_filter,
													   self._config.source_folder_filter_paths, self._config.source_folder_exclude_filter,
												   	   self._config.pds_filter, self._config.pds_exclude_filter)
			self._logger.info("cascade_acl: Not using API for PDS retrieval. Filtered PDS are NOT reported in the log.")
		# Process ACLs
		containers = self._dremio_env.list_catalog()['data']
		for container in containers:
			self._logger.debug("cascade_acl: processing container " + self._utils.get_entity_desc(container))
			if container['containerType'] == "SPACE" and self._filter.match_space_filter(container):
				self._process_space(container)
			elif container['containerType'] == "SOURCE" and self._filter.match_source_filter(container):
				self._process_source(container)

	def _process_space(self, space):
		entity = self._get_entity_definition(space)
		if entity is None:
			self._logger.error("_process_space: error reading entity for container: " + self._utils.get_entity_desc(space))
		else:
			if self._config.space_cascade_acl_origin_override_object is None:
				# Use Space ACL as an 'origin'
				self._logger.info("_process_space: SPACE: '" + str(space['path']) + "' will be used as an ACL Origin for its children FOLDERs and VDSs.")
				acl = self._get_acl(entity)
			else:
				# Use ACL from a configured object
				acl_entity = self._dremio_env.get_catalog_entity_by_path(self._config.space_cascade_acl_origin_override_object)
				if acl_entity is None:
					self._logger.error("_process_space: error reading origin entity for path: " + str(self._config.space_cascade_acl_origin_override_object))
					return
				self._logger.info("_process_space: SPACE: '" + str(space['path']) + "' Using override origin instead as an ACL Origin for its children FOLDERs and VDSs.")
				acl = self._get_acl(acl_entity)
			self._process_space_children(entity, acl)

	def _process_source(self, source):
		entity = self._get_entity_definition(source)
		if entity is None:
			self._logger.error("_process_source: error reading entity for container: " + self._utils.get_entity_desc(source))
		else:
			if self._config.source_cascade_acl_origin_override_object is None:
				# Use Source ACL as an 'origin'
				self._logger.info("_process_source: SOURCE: '" + str(source['path']) + "' will be used as an ACL Origin for its children PDSs.")
				acl = self._get_acl(entity)
			else:
				# Use ACL from a configured object
				acl_entity = self._dremio_env.get_catalog_entity_by_path(self._config.source_cascade_acl_origin_override_object)
				if acl_entity is None:
					self._logger.error("_process_source: error reading origin entity for path: " + str(self._config.source_cascade_acl_origin_override_object))
					return
				self._logger.info("_process_source: SOURCE: '" + str(source['path']) + "' Using override origin instead as an ACL Origin for its children PDSs.")
				acl = self._get_acl(acl_entity)
			# Process PDSs
			if self._config.pds_list_useapi:
				self._process_source_children(entity, acl)
			else:
				for pds in self._pds_list:
					# Does the PDS belong to the current Source
					if pds['path'][0] == source['path'][0]:
						self._logger.debug("_process_source: pds: " + self._utils.get_entity_desc(pds))
						if self._filter.match_pds_filter(pds):
							self._logger.debug("_process_source_children: applying ACL to PDS: " + self._utils.get_entity_desc(pds))
							self._apply_acl(pds, acl)

	def _process_source_children(self, parent_entity, acl):
		# This is a recursive function
		if 'children' not in parent_entity:
			return
		if 'entityType' not in parent_entity:
			self._logger.error("_process_source_children: bad data, skipping entity: " + self._utils.get_entity_desc(parent_entity))
			return
		self._logger.debug("_process_source_children: processing parent entity '" + self._utils.get_entity_desc(parent_entity) + "'")
		for child in parent_entity['children']:
			child_entity = self._get_entity_definition(child)
			if child_entity is None:
				self._logger.error("_process_source_children: error reading entity for: " + self._utils.get_entity_desc(child))
			elif child['type'] == "DATASET":
				if self._filter.match_pds_filter(child_entity):
					self._logger.debug("_process_source_children: applying ACL to PDS: " + self._utils.get_entity_desc(child_entity))
					self._apply_acl(child_entity, acl)
				else:
					self._logger.info("_process_source_children: skipping PDS: " + str(child_entity['path']) + "as per filter configuration")
			elif child['type'] == "FILE":
				self._logger.info("_process_source_children: skipping FILE: " + self._utils.get_entity_desc(child_entity))
			elif 'containerType' in child and child['containerType'] == "FOLDER":
				if self._filter.match_source_folder_filter(child_entity):
					self._process_source_children(child_entity, acl)
				else:
					self._logger.info("_process_source_children: skipping FOLDER: " + str(child_entity['path']) + "as per filter configuration")

	def _process_space_children(self, parent_entity, acl):
		# This is a recursive function
		if 'children' not in parent_entity:
			return
		if 'entityType' not in parent_entity:
			self._logger.error("_process_space_children: bad data, skipping entity: " + self._utils.get_entity_desc(parent_entity))
			return
		self._logger.debug("_process_space_children: processing parent entity '" + self._utils.get_entity_desc(parent_entity) + "'")
		for child in parent_entity['children']:
			child_entity = self._get_entity_definition(child)
			if child_entity is None:
				self._logger.error("_process_space_children: error reading entity for: " + self._utils.get_entity_desc(child))
			if child['type'] == "DATASET":
				if self._filter.match_vds_filter(child_entity):
					self._logger.debug("_process_space_children: applying ACL to VDS: " + self._utils.get_entity_desc(child_entity))
					self._apply_acl(child_entity, acl)
				else:
					self._logger.info("_process_space_children: skipping VDS: " + self._utils.get_entity_desc(child_entity))
			elif child['containerType'] == "FOLDER":
				if self._filter.match_space_folder_filter(child_entity):
					if self._filter.match_space_folder_cascade_acl_origin_filter(child_entity):
						self._logger.info("_process_space_children: FOLDER: " + str(child_entity['path']) + " will be used as an ACL Origin for its children.")
						self._process_space_children(child_entity, self._get_acl(child_entity))
					else:
						self._logger.info("_process_space_children: applying ACL to FOLDER: " + self._utils.get_entity_desc(child_entity))
						self._apply_acl(child_entity, acl)
						self._process_space_children(child_entity, acl)
				else:
					self._logger.info("_process_space_children: skipping FOLDER: " + self._utils.get_entity_desc(child_entity))
					self._process_space_children(child_entity, acl)

	def _get_entity_definition(self, src):
		if 'id' not in src:
			self._logger.error("_read_entity_definition: bad data, skipping entity: " + self._utils.get_entity_desc(src))
			return None
		else:
			entity = self._dremio_env.get_catalog_entity_by_id(src['id'])
			if entity is None:
				self._logger.error("_read_entity_definition: cannot retrieve entity for id: " + src['id'])
			return entity

	def _get_acl(self, entity):
		if 'accessControlList' in entity:
			return entity['accessControlList']
		else:
			self._logger.fatal("ACL is not defined for " + self._utils.get_entity_desc(entity))
			return None

	def _apply_acl(self, entity, acl):
		# Clear the current ACL definition
		if 'accessControlList' not in entity:
			entity['accessControlList'] = {"version": "0"}
		if 'users' in entity['accessControlList']:
			entity['accessControlList'].pop('users')
		if 'groups' in entity['accessControlList']:
			entity['accessControlList'].pop('groups')
		# Apply ACL to entity
		if 'users' in acl:
			entity['accessControlList']['users'] = acl['users']
		if 'groups' in acl:
			entity['accessControlList']['groups'] = acl['groups']
		if self._config.dry_run:
			self._logger.warn("_apply_acl: Dry Run, NOT Updating entity: " + self._utils.get_entity_desc(entity))
			return False
		self._logger.info("_apply_acl: updating entity: " + self._utils.get_entity_desc(entity))
		updated_entity = self._dremio_env.update_catalog_entity(entity['id'], entity, self._config.dry_run)
		if updated_entity is None:
			self._logger.error("_apply_acl: Error updating entity: " + self._utils.get_entity_desc(entity))
			return False
		return True

	def get_errors_count(self):
		return self._logger.errors_encountered