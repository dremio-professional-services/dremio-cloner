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
import parse_sql


###
# This class uses DremioData object to update Dremio environment.
###
class DremioWriter:

	# Dremio Cloner Config, Utils, ...
	_config = None
	_utils = None
	_logger = None
	_filter = None

	# Dremio Environment to write to
	_dremio_env = None

	# Dremio Data to write
	_d = None

	# VDS list grouped by hierarchy
	_vds_hierarchy = []
	_hierarchy_depth = 0
	_unresolved_vds = []

	# Referenced Users, Groups and Roles in the target environment
	_target_dremio_users = []
	_target_dremio_groups = []
	_target_dremio_roles = []
	# Dremio target folders
	# This is required for CI/CD use cases to compare folders from JSON with destination to be able replicate deletion
	_target_folders = []
	# Dremio target vds list
	# This is required for CI/CD use cases to compare vds list from JSON with destination to be able replicate deletion
	_target_vds_list = []
	# Dremio target reflections
	_target_reflections = []
	_target_reflections_vds_filtered = []

	# Dry run collections
	_dry_run_processed_vds_list = []
	_dry_run_processed_pds_list = []

	def __init__(self, target_dremio, dremio_data, config):
		self._config = config
		self._dremio_env = target_dremio
		self._d = dremio_data
		self._logger = DremioClonerLogger(self._config.max_errors, self._config.logging_verbose)
		self._filter = DremioClonerFilter(config)
		self._utils = DremioClonerUtils(config)

	def write_dremio_environment(self):
		self._retrieve_users_groups()
		if self._config.acl_transformation != {} and self._d.referenced_users == [] and self._d.referenced_groups == [] and self._d.referenced_roles == []:
			self._logger.warn("ACL Transformation has been defined while Referenced Users and Referenced Groups/Roles are not present in the Source Dremio Data.")

		if self._config.reflection_process_mode != 'skip':
			# Even when filtering out unnecessary reflections the behavior should be exactly the same.
			self._read_target_reflections()

		if self._config.reflection_process_mode == 'create_overwrite_delete' or self._config.vds_process_mode == 'create_overwrite_delete' or self._config.folder_process_mode == 'create_overwrite_delete':
			self._read_target_folders_and_vds_list()

		if self._config.reflection_process_mode == 'create_overwrite_delete':
			unmatched_target_reflections = self._find_deletable_reflections()
			for reflection in unmatched_target_reflections:
				self._logger.info("write_dremio_environment: Deleting reflection " + "/".join(reflection['path']) + " -> " + reflection['name'])
				self._dremio_env.delete_reflection(reflection['id'], dry_run = self._config.dry_run, report_error=True)
		if self._config.vds_process_mode == 'create_overwrite_delete':
			unmatched_target_vds = self._find_deletable_vds()
			for vds in unmatched_target_vds:
				self._logger.info("write_dremio_environment: Deleting VDS " + "/".join(vds['path']))
				self._dremio_env.delete_catalog_entity(vds['id'], dry_run = self._config.dry_run, report_error=True)
		if self._config.folder_process_mode == 'create_overwrite_delete':
			unmatched_target_folders = self._find_deletable_folders()
			for folder in unmatched_target_folders:
				self._logger.info("write_dremio_environment: Deleting folder " + "/".join(folder['path']))
				self._dremio_env.delete_catalog_entity(folder['id'], dry_run = self._config.dry_run, report_error=True)

		if self._config.source_process_mode == 'skip':
			# even though they are being skipped, we still need to map source names in case other objects depend on them
			for source in self._d.sources:
				self._map_source(source)
			self._logger.info("write_dremio_environment: Skipping source processing due to configuration source.process_mode=skip.")
		else:
			for source in self._d.sources:
				self._write_source(source, self._config.source_process_mode, self._config.source_ignore_missing_acl_user, self._config.source_ignore_missing_acl_group)
		if self._config.pds_process_mode == 'skip':
			# even though they are being skipped, we still need to map source names that appear in PDSs in case VDSs depend on them
			for pds in self._d.pds_list:
				self._map_pds_source(pds)
			self._logger.info("write_dremio_environment: Skipping source PDS processing due to configuration source.pds.process_mode=skip.")
		else:
			for pds in self._d.pds_list:
				self._write_pds(pds, self._config.pds_process_mode, self._config.pds_ignore_missing_acl_user, self._config.pds_ignore_missing_acl_group)
		if self._config.space_process_mode == 'skip':
			self._logger.info("write_dremio_environment: Skipping space processing due to configuration space.process_mode=skip.")
		else:
			for space in self._d.spaces:
				self._write_space(space, self._config.space_process_mode, self._config.space_ignore_missing_acl_user, self._config.space_ignore_missing_acl_group)
		if self._config.folder_process_mode == 'skip':
			self._logger.info("write_dremio_environment: Skipping folder processing due to configuration folder.process_mode=skip.")
		else:
			for folder in self._d.folders:
				self._write_folder(folder, self._config.folder_process_mode, self._config.folder_ignore_missing_acl_user, self._config.folder_ignore_missing_acl_group)
		if self._config.vds_process_mode == 'skip':
			self._logger.info("write_dremio_environment: Skipping VDS processing due to configuration vds.process_mode=skip.")
		else:
			self._map_vds_source()
			self._order_vds(0)
			self._write_vds_hierarchy()
			self._write_remainder_vds()
		if self._config.reflection_process_mode == 'skip':
			self._logger.info("write_dremio_environment: Skipping reflection processing due to configuration reflection.process_mode=skip.")
		else:
			for reflection in self._d.reflections:
				# if the reflection id include list is not empty, then skip reflection ids that are not in the list
				if len(self._config.reflection_id_include_list) > 0:
					if reflection['id'] not in self._config.reflection_id_include_list:
						self._logger.debug(
							"write_dremio_environment: skipping reflection id " + reflection['id'] + ", not in include list")
						continue
				self._write_reflection(reflection, self._config.reflection_process_mode)
		if self._config.reflection_refresh_mode != 'refresh':
			self._logger.info("write_dremio_environment: Skipping reflection refresh due to configuration reflection.refresh_mode=skip.")
		else:
			for pds in self._d.pds_list:
				self._dremio_env.refresh_reflections_by_pds_path(self._utils.normalize_path(pds['path']), self._config.dry_run)
		if self._config.wiki_process_mode == 'skip':
			self._logger.info("write_dremio_environment: Skipping wiki processing due to configuration wiki.process_mode=skip.")
		else:
			for wiki in self._d.wikis:
				self._write_wiki(wiki, self._config.wiki_process_mode)
		if self._config.tag_process_mode == 'skip':
			self._logger.info("write_dremio_environment: Skipping tag processing due to configuration tag.process_mode=skip.")
		else:
			for tags in self._d.tags:
				self._write_tags(tags, self._config.tag_process_mode)

	def _find_deletable_folders(self):
		# Find unmatched reflections in target system
		unmatched_folders = []
		for target_folder in self._target_folders:
			found = False
			for applied_folder in self._d.folders:
				if target_folder['path'] == applied_folder['path']:
					found = True
					break
			if not found:
				unmatched_folders.append(target_folder)
		return unmatched_folders


	def _find_deletable_vds(self):
		# Find unmatched reflections in target system
		unmatched_vds = []
		for target_vds in self._target_vds_list:
			found = False
			for applied_vds in self._d.vds_list:
				if target_vds['path'] == applied_vds['path']:
					found = True
					break
			if not found:
				unmatched_vds.append(target_vds)
		return unmatched_vds

	def _find_deletable_reflections(self):
		# Find unmatched reflections in target system
		unmatched_reflections = []
		for target_reflection in self._target_reflections_vds_filtered:
			found = False
			for applied_reflection in self._d.reflections:
				if target_reflection['path'] == applied_reflection['path'] and target_reflection['name'] == \
						applied_reflection['name']:
					found = True
					break
			if not found:
				unmatched_reflections.append(target_reflection)
		return unmatched_reflections

	def _is_reflection_in_vds_list(self, reflection):
		for vds in self._target_vds_list:
			if vds['id'] == reflection['datasetId']:
				return True
		return False

	def _read_target_reflections(self):
		self._logger.debug("_read_target_reflections")
		reflections = self._dremio_env.list_reflections()
		self._target_reflections = reflections['data'] if reflections is not None else []

	def _read_target_folders_and_vds_list(self):
		containers = self._dremio_env.list_catalog()['data']
		for container in containers:
			self._logger.debug("_read_destination_folders_and_vds_list: processing container " + self._utils.get_entity_desc(container))
			self._process_container(container)
		for reflection in self._target_reflections:
			if self._is_reflection_in_vds_list(reflection):
				reflection_dataset = self._dremio_env.get_catalog_entity_by_id(reflection['datasetId'])
				if reflection_dataset is None:
					self._logger.debug("_read_reflections: error processing reflection, cannot get path for dataset: " + reflection['datasetId'])
					continue
				reflection_path = reflection_dataset['path']
				reflection["path"] = reflection_path
				self._target_reflections_vds_filtered.append(reflection)

	# Identify a container and delegate processing
	def _process_container(self, container):
		self._logger.debug("_process_container: " + self._utils.get_entity_desc(container))
		if container['containerType'] == "SPACE":
			self._read_space(container)
		else:
			self._logger.debug("_process_container: skipping " + self._utils.get_entity_desc(container))

	def _read_space(self, container):
		self._logger.debug("_read_space: processing container: " + self._utils.get_entity_desc(container))
		if self._filter.match_space_filter(container):
			entity = self._get_entity_definition_by_id(container)
			if entity is not None:
				self._logger.debug("_read_space: " + self._utils.get_entity_desc(container))
				self._read_space_children(entity)
			else:
				self._logger.error("_read_space: error reading entity for container: " + self._utils.get_entity_desc(container))

	# Helper method, used by most read* methods
	def _get_entity_definition_by_id(self, src):
		self._logger.debug("_get_entity_definition_by_id: processing src: " + self._utils.get_entity_desc(src))
		if 'id' not in src:
			self._logger.error("_read_entity_definition: bad data, skipping entity: " + self._utils.get_entity_desc(src))
			return None
		else:
			entity = self._dremio_env.get_catalog_entity_by_id(src['id'])
			if entity is None:
				self._logger.error("_read_entity_definition: cannot retrieve entity for id: " + src['id'])
			return entity

	def _read_space_children(self, parent_entity):
		self._logger.debug("_read_space_children: processing parent_entity: " + self._utils.get_entity_desc(parent_entity))
		if 'entityType' not in parent_entity:
			self._logger.error("_read_space_children: bad data, skipping entity: " + self._utils.get_entity_desc(parent_entity))
			return
		for child in parent_entity['children']:
			if child['type'] == "DATASET":
				self._read_dataset(child)
			elif child['type'] == "FILE":
				continue
			elif child['containerType'] == "FOLDER":
				self._read_space_folder(child)
			else:
				self._logger.error("_read_space_children: not supported entity type " + child['type'])

	def _read_dataset(self, dataset):
		self._logger.debug("_read_dataset: processing dataset: " + self._utils.get_entity_desc(dataset))
		entity = self._get_entity_definition_by_id(dataset)
		if entity is not None:
			self._logger.debug("_read_dataset: " + dataset['datasetType'] + " : " + self._utils.get_entity_desc(dataset))
			if dataset['datasetType'] == "VIRTUAL":
				tags = self._dremio_env.get_catalog_tags(entity['id'])
				if self._filter.match_vds_filter(dataset, tags=tags):
					self._target_vds_list.append(entity)
			else:
				self._logger.debug("_read_dataset: Skipping " + dataset['datasetType'] + " for " + self._utils.get_entity_desc(dataset) + ".")

	def _read_space_folder(self, folder):
		self._logger.debug("_read_space_folder: processing folder: " + self._utils.get_entity_desc(folder))
		entity = self._get_entity_definition_by_id(folder)
		if entity is None:
			self._logger.error("_read_space_folder: error reading entity for folder: " + self._utils.get_entity_desc(folder))
			return
		if self._filter.match_space_folder_filter(folder):
			self._logger.debug("_read_space_folder: " + self._utils.get_entity_desc(folder))
			self._target_folders.append(entity)
			# Validate all parent folders in the path have been saved already
			folder_path = entity['path']
			for i in range(1, len(folder_path)-1):
				folderSaved = False
				for item in self._target_folders:
					if item['path'][-1] == folder_path[i]:
						folderSaved = True
				if not folderSaved:
					parent_entity = self._get_entity_definition_by_path(folder_path[0:i+1])
					self._target_folders.append(parent_entity)
		self._read_space_children(entity)

	def _get_entity_definition_by_path(self, path):
		self._logger.debug("_get_entity_definition_by_path: processing path: " + str(path))
		path = self._utils.normalize_path(path)
		entity = self._dremio_env.get_catalog_entity_by_path(path)
		if entity is None:
			self._logger.error("_read_entity_definition: cannot retrieve entity for path: " + str(path))
		return entity

	def _write_space(self, entity, process_mode, ignore_missing_acl_user_flag, ignore_missing_acl_group_flag):
		if self._filter.match_space_filter(entity):
			self._logger.debug("_write_space: processing entity: " + self._utils.get_entity_desc(entity))
			return self._write_entity(entity, process_mode, ignore_missing_acl_user_flag, ignore_missing_acl_group_flag)
		else:
			self._logger.debug("_write_space: skipping entity: " + self._utils.get_entity_desc(entity))
			return None

	def _write_source(self, entity, process_mode, ignore_missing_acl_user_flag, ignore_missing_acl_group_flag):
		if self._filter.match_source_filter(entity):
			self._logger.debug("_write_source: processing entity: " + self._utils.get_entity_desc(entity))
			self._map_source(entity)
			return self._write_entity(entity, process_mode, ignore_missing_acl_user_flag, ignore_missing_acl_group_flag)
		else:
			self._logger.debug("_write_source: skipping entity: " + self._utils.get_entity_desc(entity))
			return None

	def _write_folder(self, entity, process_mode, ignore_missing_acl_user_flag, ignore_missing_acl_group_flag):
		# Drop ACL for HOME folders
		if entity['path'][0][:1] == '@' and 'accessControlList' in entity:
			entity.pop("accessControlList")
		# Do not apply space.folder.filter to Home folders
		if entity['path'][0][:1] == '@' or self._filter.match_space_folder_filter(entity):
			self._logger.debug("_write_folder: processing entity: " + self._utils.get_entity_desc(entity))
			return self._write_entity(entity, process_mode, ignore_missing_acl_user_flag, ignore_missing_acl_group_flag)
		else:
			self._logger.debug("_write_folder: skipping entity: " + self._utils.get_entity_desc(entity))
			return None

	def _map_source(self, entity):
		# see if the current source name is being mapped to a different name in source_transformation
		for map in self._config.source_transformation:
			if entity['name'] == map['source-source-name']:
				self._logger.info("_map_source: mapping source name " + entity['name'] + " into " + map['target-source-name'])
				entity['name'] = map['target-source-name']
				break

	def _map_pds_source(self, entity):
		# see if the PDS contains a source name that is being mapped to a different name in source_transformation
		for map in self._config.source_transformation:
			if entity['path'][0] == map['source-source-name']:
				self._logger.info("_map_pds_source: mapping pds source name " + entity['path'][0] + " into " + map['target-source-name'])
				entity['path'][0] = map['target-source-name']
				if 'format' in entity and 'fullPath' in entity['format']:
					entity['format']['fullPath'][0] = map['target-source-name']
				break

	def _map_vds_source(self):
		for map in self._config.source_transformation:
			# see if the VDS definition contains a source name that is mapped to a different name according to the source_transformation
			for vds in self._d.vds_list:
				if "sqlContext" in vds and map['source-source-name'] == vds["sqlContext"][0]:
					vds["sqlContext"][0] = map['target-source-name']
					self._logger.info("_map_vds_source: updating context for " + self._utils.get_entity_desc(vds) + " with target source name: " + vds["sqlContext"][0])
				if map['source-source-name'] in vds["sql"]:
					# If the source-source-name is not quoted in the SQL text then add quotes around target-source-name.
					# This will avoid any issues with special characters in the target-source-name name
					if (map['source-source-name'] + ".") in vds["sql"]:
						vds["sql"] = vds["sql"].replace(map['source-source-name'], '"' + map['target-source-name'] + '"')
					else:
						vds["sql"] = vds["sql"].replace(map['source-source-name'], map['target-source-name'])
					self._logger.info("_map_vds_source: updating sql for " + self._utils.get_entity_desc(vds) + " with target source name: " + map['target-source-name'])

	def _map_wiki_source(self, wiki):
		# see if the wiki path contains a source name that is being mapped to a different name in source_transformation
		for map in self._config.source_transformation:
			if wiki['path'][0] == map['source-source-name']:
				self._logger.info("_map_wiki_source: mapping wiki source name in path " + wiki['path'][0] + " into " + map['target-source-name'])
				wiki['path'][0] = map['target-source-name'].replace(" ", "%20")
				break

	def _map_reflection_source(self, reflection):
		# see if the reflection path contains a source name that is being mapped to a different name in source_transformation
		for map in self._config.source_transformation:
			if reflection['path'][0] == map['source-source-name']:
				self._logger.info("_map_reflection_source: mapping reflection source name in path " + reflection['path'][0] + " into " + map['target-source-name'])
				reflection['path'][0] = map['target-source-name'].replace(" ", "%20")
				break

	def _map_tag_source(self, tag):
		# see if the tag path contains a source name that is being mapped to a different name in source_transformation
		for map in self._config.source_transformation:
			if tag['path'][0] == map['source-source-name']:
				self._logger.info("_map_tag_source: mapping tag source name in path " + tag['path'][0] + " into " + map['target-source-name'])
				tag['path'][0] = map['target-source-name'].replace(" ", "%20")
				break

	def _retrieve_users_groups(self):
		for user in self._d.referenced_users:
			target_user = self._dremio_env.get_user_by_name(user['name'])
			if target_user is not None:
				self._target_dremio_users.append(target_user)
			else:
				self._logger.error("_retrieve_users_groups: Unable to resolve user in target Dremio environment: " + str(user['name']))
		for group in self._d.referenced_groups:
			target_group = self._dremio_env.get_group_by_name(group['name'])
			if target_group is not None:
				self._target_dremio_groups.append(target_group)
			else:
				self._logger.error("_retrieve_users_groups: Unable to resolve group in target Dremio environment: " + str(group['name']))
		for role in self._d.referenced_roles:
			target_role = self._dremio_env.get_role_by_name(role['name'])
			if target_role is not None:
				self._target_dremio_roles.append(target_role)
			else:
				self._logger.error("_retrieve_users_groups: Unable to resolve role in target Dremio environment: " + str(role['name']))
		# Retrieve acl transformation target users and groups/roles
		for item in self._config.acl_transformation:
			if 'user' in item['target']:
				user = self._dremio_env.get_user_by_name(item['target']['user'])
				if user is not None:
					# dont worry about dups
					self._target_dremio_users.append(user)
				else:
					self._logger.error("_retrieve_users_groups: Unable to resolve ACL_TRANSFORMATION user in target Dremio environment: " + str(item['target']['user']))
			if 'group' in item['target']:
				group = self._dremio_env.get_group_by_name(item['target']['group'])
				if group is not None:
					# dont worry about dups
					self._target_dremio_groups.append(group)
				else:
					self._logger.error("_retrieve_users_groups: Unable to resolve ACL_TRANSFORMATION group in target Dremio environment: " + str(item['target']['group']))
			if 'role' in item['target']:
				role = self._dremio_env.get_role_by_name(item['target']['role'])
				if role is not None:
					# dont worry about dups
					self._target_dremio_roles.append(role)
				else:
					self._logger.error("_retrieve_users_groups: Unable to resolve ACL_TRANSFORMATION role in target Dremio environment: " + str(item['target']['role']))

	def _write_vds_hierarchy(self):
		for level in range(0, self._hierarchy_depth + 1): # fix 20210319: need +1 here to ensure every element in the vds hierarchy gets processed
			for item in self._vds_hierarchy:
				if item[0] == level:
					vds = item[1]
					if self._filter.match_vds_filter(vds):
						self._logger.debug("_write_vds_hierarchy: writing vds: " + self._utils.get_entity_desc(vds))
						self._write_entity(vds, self._config.vds_process_mode, self._config.vds_ignore_missing_acl_user, self._config.vds_ignore_missing_acl_group)

	def _write_remainder_vds(self):
		if not self._d.vds_list and not self._unresolved_vds:
			return
		else:
			self._logger.info("_write_remainder_vds: Attempt processing VDSs that failed ordering.")
		# Attempt to process max_hierarchy_depth
		for h in range(1, self._config.vds_max_hierarchy_depth):
			# These are VDSs that have all dependencies validated but could not be placed in the hierarchy
			# Go with decreasing index so we can remove VDS from the list
			for i in range(len(self._d.vds_list) - 1, -1, -1):
				vds = self._d.vds_list[i]
				if self._filter.match_vds_filter(vds):
					self._logger.debug("_write_remainder_vds: writing vds: " + self._utils.get_entity_desc(vds))
					if self._write_entity(vds, self._config.vds_process_mode, self._config.vds_ignore_missing_acl_user, self._config.vds_ignore_missing_acl_group, False):
						self._d.vds_list.remove(vds)
				else:
					self._d.vds_list.remove(vds)
			# Iterate through the remainder of unresolved VDS in the list
			# Go with decreasing index so we can remove VDS from the list
			for i in range(len(self._unresolved_vds) - 1, -1, -1):
				vds = self._unresolved_vds[i]
				if self._filter.match_vds_filter(vds):
					self._logger.debug("_write_remainder_vds: writing vds: " + self._utils.get_entity_desc(vds))
					if self._write_entity(vds, self._config.vds_process_mode, self._config.vds_ignore_missing_acl_user, self._config.vds_ignore_missing_acl_group, False):
						self._unresolved_vds.remove(vds)
				else:
					self._unresolved_vds.remove(vds)
		if self._d.vds_list != [] or self._unresolved_vds != []:
			self._logger.warn('_write_remainder_vds: After attempting to process VDSs that failed ordering, the following VDSs still failed. Set log level to DEBUG and see prior error messages for more information.')
			for vds in self._d.vds_list:
				self._logger.error("Failed VDS: " + str(vds['path']))
			for vds in self._unresolved_vds:
				self._logger.error("Failed VDS: " + str(vds['path']))
		else:
			self._logger.warn("_write_remainder_vds: Finished processing VDSs that failed ordering. All VDSs have been successfuly processed.")


	def _write_user(self):
		if self._config.user_process_mode == 'skip':
			self._logger.info("_write_user: Skipping user processing due to configuration user.process_mode=skip.")
			return True
		self._logger.error("_write_user: Cannot create users. API is not implemented.")

	def _write_entity(self, entity, process_mode, ignore_missing_acl_user_flag, ignore_missing_acl_group_flag, report_error = True):
		self._logger.debug("_write_entity: processing entity: " + self._utils.get_entity_desc(entity))
		# Clean up the definition
		if 'id' in entity:
			entity.pop("id")
		if 'tag' in entity:
			entity.pop("tag")
		if 'children'in entity:
			entity.pop("children")
		if 'createdAt' in entity:
			entity.pop("createdAt")
		# Process ACL as needed
		if not self._process_acl(entity, ignore_missing_acl_user_flag, ignore_missing_acl_group_flag):
			# Skip this entity due to ACL processing errors
			self._logger.info("_write_entity: Skipping entity due to ignore_missing_acl_user_flag, ignore_missing_acl_group_flag: " + self._utils.get_entity_desc(entity))
			return False
		# Check if the entity already exists
		existing_entity = self._read_entity_definition(entity)
		# Ensure we have not received FOLDER instead of DATASET. See DX-16666
		if existing_entity is not None and 'entityType' in entity and \
				'entityType' in existing_entity and entity['entityType'] != existing_entity['entityType']:
			existing_entity = None
		if existing_entity is None:  # Need to create new entity
			if process_mode == 'update_only':
				self._logger.info("_write_entity: Skipping entity creation due to configuration process_mode=update_only. " + self._utils.get_entity_desc(entity))
				return True
			# Reset version for proper concurrency
			if 'accessControlList' in entity:
				entity['accessControlList']['version'] = "0"
			if self._config.dry_run:
				self._logger.warn("_write_entity: Dry Run, NOT Creating entity: " + self._utils.get_entity_desc(entity))
				# For dry run, keep it in a seperate collection to suppress errors
				if self._utils.is_vds(entity):
					self._dry_run_processed_vds_list.append(entity)
				return False
			# Note for the CE target env, the ACL should have been popped out by _process_acl
			new_entity = self._dremio_env.create_catalog_entity(entity, self._config.dry_run)
			if new_entity is None:
				if report_error:
					self._logger.error("_write_entity: could not create entity: " + self._utils.get_entity_desc(entity))
				else:
					self._logger.debug("_write_entity: could not create entity: " + self._utils.get_entity_desc(entity))
				return False
		else:  # Entity already exists in the target environment
			if process_mode == 'create_only':
				self._logger.info("_write_entity: Found existing entity and process_mode is set to create_only. Skipping entity: " + self._utils.get_entity_desc(entity))
				return True
			self._logger.debug("_write_entity: Overwriting entity definition as per process_mode configuration : " + self._utils.get_entity_desc(entity))
			# Update entity definition with data from entity existing in the target environment
			entity['id'] = existing_entity['id']
			entity['tag'] = existing_entity['tag']  # Tag from the entity existing in the target environment required for proper concurrency control
			# Update ACL version for proper concurrency control, but do not use ACL if not really needed as HOME folders are not allowed to have ACL
			if ('path' in entity and entity['path'][0][:1] == '@') or ('name' in entity and entity['name'][:1] == '@'): 
				if 'accessControlList' in entity:
					entity.pop('accessControlList')
			else:
				# Note for the CE target env, the ACL should have been popped out by _process_acl
				if not self._config.target_ce:
					if 'accessControlList' not in entity:
						entity['accessControlList'] = {"version": "0"}
					# API changed behavior around version 4 and may not return version attribute for ACL.
					if 'accessControlList' in existing_entity and 'version' in existing_entity['accessControlList']:
						entity['accessControlList']['version'] = existing_entity['accessControlList']['version']
			if self._config.dry_run:
				self._logger.warn("_write_entity: Dry Run, NOT Updating entity: " + self._utils.get_entity_desc(entity))
				return False
			updated_entity = self._dremio_env.update_catalog_entity(entity['id'], entity, self._config.dry_run, report_error)
			if updated_entity is None:
				if report_error:
					self._logger.error("_write_entity: Error updating entity: " + self._utils.get_entity_desc(entity))
				else:
					self._logger.debug("_write_entity: Error updating entity: " + self._utils.get_entity_desc(entity))
				return False
		return True

	def _write_pds(self, entity, process_mode, ignore_missing_acl_user_flag, ignore_missing_acl_group_flag):
		self._logger.debug("_write_pds: processing entity: " + self._utils.get_entity_desc(entity))
		if self._filter.match_pds_filter(entity):
			self._map_pds_source(entity)
			existing_entity = self._read_entity_definition(entity)
			if existing_entity is None:
				self._logger.error("_write_pds: Cannot find existing entity for PDS Entity. Either Folder, File, or PDS must exist prior to promoting or updating PDS. Source PDS: " + self._utils.get_entity_desc(entity))
				return False	
			# Check if PDS needs to be promoted first
			if 'type' not in existing_entity or existing_entity['type'] != 'PHYSICAL_DATASET':
				self._promote_pds(entity, ignore_missing_acl_user_flag, ignore_missing_acl_group_flag)
			# Update PDS now
			self._logger.debug("_write_pds: writing pds: " + self._utils.get_entity_desc(entity))
			self._write_entity(entity, process_mode, ignore_missing_acl_user_flag, ignore_missing_acl_group_flag)
		else:
			return None

	def _promote_pds(self, entity, ignore_missing_acl_user_flag, ignore_missing_acl_group_flag):
		self._logger.debug("_promote_pds: processing entity: " + self._utils.get_entity_desc(entity))
		# Clean up the definition
		if 'id' in entity:
			entity.pop("id")
		if 'tag' in entity:
			entity.pop("tag")
		if 'children'in entity:
			entity.pop("children")
		if 'createdAt' in entity:
			entity.pop("createdAt")
		# Process ACL as needed
		if not self._process_acl(entity, ignore_missing_acl_user_flag, ignore_missing_acl_group_flag):
			# Skip this entity due to ACL processing errors
			self._logger.error("_promote_pds: Skipping PDS due to an error in ACL processing: " + self._utils.get_entity_desc(entity))
			return False
		# Read exisitng folder or file entity
		fs_entity = self._read_entity_definition(entity)
		if fs_entity is None:
			self._logger.error("_promote_pds: Skipping PDS. Cannot find folder or file for PDS Entity: " + self._utils.get_entity_desc(entity))
			return False
		# Add Folder ID to PDS Entity	
		entity['id'] = fs_entity['id']
		if 'accessControlList' in entity: 
			entity.pop('accessControlList')
		if self._config.dry_run:
			self._logger.warn("_promote_pds: Dry Run, NOT promoting pds: " + self._utils.get_entity_desc(entity))
			return True
		self._logger.debug("_promote_pds: promoting pds: " + self._utils.get_entity_desc(entity))
		new_pds_entity = self._dremio_env.promote_pds(entity, self._config.dry_run)
		if new_pds_entity is None:
			self._logger.error("_promote_pds: Error promoting PDS: " + self._utils.get_entity_desc(entity))
			return False
		return True


	def _write_reflection(self, reflection, process_mode):
		self._logger.debug("_write_reflection: processing reflection: " + ((reflection['id'] + " name: " + reflection['name'] + " path: ") if 'id' in reflection else (reflection['name'] + " path: ")) + self._utils.get_entity_desc(reflection))
		# Clean up the definition
		if 'id' in reflection:
			reflection.pop("id")
		if 'tag' in reflection:
			reflection.pop("tag")
		if 'createdAt' in reflection:
			reflection.pop("createdAt")
		if 'updatedAt' in reflection:
			reflection.pop("updatedAt")
		if 'currentSizeBytes' in reflection:
			reflection.pop("currentSizeBytes")
		if 'totalSizeBytes' in reflection:
			reflection.pop("totalSizeBytes")
		if 'status' in reflection:
			reflection.pop("status")
		if 'canView' in reflection:
			reflection.pop("canView")
		if 'canAlter' in reflection:
			reflection.pop("canAlter")
		self._map_reflection_source(reflection)
		reflection_path = reflection['path']
		# Write Reflection
		reflection.pop("path")
		reflected_dataset = self._dremio_env.get_catalog_entity_by_path(self._utils.normalize_path(reflection_path))
		if reflected_dataset is None:
			self._logger.error("_write_reflection: Could not resolve dataset for " + self._utils.get_entity_desc(reflection))
			return None
		# Match filters if requested
		if self._config.reflection_filter_mode == "apply_vds_pds_filter":
			if not self._filter.match_reflection_path(reflection_path, reflected_dataset):
				return False
		reflection['datasetId'] = reflected_dataset['id']
		# Check if the reflection already exists
		existing_reflection = self._find_existing_reflection(reflection, reflected_dataset)
		if existing_reflection is None:  # Need to create new entity
			if process_mode == 'update_only':
				self._logger.info("_write_reflection: Skipping reflection creation due to configuration reflection_process_mode. " + self._utils.get_entity_desc(reflection))
				return None
			if self._config.dry_run:
				self._logger.warn("_write_reflection: Dry Run, NOT Creating reflection: " + self._utils.get_entity_desc(reflection))
				return None
			new_reflection = self._dremio_env.create_reflection(reflection, self._config.dry_run)
			if new_reflection is None:
				self._logger.error("_write_reflection: could not create " + self._utils.get_entity_desc(reflection))
				return None
		else:  # Reflection already exists in the target environment
			if process_mode == 'create_only':
				self._logger.info("_write_reflection: Found existing reflection and reflection_process_mode is set to create_only. Skipping " + self._utils.get_entity_desc(reflection))
				return None
			# make sure there are changes to update as it will invalidate existing reflection data
			if self._is_reflection_equal(existing_reflection, reflection):
				# Nothing to do
				self._logger.debug("_write_reflection: No pending changes. Skipping " + self._utils.get_entity_desc(reflection))
				return None
			if self._config.dry_run:
				self._logger.warn("_write_entity: Dry Run, NOT Updating " + self._utils.get_entity_desc(reflection))
				return False
			self._logger.debug("_write_reflection: Overwriting " + self._utils.get_entity_desc(reflection))
			reflection['tag'] = existing_reflection['tag']
			updated_reflection = self._dremio_env.update_reflection(existing_reflection['id'], reflection, self._config.dry_run)
			if updated_reflection is None:
				self._logger.error("_write_reflection: Error updating " + self._utils.get_entity_desc(reflection))
				return False
		return True

	def _is_reflection_equal(self, existing_reflection, reflection):
		return reflection['type'] == existing_reflection['type'] and \
			   reflection['name'] == existing_reflection['name'] and \
			   ('partitionDistributionStrategy' not in reflection or reflection['partitionDistributionStrategy'] ==
				existing_reflection['partitionDistributionStrategy']) and \
			   ('measureFields' not in reflection or reflection['measureFields'] == existing_reflection[
				   'measureFields']) and \
			   ('dimensionFields' not in reflection or reflection['dimensionFields'] == existing_reflection[
				   'dimensionFields']) and \
			   ('displayFields' not in reflection or reflection['displayFields'] == existing_reflection[
				   'displayFields']) and \
			   ('sortFields' not in reflection or reflection['sortFields'] == existing_reflection['sortFields']) and \
			   ('partitionFields' not in reflection or reflection['partitionFields'] == existing_reflection[
				   'partitionFields']) and \
			   ('distributionFields' not in reflection or reflection['distributionFields'] == existing_reflection[
				   'distributionFields'])

	def _find_existing_reflection(self, reflection, dataset):
		for existing_reflection in self._target_reflections:
			# Match reflections by name
			if reflection['name'] == existing_reflection['name']:
				existing_dataset = self._dremio_env.get_catalog_entity_by_id(existing_reflection['datasetId'])
				# Match reflections by respective dataset's path
				if existing_dataset is not None and existing_dataset['path'] == dataset['path']:
					return existing_reflection
		return None


	def _find_existing_dataset_by_path(self, path):
		return self._dremio_env.get_catalog_entity_by_path(path)


# Searches for Users from entity's ACL in the target environment and either:
	# - removes the user from ACL if not found and ignore_missing_acl_user_flag is set 
	# - returns False if if not found and ignore_missing_acl_user_flag is not set
	# - updates the ACL with userid from the new environment if User found there 
	def _process_acl(self, entity, ignore_missing_acl_user_flag, ignore_missing_acl_group_flag):
		self._logger.debug("_process_acl: processing entity: " + self._utils.get_entity_desc(entity))
		if 'accessControlList' not in entity:
			return True
		if self._config.target_ce:
			entity.pop('accessControlList')
			return True
		acl = entity['accessControlList']
		transformed_acl = {"users": [], "groups": []}
		if 'version' in entity:
			acl.pop('version')
		if acl == {} or ('users' not in acl and 'groups' not in acl and 'roles' not in acl):
			pass
		else:
			if 'users' in acl:
				# Note, taking a copy of the list for proper removal of items
				for user_def in acl['users'][:]:
					new_acl_principal = self._find_matching_principal_for_userid(user_def['id'], user_def['permissions'])
					if new_acl_principal == "REMOVE":
						self._logger.info("_process_acl: Source User " + user_def['id'] + " is removed from ACL definition. " + self._utils.get_entity_desc(entity))
					elif new_acl_principal is None:
						if ignore_missing_acl_user_flag:
							self._logger.warn("_process_acl: Source User " + user_def['id'] + " not found in the target Dremio Environment. User is removed from ACL definition as per ignore_missing_acl_user configuration. " + self._utils.get_entity_desc(entity))
						else:
							self._logger.error("_process_acl: Source User " + user_def['id'] + " not found in the target Dremio Environment. ACL Entry cannot be processed as per ignore_missing_acl_user configuration. " + self._utils.get_entity_desc(entity))
					elif "user" in new_acl_principal:
						transformed_acl['users'].append({"id":new_acl_principal["user"],"permissions":new_acl_principal['permissions'] if "permissions" in new_acl_principal else (user_def['permissions'] if 'permissions' in user_def else [])})
					elif "group" in new_acl_principal:
						transformed_acl['groups'].append({"id":new_acl_principal["group"],"permissions":new_acl_principal['permissions'] if "permissions" in new_acl_principal else (user_def['permissions'] if 'permissions' in user_def else [])})
					elif "role" in new_acl_principal:
						if 'roles' not in transformed_acl:
							transformed_acl['roles'] = []
						transformed_acl['roles'].append({"id":new_acl_principal["role"],"permissions":new_acl_principal['permissions'] if "permissions" in new_acl_principal else (user_def['permissions'] if 'permissions' in user_def else [])})
			if 'groups' in acl:
				# Note, taking a copy of the list for proper removal of items
				for group_def in acl['groups'][:]:
					new_acl_principal = self._find_matching_principal_for_groupid(group_def['id'], group_def['permissions'])
					if new_acl_principal == "REMOVE":
						self._logger.info("_process_acl: Source Group " + group_def['id'] + " is removed from ACL definition. " + self._utils.get_entity_desc(entity))
					elif new_acl_principal is None:
						if ignore_missing_acl_group_flag:
							self._logger.warn("_process_acl: Source Group " + group_def['id'] + " not found in the target Dremio Environment. Group is removed from ACL definition as per ignore_missing_acl_group configuration. " + self._utils.get_entity_desc(entity))
						else:
							# Flag is not set - return error status
							self._logger.error("_process_acl: Source Group " + group_def['id'] + " not found in the target Dremio Environment. ACL Entry cannot be processed as per ignore_missing_acl_group configuration. " + self._utils.get_entity_desc(entity))
					elif "user" in new_acl_principal:
						transformed_acl['users'].append({"id":new_acl_principal["user"],"permissions":new_acl_principal['permissions'] if "permissions" in new_acl_principal else (group_def['permissions'] if 'permissions' in group_def else [])})
					elif "group" in new_acl_principal:
						transformed_acl['groups'].append({"id":new_acl_principal["group"],"permissions":new_acl_principal['permissions'] if "permissions" in new_acl_principal else (group_def['permissions'] if 'permissions' in group_def else [])})
					elif "role" in new_acl_principal:
						if 'roles' not in transformed_acl:
							transformed_acl['roles'] = []
						transformed_acl['roles'].append({"id":new_acl_principal["role"],"permissions":new_acl_principal['permissions'] if "permissions" in new_acl_principal else (group_def['permissions'] if 'permissions' in group_def else [])})
			if 'roles' in acl:
				# Note, taking a copy of the list for proper removal of items
				for role_def in acl['roles'][:]:
					new_acl_principal = self._find_matching_principal_for_roleid(role_def['id'], role_def['permissions'])
					if new_acl_principal == "REMOVE":
						self._logger.info("_process_acl: Source Role " + role_def['id'] + " is removed from ACL definition. " + self._utils.get_entity_desc(entity))
					elif new_acl_principal is None:
						if ignore_missing_acl_group_flag:
							self._logger.warn("_process_acl: Source Role " + role_def['id'] + " not found in the target Dremio Environment. Role is removed from ACL definition as per ignore_missing_acl_group configuration. " + self._utils.get_entity_desc(entity))
						else:
							# Flag is not set - return error status
							self._logger.error("_process_acl: Source Role " + role_def['id'] + " not found in the target Dremio Environment. ACL Entry cannot be processed as per ignore_missing_acl_group configuration. " + self._utils.get_entity_desc(entity))
					elif "user" in new_acl_principal:
						transformed_acl['users'].append({"id":new_acl_principal["user"],"permissions":new_acl_principal['permissions'] if "permissions" in new_acl_principal else role_def['permissions']})
					elif "group" in new_acl_principal:
						transformed_acl['groups'].append({"id":new_acl_principal["group"],"permissions":new_acl_principal['permissions'] if "permissions" in new_acl_principal else role_def['permissions']})
					elif "role" in new_acl_principal:
						if 'roles' not in transformed_acl:
							transformed_acl['roles'] = []
						transformed_acl['roles'].append({"id":new_acl_principal["role"],"permissions":new_acl_principal['permissions'] if "permissions" in new_acl_principal else role_def['permissions']})
			entity['accessControlList'] = transformed_acl
		return True

	def _transform_permissions(self, source_permissions, acl_mapping):
		# if permission mapping not explicitely defined, use source permissions as is
		if 'permission-mapping' not in acl_mapping:
			return source_permissions
		permissions_mapping = acl_mapping['permission-mapping']
		permissions = []
		for permission in source_permissions:
			for mapping in permissions_mapping:
				# add only once
				if permission in mapping and mapping[permission] not in permissions:
					permissions.append(mapping[permission])
		# Pre-RBAC rule: If WRITE is in the list but not READ, then add READ
		if "WRITE" in permissions and "READ" not in permissions:
			permissions.append("READ")
		return permissions

	def _find_matching_principal_for_userid(self, userid, permissions):
		self._logger.debug("_find_matching_principal_for_userid: processing user_id: " + str(userid))
		for user in self._d.referenced_users:
			if user['id'] == userid:
				transformed_principal = self._find_acl_transformation_by_username(user['name'], permissions)
				if transformed_principal == "REMOVE":
					self._logger.info("_find_matching_principal_for_userid: Source User " + user['name'] + " [" + user['id'] + "] is mapped as NONE.")
					return "REMOVE"
				# If no tranformation is defined for this user
				elif transformed_principal is None:
					for target_user in self._target_dremio_users:
						if target_user['name'] == user['name']:
							return {"user":target_user['id']}
				elif "error" in transformed_principal:
					# Something went wrong
					self._logger.error("_find_matching_principal_for_userid: error " + transformed_principal['error'])
					return None
				else:
					return transformed_principal
		# If the username is already in the target list (i.e. the mapping already happened
		# but the write_entity failed because parent objects were not yet created) then take username straight from target
		for user in self._target_dremio_users:
			if user['id'] == userid:
				transformed_principal = self._find_acl_transformation_by_username(user['name'], permissions)
				if transformed_principal is None:
					return {"user": user['id']}
				elif "error" in transformed_principal:
					# Something went wrong
					self._logger.error("_find_matching_principal_for_userid: error " + transformed_principal['error'])
					return None
				else:
					return transformed_principal
		return None

	def _find_acl_transformation_by_username(self, username, permissions):
		for item in self._config.acl_transformation:
			if 'user' in item['source'] and item['source']['user'] == username:
				if "REMOVE" in item['target']:
					return "REMOVE"
				elif "user" in item['target']:
					for target_user in self._target_dremio_users:
						if target_user['name'] == item['target']['user']:
							new_permissions = self._transform_permissions(permissions, item)
							return {"user":target_user['id'],"permissions":new_permissions}
				elif "group" in item['target']:
					for target_group in self._target_dremio_groups:
						if target_group['name'] == item['target']['group']:
							new_permissions = self._transform_permissions(permissions, item)
							return {"group":target_group['id'],"permissions":new_permissions}
				elif "role" in item['target']:
					for target_role in self._target_dremio_roles:
						if target_role['name'] == item['target']['role']:
							new_permissions = self._transform_permissions(permissions, item)
							return {"role":target_role['id'],"permissions":new_permissions}
				# The transformation is defined for this user, however, the target principal is not in the target Dremio Environment
				return {"error": "user_transformation_found_but_target_principle_is_not_in_target_dremio_environment"}
		# If the username is already in the target list (i.e. the mapping already happened
		# but the write_entity failed because parent objects were not yet created) then take username straight from target
		for item in self._config.acl_transformation:
			if 'user' in item['target'] and item['target']['user'] == username:
				for target_user in self._target_dremio_users:
					if target_user['name'] == username:
						new_permissions = self._transform_permissions(permissions, item)
						return {"user": target_user['id'], "permissions": new_permissions}
			if 'group' in item['target'] and item['target']['group'] == username:
				for target_group in self._target_dremio_groups:
					if target_group['name'] == item['target']['group']:
						new_permissions = self._transform_permissions(permissions, item)
						return {"group": target_group['id'], "permissions": new_permissions}
			if 'role' in item['target'] and item['target']['role'] == username:
				for target_role in self._target_dremio_roles:
					if target_role['name'] == item['target']['role']:
						new_permissions = self._transform_permissions(permissions, item)
						return {"role": target_role['id'], "permissions": new_permissions}
		return None

	def _find_matching_principal_for_groupid(self, groupid, permissions):
		self._logger.debug("_find_matching_groupid: processing: " + str(groupid))
		for group in self._d.referenced_groups:
			if group['id'] == groupid:
				transformed_principal = self._find_acl_transformation_by_groupname(group['name'], permissions)
				if transformed_principal == "REMOVE":
					self._logger.info("_find_matching_principal_for_groupid: Source Group " + group['name'] + " [" + group['id'] + "] is mapped as NONE.")
					return "REMOVE"
				# If no transformation is defined for this group
				elif transformed_principal is None:
					for target_group in self._target_dremio_groups:
						if target_group['name'] == group['name']:
							return {"group":target_group['id']}
				elif "error" in transformed_principal:
					# Something went wrong
					self._logger.error("_find_matching_principal_for_groupid: error " + transformed_principal['error'])
					return None
				else:
					return transformed_principal
		# If the group name is already in the target list (i.e. the mapping already happened
		# but the write_entity failed because parent objects were not yet created) then take group name straight from target
		for group in self._target_dremio_groups:
			if group['id'] == groupid:
				transformed_principal = self._find_acl_transformation_by_groupname(group['name'], permissions)
				if transformed_principal is None:
					return {"group": group['id']}
				elif "error" in transformed_principal:
					# Something went wrong
					self._logger.error("_find_matching_principal_for_groupid: error " + transformed_principal['error'])
					return None
				else:
					return transformed_principal
		return None

	def _find_matching_principal_for_roleid(self, roleid, permissions):
		self._logger.debug("_find_matching_roleid: processing: " + str(roleid))
		for role in self._d.referenced_roles:
			if role['id'] == roleid:
				self._logger.debug("_find_matching_roleid: roleid " + str(roleid) + " has role name " + role['name'])
				transformed_principal = self._find_acl_transformation_by_rolename(role['name'], permissions)
				if transformed_principal == "REMOVE":
					self._logger.info("_find_matching_principal_for_roleid: Source Role " + role['name'] + " [" + role['id'] + "] is mapped as NONE.")
					return "REMOVE"
				# If no transformation is defined for this role
				elif transformed_principal is None:
					for target_role in self._target_dremio_roles:
						if target_role['name'] == role['name']:
							return {"role":target_role['id']}
				elif "error" in transformed_principal:
					# Something went wrong
					self._logger.error("_find_matching_principal_for_roleid: error " + transformed_principal['error'])
					return None
				else:
					return transformed_principal
		# If the role name is already in the target list (i.e. the mapping already happened
		# but the write_entity failed because parent objects were not yet created) then take role name straight from target
		for role in self._target_dremio_roles:
			if role['id'] == roleid:
				self._logger.debug("_find_matching_roleid: roleid " + str(roleid) + " has role name " + role['name'])
				transformed_principal = self._find_acl_transformation_by_rolename(role['name'], permissions)
				if transformed_principal is None:
					return {"role": role['id']}
				elif "error" in transformed_principal:
					# Something went wrong
					self._logger.error("_find_matching_principal_for_roleid: error " + transformed_principal['error'])
					return None
				else:
					return transformed_principal
		return None

	def _find_acl_transformation_by_groupname(self, groupname, permissions):
		for item in self._config.acl_transformation:
			if 'group' in item['source'] and item['source']['group'] == groupname:
				if "REMOVE" in item['target']:
					return "REMOVE"
				elif "user" in item['target']:
					for target_user in self._target_dremio_users:
						if target_user['name'] == item['target']['user']:
							new_permissions = self._transform_permissions(permissions, item)
							return {"user":target_user['id'],"permissions":new_permissions}
				elif "group" in item['target']:
					for target_group in self._target_dremio_groups:
						if target_group['name'] == item['target']['group']:
							new_permissions = self._transform_permissions(permissions, item)
							return {"group":target_group['id'],"permissions":new_permissions}
				elif "role" in item['target']:
					for target_role in self._target_dremio_roles:
						if target_role['name'] == item['target']['role']:
							new_permissions = self._transform_permissions(permissions, item)
							return {"role":target_role['id'],"permissions":new_permissions}
				# The transformation is defined for this group, however, the target principal is not in the target Dremio Environment
				return {"error": "group_transformation_found_but_target_principle_is_not_in_target_dremio_environment"}
		# If the group name is already in the target list (i.e. the mapping already happened
		# but the write_entity failed because parent objects were not yet created) then take group name straight from target
		for item in self._config.acl_transformation:
			if 'user' in item['target'] and item['target']['user'] == groupname:
				for target_user in self._target_dremio_users:
					if target_user['name'] == groupname:
						new_permissions = self._transform_permissions(permissions, item)
						return {"user": target_user['id'], "permissions": new_permissions}
			if 'group' in item['target'] and item['target']['group'] == groupname:
				for target_group in self._target_dremio_groups:
					if target_group['name'] == item['target']['group']:
						new_permissions = self._transform_permissions(permissions, item)
						return {"group": target_group['id'], "permissions": new_permissions}
			if 'role' in item['target'] and item['target']['role'] == groupname:
				for target_role in self._target_dremio_roles:
					if target_role['name'] == item['target']['role']:
						new_permissions = self._transform_permissions(permissions, item)
						return {"role": target_role['id'], "permissions": new_permissions}
		return None

	def _find_acl_transformation_by_rolename(self, rolename, permissions):
		for item in self._config.acl_transformation:
			if 'role' in item['source'] and item['source']['role'] == rolename:
				if "REMOVE" in item['target']:
					return "REMOVE"
				elif "user" in item['target']:
					for target_user in self._target_dremio_users:
						if target_user['name'] == item['target']['user']:
							new_permissions = self._transform_permissions(permissions, item)
							return {"user":target_user['id'],"permissions":new_permissions}
				elif "group" in item['target']:
					for target_group in self._target_dremio_groups:
						if target_group['name'] == item['target']['group']:
							new_permissions = self._transform_permissions(permissions, item)
							return {"group":target_group['id'],"permissions":new_permissions}
				elif "role" in item['target']:
					for target_role in self._target_dremio_roles:
						if target_role['name'] == item['target']['role']:
							new_permissions = self._transform_permissions(permissions, item)
							return {"role":target_role['id'],"permissions":new_permissions}
				# The transformation is defined for this group, however, the target principal is not in the target Dremio Environment
				return {"error": "role_transformation_found_but_target_principle_is_not_in_target_dremio_environment"}
		# If the role name is already in the target list (i.e. the mapping already happened
		# but the write_entity failed because parent objects were not yet created) then take role name straight from target
		for item in self._config.acl_transformation:
			if 'user' in item['target'] and item['target']['user'] == rolename:
				for target_user in self._target_dremio_users:
					if target_user['name'] == rolename:
						new_permissions = self._transform_permissions(permissions, item)
						return {"user": target_user['id'], "permissions": new_permissions}
			if 'group' in item['target'] and item['target']['group'] == rolename:
				for target_group in self._target_dremio_groups:
					if target_group['name'] == item['target']['group']:
						new_permissions = self._transform_permissions(permissions, item)
						return {"group": target_group['id'], "permissions": new_permissions}
			if 'role' in item['target'] and item['target']['role'] == rolename:
				for target_role in self._target_dremio_roles:
					if target_role['name'] == item['target']['role']:
						new_permissions = self._transform_permissions(permissions, item)
						return {"role": target_role['id'], "permissions": new_permissions}
		return None

	def _read_entity_definition(self, entity):
		self._logger.debug("_read_entity_definition: processing entity: " + self._utils.get_entity_desc(entity))
		if 'name' in entity:
			return self._dremio_env.get_catalog_entity_by_path(entity['name'])
		elif 'path' in entity:
			return self._dremio_env.get_catalog_entity_by_path(self._utils.normalize_path(entity['path']))
		else:
			self._logger.error("_read_entity_definition: bad data: " + self._utils.get_entity_desc(entity))
			return None

	# Process vds_list and save ordered list of VDSs into _vds_hierarchy. Recursive method.
	def _order_vds(self, processing_level=0):
		# Verify for the Max Hierarchy Depth
		if processing_level >= self._config.vds_max_hierarchy_depth:
			self._logger.debug("_order_vds: Finished processing with VDSs left to process:" + str(self._d.vds_list))
			return
		any_vds_leveled = False
		# Iterate through the remainder VDS in the list
		# Go with decreasing index so we can remove VDS from the list
		for i in range(len(self._d.vds_list) - 1, -1, -1):
			vds = self._d.vds_list[i]
			self._logger.debug("_order_vds: processing vds " + self._utils.get_entity_desc(vds))
			vds_hierarchy_level = processing_level
			any_dependency_unresolved = False
			sql_dependency_paths = self._get_vds_dependency_paths(vds)
			# Iterate through SQL dependencies to determine level of hierarchy for each dependency and the VDS
			for path in sql_dependency_paths:
				self._logger.debug("_order_vds: processing sql dependency " + path)
				# Validate the dependency against VDS and PDS
				sql_context = self._utils.get_sql_context(vds)
				dependency_vds = self._find_vds_by_path(self._utils.get_absolute_path(path, sql_context))
				if dependency_vds is None:
					dependency_pds = self._find_pds_by_path(self._utils.get_absolute_path(path, sql_context))
					if dependency_pds is None:
						# Dependency could not be resolved.
						self._logger.warn("_order_vds: giving up on ordering VDS '" + self._utils.normalize_path(vds['path']) + "'. Could not resolve dependency '" + self._utils.get_absolute_path(path, sql_context) + "' Will try to process without ordering.")
						# Move VDS into unresolved list
						self._unresolved_vds.append(vds)
						self._d.vds_list.remove(vds)
						# Mark as do-not-process
						any_dependency_unresolved = True
						break
					else:
						# The dependency has been resolved as PDS, continue to the next dependency
						continue
				else:
					# Dependency was found as VDS
					dependency_hierarchy_level = self._find_vds_level_in_hierarchy(dependency_vds['id'])
					if dependency_hierarchy_level is None:
						# Dependency has not been processed yet, push this VDS to the next processing level
						vds_hierarchy_level = None
						break
					# Find the highest level of hierarchy among dependencies
					elif vds_hierarchy_level < dependency_hierarchy_level + 1:
						vds_hierarchy_level = dependency_hierarchy_level + 1
			if any_dependency_unresolved or vds_hierarchy_level is None:
				# Do not process this VDS at this recursion
				self._logger.debug("_order_vds: some dependencies cannot be validated for entity " + vds['id'] + " at processing level " + str(processing_level))
			else:
				# Add the current VDS to the vds_hierarchy_level
				self._vds_hierarchy.append([vds_hierarchy_level, vds])
				# Remove the current VDS from further processing
				self._d.vds_list.remove(vds)
				# Mark this hierarchy level as successful
				any_vds_leveled = True
				self._logger.debug("_order_vds: dependencies have been validated for entity " + vds['id'] + " for hierarchy level " + str(vds_hierarchy_level))
		# Are we done yet with recursion
		if not any_vds_leveled or len(self._d.vds_list) == 0:
			self._hierarchy_depth = processing_level + 1
			self._logger.debug("_order_vds: finished processing all VDS with hierarchy depth of :" + str(self._hierarchy_depth + 1))
			return
		# Process the next Hierarchy Level recursively
		self._order_vds(processing_level + 1)

	def _get_vds_dependency_paths(self, vds):
		if self._is_source_ce() or not self._d.vds_parents:
			# CE does not support graph
			return parse_sql.tables_in_query(vds['sql'])
		else:
			for vds_entry in self._d.vds_parents:
				if vds_entry['path'] == vds['path']:
					return vds_entry['parents']

	def _is_source_ce(self):
		for item in self._d.dremio_get_config:
			if 'source' in item:
				for param in item['source']:
					if 'is_community_edition' in param:
						return eval(param['is_community_edition'])
		return False

	def _find_vds_by_path(self, path):
		# First, try finding in the VDS list from the source file
		for vds in self._d.vds_list:
			if path == self._utils.normalize_path(vds['path']):
				return vds
		# For dry run, check processed vds
		if self._config.dry_run:
			for vds in self._dry_run_processed_vds_list:
				if path == self._utils.normalize_path(vds['path']):
					return vds
		# Finally, try finding in the target environment
		entity = self._dremio_env.get_catalog_entity_by_path(path)
		# Make sure we get VDS and not folder/file
		if entity is not None and self._utils.is_vds(entity):
			return entity
		return None

	def _find_pds_by_path(self, path):
		# First, try finding in the PDS list from the source file
		for pds in self._d.pds_list:
			if "path" in pds and path == self._utils.normalize_path(pds['path']):
				return pds
		# For dry run, check processed pds
		if self._config.dry_run:
			for pds in self._dry_run_processed_pds_list:
				if "path" in pds and path == self._utils.normalize_path(pds['path']):
					return pds
		# Finally, try finding in the target environment
		entity = self._dremio_env.get_catalog_entity_by_path(path)
		# Make sure we get promoted PDS and not folder/file
		if entity is not None and self._utils.is_pds(entity):
			return entity
		return None

	def _find_vds_level_in_hierarchy(self, vds_id):
		for item in self._vds_hierarchy:
			if item[1]['id'] == vds_id:
				return item[0]
		return None

	def get_errors_count(self):
		return self._logger.errors_encountered


	def _write_wiki(self, wiki, process_mode):
		self._logger.debug("_write_wiki: processing wiki: " + str(wiki))
		self._map_wiki_source(wiki)
		new_wiki_text = wiki['text']
		wiki_path = wiki['path']
		# Check if the wiki already exists
		existing_wiki_entity = self._find_existing_dataset_by_path(self._utils.normalize_path(wiki_path))
		if existing_wiki_entity is None:
			self._logger.error("_write_wiki: Unable to resolve wiki's dataset for " + str(wiki))
			return None
		existing_wiki = self._dremio_env.get_catalog_wiki(existing_wiki_entity['id'])
		if existing_wiki is None:  # Need to create new entity
			if process_mode == 'update_only':
				self._logger.info("_write_wiki: Skipping wiki creation due to configuration wiki_process_mode. " + str(wiki))
				return None
			if self._config.dry_run:
				self._logger.warn("_write_wiki: Dry Run, NOT Creating wiki: " + str(wiki))
				return None
			new_wiki = {"text":new_wiki_text}
			new_wiki = self._dremio_env.update_wiki(existing_wiki_entity['id'], new_wiki, self._config.dry_run)
			if new_wiki is None:
				self._logger.error("_write_wiki: could not create " + str(wiki))
				return None
		else:  # Wiki already exists in the target environment
			if process_mode == 'create_only':
				self._logger.info("_write_wiki: Found existing wiki and wiki_process_mode is set to create_only. Skipping " + str(wiki))
				return None
			# make sure there are changes to update as it will invalidate existing wiki data
			if new_wiki_text == existing_wiki['text']:
				# Nothing to do
				self._logger.debug("_write_wiki: No pending changes. Skipping " + str(wiki))
				return None
			if self._config.dry_run:
				self._logger.warn("_write_wiki: Dry Run, NOT Updating " + str(wiki))
				return False
			self._logger.debug("_write_wiki: Overwriting " + str(wiki))
			existing_wiki['text'] = new_wiki_text
			updated_wiki = self._dremio_env.update_wiki(existing_wiki_entity['id'], existing_wiki, self._config.dry_run)
			if updated_wiki is None:
				self._logger.error("_write_wiki: Error updating " + str(wiki))
				return False
		return True


	def _write_tags(self, tags, process_mode):
		self._logger.debug("_write_tag: processing tags: " + str(tags))
		self._map_tag_source(tags)
		new_tags = tags['tags']
		tags_path = tags['path']
		# Check if the tags already exist
		existing_tags_entity = self._find_existing_dataset_by_path(self._utils.normalize_path(tags_path))
		if existing_tags_entity is None:
			self._logger.error("_write_tags: Unable to resolve tag's dataset for " + str(tags))
			return None
		existing_tags = self._dremio_env.get_catalog_tags(existing_tags_entity['id'])
		if existing_tags is None:  # Need to create new entity
			if process_mode == 'update_only':
				self._logger.info("_write_tags: Skipping tags creation due to configuration tag_process_mode. " + str(tags))
				return None
			if self._config.dry_run:
				self._logger.warn("_write_tags: Dry Run, NOT Creating tags: " + str(tags))
				return None
			new_tags = {"tags":new_tags}
			new_tags = self._dremio_env.update_tag(existing_tags_entity['id'], new_tags, self._config.dry_run)
			if new_tags is None:
				self._logger.error("_write_tags: could not create " + str(tags))
				return None
		else:  # Tags already exists in the target environment
			if process_mode == 'create_only':
				self._logger.info("_write_tags: Found existing tags and tag_process_mode is set to create_only. Skipping " + str(tags))
				return None
			# make sure there are changes to update as it will invalidate existing tags data
			if new_tags == existing_tags['tags']:
				# Nothing to do
				self._logger.debug("_write_tags: No pending changes. Skipping " + str(tags))
				return None
			if self._config.dry_run:
				self._logger.warn("tags: Dry Run, NOT Updating " + str(tags))
				return False
			self._logger.debug("_write_tags: Overwriting " + str(tags))
			existing_tags['tags'] = new_tags
			updated_tags = self._dremio_env.update_tag(existing_tags_entity['id'], existing_tags, self._config.dry_run)
			if updated_tags is None:
				self._logger.error("_write_tags: Error updating " + str(tags))
				return False
		return True
