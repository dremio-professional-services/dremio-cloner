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
import parse_sql
import json


class DremioReader:

	# Dremio Cloner Configuration, Utils, ...
	_config = None
	_utils = None
	_logger = None
	_filter = None

	# Dremio object pointing to the source Dremio environment
	_dremio_env = None

	# DremioData object containing data from Dremio source environment 
	_d = DremioData()

	# Current top-level hierarchy context: Home, Space, Source
	_top_level_hierarchy_context = None

	def __init__(self, source_dremio, config):
		self._config = config
		self._dremio_env = source_dremio
		self._logger = DremioClonerLogger(self._config.max_errors, self._config.logging_verbose)
		self._utils = DremioClonerUtils(config)
		self._filter = DremioClonerFilter(config)

	# Read all data from the source Dremio environemnt
	# Return DremioData
	def read_dremio_environment(self):
		self._read_catalog()
		if not self._config.pds_list_useapi and self._filter.is_pds_in_scope():
			self._read_all_pds()
		self._read_reflections()
		self._read_rules()
		self._read_queues()
		self._read_votes()
		# Make sure that all VDS dependencies included as per configuration
		self._process_vds_dependencies()
		return self._d

	def _read_all_pds(self):
		if self._config.pds_list_useapi or not self._filter.is_pds_in_scope():
			self._logger.info("_read_all_pds: skipping PDS reading as per pds.filter configuration.")
		else:
			pds_list = self._dremio_env.list_pds(self._d.sources,
												 self._config.source_folder_filter, self._config.source_folder_exclude_filter,
												 self._config.pds_filter, self._config.pds_exclude_filter,
												 pds_error_list=self._d.pds_error_list)
			for pds in pds_list:
				if self._filter.match_pds_filter(pds):
					self._d.pds_list.append(pds)

	# Read Dremio catalog from source environment recursively going to containers and their children objects 
	def _read_catalog(self):
		containers = self._dremio_env.list_catalog()['data']
		for container in containers:
			self._logger.debug("_read_catalog: processing container " + self._utils.get_entity_desc(container))
			self._process_container(container)

	# Identify a container and delegate processing 
	def _process_container(self, container):
		self._logger.debug("_process_container: " + self._utils.get_entity_desc(container))
		if container['containerType'] == "HOME":
			self._read_home(container)
		elif container['containerType'] == "SPACE":
			self._read_space(container)
		elif container['containerType'] == "SOURCE":
			self._read_source(container)
		else:
			self._logger.fatal("_process_container: unexpected entity type " + self._utils.get_entity_desc(container))

	def _read_home(self, container):
		self._logger.debug("_read_home: processing container: " + self._utils.get_entity_desc(container))
		if self._config.home_process_mode == 'process':
			self._top_level_hierarchy_context = "HOME"
			self._d.containers.append(container)
			entity = self._get_entity_definition_by_id(container)
			if entity is not None:
				self._logger.info("_read_home: " + self._utils.get_entity_desc(entity))
				self._d.homes.append(entity)
				self._read_acl(entity)
				self._read_wiki(entity)
				self._read_space_children(entity)
			else:
				self._logger.error("_read_home: error reading entity for container: " + self._utils.get_entity_desc(container))
		else:
			self._logger.debug("_read_home: skipping due to job configuration")

	def _read_space(self, container):
		self._logger.debug("_read_space: processing container: " + self._utils.get_entity_desc(container))
		self._top_level_hierarchy_context = "SPACE"
		if self._filter.match_space_filter(container):
			self._d.containers.append(container)
			entity = self._get_entity_definition_by_id(container)
			if entity is not None:
				self._logger.debug("_read_space: " + self._utils.get_entity_desc(container))
				self._d.spaces.append(entity)
				self._read_acl(entity)
				self._read_wiki(entity)
				self._read_space_children(entity)
			else:
				self._logger.error("_read_space: error reading entity for container: " + self._utils.get_entity_desc(container))


	def _read_source(self, container):
		self._logger.debug("_read_source: processing container: " + self._utils.get_entity_desc(container))
		if self._config.source_process_mode == 'process' or (self._config.pds_process_mode == 'process' and self._config.pds_list_useapi):
			self._top_level_hierarchy_context = "SOURCE"
			if self._filter.match_source_filter(container):
				self._d.containers.append(container)
				entity = self._get_entity_definition_by_id(container)
				if entity is not None:
					# Re-validate the filter with entity since there is more details in entity
					if self._filter.match_source_filter(entity):
						self._logger.debug("_read_source: " + self._utils.get_entity_desc(entity))
						self._d.sources.append(entity)
						self._read_acl(entity)
						self._read_wiki(entity)
						# Depending on the useapi flag, PDSs can be collected via INFORMATION_SCHEMA. See also DX16597
						if self._config.pds_list_useapi:
							self._read_source_children(entity)
				else:
					self._logger.error("_read_source: error reading entity for container: " + self._utils.get_entity_desc(container))
		else:
			self._logger.debug("_read_source: skipping due to job configuration" )

	def _read_space_folder(self, folder):
		self._logger.debug("_read_space_folder: processing folder: " + self._utils.get_entity_desc(folder))
		if self._top_level_hierarchy_context not in ["SPACE", "HOME"]:
			return
		entity = self._get_entity_definition_by_id(folder)
		if entity is None:
			self._logger.error("_read_space_folder: error reading entity for folder: " + self._utils.get_entity_desc(folder))
			return
		if self._top_level_hierarchy_context == "HOME" or self._filter.match_space_folder_filter(folder):
			self._logger.debug("_read_space_folder: " + self._utils.get_entity_desc(folder))
			self._d.folders.append(entity)
			self._read_acl(entity)
			self._read_wiki(entity)
			# Validate all parent folders in the path have been saved already
			folder_path = entity['path']
			for i in range(1, len(folder_path)-1):
				folderSaved = False
				for item in self._d.folders:
					if item['path'][-1] == folder_path[i]:
						folderSaved = True
				if not folderSaved:
					parent_entity = self._get_entity_definition_by_path(folder_path[0:i+1])
					self._d.folders.append(parent_entity)
		self._read_space_children(entity)

	def _read_space_children(self, parent_entity):
		self._logger.debug("_read_space_children: processing parent_entity: " + self._utils.get_entity_desc(parent_entity))
		if 'entityType' not in parent_entity:
			self._logger.error("_read_space_children: bad data, skipping entity: " + self._utils.get_entity_desc(parent_entity))
			return
		for child in parent_entity['children']:
			if child['type'] == "DATASET":
				self._read_dataset(child)
			elif child['type'] == "FILE":
				self._read_file(child)
			elif child['containerType'] == "FOLDER":
				self._read_space_folder(child)
			else:
				self._logger.error("_read_space_children: not supported entity type " + child['type'])

	def _read_source_folder(self, folder):
		self._logger.debug("_read_source_folder: processing folder: " + self._utils.get_entity_desc(folder))
		if self._top_level_hierarchy_context == "SOURCE" and self._filter.match_source_folder_filter(folder):
			entity = self._get_entity_definition_by_id(folder)
			if entity is not None:
				self._logger.debug("_read_source_folder: " + self._utils.get_entity_desc(folder))
				self._read_source_children(entity)
			else:
				self._logger.error("_read_source_folder: error reading entity for folder: " + self._utils.get_entity_desc(folder))

	def _read_source_children(self, parent_entity):
		self._logger.debug("_read_source_children: processing parent entity '" + self._utils.get_entity_desc(parent_entity) + "'")
		if 'entityType' not in parent_entity:
			self._logger.error("_read_source_children: bad data, skipping entity: " + self._utils.get_entity_desc(parent_entity))
			return
		for child in parent_entity['children']:
			if child['type'] == "DATASET":
				self._read_dataset(child)
			elif child['type'] == "FILE":
				self._read_file(child)
			elif child['containerType'] == "FOLDER":
				self._read_source_folder(child)
			else:
				self._logger.error("_read_source_children: not supported entity type " + child['type'])

	def _read_dataset(self, dataset):
		self._logger.debug("_read_dataset: processing dataset: " + self._utils.get_entity_desc(dataset))
		entity = self._get_entity_definition_by_id(dataset)
		if entity is not None:
			self._logger.debug("_read_dataset: " + dataset['datasetType'] + " : " + self._utils.get_entity_desc(dataset))
			if dataset['datasetType'] == "PROMOTED" or dataset['datasetType'] == "DIRECT":
				self._d.pds_list.append(entity)
			elif dataset['datasetType'] == "VIRTUAL":
				tags = self._dremio_env.get_catalog_tags(entity['id'])
				if self._filter.match_vds_filter(dataset, tags=tags):
					self._d.vds_list.append(entity)
			else:
				self._logger.error("_read_dataset: Unexpected dataset type " + dataset['datasetType'] + " for " + self._utils.get_entity_desc(dataset) + ".")
			self._read_acl(entity)
			self._read_wiki(entity)
			self._read_tags(entity)

	def _read_file(self, file_name):
		# do nothing
		return

	def _read_reflections(self):
		self._logger.debug("_read_reflections: starting")
		if self._config.reflection_process_mode == 'process' and not self._config.source_ce:
			reflections = self._dremio_env.list_reflections()['data']
			for reflection in reflections:
				reflection_dataset = self._dremio_env.get_catalog_entity_by_id(reflection['datasetId'])
				if reflection_dataset is None:
					self._logger.debug("_read_reflections: error processing reflection, cannot get path for dataset: " + reflection['datasetId'])
					continue
				reflection_path = reflection_dataset['path']
				self._logger.debug("_read_reflections: processing reflection " + reflection['datasetId'] + " path: " + str(reflection_path))
				reflection["path"] = reflection_path
				self._d.reflections.append(reflection)
#				self._read_acl(reflection)
#				self._read_wiki(reflection)
		else:
			self._logger.debug("_read_reflections: skipping reflections processing as per job configuration")

	# Note, tags are only available for datasets
	def _read_tags(self, entity):
		self._logger.debug("_read_tags: for entity " + self._utils.get_entity_desc(entity))
		if self._config.tag_process_mode == 'process':
			tag = self._dremio_env.get_catalog_tags(entity['id'])
			if tag is not None:
				tag['entity_id'] = entity['id']
				if entity['entityType'] == 'space' or entity['entityType'] == 'source':
					tag['path'] = [entity['name']]
				else:
					tag['path'] = entity['path']
				if tag not in self._d.tags:
					self._d.tags.append(tag)
		else:
			self._logger.debug("_read_tags: skipping tags processing as per job configuration")

	def _read_wiki(self, entity):
		self._logger.debug("_read_wiki: for entity " + self._utils.get_entity_desc(entity))
		if self._config.wiki_process_mode == 'process':
			wiki = self._dremio_env.get_catalog_wiki(entity['id'])
			if wiki is not None:
				wiki["entity_id"] = entity['id']
				if entity['entityType'] == 'space' or entity['entityType'] == 'source' or entity['entityType'] == 'home':
					wiki['path'] = [entity['name']]
				else:
					wiki['path'] = entity['path']
				if wiki not in self._d.wikis:
					self._d.wikis.append(wiki)
		else:
			self._logger.debug("_read_wiki: skipping wiki processing as per job configuration")

	def _read_acl(self, entity):
		self._logger.debug("_read_acl: for entity " + self._utils.get_entity_desc(entity))
		if 'accessControlList' in entity:
			acl = entity['accessControlList']
			if 'users' in acl:
				for user in acl['users']:
					user_entity = self._dremio_env.get_user(user['id'])
					if user_entity is not None:
						if user_entity not in self._d.referenced_users:
							self._d.referenced_users.append(user_entity)
			if 'groups' in acl:
				for group in acl['groups']:
					group_entity = self._dremio_env.get_group(group['id'])
					if group_entity is not None:
						if group_entity not in self._d.referenced_groups:
							self._d.referenced_groups.append(group_entity)

	def _process_vds_dependencies(self):
		if self._config.vds_dependencies_process_mode == 'get':
			for vds in self._d.vds_list:
				self._discover_dependencies(vds)
			for vds in self._d.vds_list:
				self._populate_dependencies_graph(vds)

	# Discovers dependencies for the passed dataset and adds them to the self._d.vds_list
	def _discover_dependencies(self, dataset):
		self._logger.debug("_discover_dependencies: processing dataset: " + self._utils.get_entity_desc(dataset))
		if dataset is not None:
			if 'type' not in dataset:
				self._logger.error("_discover_dependencies: Expected Dataset Entity but got: " + self._utils.get_entity_desc(dataset))
				return
			if dataset['type'] == 'PHYSICAL_DATASET':
				if dataset not in self._d.pds_list:
					self._d.pds_list.append(dataset)
				return
			elif dataset['type'] == 'VIRTUAL_DATASET':
				if dataset not in self._d.vds_list:
					self._d.vds_list.append(dataset)
				# Process VDS dependencies
				sql_dependency_paths = self._get_vds_dependency_paths(dataset)
				for dependency_path in sql_dependency_paths:
					dependency_path = self._utils.get_absolute_path(dependency_path, self._utils.get_sql_context(dataset))
					entity = self._find_entity(dependency_path)
					if entity is not None:
						# Entity has already been read
						return
					dependency_dataset = self._dremio_env.get_catalog_entity_by_path(dependency_path)
					if dependency_dataset is None:
						self._logger.warn("_discover_dependencies: unable to resolve dataset likely due to datasource availability: " + dependency_path)
					else:
						self._discover_dependencies(dependency_dataset)
			else:
				self._logger.error("_discover_dependencies: Unknown Entity Type: " + dataset['type'])
		else:
			self._logger.error("_discover_dependencies: Could not resolve dependency: None")

	def _populate_dependencies_graph(self, vds):
		self._logger.debug("_populate_dependencies_graph: processing vds: " + self._utils.get_entity_desc(vds))
		# For some broken VDSs,
		vds_parent_list = self._get_vds_dependency_paths(vds)
		vds_parent_json = {'id':vds['id'], 'path':vds['path'], 'parents':vds_parent_list }
		if not self._config.source_ce and self._config.source_graph_support:
			self._d.vds_parents.append(vds_parent_json)

	def _get_vds_dependency_paths(self, vds):
		self._logger.debug("_get_vds_dependency_paths: processing vds: " + self._utils.get_entity_desc(vds))
		if self._config.source_ce or not self._config.source_graph_support:
			return parse_sql.tables_in_query(vds['sql'])
		else:
			graph = self._dremio_env.get_catalog_entity_graph_by_id(vds['id'])
			if graph is None:
				self._logger.warn("Could not receive Graph via API. Try to set graph_api_support to False in the job configuration.")
				return parse_sql.tables_in_query(vds['sql'])
			vds_parent_list = []
			for parent in graph['parents']:
				vds_parent_list.append(self._utils.normalize_path(parent['path']))
			return vds_parent_list

	def _find_entity(self, path):
		self._logger.debug("_find_entity: processing path: " + str(path))
		for vds in self._d.vds_list:
			if self._utils.normalize_path(vds['path']) == path:
				return vds
		for pds in self._d.pds_list:
			if self._utils.normalize_path(pds['path']) == path:
				return pds

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

	def _get_entity_definition_by_path(self, path):
		self._logger.debug("_get_entity_definition_by_path: processing path: " + str(path))
		path = self._utils.normalize_path(path)
		entity = self._dremio_env.get_catalog_entity_by_path(path)
		if entity is None:
			self._logger.error("_read_entity_definition: cannot retrieve entity for path: " + str(path))
		return entity

	def _read_queues(self):
		self._logger.debug("read_queues: started")
		if self._config.wlm_queue_process_mode == 'process' and not self._config.source_ce:
			self._d.queues = self._dremio_env.list_queues()['data']
		else:
			self._logger.debug("_read_queues: skipping as per job configuration")

	def _read_rules(self):
		self._logger.debug("read_rules: started")
		if self._config.wlm_rule_process_mode == 'process' and not self._config.source_ce:
			self._d.rules = self._dremio_env.list_rules()['rules']
		else:
			self._logger.debug("read_rules: skipping as per job configuration")

	def _read_votes(self):
		self._logger.debug("read_votes: started")
		if self._config.vote_process_mode == 'process' and not self._config.source_ce:
			self._d.votes = self._dremio_env.list_votes()['data']
		else:
			self._logger.debug("read_votes: skipping as per job configuration")

	def get_errors_count(self):
		return self._logger.errors_encountered