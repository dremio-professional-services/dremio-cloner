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

import fnmatch, re
from DremioClonerUtils import DremioClonerUtils
from DremioClonerLogger import DremioClonerLogger

class DremioClonerFilter():

	_config = None
	_utils = None
	_logger = None

	def __init__(self, config):
		self._config = config
		self._logger = DremioClonerLogger(self._config.max_errors, self._config.logging_verbose)
		self._utils = DremioClonerUtils(config)

	def is_pds_in_scope(self):
		return self._config._source_filter_re is not None and \
				self._config._pds_filter_re is not None and \
				self._config.source_folder_exclude_filter != '*' and \
				self._config.pds_exclude_filter != '*' and \
				self._config.pds_process_mode == 'process'

	def _match_listed_space_names(self, container):
		if self._config.space_filter_names != [] and ( \
						('path' in container and container['path'][0] not in self._config.space_filter_names) \
						or ('name' in container and container['name'] not in self._config.space_filter_names) ):
			return False
		return True

	def match_space_filter(self, container, loginfo = False):
		if not self._match_listed_space_names(container):
			return False
		# Filter by space name pattern
		if self._match_path(self._config._space_filter_re, self._config._space_exclude_filter_re, None, None, None, None, container):
			return True
		if loginfo:
			self._logger.info("match_space_filter: skipping SPACE " + container['path'][0] if 'path' in container else container['name'] + " as per job configuration")
		return False

	def _match_listed_space_folder_filter_paths(self, container):
		if self._config.space_folder_filter_paths != []:
			if 'path' not in container:
				return False
			path = container['path']
			folder_matched = False
			for space_folder_filter in self._config.space_folder_filter_paths:
				if not folder_matched:
					space_folder_filter_re = self._config._compile_pattern(space_folder_filter)
					for i in range(len(path)):
						if space_folder_filter_re.match(self._utils.normalize_path(path[1:len(path) - i])) is not None:
							folder_matched = True
							break
			if not folder_matched:
				return False
		return True

	def _match_listed_space_folder_exclude_filter_paths(self, container):
		if self._config.space_folder_exclude_filter_paths != []:
			if 'path' not in container:
				return False
			path = container['path']
			folder_matched = False
			for space_folder_exclude_filter in self._config.space_folder_exclude_filter_paths:
				if not folder_matched:
					space_folder_filter_re = self._config._compile_pattern(space_folder_exclude_filter)
					for i in range(len(path)):
						if space_folder_filter_re.match(self._utils.normalize_path(path[1:len(path) - i])) is not None:
							folder_matched = True
							break
			if not folder_matched:
				return False
			return True
		else:
			return False

	def match_space_folder_filter(self, container, loginfo = True):
		if not self._match_listed_space_names(container):
			return False
		if not self._match_listed_space_folder_filter_paths(container):
			return False
		# Explicit exclusion of folders wins over explicit inclusion
		if self._match_listed_space_folder_exclude_filter_paths(container):
			return False
		if self._match_path(self._config._space_filter_re, self._config._space_exclude_filter_re, self._config._space_folder_filter_re, self._config._space_folder_exclude_filter_re, None, None, container):
			return True
		if loginfo:
			self._logger.debug("match_space_folder_filter: skipping SPACE FOLDER " + container['path'][0] if 'path' in container else container['name'] + " as per job configuration")
		return False

	def match_space_folder_cascade_acl_origin_filter(self, container):
		if self._config.space_folder_cascade_acl_origin_filter is None:
			return False
		elif (  # Do not filter out folders in HOME hierarchies
				(container['path'][0][:1] == '@') or
				# Match both Folder filter and Space filter
				((self._config._space_folder_cascade_acl_origin_filter_re.match(self._utils.normalize_path(container['path'][1:])) is not None) and
				 self.match_space_filter(container)) ):
			return True
		else:
			return False

	def match_source_filter(self, container, loginfo = True):
		# First filter by source types
		if container['type'] != 'CONTAINER' and self._config.source_filter_types != [] and (container['entityType'] != 'source' or container['type'] not in self._config.source_filter_types):
			return False
		# Also filter by source names
		if container['type'] != 'CONTAINER' and self._config.source_filter_names != [] and (container['entityType'] != 'source' or container['name'] not in self._config.source_filter_names):
			return False
		# Finally filter by filter pattern
		if self._match_path(self._config._source_filter_re, self._config._source_exclude_filter_re, None, None, None, None, container):
			return True
		if loginfo:
			self._logger.debug("match_source_filter: skipping SOURCE " + container['path'][0] if 'path' in container else container['name'] + " as per job configuration")
		return False

	def _match_listed_source_folder_paths(self, container):
		if self._config.source_folder_filter_paths != []:
			if 'path' not in container:
				return False
			path = container['path']
			folder_matched = False
			for source_folder_filter in self._config.source_folder_filter_paths:
				if not folder_matched:
					source_folder_filter_re = self._config._compile_pattern(source_folder_filter)
					for i in range(len(path[1:])):
						normalized_path = self._utils.normalize_path(path[1:len(path) - i])
						if source_folder_filter_re.match(normalized_path) is not None:
							folder_matched = True
							break
						# check if the full normalized path is a substring of the source_folder_filter (assumes no wildcards)
						# only really applicable when pds.list.useapi is True (which should be never due to inefficiencies) and hence we are traversing a folder structure
						if i == 0 and source_folder_filter.find(normalized_path) >= 0:
							folder_matched = True
							break
			if not folder_matched:
				return False
		return True

	def match_source_folder_filter(self, container, loginfo = True):
		if not self._match_listed_source_folder_paths(container):
			return False
		if self._match_path(self._config._source_filter_re, self._config._source_exclude_filter_re, self._config._source_folder_filter_re, self._config._source_folder_exclude_filter_re, None, None, container):
			return True
		if loginfo:
			self._logger.debug("match_source_folder_filter: skipping SOURCE FOLDER " + container['path'][0] if 'path' in container else container['name'] + " as per job configuration")
		return False

	def _match_listed_pds_names(self, pds):
		if self._config.pds_filter_names != [] and ('path' in pds and pds['path'][-1] not in self._config.pds_filter_names):
			return False
		return True

	def match_pds_filter(self, pds, loginfo = True):
		if not self._match_listed_source_folder_paths(pds):
			return False
		if not self._match_listed_pds_names(pds):
			return False
		if self._match_path(self._config._source_filter_re, self._config._source_exclude_filter_re, self._config._source_folder_filter_re, self._config._source_folder_exclude_filter_re, self._config._pds_filter_re, self._config._pds_exclude_filter_re, pds):
			return True
		if loginfo:
			self._logger.debug("match_pds_filter: skipping PDS " + pds['path'][-1] if 'path' in pds else pds['name'] + " as per job configuration")
		return False

	def _match_listed_vds_names(self, vds):
		if self._config.vds_filter_names != [] and ('path' in vds and vds['path'][-1] not in self._config.vds_filter_names):
			return False
		return True

	def _match_listed_vds_exclude_filter_paths(self, vds):
		if self._config.vds_exclude_filter_paths != [] and 'path' in vds:
			path = vds['path']
			for vds_exclude_filter in self._config.vds_exclude_filter_paths:
				vds_exclude_filter_re = self._config._compile_pattern(vds_exclude_filter)
				if vds_exclude_filter_re.match(self._utils.normalize_path(path[1:len(path)])):
					return True
		return False

	def match_vds_filter(self, vds, tags=None, loginfo = True):
		if not self._match_listed_space_names(vds):
			return False
		# Handle folders while avoiding case of VDS located directly in space
		if len(vds.get('path', 0)) > 2:
			if not self._match_listed_space_folder_filter_paths(vds):
				return False
			# Explicit exclusion of folders wins over explicit inclusion
			if self._match_listed_space_folder_exclude_filter_paths(vds):
				return False
		if not self._match_listed_vds_names(vds):
			return False
		# Explicit exclusion of VDSs wins over explicit inclusion
		if self._match_listed_vds_exclude_filter_paths(vds):
			return False
		if self._match_path(self._config._space_filter_re, self._config._space_exclude_filter_re, self._config._space_folder_filter_re, self._config._space_folder_exclude_filter_re, self._config._vds_filter_re, self._config._vds_exclude_filter_re, vds):
			if self._config.vds_filter_tag is None or self._config.vds_filter_tag == "*":
				return True
			elif tags is not None and self._match_tag(tags):
				return True
		if loginfo:
			self._logger.debug("match_vds_filter: skipping VDS " + vds['path'][-1] if 'path' in vds else vds['name'] + " as per job configuration")
		return False

	def _match_tag(self, tags):
		if 'tags' not in tags:
			return False
		for tag in tags['tags']:
			if tag == self._config.vds_filter_tag:
				return True
		return False

	def match_reflection_path(self, reflection_path, reflection_dataset):
		if 'type' in reflection_dataset and reflection_dataset['type'] == 'VIRTUAL_DATASET':
			if self._match_hierarchy_path(self._config._space_filter_re, self._config._space_exclude_filter_re, self._config._space_folder_filter_re, self._config._space_folder_exclude_filter_re, self._config._vds_filter_re, self._config._vds_exclude_filter_re, reflection_path):
				return True
		else:
			if self._match_hierarchy_path(self._config._source_filter_re, self._config._source_exclude_filter_re, self._config._source_folder_filter_re, self._config._source_folder_exclude_filter_re, self._config._pds_filter_re, self._config._pds_exclude_filter_re, reflection_path):
				return True
		return False

	def _match_hierarchy_path(self, root_re, root_exclusion_re, folder_re, folder_exclusion_re, object_re, object_exclusion_re, hierarchy_path):
		if root_re is None:
			return False
		# Match root object (Space of Source)
		if root_re.match(hierarchy_path[0]) is None:
			return False
		if root_exclusion_re is not None and root_exclusion_re.match(hierarchy_path[0]) is not None:
			return False
		# Match object
		if object_re is not None and object_re.match(self._utils.normalize_path(hierarchy_path[-1])) is None:
			return False
		if object_exclusion_re is not None and object_exclusion_re.match(self._utils.normalize_path(hierarchy_path[1:])) is not None:
			return False
		# Match Folders. Note, child folders do not need to be matched if its parent match
		if folder_re is None:
			return False
		else:
			folder_matched = False
			for i in range(len(hierarchy_path)):
				if folder_re.match(self._utils.normalize_path(hierarchy_path[1:len(hierarchy_path) - i])) is not None:
					folder_matched = True
					break
			if not folder_matched:
				return False
			if folder_exclusion_re is not None:
				folder_exclusion_matched = False
				for i in range(len(hierarchy_path)):
					if folder_exclusion_re.match(self._utils.normalize_path(hierarchy_path[1:len(hierarchy_path) - i])) is not None:
						folder_exclusion_matched = True
						break
				if folder_exclusion_matched:
					return False
		return True

	def _match_path(self, root_re, root_exclusion_re, folder_re, folder_exclusion_re, object_re, object_exclusion_re, entity):
		# If inclusion filter is not specified, nothing to process
		if root_re is None:
			return False
		# Validate parameters
		if ('containerType' in entity and entity['containerType'] == 'SPACE') or \
		   ('entityType' in entity and entity['entityType'] == 'space') or \
		   ('containerType' in entity and entity['containerType'] == 'SOURCE') or \
		   ('entityType' in entity and entity['entityType'] == 'source')	:
			pass
		elif ('entityType' in entity and entity['entityType'] == 'folder') or \
				('containerType' in entity and entity['containerType'] == 'FOLDER'):
			if root_re is None: # Not validating folder_re as the call might be to validate if the folder is from the unfiltered space
				return False
		elif ('entityType' in entity and entity['entityType'] == 'dataset') or \
				('type' in entity and entity['type'] == 'DATASET'):
			if root_re is None: # Not validating folder_re, object_re as the call might be to validate if the folder is from the unfiltered space
				return False
		else:
			self._logger.fatal("_match_path: Unexpected Entity Type " + str(entity))
		if 'path' not in entity:
			if root_re.match(entity['name']) is None:
				return False
			if root_exclusion_re is not None and root_exclusion_re.match(entity['name']) is not None:
				return False
		else:
			path = entity['path']
			# Handle special case, where VDS is in space root
			if entity.get('datasetType') == 'VIRTUAL' and len(path) == 2:
				# In this case, do not exclude based on folder exclusion patterns
				folder_exclusion_re = None
			# Match root object (Space of Source)
			if root_re.match(path[0]) is None:
				return False
			if root_exclusion_re is not None and root_exclusion_re.match(path[0]) is not None:
				return False
			# Match object
			if object_re is not None and object_re.match(self._utils.normalize_path(path[-1])) is None:
				return False
			if object_exclusion_re is not None and object_exclusion_re.match(self._utils.normalize_path(path[1:])) is not None:
				return False
			# Match Folders. Note, child folders do not need to be matched if its parent match
			if folder_re is not None or folder_exclusion_re is not None:
				if entity.get('type') == 'DATASET':
					# Do not include dataset name in folder filtering logic
					path = path[:-1]
				if folder_re is not None:  # Avoids potential NoneType Error
					folder_matched = False
					for i in range(len(path)):
						normalized_folder_path = self._utils.normalize_path(path[1:len(path) - i])
						if folder_re.match(normalized_folder_path) is not None:
							folder_matched = True
							break
					if not folder_matched:
						return False
				if folder_exclusion_re is not None:
					folder_exclusion_matched = False
					for i in range(len(path)):
						if folder_exclusion_re.match(self._utils.normalize_path(path[1:len(path) - i])) is not None:
							folder_exclusion_matched = True
							break
					if folder_exclusion_matched:
						return False
		return True

