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

import re
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

	def _match_include_filters(self, container, is_space, is_dataset):
		if 'path' not in container:
			self._logger.debug("_match_include_filters: 'path' property not found in container. Skipping object.")
			return False
		path = container['path']
		normalized_path = self._utils.normalize_path(path)

		for f in self._config.include_filter_paths:
			# Object is along a valid subfolder path
			if re.match('^' + f + '/.*', normalized_path):
				return True
			# Special case for spaces
			if is_space and re.match('^' + f + '$', normalized_path) and '/' not in f:
				return True
			# Datasets must match the regex filter exactly
			if is_dataset and re.match('^' + f + '$', normalized_path):
				return True
			if not is_dataset and re.match('^' + normalized_path + '/.*', f):
				return True
			if not is_dataset and re.match('^' + normalized_path + '$', f):
				return True

		return False

	def _match_exclude_filters(self, container, is_space, is_dataset):
		if 'path' not in container:
			self._logger.debug("_match_exclude_filters: 'path' property not found in container. Skipping object.")
			return False
		path = container['path']
		normalized_path = self._utils.normalize_path(path)

		for f in self._config.exclude_filter_paths:
			# Object is along a valid subfolder path
			if re.match('^' + f + '/.*', normalized_path):
				return True
			# Special case for spaces
			if is_space and re.match('^' + f + '$', normalized_path) and '/' not in f:
				return True
			# Datasets must match the regex filter exactly
			if is_dataset and re.match('^' + f + '$', normalized_path):
				return True
			if not is_dataset and re.match('^' + normalized_path + '$', f):
				return True
		return False

	def _match_path(self, container, is_space=False, is_dataset=False):

		# Exclude overrides include filter
		if self._match_exclude_filters(container, is_space, is_dataset):
			return False
		if self._match_include_filters(container, is_space, is_dataset):
			return True
		return False


	def match_space_filter(self, container, loginfo = True):
		if self._match_path(container, is_space=True):
			return True
		if loginfo:
			self._logger.info("match_space_filter: skipping SPACE " + container['path'][0] if 'path' in container else container['name'] + " as per job configuration")
		return False


	def match_space_folder_filter(self, container, loginfo = True):
		if self._match_path(container):
			return True
		if loginfo:
			self._logger.debug("match_space_folder_filter: skipping SPACE FOLDER " + container['path'][0] if 'path' in container else container['name'] + " as per job configuration")
		return False

	def match_source_filter(self, container, loginfo = True):
		if self._match_path(container, is_space=True):
			return True
		if loginfo:
			self._logger.debug("match_source_filter: skipping SOURCE " + container['path'][0] if 'path' in container else container['name'] + " as per job configuration")
		return False

	def match_source_folder_filter(self, container, loginfo = True):
		if self._match_path(container):
			return True
		if loginfo:
			self._logger.debug("match_source_folder_filter: skipping SOURCE FOLDER " + container['path'][0] if 'path' in container else container['name'] + " as per job configuration")
		return False

	def match_pds_filter(self, pds, loginfo = True):
		if self._match_path(pds, is_dataset=True):
			return True
		if loginfo:
			self._logger.debug("match_pds_filter: skipping PDS " + pds['path'][-1] if 'path' in pds else pds['name'] + " as per job configuration")
		return False

	def match_vds_filter(self, vds, tags=None, loginfo = True):
		if self._match_path(vds, is_dataset=True):
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
