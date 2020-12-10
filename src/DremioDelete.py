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


class DremioDelete:

	# Dremio Cloner Config, Logger, Utils
	_config = None
	_logger = None
	_utils = None
	_filter = None

	# Dremio Environment to write to
	_dremio_env = None

	# List of PDS for processing
	_pds_list = None

	def __init__(self, dremio, config):
		self._config = config
		self._dremio_env = dremio
		self._logger = DremioClonerLogger(self._config.max_errors, self._config.logging_verbose)
		self._utils = DremioClonerUtils(config)
		self._filter = DremioClonerFilter(config)

	def delete(self):
		# Delete VDSs
		if (self._config.vds_process_mode != "delete"):
			self._logger.info("delete: Not deleting VDS as per 'vds.process_mode' configuration")
		else:
			for vds_path in self._config.delete_vds:
				vds_json = self._dremio_env.get_catalog_entity_by_path(vds_path, report_error=True)
				if (vds_json is None):
					self._logger.error("delete: unable to find VDS for path: '" + vds_path + "'")
				else:
					self._dremio_env.delete_catalog_entity(vds_json["id"], dry_run = self._config.dry_run, report_error=True)
		# Delete Folders
		if (self._config.folder_process_mode != "delete"):
			self._logger.info("delete: Not deleting Folders as per 'folder.process_mode' configuration")
		else:
			for folder_path in self._config.delete_folders:
				folder_json = self._dremio_env.get_catalog_entity_by_path(folder_path, report_error=True)
				if (folder_json is None):
					self._logger.error("delete: unable to find Folder for path: '" + folder_path + "'")
				else:
					self._dremio_env.delete_catalog_entity(folder_json["id"], dry_run = self._config.dry_run, report_error=True)

	def get_errors_count(self):
		return self._logger.errors_encountered