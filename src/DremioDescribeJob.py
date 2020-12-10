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
from DremioClonerConfig import DremioClonerConfig
from DremioClonerUtils import DremioClonerUtils
from DremioClonerLogger import DremioClonerLogger
import parse_sql


class DremioDescribeJob:

	# Dremio Cloner Configuration, Utils, ...
	_config = None
	_utils = None
	_logger = None

	# Dremio Environment to write to
	_dremio_env = None

	# Working lists
	_pds_list = []
	_vds_list = []
	_final_sql = ""

	def __init__(self, source_dremio, config):
		self._config = config
		self._dremio_env = source_dremio
		self._logger = DremioClonerLogger(self._config.max_errors, self._config.logging_verbose)
		self._utils = DremioClonerUtils(config)

	def describe_job_sql_dependencies(self):
		sql = self._config.job_sql
		self._process_sql(sql)
		# Write output files
		pass
		a= 1

	# recursive function
	def _process_sql(self, sql, sql_context = None):
		if sql_context is not None:
			schema = self._utils.normalize_path(sql_context) + "/"
		else:
			schema = ""
		paths = parse_sql.tables_in_query(sql)
		# Collect all PDS and VDS with the entire dependency hierarchy
		for path in paths:
			self._discover_dependencies(schema + path)
		# Create SQL statements for all dependencies
		for pds in self._pds_list:
			self._process_pds(pds)
		for vds in self._vds_list:
			self._process_vds(vds)
		# Write file
		self._write_file()

	def _discover_dependencies(self, path):
		dataset = self._dremio_env.get_catalog_entity_by_path(path)
		if dataset is not None:
			if dataset['type'] == 'VIRTUAL_DATASET':
				self._vds_list.append(dataset)
			elif dataset['type'] == 'PHYSICAL_DATASET':
				self._pds_list.append(dataset)
				return
			else:
				self._logger.fatal("_discover_dependencies: Unknown Entity Type: " + dataset['type'])
		else:
			self._logger.fatal("_discover_dependencies: Could not resolve dependency: " + path)
		# Process recursive dependencies
		sql_dependency_paths = parse_sql.tables_in_query(dataset['sql'])
		for dataset_dependency_path in sql_dependency_paths:
			sql_context = self._utils.get_sql_context(dataset)
			self._discover_dependencies(self._utils.get_absolute_path(dataset_dependency_path, sql_context))

	def _process_pds(self, pds):
		fields = pds['fields']
		sql_context = self._utils.get_sql_context(pds)
		name = pds['path'][-1:][0]
		stmt = 'CREATE TABLE ' + name + ' ('
		for field in fields:
			stmt = stmt + field['name'] + ' ' + field['type']['name'] + ', '
		stmt = stmt[:-2] + ')'
		comment = '-- PDS: ' + self._utils.get_absolute_path(pds['path'], sql_context)
		self._final_sql = self._final_sql + comment + "\n" + stmt + ";\n\n"

	def _process_vds(self, vds):
		fields = vds['fields']
		sql_context = self._utils.get_sql_context(vds)
		name = vds['path'][-1:][0]
		vds_sql = vds['sql']
		stmt = 'CREATE VIEW ' + name + ' AS ' + vds_sql + ";\n"
		comment = '-- VDS: ' + self._utils.get_absolute_path(vds['path'], sql_context)
		self._final_sql = self._final_sql + comment + "\n" + stmt + ";\n\n"

	def _write_file(self):
		f = open(self._config.target_filename, "w")
		f.write(self._final_sql)
		f.close()

	def get_errors_count(self):
		return self._looger.errors_encountered