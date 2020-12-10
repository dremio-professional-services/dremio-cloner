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

from DremioData import DremioData
from datetime import datetime
import json
from DremioClonerUtils import DremioClonerUtils


class DremioReportAcl:

	# Dremio Cloner Configuration
	_config = None

	# Dremio object pointing to the source Dremio environment
	_dremio_env = None

	# DremioData object containing data from Dremio source environment 
	_d = None

	# Dremio Utils
	_utils = None

	# File descriptor
	_f = None

	# Misc
	_delimeter = None
	_newline = None

	def __init__(self, source_dremio, dremio_data, config):
		self._config = config
		self._dremio_env = source_dremio
		self._d = dremio_data
		self._delimeter = self._config.report_csv_delimiter
		self._newline = self._config.report_csv_newline
		self._utils = DremioClonerUtils(config)

	def save_dremio_report_acl(self):
		self._f = open(self._config.target_filename, "w")
		self._f.write('catalog_id' + self._delimeter + 'name' + self._delimeter + 'path' + self._delimeter +
			'entity_type' + self._delimeter + 'source_type' + self._delimeter + 'acl_protected' + self._delimeter +
			'user_id' + self._delimeter + 'user_name' + self._delimeter +
			'group_id' + self._delimeter + 'group_name' + self._delimeter +
			'read' + self._delimeter + 'write' + self._delimeter + 'location' + self._delimeter + 'vds_sql' + self._newline)

		for source in self._d.sources:
			self._write_acl_lines(source, 'SOURCE')

		for space in self._d.spaces:
			self._write_acl_lines(space, 'SPACE')

		for folder in self._d.folders:
			self._write_acl_lines(folder, 'FOLDER')

		for pds in self._d.pds_list:
			self._write_acl_lines(pds, 'PDS')

		for vds in self._d.vds_list:
			self._write_acl_lines(vds, 'VDS')

		for entity in self._d.pds_error_list:
			self._write_error(entity, 'PDS')

		self._f.close()

	def _write_acl_lines(self, entity, entity_type):
		# catalog_id, name, path, entity_type, source_type, 
		acl_line_prefix = str(entity['id']) + self._delimeter + \
					(str(entity['name']) if 'name' in entity else '') + self._delimeter + \
					(self._normalize_path(entity['path']) if 'path' in entity else '') + self._delimeter + \
					entity_type + self._delimeter + \
					'' + self._delimeter
		# location, vds_sql \n
		acl_line_suffix = ''
		# Add location for PDS
		if entity_type == 'PDS' and 'format' in entity and 'location' in entity['format']:
			acl_line_suffix = acl_line_suffix + str(entity['format']['location']) + self._delimeter
		else:
			acl_line_suffix = acl_line_suffix + self._delimeter
		# Add SQL for VDS
		if entity_type == 'VDS':
			acl_line_suffix = acl_line_suffix + str(entity['sql']).replace('\n', ' ') + self._newline
		else:
			acl_line_suffix = acl_line_suffix + self._newline

		if 'accessControlList' in entity:
			if 'users' in entity['accessControlList']:
				for user in entity['accessControlList']['users']:
					# acl_protected, user_id, user_name, group_id, group_name,
					acl_line = 'true' + self._delimeter + user['id'] + self._delimeter + self._get_user_name(user['id']) + self._delimeter + self._delimeter + self._delimeter
					read_permission = False
					write_permission = False
					for permission in user['permissions']:
						if permission == 'READ':
							read_permission = True
						elif permission == 'WRITE':
							write_permission = True
					# read, write,
					acl_line = acl_line + str(read_permission).lower() + self._delimeter + str(write_permission).lower() + self._delimeter
					self._f.write(acl_line_prefix + acl_line + acl_line_suffix)
			if 'groups' in entity['accessControlList']:
				for group in entity['accessControlList']['groups']:
					# acl_protected, user_id, user_name, group_id, group_name,
					acl_line = 'true' + self._delimeter+ self._delimeter + self._delimeter + group['id'] + self._delimeter + self._get_group_name(group['id']) + self._delimeter
					read_permission = False
					write_permission = False
					for permission in group['permissions']:
						if permission == 'READ':
							read_permission = True
						elif permission == 'WRITE':
							write_permission = True
					# read, write,
					acl_line = acl_line + str(read_permission).lower() + self._delimeter + str(write_permission).lower() + self._delimeter
					self._f.write(acl_line_prefix + acl_line + acl_line_suffix)
		if 'accessControlList' not in entity or ('users' not in entity['accessControlList'] and 'groups' not in entity['accessControlList']):
			# acl_protected, user_id, user_name, group_id, group_name, read, write,
			acl_line = 'false' + self._delimeter + self._delimeter + self._delimeter + self._delimeter + self._delimeter + self._delimeter + self._delimeter
			self._f.write(acl_line_prefix + acl_line + acl_line_suffix)

	def _write_error(self, entity, entity_type):
		self._f.write('ERROR reading Dremio Entity. Review LOG file.' + self._delimeter + entity['name'] +
					  self._delimeter + entity['path'] + self._delimeter +
					  entity_type + self._delimeter + '' + self._delimeter + '' + self._delimeter +
					  '' + self._delimeter + '' + self._delimeter +
					  '' + self._delimeter + '' + self._delimeter +
					  '' + self._delimeter + '' + self._delimeter + '' + self._delimeter + '' + self._newline)

	def _get_user_name(self, user_id):
		for user in self._d.referenced_users:
			if user['id'] == user_id:
				return user['name']

	def _get_group_name(self, group_id):
		for group in self._d.referenced_groups:
			if group['id'] == group_id:
				return group['name']

	def _normalize_path(self, path):
		new_path = []
		for item in path:
			new_path.append(str(item))
		return str(new_path)
