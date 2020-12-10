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


class DremioClonerUtils:

	_config = None

	def __init__(self, config):
		self._config = config
		return

	def normalize_path(self, path):
		# Only normalize lists, do not modify strings
		if type(path) != list:
			return path
		normalized_path = ""
		for item in path:
			normalized_path = normalized_path + item + "/"
		return normalized_path[:-1]

	def get_absolute_path(self, path, sql_context):
		path = self.normalize_path(path)
		if '/' not in path and sql_context is not None and sql_context != "":
			path = self.normalize_path(sql_context) + "/" + path
		return path

	def get_entity_desc(self, entity, verbose = False):
		if verbose or self._config.logging_verbose:
			return str(entity)
		if 'path' in entity:
			if 'entityType' in entity:
				return str(entity['entityType']) + ":" + self.normalize_path(entity['path'])
			else:
				return self.normalize_path(entity['path'])
		if 'entityType' in entity:
			if 'name' in entity:
				return str(entity['entityType']) + ":" + str(entity['name'])
			else:
				return str(entity['entityType']) + ":" + str(entity['id'])
		return str(entity['id'])

	def is_vds(self, entity):
		return entity['entityType'] == 'dataset' and entity['type'] == 'VIRTUAL_DATASET'

	def is_pds(self, entity):
		return entity['entityType'] == 'dataset' and entity['type'] == 'PHYSICAL_DATASET'

	def get_sql_context(self, entity):
		return entity["sqlContext"] if "sqlContext" in entity else None

	def search_list(self, list, key):
		for item in list:
			if key in item:
				return item[key]
		return None