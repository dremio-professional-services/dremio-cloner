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
from DremioClonerConfig import DremioClonerConfig
from DremioClonerUtils import DremioClonerUtils
from datetime import datetime
import json
import logging
import os, errno
from shutil import rmtree

class DremioFile():

	_config = None
	_utils = None

	def __init__(self, config):
		self._config = config
		self._utils = DremioClonerUtils(config)
		return

	def save_dremio_environment(self, dremio_data):
		if self._config.target_filename is not None:
			return self.save_dremio_environment_as_json_file(dremio_data)
		elif self._config.target_directory is not None:
			return self.save_dremio_environment_as_directory(dremio_data)
		else:
			raise Exception('Target filename or directory must be specified.')

	def read_dremio_environment(self):
		if self._config.source_filename is not None:
			return self.read_dremio_environment_from_json_file(self._config.source_filename)
		elif self._config.source_directory is not None:
			return self.read_dremio_environment_from_directory()
		else:
			raise Exception('Source filename or directory must be specified.')

	def save_dremio_environment_as_json_file(self, dremio_data):
		filename = self._config.target_filename
		if os.path.isfile(filename):
			os.remove(filename)
		f = open(filename, "w")
		f.write('{ "data": [')
		json.dump({'dremio_environment': [{'file_version':'0.3'},{'base_url':self._config.source_endpoint},{'timestamp_utc':str(datetime.utcnow())}]}, f)
		# Remove password if present
		for config_item in self._config.cloner_conf_json:
			if 'source' in config_item:
				for source_item in config_item['source']:
					if 'password' in source_item:
						source_item['password'] = ''
						break
		f.write(',')
		json.dump({'dremio_get_config':self._config.cloner_conf_json}, f)
		f.write(',')
		json.dump({'containers':dremio_data.containers}, f)
		if self._config.home_process_mode == 'process':
			f.write(',')
			json.dump({'homes':dremio_data.homes}, f)
		if self._config.source_process_mode == 'process':
			f.write(',')
			json.dump({'sources':dremio_data.sources}, f)
		if self._config.space_process_mode == 'process':
			f.write(',')
			json.dump({'spaces':dremio_data.spaces}, f)
		if self._config.folder_process_mode == 'process':
			f.write(',')
			json.dump({'folders':dremio_data.folders}, f)
		if self._config.pds_process_mode == 'process':
			f.write(',')
			json.dump({'pds':dremio_data.pds_list}, f)
		if self._config.vds_process_mode == 'process':
			f.write(',')
			json.dump({'vds':dremio_data.vds_list}, f)
		f.write(',')
		json.dump({'files':dremio_data.files}, f)
		if self._config.reflection_process_mode == 'process':
			f.write(',')
			json.dump({'reflections':dremio_data.reflections}, f)
		if self._config.user_process_mode == 'process':
			f.write(',')
			json.dump({'referenced_users':dremio_data.referenced_users}, f)
		if self._config.group_process_mode == 'process':
			f.write(',')
			json.dump({'referenced_groups':dremio_data.referenced_groups}, f)
		if self._config.wlm_queue_process_mode == 'process':
			f.write(',')
			json.dump({'queues':dremio_data.queues}, f)
		if self._config.wlm_rule_process_mode == 'process':
			f.write(',')
			json.dump({'rules':dremio_data.rules}, f)
		if self._config.tag_process_mode == 'process':
			f.write(',')
			json.dump({'tags':dremio_data.tags}, f)
		if self._config.wiki_process_mode == 'process':
			f.write(',')
			json.dump({'wikis':dremio_data.wikis}, f)
		if self._config.vote_process_mode == 'process':
			f.write(',')
			json.dump({'votes':dremio_data.votes}, f)
		if dremio_data.vds_parents:
			f.write(',')
			json.dump({'vds_parents':dremio_data.vds_parents}, f)
		f.write(' ] }')
		f.close()

	def read_dremio_environment_from_json_file(self, filename):
		f = open(filename, "r")
		data = json.load(f)['data']
		f.close()
		dremio_data = DremioData()
		for item in data:
			if ('dremio_environment' in item):
				logging.info("read_dremio_environment: processing environment " + str(item))
			elif ('containers' in item):
				dremio_data.containers = item['containers']
			elif ('homes' in item):
				dremio_data.homes = item['homes']
			elif ('sources' in item):
				dremio_data.sources = item['sources']
			elif ('spaces' in item):
				dremio_data.spaces = item['spaces']
			elif ('folders' in item):
				dremio_data.folders = item['folders']
			elif ('pds' in item):
				dremio_data.pds_list = item['pds']
			elif ('vds' in item):
				dremio_data.vds_list = item['vds']
			elif ('files' in item):
				dremio_data.files = item['files']
			elif ('reflections' in item):
				dremio_data.reflections = item['reflections']
			elif ('referenced_users' in item):
				dremio_data.referenced_users = item['referenced_users']
			elif ('referenced_groups' in item):
				dremio_data.referenced_groups = item['referenced_groups']
			elif ('queues' in item):
				dremio_data.queues = item['queues']
			elif ('rules' in item):
				dremio_data.rules = item['rules']
			elif ('tags' in item):
				dremio_data.tags = item['tags']
			elif ('wikis' in item):
				dremio_data.wikis = item['wikis']
			elif ('votes' in item):
				dremio_data.votes = item['votes']
			elif ('vds_parents' in item):
				dremio_data.vds_parents = item['vds_parents']
			elif ('dremio_get_config' in item):
				dremio_data.dremio_get_config = item['dremio_get_config']
			else:
				logging.warn("read_dremio_environment: unexpected data in the source file " + str(item))
		return dremio_data


	def save_dremio_environment_as_directory(self, dremio_data):
		target_directory = self._config.target_directory
		try:
			# create directory structure as needed
			if os.path.isdir(target_directory):
				rmtree(target_directory)
			os.makedirs(target_directory)
			if self._config.home_process_mode == 'process':
				os.makedirs(os.path.join(target_directory, 'homes'))
			if self._config.source_process_mode == 'process' or self._config.pds_process_mode == 'process':
				os.makedirs(os.path.join(target_directory, 'sources'))
			if self._config.space_process_mode == 'process' or self._config.vds_process_mode == 'process':
				os.makedirs(os.path.join(target_directory, 'spaces'))
			if self._config.reflection_process_mode == 'process':
				os.makedirs(os.path.join(target_directory, 'reflections'))
			if self._config.user_process_mode == 'process':
				os.makedirs(os.path.join(target_directory, 'referenced_users'))
			if self._config.group_process_mode == 'process':
				os.makedirs(os.path.join(target_directory, 'referenced_groups'))
			if self._config.wlm_queue_process_mode == 'process':
				os.makedirs(os.path.join(target_directory, 'queues'))
			if self._config.wlm_rule_process_mode == 'process':
				os.makedirs(os.path.join(target_directory, 'rules'))
			if self._config.tag_process_mode == 'process':
				os.makedirs(os.path.join(target_directory, 'tags'))
			if self._config.wiki_process_mode == 'process':
				os.makedirs(os.path.join(target_directory, 'wikis'))
			if self._config.vote_process_mode == 'process':
				os.makedirs(os.path.join(target_directory, 'votes'))
			if self._config.source_graph_support and self._config.vds_dependencies_process_mode == 'get':
				os.makedirs(os.path.join(target_directory, 'vds_parents'))
		except OSError as e:
			raise Exception("Error processing directory structure. OS Error: " + e.strerror)
		try:
			# Save configuration
			# Remove password if present
			for config_item in self._config.cloner_conf_json:
				if 'source' in config_item:
					for source_item in config_item['source']:
						if 'password' in source_item:
							source_item['password'] = ''
							break
			f = open(os.path.join(target_directory, self._config.dremio_conf_filename), "w")
			json.dump({'dremio_get_config':self._config.cloner_conf_json}, f)
			f.close()
			# Process all entities
			if self._config.home_process_mode == 'process':
				for home in dremio_data.homes:
					os.makedirs(os.path.join(target_directory, "homes", self._replace_special_characters(home['name'])))
					self._write_container_json_file(os.path.join(target_directory, "homes"), home)
			if self._config.space_process_mode == 'process':
				for space in dremio_data.spaces:
					os.makedirs(os.path.join(target_directory, "spaces", self._replace_special_characters(space['name'])))
					self._write_container_json_file(os.path.join(target_directory, "spaces"), space)
			if self._config.source_process_mode == 'process':
				for source in dremio_data.sources:
					os.makedirs(os.path.join(target_directory, "sources", self._replace_special_characters(source['name'])))
					self._write_container_json_file(os.path.join(target_directory, "sources"), source)
			if self._config.folder_process_mode == 'process' or self._config.vds_process_mode == 'process':
				for folder in dremio_data.folders:
					# ignore directory exists error, we might have created it prior
					dirpath = os.path.join(target_directory, "spaces", self._get_fs_path(folder['path']))
					if not os.path.isdir(dirpath):
						os.makedirs(dirpath)
					if self._config.folder_process_mode == 'process':
						self._write_folder_json_file(os.path.join(target_directory, "spaces"), folder)
			if self._config.vds_process_mode == 'process':
				for vds in dremio_data.vds_list:
					self._write_entity_json_file(os.path.join(target_directory, "spaces"), vds)
			if self._config.pds_process_mode == 'process':
				for pds in dremio_data.pds_list:
					self._write_entity_json_file(os.path.join(target_directory, "sources"), pds)
			if self._config.reflection_process_mode == 'process':
				for reflection in dremio_data.reflections:
					self._write_object_json_file(os.path.join(target_directory, "reflections"), reflection)
			if self._config.user_process_mode == 'process':
				for user in dremio_data.referenced_users:
					self._write_object_json_file(os.path.join(target_directory, "referenced_users"), user)
			if self._config.group_process_mode == 'process':
				for group in dremio_data.referenced_groups:
					self._write_object_json_file(os.path.join(target_directory, "referenced_groups"), group)
			if self._config.wlm_queue_process_mode == 'process':
				for queue in dremio_data.queues:
					self._write_object_json_file(os.path.join(target_directory, "queues"), queue)
			if self._config.wlm_rule_process_mode == 'process':
				for rule in dremio_data.rules:
					self._write_object_json_file(os.path.join(target_directory, "rules"), rule)
			if self._config.tag_process_mode == 'process':
				for tag in dremio_data.tags:
					self._write_tag_json_file(os.path.join(target_directory, "tags"), tag)
			if self._config.wiki_process_mode == 'process':
				for wiki in dremio_data.wikis:
					self._write_wiki_json_file(os.path.join(target_directory, "wikis"), wiki)
			if self._config.vote_process_mode == 'process':
				for vote in dremio_data.votes:
					self._write_vote_json_file(os.path.join(target_directory, "votes"), vote)
			for vds_parent in dremio_data.vds_parents:
				self._write_object_json_file(os.path.join(target_directory, "vds_parents"), vds_parent)
		except OSError as e:
			raise Exception("Error writing file. OS Error: " + e.strerror)


	def read_dremio_environment_from_directory(self):
		try:
			source_directory = self._config.source_directory
			dremio_data = DremioData()
			f = open(os.path.join(source_directory, self._config.dremio_conf_filename), "r")
			dremio_data.dremio_get_config = json.load(f)
			f.close()
			self._collect_directory(os.path.join(source_directory, 'homes'), dremio_data.homes, dremio_data.folders, dremio_data.homes)
			self._collect_directory(os.path.join(source_directory, 'spaces'), dremio_data.spaces, dremio_data.folders, dremio_data.vds_list)
			self._collect_directory(os.path.join(source_directory, 'sources'), dremio_data.sources, None, dremio_data.pds_list)
			self._collect_directory(os.path.join(source_directory, 'reflections'), None, None, dremio_data.reflections)
			self._collect_directory(os.path.join(source_directory, 'referenced_users'), None, None, dremio_data.referenced_users)
			self._collect_directory(os.path.join(source_directory, 'referenced_groups'), None, None, dremio_data.referenced_groups)
			self._collect_directory(os.path.join(source_directory, 'queues'), None, None, dremio_data.queues)
			self._collect_directory(os.path.join(source_directory, 'rules'), None, None, dremio_data.rules)
			self._collect_directory(os.path.join(source_directory, 'tags'), None, None, dremio_data.tags)
			self._collect_directory(os.path.join(source_directory, 'wikis'), None, None, dremio_data.wikis)
		except OSError as e:
			raise Exception("Error reading file. OS Error: " + e.strerror)
		return dremio_data


	def _collect_directory(self, directory, container_list, folder_list, object_list):
		for (dirpath, dirnames, filenames) in os.walk(directory):
			for filename in filenames:
				f = open(os.path.join(dirpath, filename), "r")
				data = json.load(f)
				f.close()
				if self._config.container_filename == filename:
					# First level of dirpath is a container if container_list passed
					if container_list is None or ('/' in dirpath[len(directory)+1:] or '\\' in dirpath[len(directory)+1:]):
						if folder_list is not None:
							folder_list.append(data)
					else:
						container_list.append(data)
				else:
					object_list.append(data)

	def _write_container_json_file(self, root_dir, container):
		filepath = os.path.join(root_dir, container['name'], self._config.container_filename)
		f = open(filepath, "w")
		json.dump(container, f)
		f.close()


	def _write_wiki_json_file(self, root_dir, wiki):
		filepath = os.path.join(root_dir, wiki['entity_id'] + ".json")
		f = open(filepath, "w")
		json.dump(wiki, f)
		f.close()


	def _write_tag_json_file(self, root_dir, wiki):
		filepath = os.path.join(root_dir, wiki['entity_id'] + ".json")
		f = open(filepath, "w")
		json.dump(wiki, f)
		f.close()


	def _write_object_json_file(self, root_dir, object):
		filepath = os.path.join(root_dir, object['id'] + ".json")
		f = open(filepath, "w")
		json.dump(object, f)
		f.close()


	def _write_vote_json_file(self, root_dir, object):
		filepath = os.path.join(root_dir, object['datasetId'] + ".json")
		f = open(filepath, "w")
		json.dump(object, f)
		f.close()


	def _write_folder_json_file(self, root_dir, folder):
		filepath = os.path.join(root_dir, self._get_fs_path(folder['path']), self._config.container_filename)
		f = open(filepath, "w")
		json.dump(folder, f)
		f.close()


	def _write_entity_json_file(self, root_dir, entity):
		# check if any folder needs to be created
		path = entity['path']
		filepath = root_dir
		for item in path:
			if not os.path.isdir(filepath):
				try:
					os.makedirs(filepath)
				except OSError as e:
					if e.errno != errno.EEXIST:
						raise "Cannot create directory: " + filepath
			# Replace special characters with underscore
			filepath = os.path.join(filepath, self._replace_special_characters(item))
		# write entity into json file
		f = open(filepath + ".json", "w")
		json.dump(entity, f)
		f.close()


	def _replace_special_characters(self, fs_item):
		return fs_item.replace("\\", "_").replace("/", "_")


	def _get_fs_path(self, path):
		fs_path = ""
		for item in path:
			fs_path = os.path.join(fs_path, self._replace_special_characters(item))
		return fs_path
