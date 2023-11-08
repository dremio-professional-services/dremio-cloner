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

import logging, sys
import json
import os
import fnmatch, re
from DremioClonerLogger import DremioClonerLogger

class DremioClonerConfig():

	# Dremio Utils
	_utils = None
	_logger = None

	CMD_GET = 'get'
	CMD_PUT = 'put'
	CMD_CASCADE_ACL = 'cascade-acl'
	CMD_DESCRIBE_JOB = 'describe-job'
	CMD_REPORT_ACL = 'report-acl'
	CMD_REPORT_REFLECTIONS = 'report-reflections'
	CMD_DELETE = 'delete-beta'

	# Config json code
	cloner_conf_json = None
	# Command to execute: put, get, cp, report-acl, cascade-acl
	command = None
	dry_run = True
	# Source Dremio Environment definition
	source_endpoint = None
	source_verify_ssl = True
	source_username = None
	source_password = None
	source_filename = None
	source_directory = None
	source_ce = False
	source_graph_support = False
	source_rbac = False
	source_dremio_cloud = False
	source_dremio_cloud_org_id = None
	source_dremio_cloud_project_id = None

	job_sql = None
	# Target Dremio Environment definition
	target_ce = False
	target_endpoint = None
	target_accept_eula = False
	target_verify_ssl = True
	target_username = None
	target_password = None
	target_filename = None
	target_directory = None
	target_file_or_dir_overwrite = False
	target_separate_sql_and_metadata_files = False
	target_type = None
	target_dremio_cloud = False
	target_dremio_cloud_org_id = None
	target_dremio_cloud_project_id = None
	container_filename = "___container.json"
	dremio_conf_filename = "___dremio_cloner_conf.json"
	# Options
	max_errors = 9999
	http_timeout = 10 # seconds
	# Logging options
	logging_level = logging.INFO
	logging_format = "%(levelname)s:%(asctime)s:%(message)s"
	logging_filename = None
	logging_verbose = False
	# Processing 
	user_process_mode = None				# Flag to process User: process, skip
	group_process_mode = None				# Flag to process Group: process, skip
	space_filter = None						# Filter for Space entity type
	space_filter_names = []					# List of Spaces to process if not empty
	space_exclude_filter = None				# Exclusion Filter for Space entity type
	space_cascade_acl_origin_override_object = None	# An ACL from this object will be utilized instead of the Space ACL as an ACL to set inside all Folders and VDSs in the Space
	space_folder_filter = None				# Filter for Space Folder entity type
	space_folder_filter_paths = []  		# List of Space Folder paths (as regex) to process if not empty
	space_folder_exclude_filter = None		# Exclusion Filter for Space Folder entity type
	space_folder_exclude_filter_paths = []	# List of Space Folder paths (as regex) to exclude if not empty
	space_folder_cascade_acl_origin_filter = None	# Filter for folders that will be used as ACL origins if specified
	space_process_mode = None				# Flag to process Space: process, skip, create_only, update_only, create_overwrite
	space_ignore_missing_acl_user = False	# Flag to write a Space if an ACL user is missing in the target Dremio environment
	space_ignore_missing_acl_group = False	# Flag to write a Space if an ACL group is missing in the target Dremio environment
	source_filter = None					# Filter for Source entity type
	source_filter_names = []				# List of Sources to process if not empty
	source_filter_types = []				# List of Source Types to process if not empty
	source_exclude_filter = None			# Exclusion Filter for Source entity type
	source_cascade_acl_origin_override_object = None	# An ACL from this object will be utilized instead of the Source ACL as an ACL to set inside all PDS in the Source
	source_folder_filter = None				# Filter for Source Folder entity type
	source_folder_filter_paths = []  		# List of Source Folder paths (as regex) to process if not empty
	source_folder_exclude_filter = None		# Exclusion Filter for Source Folder entity type
	source_process_mode = None				# Flag to process Sources: process, skip, create_only, update_only, create_overwrite
	source_ignore_missing_acl_user = False	# Flag to write a Source if an ACL user is missing in the target Dremio environment
	source_ignore_missing_acl_group = False	# Flag to write a Source if an ACL group is missing in the target Dremio environment
	source_retry_timedout = False			# Flag to retry Sources that timed out
	folder_process_mode = None				# Flag to process Folder: process, skip, create_only, update_only, create_overwrite, create_overwrite_delete
	folder_ignore_missing_acl_user = False	# Flag to write a Folder if an ACL user is missing in the target Dremio environment
	folder_ignore_missing_acl_group = False	# Flag to write a Folder if an ACL group is missing in the target Dremio environment
	pds_list_useapi = False					# Using API for listing PDS may cause issues when the source is not available at the runtime
	pds_filter = None						# Filter for PDS
	pds_filter_names = []  					# List of PDSs to process if not empty
	pds_exclude_filter = None				# Exclusion Filter for PDS
	pds_process_mode = None					# Flag to process Source PDS: process, skip, promote
	pds_ignore_missing_acl_user = False		# Flag to write a Source PDS if an ACL user is missing in the target Dremio environment
	pds_ignore_missing_acl_group = False	# Flag to write a Source PDS if an ACL group is missing in the target Dremio environment
	vds_filter = None						# Filter for VDS
	vds_filter_names = []  					# List of VDSs to process if not empty
	vds_filter_tag = None					# Filter for VDS
	vds_exclude_filter = None				# Exclusion Filter for VDS
	vds_exclude_filter_paths = []			# List of VDS paths (as regex) to exclude if not empty
	vds_process_mode = None					# Flag to process VDS: process, skip, create_only, update_only, create_overwrite, create_overwrite_delete
	vds_dependencies_process_mode = 'ignore' # Flag to process VDS dependencies (VDS and PDS): ignore, get
	vds_ignore_missing_acl_user = False		# Flag to write a VDS if an ACL user is missing in the target Dremio environment
	vds_ignore_missing_acl_group = False	# Flag to write a VDS if an ACL group is missing in the target Dremio environment
	vds_max_hierarchy_depth = 100			# The max hierarchy depth to process
	reflection_process_mode = None			# Flag to process reflection: process, skip, create_only, update_only, create_overwrite, create_overwrite_delete
	reflection_filter_mode = None			# Flag to filter reflection: apply_vds_pds_filter
	reflection_id_include_list = []			# List of reflection ids to include. Empty list means include all reflections which is the default behaviour
	reflection_refresh_mode = 'skip' 		# Flag to refresh reflections: refresh, skip
	reflection_only_matching_vds = False 	# Flag to export only reflections which have a matching VDS. The old and standard behavior is exporting all reflections, regardless
	wlm_queue_process_mode = 'process'		# Flag to process WLM Queues: process, skip
	wlm_rule_process_mode = 'process'		# Flag to process WLM Rules: process, skip
	wiki_process_mode = 'process'			# Flag to process Wikis: process, skip, create_only, update_only, create_overwrite
	tag_process_mode ='process'				# Flag to process Tags: process, skip
	home_process_mode = 'process'			# Flag to process Homes: process, skip
	vote_process_mode = 'process'			# Flag to process Votes: process, skip
	acl_transformation = {}					# Contains all ACL transformation definitions
	source_transformation = {}  			# Contains all source transformation definitions
	# Delete VDS List
	delete_vds = []							# List of VDS to delete from the target environment
	delete_folders = []						# List of Folders to delete from the target environment


	# Report options
	report_csv_delimiter = "\t"
	report_csv_newline = "\n"
	# Misc options
	# Compiled filters
	_space_filter_re = None
	_space_exclude_filter_re = None
	_space_folder_filter_re = None
	_space_folder_exclude_filter_re = None
	_space_folder_cascade_acl_origin_filter_re = None
	_source_filter_re = None
	_source_exclude_filter_re = None
	_source_folder_filter_re = None
	_source_folder_exclude_filter_re = None
	_pds_filter_re = None
	_pds_exclude_filter_re = None
	_vds_filter_re = None
	_vds_exclude_filter_re = None

	def __init__(self, config_file_name):
		# Read configuration file
		if sys.version_info.major > 2:
			f_open = lambda filename: open(filename, "r",encoding='utf-8')
		else:
			f_open = lambda filename: open(filename, "r")

		f = f_open(config_file_name)

		cloner_conf_json_tmp = json.load(f)
		stdout_logging = False
		if 'dremio_get_config' in cloner_conf_json_tmp:
			self.cloner_conf_json = cloner_conf_json_tmp['dremio_get_config']
			stdout_logging = True
		elif 'data' in cloner_conf_json_tmp:
			for el in cloner_conf_json_tmp['data']:
				if 'dremio_get_config' in el:
					self.cloner_conf_json = el['dremio_get_config']
					stdout_logging = True
					break
		else:
			# old behaviour
			self.cloner_conf_json = cloner_conf_json_tmp['dremio_cloner']

		f.close()
		for element in self.cloner_conf_json:
			if 'command' in element:
				self._process_command(element)
			elif 'source' in element:
				self._process_source(element)
			elif 'target' in element:
				self._process_target(element)
			elif 'options' in element:
				self._process_options(element)
		if self.logging_filename == "STDOUT" or stdout_logging:
			root = logging.getLogger()
			root.setLevel(self.logging_level)
			handler = logging.StreamHandler(sys.stdout)
			handler.setLevel(logging.DEBUG)
			formatter = logging.Formatter(self.logging_format)
			handler.setFormatter(formatter)
			root.addHandler(handler)
			handler = logging.StreamHandler(sys.stderr)
			handler.setLevel(logging.ERROR)
			formatter = logging.Formatter(self.logging_format)
			handler.setFormatter(formatter)
			root.addHandler(handler)
		else:
			handlers = [logging.FileHandler(filename=self.logging_filename, encoding='utf-8', mode='a+')]
			logging.basicConfig(handlers=handlers, format=self.logging_format, level=self.logging_level)
		self._logger = DremioClonerLogger(self.max_errors, self.logging_verbose)
		self._validate_configuration()

	def _process_command(self, json_conf):
		self.command = json_conf['command']

	def _process_target(self, json_conf):
		for item in json_conf['target']:
			if 'endpoint' in item:
				self.target_endpoint = item['endpoint']
			if 'accept_eula' in item:
				self.target_accept_eula = self._bool(item, 'accept_eula')
			elif 'username' in item:
				self.target_username = item['username']
			elif 'password' in item:
				self.target_password = item['password']
			elif 'filename' in item:
				self.target_filename = item['filename']
			elif 'directory' in item:
				self.target_directory = item['directory']
			elif 'overwrite' in item:
				self.target_file_or_dir_overwrite = self._bool(item, 'overwrite')
			elif 'separate_sql_and_metadata_files' in item:
				self.target_separate_sql_and_metadata_files = self._bool(item, 'separate_sql_and_metadata_files')
			elif 'verify_ssl' in item:
				self.target_verify_ssl = self._bool(item, 'verify_ssl')
			elif 'is_community_edition' in item:
				self.target_ce = self._bool(item, 'is_community_edition')
			elif 'target.type' in item:
				self.target_type = self._str(item, 'target.type')
			elif 'is_dremio_cloud' in item:
				self.target_dremio_cloud = self._bool(item, 'is_dremio_cloud')
			elif 'dremio_cloud_org_id' in item:
				self.target_dremio_cloud_org_id = item['dremio_cloud_org_id']
			elif 'dremio_cloud_project_id' in item:
				self.target_dremio_cloud_project_id = item['dremio_cloud_project_id']

	def _process_source(self, json_conf):
		for item in json_conf['source']:
			if 'endpoint' in item:
				self.source_endpoint = item['endpoint']
			elif 'username' in item:
				self.source_username = item['username']
			elif 'password' in item:
				self.source_password = item['password']
			elif 'filename' in item:
				self.source_filename = item['filename']
			elif 'directory' in item:
				self.source_directory = item['directory']
			elif 'verify_ssl' in item:
				self.source_verify_ssl = self._bool(item, 'verify_ssl')
			elif 'is_community_edition' in item:
				self.source_ce = self._bool(item, 'is_community_edition')
			elif 'graph_api_support' in item:
				self.source_graph_support = self._bool(item, 'graph_api_support')
			elif 'job-sql' in item:
				self.job_sql = self._str(item, 'job-sql')
			elif 'is_rbac_version' in item:
				self.source_rbac = self._bool(item, 'is_rbac_version')
			elif 'is_dremio_cloud' in item:
				self.source_dremio_cloud = self._bool(item, 'is_dremio_cloud')
			elif 'dremio_cloud_org_id' in item:
				self.source_dremio_cloud_org_id = item['dremio_cloud_org_id']
			elif 'dremio_cloud_project_id' in item:
				self.source_dremio_cloud_project_id = item['dremio_cloud_project_id']

	def _process_options(self, json_conf):
		for item in json_conf['options']:
			if 'dry_run' in item:
				self.dry_run = self._bool(item, 'dry_run')
			elif 'max_errors' in item:
				self.max_errors = self._eval(item, 'max_errors')
			elif 'logging.level' in item:
				self.logging_level = self._eval(item, 'logging.level')
			elif 'logging.format' in item:
				self.logging_format = self._str(item, 'logging.format')
			elif 'logging.filename' in item:
				self.logging_filename  = self._str(item, 'logging.filename')
			elif 'logging.verbose' in item:
				self.logging_verbose  = self._bool(item, 'logging.verbose')
			elif 'http_timeout' in item:
				self.http_timeout = self._int(item, 'http_timeout')
			elif 'user.process_mode' in item:
				self.user_process_mode = self._str(item, 'user.process_mode')
			elif 'group.process_mode' in item:
				self.group_process_mode = self._str(item, 'group.process_mode')
			elif 'space.process_mode' in item:
				self.space_process_mode = self._str(item, 'space.process_mode')
			elif 'space.filter' in item:
				self.space_filter = self._str(item, 'space.filter')
				self._space_filter_re = self._compile_pattern(self.space_filter)
			elif 'space.filter.names' in item:
				self.space_filter_names = self._array(item, 'space.filter.names')
			elif 'space.exclude.filter' in item:
				self.space_exclude_filter = self._str(item, 'space.exclude.filter')
				self._space_exclude_filter_re = self._compile_pattern(self.space_exclude_filter)
			elif 'space.cascade-acl-origin.override-object' in item:
				self.space_cascade_acl_origin_override_object = self._str(item, 'space.cascade-acl-origin.override-object')
			elif 'space.folder.filter' in item:
				self.space_folder_filter = self._str(item, 'space.folder.filter')
				self._space_folder_filter_re = self._compile_pattern(self.space_folder_filter)
			elif 'space.folder.filter.paths' in item:
				self.space_folder_filter_paths = self._array(item, 'space.folder.filter.paths')
			elif 'space.folder.exclude.filter' in item:
				self.space_folder_exclude_filter = self._str(item, 'space.folder.exclude.filter')
				self._space_folder_exclude_filter_re = self._compile_pattern(self.space_folder_exclude_filter)
			elif 'space.folder.exclude.filter.paths' in item:
				self.space_folder_exclude_filter_paths = self._array(item, 'space.folder.exclude.filter.paths')
			elif 'space.folder.cascade-acl-origin.filter' in item:
				self.space_folder_cascade_acl_origin_filter = self._str(item, 'space.folder.cascade-acl-origin.filter')
				self._space_folder_cascade_acl_origin_filter_re = self._compile_pattern(self.space_folder_cascade_acl_origin_filter)
			elif 'space.ignore_missing_acl_user' in item:
				self.space_ignore_missing_acl_user = self._bool(item, 'space.ignore_missing_acl_user')
			elif 'space.ignore_missing_acl_group' in item:
				self.space_ignore_missing_acl_group = self._bool(item, 'space.ignore_missing_acl_group')
			elif 'source.process_mode' in item:
				self.source_process_mode = self._str(item, 'source.process_mode')
			elif 'source.filter.names' in item:
				self.source_filter_names = self._array(item, 'source.filter.names')
			elif 'source.filter.types' in item:
				self.source_filter_types = self._array(item, 'source.filter.types')
			elif 'source.filter' in item:
				self.source_filter = self._str(item, 'source.filter')
				self._source_filter_re = self._compile_pattern(self.source_filter)
			elif 'source.exclude.filter' in item:
				self.source_exclude_filter = self._str(item, 'source.exclude.filter')
				self._source_exclude_filter_re = self._compile_pattern(self.source_exclude_filter)
			elif 'source.folder.filter' in item:
				self.source_folder_filter = self._str(item, 'source.folder.filter')
				self._source_folder_filter_re = self._compile_pattern(self.source_folder_filter)
			elif 'source.folder.filter.paths' in item:
				self.source_folder_filter_paths = self._array(item, 'source.folder.filter.paths')
			elif 'source.cascade-acl-origin.override-object' in item:
				self.source_cascade_acl_origin_override_object = self._str(item, 'source.cascade-acl-origin.override-object')
			elif 'source.folder.exclude.filter' in item:
				self.source_folder_exclude_filter = self._str(item, 'source.folder.exclude.filter')
				self._source_folder_exclude_filter_re = self._compile_pattern(self.source_folder_exclude_filter)
			elif 'source.ignore_missing_acl_user' in item:
				self.source_ignore_missing_acl_user = self._bool(item, 'source.ignore_missing_acl_user')
			elif 'source.ignore_missing_acl_group' in item:
				self.source_ignore_missing_acl_group = self._bool(item, 'source.ignore_missing_acl_group')
			elif 'source.retry_timedout' in item:
				self.source_retry_timedout = self._bool(item, 'source.retry_timedout')
			elif 'folder.process_mode' in item:
				self.folder_process_mode = self._str(item, 'folder.process_mode')
			elif 'folder.ignore_missing_acl_user' in item:
				self.folder_ignore_missing_acl_user = self._bool(item, 'folder.ignore_missing_acl_user')
			elif 'folder.ignore_missing_acl_group' in item:
				self.folder_ignore_missing_acl_group = self._bool(item, 'folder.ignore_missing_acl_group')
			elif 'pds.process_mode' in item:
				self.pds_process_mode = self._str(item, 'pds.process_mode')
			elif 'pds.list.useapi' in item:
				self.pds_list_useapi = self._bool(item, 'pds.list.useapi')
			elif 'pds.filter' in item:
				self.pds_filter = self._str(item, 'pds.filter')
				self._pds_filter_re = self._compile_pattern(self.pds_filter)
			elif 'pds.filter.names' in item:
				self.pds_filter_names = self._array(item, 'pds.filter.names')
			elif 'pds.exclude.filter' in item:
				self.pds_exclude_filter = self._str(item, 'pds.exclude.filter')
				self._pds_exclude_filter_re = self._compile_pattern(self.pds_exclude_filter)
			elif 'pds.ignore_missing_acl_user' in item:
				self.pds_ignore_missing_acl_user = self._bool(item, 'pds.ignore_missing_acl_user')
			elif 'pds.ignore_missing_acl_group' in item:
				self.pds_ignore_missing_acl_group = self._bool(item, 'pds.ignore_missing_acl_group')
			elif 'vds.process_mode' in item:
				self.vds_process_mode = self._str(item, 'vds.process_mode')
			elif 'vds.dependencies.process_mode' in item:
				self.vds_dependencies_process_mode = self._str(item, 'vds.dependencies.process_mode')
			elif 'vds.filter' in item:
				self.vds_filter = self._str(item, 'vds.filter')
				self._vds_filter_re = self._compile_pattern(self.vds_filter)
			elif 'vds.filter.names' in item:
				self.vds_filter_names = self._array(item, 'vds.filter.names')
			elif 'vds.filter.tag' in item:
				self.vds_filter_tag = self._str(item, 'vds.filter.tag')
			elif 'vds.exclude.filter' in item:
				self.vds_exclude_filter = self._str(item, 'vds.exclude.filter')
				self._vds_exclude_filter_re = self._compile_pattern(self.vds_exclude_filter)
			elif 'vds.exclude.filter.paths' in item:
				self.vds_exclude_filter_paths = self._array(item, 'vds.exclude.filter.paths')
			elif 'vds.ignore_missing_acl_user' in item:
				self.vds_ignore_missing_acl_user = self._bool(item, 'vds.ignore_missing_acl_user')
			elif 'vds.ignore_missing_acl_group' in item:
				self.vds_ignore_missing_acl_group = self._bool(item, 'vds.ignore_missing_acl_group')
			elif 'vds.max_hierarchy_depth' in item:
				self.vds_max_hierarchy_depth = self._int(item, 'vds.max_hierarchy_depth')
			# Reflection options
			elif 'reflection.process_mode' in item:
				self.reflection_process_mode = self._str(item, 'reflection.process_mode')
			elif 'reflection.filter_mode' in item:
				self.reflection_filter_mode = self._str(item, 'reflection.filter_mode')
			elif 'pds.reflection_refresh_mode' in item:
				self.reflection_refresh_mode = self._str(item, 'pds.reflection_refresh_mode')
			elif 'reflection.id_include_list' in item:
				self.reflection_id_include_list = self._array(item, 'reflection.id_include_list')
			elif 'reflection.only_for_matching_vds' in item:
				self.reflection_only_matching_vds = self._bool(item, 'reflection.only_for_matching_vds')
			# Report Options
			elif 'report.csv.delimiter' in item:
				self.report_csv_delimiter = self._str(item, 'report.csv.delimiter')
			elif 'report.csv.newline' in item:
				self.report_csv_newline = self._str(item, 'report.csv.newline')
			# Misc options
			elif 'wlm.queue.process_mode' in item:
				self.wlm_queue_process_mode = self._str(item, 'wlm.queue.process_mode')
			elif 'wlm.rule.process_mode' in item:
				self.wlm_rule_process_mode = self._str(item, 'wlm.rule.process_mode')
			elif 'wiki.process_mode' in item:
				self.wiki_process_mode = self._str(item, 'wiki.process_mode')
			elif 'tag.process_mode' in item:
				self.tag_process_mode = self._str(item, 'tag.process_mode')
			elif 'home.process_mode' in item:
				self.home_process_mode = self._str(item, 'home.process_mode')
			elif 'vote.process_mode' in item:
				self.vote_process_mode = self._str(item, 'vote.process_mode')
			elif 'transformation' in item:
				if 'acl' in item['transformation']:
					acl_transformation_filename = self._str(item['transformation']['acl'], 'file')
					f = open(acl_transformation_filename, "r")
					self.acl_transformation = json.load(f)['acl-transformation']
					f.close()
				if 'source' in item['transformation']:
					source_transformation_filename = self._str(item['transformation']['source'], 'file')
					f = open(source_transformation_filename, "r")
					self.source_transformation = json.load(f)['source-transformation']
					f.close()
			elif 'vds.delete_list' in item:
				self.delete_vds = self._str_array(item, 'vds.delete_list')
			elif 'folder.delete_list' in item:
				self.delete_folders = self._str_array(item, 'folder.delete_list')

	def _validate_configuration(self):
		if (self.command is None):
			self._logger.fatal("missing 'command' entry.")
		elif self.command == self.CMD_GET and (self.source_endpoint is None or self.source_username is None or self.source_password is None or (self.target_filename is None and self.target_directory is None)):
			self._logger.fatal("Invalid configuration for command 'get'.")
		elif self.command == self.CMD_PUT and ((self.source_filename is None and self.source_directory is None) or self.target_endpoint is None or self.target_username is None or self.target_password is None):
			self._logger.fatal("Invalid configuration for command 'get'.")
		elif self.command == self.CMD_REPORT_ACL and (self.source_endpoint is None or self.source_username is None or self.source_password is None or self.target_filename is None):
			self._logger.fatal("Invalid configuration for command 'report-acl'.")

		if (self.command == self.CMD_PUT and (self.space_process_mode is None or
			     (self.space_process_mode != 'skip' and self.space_process_mode != 'update_only' and 
			     	self.space_process_mode != 'create_only' and self.space_process_mode != 'create_overwrite'))):
			self._logger.fatal("Invalid configuration for space.process_mode.")
		if (self.command == self.CMD_PUT and (self.source_process_mode is None or
			     (self.source_process_mode != 'skip' and self.source_process_mode != 'update_only' and 
			     	self.source_process_mode != 'create_only' and self.source_process_mode != 'create_overwrite'))):
			self._logger.fatal("Invalid configuration for source.process_mode.")
		if (self.command == self.CMD_PUT and (self.pds_process_mode is None or
			     (self.pds_process_mode != 'skip' and self.pds_process_mode != 'promote'))):
			self._logger.fatal("Invalid configuration for pds.process_mode.")
		if (self.command == self.CMD_PUT and (self.vds_process_mode is None or
			     (self.vds_process_mode != 'skip' and self.vds_process_mode != 'update_only' and 
			     	self.vds_process_mode != 'create_only' and self.vds_process_mode != 'create_overwrite' and
				 	self.vds_process_mode != 'create_overwrite_delete' ))):
			self._logger.fatal("Invalid configuration for vds.process_mode.")
		# Make sure we do not overwrite JSON environment file
		if (self.command == self.CMD_GET and self.target_filename is not None and not self.target_file_or_dir_overwrite and os.path.isfile(self.target_filename)):
			self._logger.fatal("File " + str(self.target_filename) + " already exists. Cannot overwrite.")
		if (self.command == self.CMD_GET and self.target_directory is not None and not self.target_file_or_dir_overwrite and os.path.isdir(self.target_directory)):
			self._logger.fatal("Directory " + str(self.target_directory) + " already exists. Cannot overwrite.")
		if (self.command == self.CMD_REPORT_ACL and os.path.isfile(self.target_filename)):
			self._logger.fatal("File " + str(self.target_filename) + " already exists. Cannot overwrite.")
		if self.command == self.CMD_REPORT_ACL:
			# make sure sources and PDSs get processed
			self.source_process_mode = "process"
			self.pds_process_mode = "process"

	def _bool(self, conf, param_name):
		if (param_name in conf):
			try:
				return eval(conf[param_name].title())
			except NameError:
				self._logger.fatal("Invalid boolean value for parameter " + param_name)
		else:
			return None

	def _array(self, conf, param_name):
		if (param_name in conf):
			try:
				return conf[param_name]
			except:
				self._logger.fatal("Invalid array value for parameter " + param_name)
		else:
			return None

	def _int(self, conf, param_name):
		if (param_name in conf):
			try:
				return int(conf[param_name])
			except:
				self._logger.fatal("Invalid integer value for parameter " + param_name)
		else:
			return None

	def _str(self, conf, param_name):
		if (param_name in conf and not conf[param_name] == ""):
			return conf[param_name]
		return None

	def _str_array(self, conf, param_name):
		if (param_name in conf and not conf[param_name] == ""):
			return conf[param_name]
		return None

	def _eval(self, conf, param_name):
		if (param_name in conf):
			try:
				return eval(conf[param_name])
			except:
				self._logger.fatal("Invalid value for parameter " + param_name)
		else:
			return None
 

	def _compile_pattern(self, pattern):
		if pattern is None:
			return None
		return re.compile(fnmatch.translate(pattern))

