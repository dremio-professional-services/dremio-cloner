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
import time
from DremioClonerUtils import DremioClonerUtils
from DremioClonerLogger import DremioClonerLogger


class DremioReportReflections:

	# Dremio Cloner Configuration, Utils, ...
	_config = None
	_utils = None
	_logger = None

	# Dremio object pointing to the source Dremio environment
	_dremio_env = None

	# Misc
	_delimiter = None
	_newline = None
	_report_reflections = []

	def __init__(self, source_dremio, config):
		self._config = config
		self._dremio_env = source_dremio
		self._delimiter = self._config.report_csv_delimiter
		self._newline = self._config.report_csv_newline
		self._logger = DremioClonerLogger(self._config.max_errors, self._config.logging_verbose)
		self._utils = DremioClonerUtils(config)

	def process_dremio_reflections(self):
		_query_reflections = self._retrieve_reflections()
		for query_reflection in _query_reflections:
			api_reflection = self._dremio_env.get_reflection(query_reflection['REFLECTION_ID'])
			normalized_dataset_path = self._normalize_dataset_path(query_reflection['DATASET'])
			dataset_entity = self._dremio_env.get_catalog_entity_by_path(normalized_dataset_path)
			if dataset_entity is None:
				self._logger.error("process_dremio_reflections: unable to retrieve dataset from API: " + query_reflection['DATASET'])
				source_pds_list = []
			else:
				graph = self._dremio_env.get_catalog_entity_graph_by_id(dataset_entity['id'])
				if graph is None:
					self._logger.error("process_dremio_reflections: unable to retrieve Graph for dataset from API: " + query_reflection['DATASET'])
					source_pds_list = []
				elif len(graph['parents']) == 0:
					source_pds_list = [self._utils.normalize_path(dataset_entity['path'])]
				else:
					source_pds_list = list(self._get_dependency_pds_list(graph['parents']))
			self._report_reflections.append({'ID':query_reflection['REFLECTION_ID'],
											 'NAME':query_reflection['NAME'],
											 'STATUS':query_reflection['STATUS'],
											 'TYPE':query_reflection['TYPE'],
											 'DATASET_ID':query_reflection['dataset_id'],
											 'DATASET_PATH':query_reflection['DATASET'],
											 'MEASURES':query_reflection['measures'],
											 'DIMENSIONS':query_reflection['dimensions'],
											 'DISPLAY_COLUMNS':query_reflection['displayColumns'],
											 'SORT_COLUMNS':query_reflection['sortColumns'],
											 'PARTITION_COLUMNS':query_reflection['partitionColumns'],
											 'DISTRIBUTION_COLUMNS':query_reflection['distributionColumns'],
											 'EXTERNAL_REFLECTION':query_reflection['externalReflection'],
											 'NUM_FAILURES':query_reflection['NUM_FAILURES'],
											 'STATUS_EXTENDED': '' if api_reflection is None else api_reflection['status'],
											 'TOTAL_SIZE_BYTES': '' if api_reflection is None else api_reflection['totalSizeBytes'],
											 'ENABLED': '' if api_reflection is None else api_reflection['enabled'],
											 'PARTITION_DISTRIBUTION_STRATEGY': '' if api_reflection is None else api_reflection['partitionDistributionStrategy'],
											 'CREATED_AT': '' if api_reflection is None else api_reflection['createdAt'],
											 'UPDATED_AT': '' if api_reflection is None else api_reflection['updatedAt'],
											 'SOURCE_PDS_LIST': source_pds_list
											 })
		self.save_dremio_report_reflections()

	def _retrieve_reflections(self):
		sql = 'SELECT REFLECTION_ID, NAME, TYPE, STATUS, NUM_FAILURES, CAST(NULL AS VARCHAR) AS dataset_id, DATASET, sortColumns, partitionColumns, distributionColumns, dimensions, measures, displayColumns, externalReflection FROM SYS.REFLECTIONS '
		sql_v2 = 'SELECT REFLECTION_ID, reflection_name AS NAME, TYPE, STATUS, NUM_FAILURES, dataset_id, dataset_name AS DATASET, sort_columns AS sortColumns, partition_columns AS partitionColumns, distribution_columns AS distributionColumns, dimensions, measures, display_columns AS displayColumns, external_reflection AS externalReflection FROM SYS.REFLECTIONS '
		jobid = self._dremio_env.submit_sql(sql)
		# Wait for the job to complete. Should only take a moment
		while True:
			job_info = self._dremio_env.get_job_info(jobid)
			self._logger.debug("_retrieve_reflections: waiting for SQL query to finish. Job status: " + job_info["jobState"])
			if job_info is None:
				self._logger.fatal("_retrieve_reflections: unexpected error. Cannot get a list of Reflections.")
			if job_info["jobState"] in ['CANCELED', 'FAILED']:
				self._logger.info("_retrieve_reflections: Possible schema error, retrying with new sys.reflections schema.")
				jobid = self._dremio_env.submit_sql(sql_v2)
				while True:
					job_info = self._dremio_env.get_job_info(jobid)
					if job_info is None:
						self._logger.fatal("_retrieve_reflections: unexpected error. Cannot get a list of Reflections.")
					if job_info["jobState"] in ['CANCELED', 'FAILED']:
						self._logger.fatal("_retrieve_reflections: unexpected error, SQL job failed. Cannot get a list of PDS.")
					if job_info["jobState"] == 'COMPLETED':
						break
			if job_info["jobState"] == 'COMPLETED':
				break
			time.sleep(1)
		# Retrieve list of PDS
		job_result = self._dremio_env.get_job_result(jobid)
		num_rows = int(job_result['rowCount'])
		if num_rows == 0:
			self._logger.warn("_retrieve_reflections: no Reflections found.")
			return
		self._logger.debug("_retrieve_reflections: processing " + str(num_rows) + " Reflectionss in batches of 100.")
		# Page through the results, 100 rows per page
		limit = 100
		reflections = []
		for i in range(0, int(num_rows / limit) + 1):
			self._logger.debug("_retrieve_reflections: processing batch " + str(i + 1))
			job_result = self._dremio_env.get_job_result(jobid, limit * i, limit)
			for row in job_result['rows']:
				reflections.append(row)
		return reflections

	def _get_dependency_pds_list(self, parents):
		pds_set = set()
		for dataset in parents:
			if dataset['datasetType'] == 'PROMOTED' or dataset['datasetType'] == 'DIRECT':
				pds_set.add(self._utils.normalize_path(dataset['path']))
			elif dataset['datasetType'] == 'VIRTUAL':
				graph = self._dremio_env.get_catalog_entity_graph_by_id(dataset['id'])
				pds_set |= self._get_dependency_pds_list(graph['parents'])
			else:
				self._logger.fatal("_gather_dependency_pds_list: unexpected entity type " + dataset['datasetType'])
		return pds_set

	def _get_optimization_confidence_pct(self, reflection):
		if len(reflection['SOURCE_PDS_LIST']) == 0:
			return 0
		max_match_count = 0
		for r in self._report_reflections:
			# Match only with another reflection of the same TYPE (RAW/AGGREGATION)
			if r == reflection or r['TYPE'] != reflection['TYPE']:
				continue
			match_count = 0
			for s in r['SOURCE_PDS_LIST']:
				if s in reflection['SOURCE_PDS_LIST']:
					match_count = match_count + 1
			if match_count > max_match_count:
				max_match_count = match_count
		return max_match_count * 100 / len(reflection['SOURCE_PDS_LIST'])

	def save_dremio_report_reflections(self):
		self._f = open(self._config.target_filename, "w")
		self._f.write(   'REFLECTION_ID' + self._delimiter +
						 'NAME' + self._delimiter +
						 'STATUS' + self._delimiter +
						 'TYPE' + self._delimiter +
						 'OPTIMIZATION_CONFIDENCE_PCT' + self._delimiter +
						 'DATASET_ID' + self._delimiter +
						 'DATASET_PATH' + self._delimiter +
						 'MEASURES' + self._delimiter +
						 'DIMENSIONS' + self._delimiter +
						 'DISPLAY_COLUMNS' + self._delimiter +
						 'SORT_COLUMNS' + self._delimiter +
						 'PARTITION_COLUMNS' + self._delimiter +
						 'DISTRIBUTION_COLUMNS' + self._delimiter +
						 'EXTERNAL_REFLECTION' + self._delimiter +
						 'NUM_FAILURES' + self._delimiter +
						 'STATUS_EXTENDED' + self._delimiter +
						 'TOTAL_SIZE_BYTES' + self._delimiter +
						 'ENABLED' + self._delimiter +
						 'PARTITION_DISTRIBUTION_STRATEGY' + self._delimiter +
						 'CREATED_AT' + self._delimiter +
						 'UPDATED_AT' + self._delimiter +
						 'SOURCE_PDS_LIST' + self._newline)

		for reflection in self._report_reflections:
			line = str(reflection['ID']) + self._delimiter + \
				   str(reflection['NAME']) + self._delimiter + \
				   str(reflection['STATUS']) + self._delimiter + \
				   str(reflection['TYPE']) + self._delimiter + \
				   str(self._get_optimization_confidence_pct(reflection)) + self._delimiter + \
				   str(reflection['DATASET_ID']) + self._delimiter + \
				   str(reflection['DATASET_PATH']) + self._delimiter + \
				   str(reflection['MEASURES']) + self._delimiter + \
				   str(reflection['DIMENSIONS']) + self._delimiter + \
				   str(reflection['DISPLAY_COLUMNS']) + self._delimiter + \
				   str(reflection['SORT_COLUMNS']) + self._delimiter + \
				   str(reflection['PARTITION_COLUMNS']) + self._delimiter + \
				   str(reflection['DISTRIBUTION_COLUMNS']) + self._delimiter + \
				   str(reflection['EXTERNAL_REFLECTION']) + self._delimiter + \
				   str(reflection['NUM_FAILURES']) + self._delimiter + \
				   str(reflection['STATUS_EXTENDED']) + self._delimiter + \
				   str(reflection['TOTAL_SIZE_BYTES']) + self._delimiter + \
				   str(reflection['ENABLED']) + self._delimiter + \
				   str(reflection['PARTITION_DISTRIBUTION_STRATEGY']) + self._delimiter + \
				   str(reflection['CREATED_AT']) + self._delimiter + \
				   str(reflection['UPDATED_AT']) + self._delimiter + \
				   str(reflection['SOURCE_PDS_LIST']) + self._newline
			self._f.write(line)
		self._f.close()

	def _normalize_dataset_path(self, path):
		path = path.split('.')
		normalized_path = ""
		for i in range(0, len(path)):
			if path[i].startswith('"') and path[i].endswith('"'):
				normalized_path = normalized_path + path[i][1:-1]
			else:
				normalized_path = normalized_path + path[i]
			if normalized_path.startswith('"') and normalized_path.endswith('"'):
				normalized_path = normalized_path[1:-1]
			entity = self._dremio_env.get_catalog_entity_by_path(normalized_path, report_error=False)
			if entity is not None:
				normalized_path = normalized_path + '/'
			else:
				normalized_path = normalized_path + '.'
		return normalized_path[:-1]
