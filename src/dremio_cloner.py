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
from DremioCloud import DremioCloud
from DremioData import DremioData
from DremioFile import DremioFile
from DremioReader import DremioReader
from DremioWriter import DremioWriter
from DremioReportAcl import DremioReportAcl
from DremioReportReflections import DremioReportReflections
from DremioCascadeAcl import DremioCascadeAcl
from DremioDelete import DremioDelete
from DremioDescribeJob import DremioDescribeJob
from DremioClonerConfig import DremioClonerConfig
from datetime import datetime
import logging
import sys
import json
import getpass


def main():
	config = None

	if len(sys.argv) != 2 and (len(sys.argv) != 4 or sys.argv[2] != '-p'):
		print_usage()
	else:
		config = DremioClonerConfig(sys.argv[1])
		obtain_password(config, sys.argv)
		# Execute command
		if config.command == DremioClonerConfig.CMD_GET:
			get_dremio_environment(config)
		elif config.command == DremioClonerConfig.CMD_PUT:
			put_dremio_environment(config)
		elif config.command == DremioClonerConfig.CMD_REPORT_ACL:
			report_acl(config)
		elif config.command == DremioClonerConfig.CMD_CASCADE_ACL:
			cascade_acl(config)
		elif config.command == DremioClonerConfig.CMD_DESCRIBE_JOB:
			describe_job(config)
		elif config.command == DremioClonerConfig.CMD_REPORT_REFLECTIONS:
			report_reflections(config)
		elif config.command == DremioClonerConfig.CMD_DELETE:
			delete_objects(config)
		else:
			print_usage()


def print_usage():
	print("""usage: dremio_cloner config_file -p password
Make sure the config file is correct. """)


def get_dremio_environment(config):
	logging.info("Executing command 'get'.")
	# Added a DremioCloud class for interacting directly with Dremio Cloud without upsetting the DremioWriter and DremioReader code
	if config.source_dremio_cloud:
		dremio = DremioCloud(config.source_endpoint, config.source_username, config.source_password, config.source_dremio_cloud_org_id, config.source_dremio_cloud_project_id,
						   config.http_timeout,	verify_ssl=config.source_verify_ssl)
	else:
		dremio = Dremio(config.source_endpoint, config.source_username, config.source_password, False, config.http_timeout, config.source_retry_timedout, config.source_verify_ssl)
	reader = DremioReader(dremio, config)
	dremio_data = reader.read_dremio_environment()
	file = DremioFile(config)
	file.save_dremio_environment(dremio_data)
	logging.info("Command 'get' finished with " + str(reader.get_errors_count()) + " error(s).")
	print("Done with " + str(reader.get_errors_count()) + " error(s). Please review log file for details.")


def put_dremio_environment(config):
	logging.info("Executing command 'put'.")
	file = DremioFile(config)
	dremio_data = file.read_dremio_environment()
	#Added a DremioCloud class for interacting directly with Dremio Cloud without upsetting the DremioWriter and DremioReader code
	if config.target_dremio_cloud:
		dremio = DremioCloud(config.target_endpoint, config.target_username, config.target_password, config.target_dremio_cloud_org_id, config.target_dremio_cloud_project_id,
						   config.http_timeout,	verify_ssl=config.target_verify_ssl)
	else:
		dremio = Dremio(config.target_endpoint, config.target_username, config.target_password, config.target_accept_eula, config.http_timeout, verify_ssl=config.target_verify_ssl)
	writer = DremioWriter(dremio, dremio_data, config)
	writer.write_dremio_environment()
	logging.info("Command 'put' finished with " + str(writer.get_errors_count()) + " error(s).")
	print("Done with " + str(writer.get_errors_count()) + " error(s). Please review log file for details.")


def report_acl(config):
	logging.info("Executing command 'report-acl'.")
	dremio = Dremio(config.source_endpoint, config.source_username, config.source_password, False, config.http_timeout, config.source_retry_timedout, config.source_verify_ssl)
	reader = DremioReader(dremio, config)
	dremio_data = reader.read_dremio_environment()
	dremio_report = DremioReportAcl(dremio, dremio_data, config)
	dremio_report.save_dremio_report_acl()
	logging.info("Command 'report-acl' finished with " + str(reader.get_errors_count()) + " error(s).")
	print("Done with " + str(reader.get_errors_count()) + " error(s). Please review log file for details.")


def report_reflections(config):
	logging.info("Executing command 'report-reflections'.")
	dremio = Dremio(config.source_endpoint, config.source_username, config.source_password, False, config.http_timeout, config.source_retry_timedout, config.source_verify_ssl)
	dremio_report = DremioReportReflections(dremio, config)
	dremio_report.process_dremio_reflections()
	print("Done. Please review log file for details.")


def cascade_acl(config):
	logging.info("Executing command 'cascade-acl'.")
	dremio = Dremio(config.target_endpoint, config.target_username, config.target_password, False, config.http_timeout, verify_ssl=config.target_verify_ssl)
	cascader = DremioCascadeAcl(dremio, config)
	cascader.cascade_acl()
	logging.info("Command 'cascade-acl' finished with " + str(cascader.get_errors_count()) + " error(s).")
	print("Done with " + str(cascader.get_errors_count()) + " error(s). Please review log file for details.")


def describe_job(config):
	logging.info("Executing command 'describe-job'.")
	dremio = Dremio(config.source_endpoint, config.source_username, config.source_password, False, config.http_timeout, verify_ssl=config.source_verify_ssl)
	describer = DremioDescribeJob(dremio, config)
	if config.target_type == 'sql-dependencies':
		dremio_data = describer.describe_job_sql_dependencies()
	else:
		print_usage()


def delete_objects(config):
	logging.info("Executing command '" + DremioClonerConfig.CMD_DELETE + "'.")
	dremio = Dremio(config.target_endpoint, config.target_username, config.target_password, False, config.http_timeout, verify_ssl=config.target_verify_ssl)
	deleter = DremioDelete(dremio, config)
	deleter.delete()
	logging.info("Command '" + DremioClonerConfig.CMD_DELETE + "' finished with " + str(deleter.get_errors_count()) + " error(s).")
	print("Done with " + str(deleter.get_errors_count()) + " error(s). Please review log file for details.")


def obtain_password(config, argv):
	# Try to get the password from the parameters first
	if len(argv) == 4:
		config.source_password = argv[3]
		config.target_password = config.source_password
	# Then check if one is present in the configuration file, else ask for password
	elif (config.source_password is None or config.source_password == "") and (config.target_password is None or config.target_password == ""):
		config.source_password = getpass.getpass("Enter password:")
		config.target_password = config.source_password

if __name__ == "__main__":
	main()
