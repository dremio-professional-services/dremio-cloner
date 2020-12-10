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


import logging


class DremioClonerLogger:

	# Configuration
	_max_errors = 9999
	_verbose = False

	# Error counter
	errors_encountered = 0

	def __init__(self, max_errors = 9999, is_verbose = False):
		self._max_errors = max_errors
		self._verbose = is_verbose

	def fatal(self, error):
		return self.error(error, True)

	def error(self, error, is_critical = False):
		if is_critical:
			logging.critical(error)
			raise RuntimeError("Critical error: " + str(error))
		else:
			logging.error(error)
			self.errors_encountered = self.errors_encountered + 1
			if self.errors_encountered > self._max_errors:
				logging.critical("Reached max number of errors: " + str(self._max_errors))
				raise RuntimeError("Reached max number of errors: " + str(self._max_errors))

	def warn(self, warn):
		logging.warning(warn)

	def info(self, info):
		logging.info(info)

	def debug(self, info):
		logging.debug(info)
