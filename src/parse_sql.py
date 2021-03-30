
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

from moz_sql_parser import parse
import json, re

tablist = []
def traverse(v, prefix=''):
    if isinstance(v, dict):
        for k, v2 in v.items():
            p2 = "{}['{}']".format(prefix, k)
            traverse(v2, p2)
    elif isinstance(v, list):
        for i, v2 in enumerate(v):
            p2 = "{}".format(prefix)
            traverse(v2, p2)
    else:
        if (prefix.endswith("['from']['value']") 
            or prefix.endswith("['from']") 
            or prefix.endswith(" join']['value']")
            or prefix.endswith(" join']")):
            # print(repr(v))
            tablist.append(repr(v).replace("'","").replace(".","/"))

    return tablist

def tables_in_query(sql):

    # remove the /* */ comments
    sql = re.sub(r"/\*[^*]*\*+(?:[^*/][^*]*\*+)*/", "", sql)
    sql = re.sub("trim\(.*?\)",'trim()',sql, flags=re.DOTALL)

	# remove whole line -- and # comments
    lines = [line for line in sql.splitlines() if not re.match("^\s*(--|#)", line)]

	# remove trailing -- and # comments
    sql = " ".join([re.split("--|#", line)[0] for line in lines])

    parsed_query = parse(sql)
    # print(parsed_query)
    tables = traverse(parsed_query)

    return tables