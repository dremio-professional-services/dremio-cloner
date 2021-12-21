
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

from mo_sql_parsing import parse
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

def tables_in_query_b(sql_str):

	# remove the /* */ comments
	q = re.sub(r"/\*[^*]*\*+(?:[^*/][^*]*\*+)*/", "", sql_str)
	q = re.sub("trim\(.*?\)",'trim()',sql_str, flags=re.DOTALL|re.I)
	q = re.sub("right\(.*?\)",'trim()',sql_str, flags=re.DOTALL|re.I)
	q = re.sub("ltrim\(.*?\)",'trim()',sql_str, flags=re.DOTALL|re.I)
	# remove whole line -- and # comments
	lines = [line for line in q.splitlines() if not re.match("^\s*(--|#)", line)]

	# remove trailing -- and # comments
	q = " ".join([re.split("--|#", line)[0] for line in lines])

	# split on blanks, parens and semicolons 
	# Added ',' to support list of tables in FROM clause
	tokens = re.split(r"[\s)(,;]+", q)

	# scan the tokens. if we see a FROM or JOIN, we set the get_next
	# flag, and grab the next one (unless it's SELECT).

	result = list()
	get_next = False
	for tok in tokens:
		if get_next:
			if tok.lower() not in ["", "select"]:
				# Added support for recovering quoted names with spaces
				if tok[0:1] == '"' and tok[-1:] != '"':
					quoted = sql_str[sql_str.find(tok) + 1:]
					quoted = quoted[:quoted.find('"')]
					result.append(normalize_path(quoted))
				else:
					result.append(normalize_path(tok))
			get_next = False
		get_next = tok.lower() in ["from", "join"]

	return result

def normalize_path(token):
	# [S3."asd"."ss.txt"] -> S3/asd/ss.txt
	p = """"([^"]*)"|'([^']*)'|[\.]+"""
	path_list = re.split(p, token)
	path = ""
	for item in path_list:
		if item != None and item != '':
			path = path + re.sub('"', '', item) + "/"
	return path[:-1]

def tables_in_query_a(sql):

    # remove the /* */ comments
    sql = re.sub(r"/\*[^*]*\*+(?:[^*/][^*]*\*+)*/", "", sql)
    sql = re.sub("trim\(.*?\)",'trim()',sql, flags=re.DOTALL|re.I)
    sql = re.sub("right\(.*?\)",'trim()',sql, flags=re.DOTALL|re.I)
    sql = re.sub("left\(.*?\)",'trim()',sql, flags=re.DOTALL|re.I)

	# remove whole line -- and # comments
    lines = [line for line in sql.splitlines() if not re.match("^\s*(--|#)", line)]

	# remove trailing -- and # comments
    sql = " ".join([re.split("--|#", line)[0] for line in lines])

    parsed_query = parse(sql)
    # print(parsed_query)
    tables = traverse(parsed_query)

    return tables

def tables_in_query(sql):
    try:
        return tables_in_query_a(sql)
    except:
        return tables_in_query_b(sql)