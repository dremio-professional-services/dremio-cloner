import re


# Based on https://grisha.org/blog/2016/11/14/table-names-from-sql/
def tables_in_query(sql_str):

	# remove the /* */ comments
	q = re.sub(r"/\*[^*]*\*+(?:[^*/][^*]*\*+)*/", "", sql_str)

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