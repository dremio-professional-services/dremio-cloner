import sys

from mo_sql_parsing import parse
from mo_sql_parsing import format
import sqlparse

from DremioFile import DremioFile
from DremioClonerConfig import DremioClonerConfig
import json
import uuid

def path_matches(match_path, resource_path):
    if len(match_path) > len(resource_path):
        return False
    for i in range(0, len(match_path)):
        if match_path[i] != resource_path[i]:
            return False
    return True

def path_matches_sqlcontext(match_path, resource_path):
    for i in range(0, min(len(match_path), len(resource_path))):
        if match_path[i] != resource_path[i]:
            return False
    return True

def rebuild_path(migration, resource_path):
    src_elem_count = len(migration['srcPath'])
    new_path_end =  resource_path[src_elem_count:]
    return migration['dstPath'] + new_path_end

def rebuild_path_sqlcontext(migration, resource_path):
    if len(migration['srcPath']) >= len(resource_path):
        return migration['dstPath'][:len(resource_path)]
    return rebuild_path(migration, resource_path)

#
# def quote(str):
#     return '"' + str + '"'

# def generate_all_quoted_and_non_quoted_permutations(src_path):
#     nonquoted = src_path
#     quoted = list(map(quote, nonquoted))
#     permutations = []
#     for x in range(len(nonquoted)):
#         for y in range(len(quoted)):
#             t1 = nonquoted[:]
#             t2 = quoted[:]
#             t1[x] = quoted[x]
#             t2[x] = nonquoted[x]
#             t1[y] = quoted[y]
#             t2[y] = nonquoted[y]
#             permutations.append(t1)
#             permutations.append(t2)
#     permutations.append(nonquoted)
#     permutations.append(quoted)
#     strnewlist = []
#     for e in permutations:
#         strnewlist.append(".".join(e))
#     return set(strnewlist)


def replace_table_names(parsed, vds_path, src_path, dst_path, log_text):
    if not isinstance(parsed, dict):
        print("ERROR: passed parsed needs to be of tope DICT " + str(type(parsed)))
        return

    join_keys = [key for key in parsed.keys() if key.lower().find("join") != -1]
    _key = None
    _value = None
    if 'from' in parsed:
        _key = 'from'
        _value = parsed['from']
    elif 'value' in parsed:
        _key = 'value'
        _value = parsed['value']
    elif len(join_keys) > 0:
        for join_key in join_keys:
            replace_table_names(parsed[join_key], vds_path, src_path, dst_path, log_text)
        return
    else:
        print("VDS not having any FROM clause - unhandled parse key: " + str(parsed))
        return

    if isinstance(_value, list):
        for item in _value:
            replace_table_names(item, vds_path, src_path, dst_path, log_text)
    elif isinstance(_value, str):
        vds_path_str = '.'.join(vds_path)
        # for permutation in src_permutations:
        if _value.lower().startswith(src_path.lower()):
            _newvalue = dst_path + _value[len(src_path):]
            parsed[_key] = _newvalue
            print(log_text + ' - Matching VDS SQL (' + (vds_path_str) + '): ' + _value + ' -> ' + _newvalue)

    elif isinstance(_value, dict):
        replace_table_names(_value, vds_path, src_path, dst_path, log_text)
    else:
        print("ERROR: _value is of type " + str(_value))

def should_quote(identifier, dremio_data):
    if identifier == "default":
        return True
    if identifier.find(".") != -1:
        return True
    for vds in dremio_data.vds_list:
        if identifier in vds['path']:
            return True
    for pds in dremio_data.pds_list:
        if identifier in pds['path']:
            return True
    return False

def main():
    if len(sys.argv) != 2:
        print("Please pass a configuration file.")
        return

    config_file = open(sys.argv[1], "r", encoding='utf-8')
    migration_conf = json.load(config_file)
    spaceFolderMigrations = migration_conf['spaceFolderMigrations']
    sourceMigrations = migration_conf['sourceMigrations']
    if 'sourceFile' in migration_conf:
        config = DremioClonerConfig(migration_conf['sourceFile'])
    else:
        config = DremioClonerConfig(migration_conf['sourceDirectory'] + '\\___dremio_cloner_conf.json')

    if 'sourceDirectory' in migration_conf:
        config.source_directory = migration_conf['sourceDirectory']
    if 'destinationDirectory' in migration_conf:
        config.target_directory = migration_conf['destinationDirectory']
    if 'sourceFile' in migration_conf:
        config.source_filename = migration_conf['sourceFile']
    if 'destinationFile' in migration_conf:
        config.target_filename = migration_conf['destinationFile']

    file = DremioFile(config)
    dremio_data = file.read_dremio_environment()

    # Only container types SPACE and FOLDER is migrated, no SOURCES
    dremio_data.containers = [container for container in dremio_data.containers if container['containerType'] in ['SPACE', 'FOLDER']]

    if spaceFolderMigrations is not None and len(spaceFolderMigrations) > 0:
        for migration in spaceFolderMigrations:
            # Migrate containers
            #####################
            for container in dremio_data.containers:
                min_len = min(len(container['path']), len(migration['dstPath']))
                if container['path'][:min_len] == migration['srcPath'][:min_len]:
                    # space['id'] = str(uuid.uuid4())
                    oldpath = container['path']
                    container['path'] = migration['dstPath'][:min_len]
                    print("Matching container: " + ('.'.join(oldpath)) + " -> " + ('.'.join(container['path'])))

            # Migrate spaces
            #####################
            for space in dremio_data.spaces:
                if space['name'] == migration['srcPath'][0]:
                    # space['id'] = str(uuid.uuid4())
                    oldspace = space['name']
                    space['name'] = migration['dstPath'][0]
                    print("Matching space: " + oldspace + " -> " + space['name'])
                    # Delete children, that will be reconstructed in a later phase
                    space['children'] = []

            # Migrate folders
            ####################
            for folder in dremio_data.folders:
                if path_matches(migration['srcPath'], folder['path']):
                    # folder['id'] = str(uuid.uuid4())
                    oldpath = folder['path']
                    folder['path'] = rebuild_path(migration, oldpath)
                    print("Matching folders: " + ('.'.join(oldpath)) + " -> " + ('.'.join(folder['path'])))
                    # Delete children, that will be reconstructed in a later phase
                    folder['children'] = []

            # Migrate reflections
            #####################
            for reflection in dremio_data.reflections:
                if path_matches(migration['srcPath'], reflection['path']):
                    # reflection['id'] = str(uuid.uuid4())
                    oldpath = reflection['path']
                    reflection['path'] = rebuild_path(migration, oldpath)
                    print("Matching reflection (" + reflection['name'] + "): " + ('.'.join(oldpath)) + " -> " + ('.'.join(reflection['path'])))

            # Migrate tags
            #####################
            for tag in dremio_data.tags:
                if path_matches(migration['srcPath'], tag['path']):
                    oldpath = tag['path']
                    tag['path'] = rebuild_path(migration, oldpath)
                    print("Matching tag: " + ('.'.join(oldpath)) + " -> " + ('.'.join(tag['path'])))

            # Migrate vds_parents
            ####################
            for vds_parent in dremio_data.vds_parents:
                if path_matches(migration['srcPath'], vds_parent['path']):
                    oldpath = vds_parent['path']
                    vds_parent['path'] = rebuild_path(migration, oldpath)
                    vds_parent['parents'] = [parent.replace('/'.join(migration['srcPath']), '/'.join(migration['dstPath'])) for parent in vds_parent['parents']]
                    print("Matching vds_parent: " + ('.'.join(oldpath)) + " -> " + ('.'.join(vds_parent['path'])))

            # Migrate vds_list
            #####################
            # src_permutations = generate_all_quoted_and_non_quoted_permutations(migration['srcPath'])
            src_path = ".".join(migration['srcPath'])
            dst_path = ".".join(migration['dstPath'])
            for vds in dremio_data.vds_list:
                if 'sqlContext' in vds and path_matches_sqlcontext(migration['srcPath'], vds['sqlContext']):
                    oldpath = vds['sqlContext']
                    vds['sqlContext'] = rebuild_path_sqlcontext(migration, oldpath)
                    print("Matching VDS SQL Context: " + ('.'.join(oldpath)) + " -> " + ('.'.join(vds['sqlContext'])))
                if path_matches(migration['srcPath'], vds['path']):
                    oldpath = vds['path']
                    vds['path'] = rebuild_path(migration, oldpath)
                    print("Matching VDS path: " + ('.'.join(oldpath)) + " -> " + ('.'.join(vds['path'])))
                sql = vds['sql']
                parsed = parse(sql)
                replace_table_names(parsed, vds['path'], src_path, dst_path, 'VDS migration')
                vds['sql'] = format(parsed, ansi_quotes=True, should_quote= lambda x: should_quote(x, dremio_data))

                # for permutation in src_permutations:
                #     escaped = re.escape(permutation)
                #     if re.search(escaped, sql, flags=re.IGNORECASE):
                #         sql = re.sub(escaped, dst_path, sql, flags=re.IGNORECASE)
                #         print("Matching VDS SQL (" + '.'.join(vds['path']) + "): " + permutation + " -> " + dst_path)
                # vds['sql'] = sql

            # Migrate wiki
            #####################
            for wiki in dremio_data.wikis:
                if path_matches(migration['srcPath'], wiki['path']):
                    oldpath = wiki['path']
                    wiki['path'] = rebuild_path(migration, oldpath)
                    print("Matching Wiki: " + ('.'.join(oldpath)) + " -> " + ('.'.join(wiki['path'])))

        # Delete spaces which do not match any dstPath
        non_matching_spaces = []
        for space in dremio_data.spaces:
            found = False
            for migration in spaceFolderMigrations:
                if migration['dstPath'][0] == space['name']:
                    found = True
                    break
            if not found:
                print("Dropping space which does not match any dstPath -> " + ".".join(space['name']))
                non_matching_spaces.append(space['name'])

        dremio_data.spaces = [space for space in dremio_data.spaces if space['name'] not in non_matching_spaces]

        # Delete folders which do not matching dstPath
        non_matching_folders = []
        for folder in dremio_data.folders:
            found = False
            for migration in spaceFolderMigrations:
                min_len = min(len(migration['dstPath']), len(folder['path']))
                dst_path = migration['dstPath'][:min_len]
                folder_path = folder['path'][:min_len]
                if dst_path == folder_path:
                    found = True
                    break
            if not found:
                print("Dropping folder which does not match any dstPath -> " + ".".join(folder['path']))
                non_matching_folders.append(folder['path'])
        dremio_data.folders = [folder for folder in dremio_data.folders if folder['path'] not in non_matching_folders]

        # Delete non matching VDS definitions
        non_matching_vds = []
        for vds in dremio_data.vds_list:
            found = False
            for migration in spaceFolderMigrations:
                min_len = min(len(migration['dstPath']), len(vds['path']))
                dst_path = migration['dstPath'][:min_len]
                vds_path = vds['path'][:min_len]
                if dst_path == vds_path:
                    found = True
                    break
            if not found:
                print("Dropping VDS which does not match any dstPath -> " + ".".join(vds['path']))
                non_matching_vds.append(vds['path'])
        dremio_data.vds_list = [vds for vds in dremio_data.vds_list if vds['path'] not in non_matching_vds]

        # Delete non matching tags definitions
        non_matching_tags = []
        for tag in dremio_data.tags:
            found = False
            for migration in spaceFolderMigrations:
                min_len = min(len(migration['dstPath']), len(tag['path']))
                dst_path = migration['dstPath'][:min_len]
                tag_path = tag['path'][:min_len]
                if dst_path == tag_path:
                    found = True
                    break
            if not found:
                print("Dropping Tag which does not match any dstPath -> " + ".".join(tag['path']))
                non_matching_tags.append(tag['path'])
        dremio_data.tags = [tag for tag in dremio_data.tags if tag['path'] not in non_matching_tags]

        # Delete non matching tags definitions
        non_matching_wikis = []
        for wiki in dremio_data.wikis:
            found = False
            for migration in spaceFolderMigrations:
                min_len = min(len(migration['dstPath']), len(wiki['path']))
                dst_path = migration['dstPath'][:min_len]
                wiki_path = wiki['path'][:min_len]
                if dst_path == wiki_path:
                    found = True
                    break
            if not found:
                print("Dropping Wiki which does not match any dstPath -> " + ".".join(wiki['path']))
                non_matching_wikis.append(wiki['path'])
        dremio_data.wikis = [wiki for wiki in dremio_data.wikis if wiki['path'] not in non_matching_wikis]

        # Built VDS references
        unreferenced_vds = find_unreferenced_vds(dremio_data)
        for vds in unreferenced_vds:
            parent_folder_path = vds['path'][:-1]
            if len(parent_folder_path) == 1:
                parent_space = None
                for space in dremio_data.spaces:
                    if space['name'] == parent_folder_path[0]:
                        parent_space = space
                        break
                if parent_space == None:
                    print("ERROR - Space not found: " + parent_folder_path[0])
                    exit(1)
                else:
                    print("Appending VDS " + ('.'.join(vds['path'])) + " to space " + ('.'.join(parent_space['name'])))
                    parent_space['children'].append(
                        {'id': vds['id'], 'path': vds['path'],
                         'type': 'DATASET', 'datasetType': 'VIRTUAL'})
            else:
                parent_folder = None
                for folder in dremio_data.folders:
                    if folder['path'] == parent_folder_path:
                        parent_folder = folder
                        break
                if parent_folder == None:
                    print("No existing parent folder found, creating one: " + ('.'.join(parent_folder_path)))
                    parent_folder = {
                        'id': str(uuid.uuid4()),
                        'accessControlList': {'roles': []},
                        'entityType': 'folder',
                        'path': parent_folder_path,
                        'children': []
                    }
                    dremio_data.folders.append(parent_folder)
                print("Appending VDS " + str(vds['path']) + " to folder " + str(parent_folder['path']))
                parent_folder['children'].append({'id': vds['id'], 'path': vds['path'],
                         'type': 'DATASET', 'datasetType': 'VIRTUAL'})

        # Generate missing folder is hierarchy
        unreferenced_folders = find_unreferenced_folders(dremio_data)
        while len(unreferenced_folders) > 0:
            for unreferenced_folder in unreferenced_folders:
                parent_folder_path = unreferenced_folder['path'][:-1]
                if len(parent_folder_path) == 1:
                    # space should be there
                    parent_space = None
                    for space in dremio_data.spaces:
                        if space['name'] == parent_folder_path[0]:
                            parent_space = space
                            break
                    if parent_space == None:
                        print("ERROR - Space not found: " + parent_folder_path[0])
                        exit(1)
                    else:
                        print("Appending folder " + ('.'.join(unreferenced_folder['path'])) + " to space " + parent_space['name'])
                        parent_space['children'].append({
                            'id': unreferenced_folder['id'],
                            'containerType': 'FOLDER',
                            'type': 'CONTAINER',
                            'path': unreferenced_folder['path']
                        })
                else:
                    parent_folder = None
                    for folder in dremio_data.folders:
                        if folder['path'] == parent_folder_path:
                            parent_folder = folder
                            break
                    if parent_folder == None:
                        print("No existing parent folder found, creating one: " + ('.'.join(parent_folder_path)))
                        parent_folder = {
                            'id': str(uuid.uuid4()),
                            'accessControlList': {'roles': []},
                            'entityType': 'folder',
                            'path': parent_folder_path,
                            'children': []
                        }
                        # needs to go to first position otherwise dependency creation could fail
                        dremio_data.folders.insert(0, parent_folder)
                    print("Appending folder " + ('.'.join(unreferenced_folder['path'])) + " to folder " + ('.'.join(parent_folder['path'])))
                    parent_folder['children'].append({
                        'id': unreferenced_folder['id'],
                        'containerType': 'FOLDER',
                        'type': 'CONTAINER',
                        'path': unreferenced_folder['path']
                    })
            unreferenced_folders = find_unreferenced_folders(dremio_data)

    if sourceMigrations is not None and len(sourceMigrations) > 0:
        for migration in sourceMigrations:
            # Migrate vds_list
            #####################
            # src_permutations = generate_all_quoted_and_non_quoted_permutations(migration['srcPath'])
            src_path = ".".join(migration['srcPath'])
            dst_path = ".".join(migration['dstPath'])
            # dst_path = ".".join(list(map(quote, migration['dstPath'])))
            for vds in dremio_data.vds_list:
                if 'sqlContext' in vds and path_matches(migration['srcPath'], vds['sqlContext']):
                    oldpath = vds['sqlContext']
                    vds['sqlContext'] = rebuild_path(migration, oldpath)
                    print("Source Migration - Matching VDS SQL Context (" + '.'.join(vds['path']) + "): " + ('.'.join(oldpath)) + " -> " + ('.'.join(vds['sqlContext'])))
                sql = vds['sql']
                parsed = parse(sql)
                replace_table_names(parsed, vds['path'], src_path, dst_path, 'Source Migration')
                vds['sql'] = format(parsed, ansi_quotes=True, should_quote= lambda x: should_quote(x, dremio_data))
                # for permutation in src_permutations:
                #     escaped = re.escape(permutation)
                #     if re.search(escaped, sql, flags=re.IGNORECASE):
                #         sql = re.sub(escaped, dst_path, sql, flags=re.IGNORECASE)
                #         print("Source Migration - Matching VDS SQL (" + '.'.join(vds['path']) + "): " + permutation + " -> " + dst_path)
                # vds['sql'] = sql
            for vds_parent in dremio_data.vds_parents:
                src_path = '/'.join(migration['srcPath'])
                dst_path = '/'.join(migration['dstPath'])
                parents = []
                for parent in vds_parent['parents']:
                    if parent.lower().startswith(src_path.lower()):
                        print("Matching vds_parent: " + ('.'.join(vds_parent['path'])) + " - changed dependency: " + src_path + " -> " + dst_path)
                        # parents.append(parent.lstrip(src_path) + dst_path)
                        parents.append(dst_path + parent[len(src_path):])
                    else:
                        parents.append(parent)

                vds_parent['parents'] = parents

    # Maybe make configurable
    for vds in dremio_data.vds_list:
        vds['sql'] = sqlparse.format(vds['sql'], reindent=True, indent_width=2)
    # sqlparse_format = sqlparse.format(format(parsed), reindent=True, indent_width=2)
    # TODO probably we can also migrate PDS promotions, for now we do not handle it and just export an empty list
    dremio_data.pds_list = []
    dremio_data.sources = []
    dremio_data.homes = []

    file.save_dremio_environment(dremio_data)


def find_unreferenced_folders(dremio_data):
    unreferenced_folders = []
    for folder in dremio_data.folders:
        found = False
        for space in dremio_data.spaces:
            for child in space['children']:
                if child['path'] == folder['path']:
                    found = True
        for folder2 in dremio_data.folders:
            for child in folder2['children']:
                if child['path'] == folder['path']:
                    found = True
        if not found:
            unreferenced_folders.append(folder)
    return unreferenced_folders

def find_unreferenced_vds(dremio_data):
    unreferenced_vds = []
    for vds in dremio_data.vds_list:
        found = False
        for space in dremio_data.spaces:
            for child in space['children']:
                if child['path'] == vds['path']:
                    found = True
        for folder2 in dremio_data.folders:
            for child in folder2['children']:
                if child['path'] == vds['path']:
                    found = True
        if not found:
            unreferenced_vds.append(vds)
    return unreferenced_vds


if __name__ == "__main__":
	main()
