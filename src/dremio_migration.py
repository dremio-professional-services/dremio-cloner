import sys

from DremioFile import DremioFile
from DremioClonerConfig import DremioClonerConfig
import re
import json

def path_matches(match_path, resource_path):
    if len(match_path) > len(resource_path):
        return False
    for i in range(0, len(match_path)):
        if match_path[i] != resource_path[i]:
            return False
    return True

def rebuild_path(migration, resource_path):
    src_elem_count = len(migration['srcPath'])
    new_path_end =  resource_path[src_elem_count:]
    return migration['dstPath'] + new_path_end

def quote(str):
    return '"' + str + '"'

def generate_all_quoted_and_non_quoted_permutations(src_path):
    nonquoted = src_path
    quoted = list(map(quote, nonquoted))
    permutations = []
    for x in range(len(nonquoted)):
        for y in range(len(quoted)):
            t1 = nonquoted[:]
            t2 = quoted[:]
            t1[x] = quoted[x]
            t2[x] = nonquoted[x]
            t1[y] = quoted[y]
            t2[y] = nonquoted[y]
            permutations.append(t1)
            permutations.append(t2)
    permutations.append(nonquoted)
    permutations.append(quoted)
    strnewlist = []
    for e in permutations:
        strnewlist.append(".".join(e))
    return set(strnewlist)


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

    for migration in spaceFolderMigrations:
        # Migrate folders
        ####################
        for folder in dremio_data.folders:
            if path_matches(migration['srcPath'], folder['path']):
                oldpath = folder['path']
                folder['path'] = rebuild_path(migration, oldpath)
                print("Matching folders: " + ('.'.join(oldpath)) + " -> " + ('.'.join(folder['path'])))
                for child in folder['children']:
                    if path_matches(migration['srcPath'], child['path']):
                        child['path'] = rebuild_path(migration, child['path'])

        # Migrate reflections
        #####################
        for reflection in dremio_data.reflections:
            if path_matches(migration['srcPath'], reflection['path']):
                oldpath = reflection['path']
                reflection['path'] = rebuild_path(migration, oldpath)
                print("Matching reflection (" + reflection['name'] + "): " + ('.'.join(oldpath)) + " -> " + ('.'.join(reflection['path'])))

        # Migrate spaces
        #####################
        for space in dremio_data.spaces:
            if space['name'] == migration['srcPath'][0]:
                oldspace = space['name']
                space['name'] = migration['dstPath'][0]
                print("Matching space: " + oldspace + " -> " + space['name'])

            for child in space['children']:
                if path_matches(migration['srcPath'], child['path']):
                    child['path'] = rebuild_path(migration, child['path'])

        # Migrate tags
        #####################
        for tag in dremio_data.tags:
            if path_matches(migration['srcPath'], tag['path']):
                oldpath = tag['path']
                tag['path'] = rebuild_path(migration, oldpath)
                print("Matching tag: " + ('.'.join(oldpath)) + " -> " + ('.'.join(tag['path'])))

        # Migrate vds_list
        #####################
        src_permutations = generate_all_quoted_and_non_quoted_permutations(migration['srcPath'])
        dst_path = ".".join(list(map(quote, migration['dstPath'])))
        for vds in dremio_data.vds_list:
            if 'sqlContext' in vds and path_matches(migration['srcPath'], vds['sqlContext']):
                oldpath = vds['sqlContext']
                vds['sqlContext'] = rebuild_path(migration, oldpath)
                print("Matching VDS SQL Context: " + ('.'.join(oldpath)) + " -> " + ('.'.join(vds['sqlContext'])))
            if path_matches(migration['srcPath'], vds['path']):
                oldpath = vds['path']
                vds['path'] = rebuild_path(migration, oldpath)
                print("Matching VDS path: " + ('.'.join(oldpath)) + " -> " + ('.'.join(vds['path'])))
            sql = vds['sql']
            for permutation in src_permutations:
                escaped = re.escape(permutation)
                if re.search(escaped, sql, flags=re.IGNORECASE):
                    sql = re.sub(escaped, dst_path, sql, flags=re.IGNORECASE)
                    print("Matching VDS SQL (" + '.'.join(vds['path']) + "): " + permutation + " -> " + dst_path)
            vds['sql'] = sql

        # Migrate wiki
        #####################
        for wiki in dremio_data.wikis:
            if path_matches(migration['srcPath'], wiki['path']):
                oldpath = wiki['path']
                wiki['path'] = rebuild_path(migration, oldpath)
                print("Matching Wiki: " + ('.'.join(oldpath)) + " -> " + ('.'.join(wiki['path'])))

    for migration in sourceMigrations:
        # Migrate vds_list
        #####################
        src_permutations = generate_all_quoted_and_non_quoted_permutations(migration['srcPath'])
        dst_path = ".".join(list(map(quote, migration['dstPath'])))
        for vds in dremio_data.vds_list:
            if 'sqlContext' in vds and path_matches(migration['srcPath'], vds['sqlContext']):
                oldpath = vds['sqlContext']
                vds['sqlContext'] = rebuild_path(migration, oldpath)
                print("Source Migration - Matching VDS SQL Context (" + '.'.join(vds['path']) + "): " + ('.'.join(oldpath)) + " -> " + ('.'.join(vds['sqlContext'])))
            sql = vds['sql']
            for permutation in src_permutations:
                escaped = re.escape(permutation)
                if re.search(escaped, sql, flags=re.IGNORECASE):
                    sql = re.sub(escaped, dst_path, sql, flags=re.IGNORECASE)
                    print("Source Migration - Matching VDS SQL (" + '.'.join(vds['path']) + "): " + permutation + " -> " + dst_path)
            vds['sql'] = sql

    file.save_dremio_environment(dremio_data)


if __name__ == "__main__":
	main()
