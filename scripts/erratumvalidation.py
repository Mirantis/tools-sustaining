#    Copyright 2015 Mirantis, Inc.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import os
import re
import sys
import urllib2
import logging

import yaml
from jsonschema import validate

logger = logging.getLogger()
logger.setLevel(logging.DEBUG)
ch = logging.StreamHandler()
ch.setLevel(logging.INFO)
formatter = logging.Formatter(
    '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
ch.setFormatter(formatter)
logger.addHandler(ch)

SCHEMA = "http://json-schema.org/draft-04/schema"

CVE_URL = "https://cve.mitre.org/cgi-bin/cvename.cgi?name={bug}"

MIRROR_URLS = ['http://osci-obs.vm.mirantis.net:82/',
               'http://obs-1.mirantis.com:82/']

CONFIG_SCHEMA = {
    "type": "object",
    "$schema": SCHEMA,
    "definitions": {
        "short_string_schema": {
            "type": "string",
            "maxLength": 200
        },
        "array_schema": {
            "type": "array",
            "items": {
                "type": "string"
            },
            "minItems": 1,
            "uniqueItems": True
        },
        "target_schema": {
            "enum": ["master", "slaves", "controller_role", "compute_role",
                     "cinder_role", "ceph-osd_role", "mongo_role",
                     "zabbix-server_role", "base-os_role"]
        },
        "bool_schema": {
            "type": "boolean",
            "default": False
        },
        "os_step_upload_script_schema": {
            "type": "object",
            "$schema": SCHEMA,
            "properties": {
                "id": {
                    "type": "integer",
                },
                "type": {
                    "enum": ["upload_script"]
                },
                "target": {
                    "type": "array",
                    "items": {
                        "$ref": "#/definitions/target_schema"
                    },
                    "minItems": 1,
                    "uniqueItems": True
                },
                "script": {
                    "type": "string",
                    "minLength": 1
                },
                "upload_path": {
                    "type": "string",
                    "minLength": 1
                },
            },
            "required": ["id", "type", "target", "script", "upload_path"],
            "additionalProperties": False,
        },
        "os_step_run_command_schema": {
            "type": "object",
            "$schema": SCHEMA,
            "properties": {
                "id": {
                    "type": "integer",
                },
                "type": {
                    "enum": ["run_command"]
                },
                "target": {
                    "type": "array",
                    "items": {
                        "$ref": "#/definitions/target_schema"
                    },
                    "minItems": 1,
                    "uniqueItems": True
                },
                "command": {
                    "type": "string",
                    "minLength": 1
                },
            },
            "required": ["id", "type", "target", "command"],
            "additionalProperties": False,
        },
        "os_step_run_tasks_schema": {
            "type": "object",
            "$schema": SCHEMA,
            "properties": {
                "id": {
                    "type": "integer",
                },
                "type": {
                    "enum": ["run_tasks"]
                },
                "target": {
                    "type": "array",
                    "items": {
                        "$ref": "#/definitions/target_schema"
                    },
                    "minItems": 1,
                    "uniqueItems": True
                },
                "tasks": {
                    "type": "string",
                    "minLength": 1
                },
            },
            "required": ["id", "type", "target", "tasks"],
            "additionalProperties": False,
        },
        "os_step_text_schema": {
            "type": "object",
            "$schema": SCHEMA,
            "properties": {
                "id": {
                    "type": "integer",
                },
                "type": {
                    "enum": ["text"]
                },
                "target": {
                    "type": "array",
                    "items": {
                        "$ref": "#/definitions/target_schema"
                    },
                    "minItems": 1,
                    "uniqueItems": True
                },
                "text": {
                    "type": "string",
                    "minLength": 1
                },
            },
            "required": ["id", "type", "text"],
            "additionalProperties": False,
        },
        "os_step_server_action_schema": {
            "type": "object",
            "$schema": SCHEMA,
            "properties": {
                "id": {
                    "type": "integer",
                },
                "type": {
                    "enum": ["server_down", "server_up", "server_reboot"]
                },
                "target": {
                    "type": "array",
                    "items": {
                        "$ref": "#/definitions/target_schema"
                    },
                    "minItems": 1,
                    "uniqueItems": True
                },
            },
            "required": ["id", "type", "target"],
            "additionalProperties": False,
        },
        "os_step_schema": {
            "type": "array",
            "items": {
                "oneOf": [
                    {"$ref": "#/definitions/os_step_upload_script_schema"},
                    {"$ref": "#/definitions/os_step_run_command_schema"},
                    {"$ref": "#/definitions/os_step_run_tasks_schema"},
                    {"$ref": "#/definitions/os_step_text_schema"},
                    {"$ref": "#/definitions/os_step_server_action_schema"}
                ]
            }
        },
        "scenario_schema": {
            "type": "object",
            "$schema": SCHEMA,
            "patternProperties": {
                'ubuntu|centos': {
                    "$ref": "#/definitions/os_step_schema"
                }
            },
            "anyOf": [{"required": ['ubuntu']}, {"required": ['centos']}],
            "additionalProperties": False
        },
    },
    "properties": {
        "title": {
            "$ref": "#/definitions/short_string_schema"
        },
        "description": {
            "type": "string",
            "maxLength": 1000
        },
        "cve": {
            "$ref": "#/definitions/short_string_schema"
        },
        "ossa": {
            "$ref": "#/definitions/short_string_schema"
        },
        "regenerate_image_ubuntu": {
            "$ref": "#/definitions/bool_schema"
        },
        "regenerate_image_centos": {
            "$ref": "#/definitions/bool_schema"
        },
        "regenerate_bootstrap": {
            "$ref": "#/definitions/bool_schema"
        },
        "regenerate_containers": {
            "$ref": "#/definitions/bool_schema"
        },
        "security": {
            "$ref": "#/definitions/bool_schema"
        },
        "verify_visible": {
            "$ref": "#/definitions/bool_schema"
        },
        "tests": {
            "$ref": "#/definitions/array_schema"
        },
        "rally": {
            "$ref": "#/definitions/array_schema"
        },
        "affected-pkgs": {
            "type": "object",
            "$schema": SCHEMA,
            "patternProperties": {
                'ubuntu|centos': {
                    "$ref": "#/definitions/array_schema"
                }
            },
            "anyOf": [{"required": ['ubuntu']}, {"required": ['centos']}],
            "additionalProperties": False
        },
        "targets": {
            "type": "array",
            "items": {
                "type": "object",
                "$schema": SCHEMA,
                "properties": {
                    "type": {
                        "enum": ["master", "environment"]
                    },
                    "patch-scenario": {
                        "$ref": "#/definitions/scenario_schema"
                    },
                    "verify-scenario": {
                        "$ref": "#/definitions/scenario_schema"
                    }
                },
                "additionalProperties": False,
                "required": ["type", "patch-scenario"]
            }

        }
    },
    "required": ["title", "affected-pkgs"],
    "additionalProperties": False
}

# TODO(vrovachev): TBD after create general schema for erratum version 2
CONFIG_SCHEMA_V2 = {}


def validate_schema(erratum_file):
    """
    Check that erratum schema is correctly
    :param erratum_file: erratum.yaml file
    :return: raise or return 0
    """

    with open(erratum_file) as f:
        content = f.read()
        dict_content = yaml.load(content)
        validate_schema = CONFIG_SCHEMA

        if dict_content.get('version') == 2:
            validate_schema = CONFIG_SCHEMA_V2

        #   validate schema
        logger.info("[   Check erratum schema   ]")
        validate(dict_content, validate_schema)
        logger.info("[ Done ]\n")

        #   Check that OS in affected-pkgs has in patch-scenario and
        #   in verify-scenario if verify-scenario specified

        logger.info("[   Check that OS in affected-pkgs has in "
                    "patch-scenario   ]")
        os_error_msg = ("{system} OS specified in affected-pkgs but not "
                        "specified in {vol}-scenario steps")
        for distro in dict_content['affected-pkgs']:
            for target in dict_content['targets']:
                if not target['patch-scenario'].get(distro):
                    raise Exception(os_error_msg.format(system=distro,
                                                        vol="patch"))
                if target.get('verify-scenario'):
                    if not target['verify-scenario'].get(distro):
                        raise Exception(os_error_msg.format(system=distro,
                                                            vol="verify"))
        logger.info("[ Done ]\n")

        # Check CVE bug if cve bug number specified
        cve_error_msg = ("CVE bub with number: {number} specified in erratum"
                         " file but this bug not found."
                         " URL for search: {search_url}")
        if dict_content.get("cve"):
            logger.info("[   Check CVE bug   ]")
            url_for_cve = CVE_URL.format(bug=dict_content["cve"])
            resp = urllib2.urlopen(url_for_cve)
            if resp.read().find("ERROR:") != -1:
                raise Exception(cve_error_msg.format(
                    number=dict_content['cve'], search_url=url_for_cve))
            logger.info("[ Done ]\n")
    return dict_content


def _get_packages_from_url(mirror, package_url, message=None):

    rpm_regexp = '(?<=href=")([a-z0-9-.]+).rpm'
    deb_regexp = '(?<=href=")([a-z0-9-~_+%.]+).deb'

    if package_url.startswith('centos'):
        distro = 'centos'
        postfix = 'centos/noarch/'
        package_regexp = rpm_regexp
    elif package_url.startswith(('ubuntu', 'trusty')):
        distro = 'ubuntu'
        postfix = 'ubuntu/all/'
        package_regexp = deb_regexp
    mirror_repo_url = "{glob_url}{pkg_url}{postfix}".format(
        glob_url=mirror, pkg_url=package_url, postfix=postfix)
    packages = urllib2.urlopen(
        mirror_repo_url).read().split('\n')

    if message:
        logger.info("-"*40)
        logger.info(message)
        logger.info("-"*40)
        logger.info(mirror_repo_url)
        logger.info("-"*40)

    packages_list = []
    for package in packages:
        package_regexp_result = re.search(package_regexp,
                                          package)
        if package_regexp_result:
            package_name = package_regexp_result.group()

            if message:
                logger.info(package_name)

            packages_list.append((distro, package_name))
    return packages_list


def check_affected_packages(erratum_dict):
    """
    Check that all affected packages has in mirrors
    :param erratum_dict: dictionary with erratum variables
    :return: raise or return 0
    """
    logger.info("[   Check affected packages   ]")
    branch = os.environ.get('GERRIT_BRANCH').split('/')[-1]
    bug = os.environ.get('GERRIT_TOPIC').split('/')[-1]
    logger.info("GERRIT_BRANCH: {branch}".format(branch=branch))
    logger.info("GERRIT_TOPIC: {topic}".format(topic=bug))

    compiled_packages = {'centos': [],
                         'ubuntu': []}
    stable_packages = {'centos': {},
                       'ubuntu': {}}
    get_pkg_part = {
        'centos': {
            'name': (lambda pkg: "-".join(pkg.split('-')[:-2])),
            'version': (lambda pkg, regex=(
                lambda pkg: re.search('(?<=mira)[1-9]+(?<=.)', pkg)):
                int(regex(pkg).group()) if regex(pkg) else 0),
            'full_name': (lambda pkg: pkg.replace(".noarch.rpm", ""))
        },
        'ubuntu': {
            'name': (lambda pkg: pkg.split('_')[0]),
            'version': (lambda pkg, regex=(
                lambda pkg: re.search('(?<=mos)[1-9]+(?<=.)', pkg)):
                int(regex(pkg).group()) if regex(pkg) else 0),
            'full_name': (lambda pkg: pkg.replace("_all.deb", ""))
        }
    }
    affected_packages = {
        "centos": [x.split("=")[0] for x
                   in erratum_dict['affected-pkgs']['centos']],
        "ubuntu": [x.split("=")[0] for x
                   in erratum_dict['affected-pkgs']['ubuntu']]
    }
    affected_pkgs_with_version = {
        "centos": [x.replace("=", "-") for x
                   in erratum_dict['affected-pkgs']['centos']],
        "ubuntu": [x.replace("=", "-") for x
                   in erratum_dict['affected-pkgs']['ubuntu']],
    }
    patch_numbers_in_branch = []
    bug_regexp = ('(?<=href=")(centos|ubuntu|trusty)'
                  '-fuel-{branch}-([a-z-]+)LP{bug}/')
    stable_regexp = ('(?<=href=")(centos|ubuntu|trusty)'
                     '-fuel-{branch}-stable(-updates/|/)')

    for mirror in MIRROR_URLS:
        all_mirror_packages = urllib2.urlopen(mirror).read().split('\n')

        # Find all packages which built in patches for bug on specified mirror
        for package in all_mirror_packages:
            bug_regexp_result = re.search(
                bug_regexp.format(
                    branch=branch, bug=bug), package)
            stable_regexp_result = re.search(
                stable_regexp.format(branch=branch), package)

            if bug_regexp_result:
                package_url = bug_regexp_result.group()

                packages = _get_packages_from_url(
                    mirror, package_url, "found mirror packages repo")

                for distro, package in packages:
                    compiled_packages[distro].append(
                        get_pkg_part[distro]['name'](package))

            if stable_regexp_result:
                stable_url = stable_regexp_result.group()
                packages = _get_packages_from_url(mirror, stable_url)
                for distro, package in packages:
                    package_name = get_pkg_part[distro]['name'](package)
                    package_ver = get_pkg_part[distro]['version'](package)
                    full_name = get_pkg_part[distro]['full_name'](package)
                    if package_name in affected_packages[distro]:
                        if package_name in stable_packages[distro]:
                            if (stable_packages[
                                    distro][package_name]['version']
                                    < package_ver):
                                stable_packages[distro][package_name] = {
                                    'full': full_name,
                                    'version': package_ver
                                }
                        else:
                            stable_packages[distro][package_name] = {
                                'full': full_name,
                                'version': package_ver
                            }

        # Check versions for affected packages

    compiled_packages['ubuntu'].sort()
    compiled_packages['centos'].sort()
    affected_packages['centos'].sort()
    affected_packages['ubuntu'].sort()

    logger.info("-"*40)

    if set(compiled_packages['ubuntu']).symmetric_difference(
            set(affected_packages['ubuntu'])):
        compiled = set(compiled_packages['ubuntu']).difference(
            affected_packages['ubuntu'])
        affected = set(affected_packages['ubuntu']).difference(
            compiled_packages['ubuntu'])
        if compiled:
            logger.warn("Compiled Ubuntu packages but not in erratum "
                        "file:\n{}".format("\n".join(list(compiled))))
        if affected:
            raise BaseException("Ubuntu packages in erratum file but not "
                                "compiled:\n{}".format(
                                "\n".join(list(affected))))

    if set(compiled_packages['centos']).symmetric_difference(
            affected_packages['centos']):
        compiled = set(compiled_packages['centos']).difference(
            affected_packages['centos'])
        affected = set(affected_packages['centos']).difference(
            compiled_packages['centos'])
        if compiled:
            logger.warn("Compiled CentOS packages but not in erratum "
                        "file:\n{}".format("\n".join(list(compiled))))
        if affected:
            raise BaseException("Ubuntu packages in erratum file but not "
                                "compiled:\n{}".format(
                                "\n".join(list(affected))))

    logger.info("[ Done ]\n")
    logger.info("[ Check that in affected_pkgs specified "
                "last package versions ]")

    found_affected_centos = [value['full'] for key, value
                             in stable_packages['centos'].iteritems()]
    found_affected_ubuntu = [value['full'].replace('%2b', '+')
                             for key, value
                             in stable_packages['ubuntu'].iteritems()]

    found_affected_centos.sort()
    found_affected_ubuntu.sort()
    affected_pkgs_with_version['centos'].sort()
    affected_pkgs_with_version['ubuntu'].sort()

    centos_difference = set(found_affected_centos).symmetric_difference(
        set(affected_pkgs_with_version['centos']))
    ubuntu_difference = set(found_affected_ubuntu).symmetric_difference(
        set(affected_pkgs_with_version['ubuntu']))

    err_msg = ('Found difference in {} affected packages in erratum file and '
               'in mirrors.\n '
               'Packages in erratum file:\n{}\n Found Packages:\n{}\n')
    if centos_difference:
        logger.warning(err_msg.format("CentOS",
                                      "\n".join(
                                          affected_pkgs_with_version[
                                              'centos']),
                                      "\n".join(found_affected_centos)))
    if ubuntu_difference:
        logger.warning(err_msg.format("Ubuntu",
                                      "\n".join(
                                          affected_pkgs_with_version[
                                              'ubuntu']),
                                      "\n".join(found_affected_ubuntu)))
    logger.info("[ Done ]\n")


if __name__ == "__main__":
    erratum_dict = validate_schema(sys.argv[1])
    check_affected_packages(erratum_dict)
