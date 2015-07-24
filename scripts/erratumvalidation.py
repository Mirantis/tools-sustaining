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

from jsonschema import validate
import yaml
import sys
import urllib2

SCHEMA = "http://json-schema.org/draft-04/schema"

CVE_URL = "https://cve.mitre.org/cgi-bin/cvename.cgi?name={bug}"

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

    with open(erratum_file) as f:
        content = f.read()
        dict_content = yaml.load(content)
        validate_schema = CONFIG_SCHEMA

        if dict_content.get('version') == 2:
            validate_schema = CONFIG_SCHEMA_V2

        #   validate schema
        validate(dict_content, validate_schema)

        #   Check that OS in affected-pkgs has in patch-scenario and
        #   in verify-scenario if verify-scenario specified
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

        # Check CVE bug if cve bug number specified
        cve_error_msg = ("CVE bub with number: {number} specified in erratum"
                         " file but this bug not found."
                         " URL for search: {search_url}")
        if dict_content.get("cve"):
            url_for_cve = CVE_URL.format(bug=dict_content["cve"])
            resp = urllib2.urlopen(url_for_cve)
            if resp.read().find("ERROR:") != -1:
                raise Exception(cve_error_msg.format(
                    number=dict_content['cve'], search_url=url_for_cve))

if __name__ == "__main__":
    validate_schema(sys.argv[1])
