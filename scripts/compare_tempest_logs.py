#!/usr/bin/env python
# Copyright 2015 Mirantis, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import xml.etree.ElementTree as ET
from argparse import ArgumentParser


success_cases = []
failed_cases = []
skipped_cases = []
testcases_statuses = {}
success_cases_compared = []
failed_cases_compared = []
skipped_cases_compared = []
testcases_diffs = {}
testcases_new = {}
testcases_removed = {}


def process_report(filename, testcase_handler):
    tree = ET.parse(filename)
    testsuite = tree.getroot()
    for testcase in testsuite:
        testcase_handler(testcase)
    if testcase_handler == compare_testcase:
        for key in testcases_statuses.keys():
            if not testcases_statuses[key]["matched"]:
                testcases_removed[key] = testcases_statuses[key]


def save_base_testcase(element):
    children_tags = [elem.tag for elem in element.iter()
                     if elem is not element]
    testcase_name = element.attrib['name'].split('[')[0]
    classname = element.attrib["classname"]
    testcase_fullname = classname + "::" + testcase_name if classname \
        else testcase_name
    testcase_status = {
        "classname": element.attrib["classname"],
        "matched": False
    }
    if not children_tags:
        success_cases.append(testcase_fullname)
        testcase_status.update({
            "status": "success",
        })
    elif "skipped" in children_tags:
        skipped_cases.append(testcase_fullname)
        testcase_status.update({
            "status": "skipped",
            "reason": element[0].text,
        })
    elif "failure" in children_tags:
        failed_cases.append(testcase_fullname)
        testcase_status.update({
            "status": "failure",
            "type": element[0].attrib["type"],
            "traceback": element[0].text,
        })
    testcases_statuses[testcase_fullname] = testcase_status


def compare_testcase(element):
    children_tags = [elem.tag for elem in element.iter()
                     if elem is not element]
    testcase_name = element.attrib["name"].split("[")[0]
    classname = element.attrib["classname"]
    testcase_fullname = classname + "::" + testcase_name if classname \
        else testcase_name

    testcase_data = {}
    if not children_tags:
        success_cases_compared.append(testcase_fullname)
        testcase_data["status"] = "success"
        process_testcase_data(testcase_fullname, testcase_data, "success")
    elif "skipped" in children_tags:
        skipped_cases_compared.append(testcase_fullname)
        testcase_data["status"] = "skipped"
        testcase_data["reason"] = element[0].text
        process_testcase_data(testcase_fullname, testcase_data, "skipped")
    elif "failure" in children_tags:
        failed_cases_compared.append(testcase_fullname)
        testcase_data["status"] = "failure"
        testcase_data["type"] = element[0].attrib["type"]
        testcase_data["traceback"] = element[0].text
        process_testcase_data(testcase_fullname, testcase_data, "failure")


def process_testcase_data(fullname, data, oldstatus):
    if fullname in testcases_statuses:
        testcases_statuses[fullname]["matched"] = True
        if testcases_statuses[fullname]["status"] != oldstatus:
            data["oldstatus"] = testcases_statuses[fullname]["status"]
            testcases_diffs[fullname] = data
    else:
        testcases_new[fullname] = data


def print_reports_diff(detailed, show_emerging=False):
    testcases = sorted(testcases_diffs.keys())
    if not len(testcases):
        print "No differences found in results."
    else:
        counter = 1
        for testcase in testcases:
            if detailed:
                print "=============================================="
            testcase_data = testcases_diffs[testcase]
            print "{0}) {1}: {2} --> {3}".format(
                counter, testcase,
                testcase_data["oldstatus"].upper(),
                testcase_data["status"].upper())
            if detailed:
                if "reason" in testcase_data:
                    print "reason: {0}".format(testcase_data["reason"])
                if "type" in testcase_data:
                    print "failure type: {0}".format(testcase_data["type"])
                    print "traceback:\n{0}".format(testcase_data["traceback"])
            counter += 1

    if show_emerging:
        testcases = sorted(testcases_new.keys())
        if len(testcases):
            print "\n"
            print "NEW testcases found:"
            counter = 1
            for testcase in testcases:
                if detailed:
                    print "=============================================="
                testcase_data = testcases_new[testcase]
                print "{0}) {1}: {2}".format(
                    counter, testcase,
                    testcase_data["status"].upper())
                if detailed:
                    if "reason" in testcase_data:
                        print "reason: {0}".format(testcase_data["reason"])
                    if "type" in testcase_data:
                        print "failure type: {0}".format(testcase_data["type"])
                        print "traceback:\n{0}".format(
                            testcase_data["traceback"])
                counter += 1
        testcases = sorted(testcases_removed.keys())
        if len(testcases):
            print "\n"
            print "REMOVED testcases (showing OLD details):"
            counter = 1
            for testcase in testcases:
                if detailed:
                    print "=============================================="
                testcase_data = testcases_statuses[testcase]
                print "{0}) {1}: status - {2}".format(
                    counter, testcase,
                    testcase_data["status"].upper())
                if detailed:
                    if "reason" in testcase_data:
                        print "reason: {0}".format(testcase_data["reason"])
                    if "type" in testcase_data:
                        print "failure type: {0}".format(testcase_data["type"])
                        print "traceback:\n{0}".format(
                            testcase_data["traceback"])
                counter += 1


def main():
    parser = ArgumentParser(description="Compare Tempest logs")
    parser.add_argument("base", type=str,
                        help="first (base) log",
                        metavar="base")
    parser.add_argument("--compare", type=str,
                        help="second (right) log to compare",
                        metavar="right")
    parser.add_argument("--detailed", dest="detailed",
                        action="store_true",
                        help="show detailed info for diffed testcases")
    parser.add_argument("--show-emerging", dest="show_emerging",
                        action="store_true",
                        help="show emerged or disappeared testcases")
    args = parser.parse_args()
    process_report(args.base, save_base_testcase)
    initial_results = "success: {0}; failures: {1}; skipped: {2}".format(
        len(success_cases),
        len(failed_cases),
        len(skipped_cases))
    if args.compare:
        print "was: " + initial_results
        process_report(args.compare, compare_testcase)
        print "now: success: {0}; failures: {1}; skipped: {2}".format(
            len(success_cases_compared),
            len(failed_cases_compared),
            len(skipped_cases_compared))
        print_reports_diff(args.detailed, args.show_emerging)
    else:
        print initial_results

if __name__ == "__main__":
    main()
