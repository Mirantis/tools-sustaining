#!/usr/bin/env python

import re
import sys
import urllib2

mos_repo_template = {
    "6.1": {
    "ubuntu": "http://mirror.fuel-infra.org/mos/ubuntu/dists/mos6.1-{REPO_NAME}/",
    "centos": "http://mirror.fuel-infra.org/mos/centos-6/mos6.1/{REPO_NAME}/",
    },
    "7.0": {
        "ubuntu": "http://mirror.fuel-infra.org/mos-repos/ubuntu/7.0/dists/mos7.0-{REPO_NAME}/",
        #"ubuntu": "http://mirror.seed-cz1.fuel-infra.org/mos-repos/ubuntu/7.0/dists/mos7.0-{REPO_NAME}/",
        "centos": "http://mirror.fuel-infra.org/mos-repos/centos/mos7.0-centos6-fuel/{REPO_NAME}/"
    },
    "8.0": {
        "ubuntu": "http://mirror.seed-cz1.fuel-infra.org/mos-repos/ubuntu/8.0/dists/mos8.0-{REPO_NAME}/",
    }

}

latest_mos_repo_template = {
    "6.1": {
    "ubuntu": "http://mirror.fuel-infra.org/mos/snapshots/ubuntu-latest/dists/mos6.1-{REPO_NAME}/",
    "centos": "http://mirror.fuel-infra.org/mos/snapshots/centos-6-latest/mos6.1/{REPO_NAME}/",
    },
    "7.0": {
        "ubuntu": "http://mirror.seed-cz1.fuel-infra.org/mos-repos/ubuntu/snapshots/7.0-latest/dists/mos7.0-{REPO_NAME}/",
    },
    "8.0": {
        "ubuntu": "http://mirror.seed-cz1.fuel-infra.org/mos-repos/ubuntu/snapshots/8.0-latest/dists/mos8.0-{REPO_NAME}/",
    }
}


class Ubuntu_packages():

    def __init__(self, version, repo, use_latest):
        if use_latest:
            self.ubuntu_url = latest_mos_repo_template[version]['ubuntu'].format(REPO_NAME=repo)
        else:
            self.ubuntu_url = mos_repo_template[version]['ubuntu'].format(REPO_NAME=repo)
        packages_list = self.create_package_list()
        print "Packages"
        print "------------------------------"
        for package in packages_list:
            print package

    @staticmethod
    def download_release_file(ubuntu_url):
        url = ubuntu_url + "main/binary-amd64/Packages"
        print "URL\n------------------------------"
        print url
        print "------------------------------"
        return urllib2.urlopen(url).read()

    def create_package_list(self):
        packages_list = []
        list = self.download_release_file(self.ubuntu_url).split('\n')
        for str in list:
            if str.startswith("Filename:"):
                packages_list.append(str.split('/')[-1])
        return packages_list


class Centos_packages():

    def __init__(self, version, repo, use_latest):
        self.centos_url = None
        if use_latest:
            if 'centos' in latest_mos_repo_template[version]:
                self.centos_url = latest_mos_repo_template[version]['centos'].format(REPO_NAME=repo)
        else:
            if 'centos' in mos_repo_template[version]:
                self.centos_url = mos_repo_template[version]['centos'].format(REPO_NAME=repo)
        if not self.centos_url:
            print "Centos mirrors for version:{} not found.".format(version)
            return
        packages = self.create_package_list()
        print "Packages"
        print "------------------------------"
        for package in packages:
            print package

    @staticmethod
    def download_all_package_names(centos_url):
        url = centos_url
        print "URL\n------------------------------"
        print url
        print "------------------------------"
        prev_dir = urllib2.urlopen(url).read()
        if "Packages" in prev_dir:
            return urllib2.urlopen(url + "Packages/").read()
        elif "noarch" in prev_dir:
            return urllib2.urlopen(url + "noarch/").read()
        elif "x86_64" in prev_dir:
            return urllib2.urlopen(url + "x86_64/Packages/").read()

    def create_package_list(self):
        package_list = []
        packages = self.download_all_package_names(self.centos_url).split("\n")
        re_str = "[\w.-]+.rpm"
        req = re.compile(re_str)
        for package in packages:
            result = req.search(package)
            if result:
                package_list.append(result.group())
        return package_list


if __name__ == "__main__":
    version = "7.0"
    repo = "proposed"
    use_latest = False
    for cmd in sys.argv[1:]:
        if "--version" in cmd:
            version = cmd.split('=')[1]
        if "--repo" in cmd:
            repo = cmd.split('=')[1]
        if cmd == "--use-latest":
            use_latest = True
    Ubuntu_packages(version, repo, use_latest)
    Centos_packages(version, repo, use_latest)
