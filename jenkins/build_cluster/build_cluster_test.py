#!/usr/bin/env python

import build_cluster
import netaddr


CONNECT_LINE = "root@780_admin"
PSWD = "r00tme"


def test_bool(name, func):
    if func:
        print "\033[32mOK\033[00m   - "+name
    else:
        print "\033[31mFAIL\033[00m   - "+name


def main():

    node = build_cluster.SSHHost(conn_line=CONNECT_LINE,
                                 pswd=PSWD)

    test_bool("ssh execute",
              node.execute(["hostname"]))

    test_bool("ssh execute fail",
              not node.execute(["exit", "1"]))

    test_bool("scp put file",
            node.put_file("./update_helper.sh"))

    test_bool("scp put file check file",
              node.execute(["test", "-f","/tmp/update_helper.sh"]))

    test_bool("scp put file remove file",
              node.execute(["rm", "-f","/tmp/update_helper.sh"]))

    test_bool("scp put file check file",
              not node.execute(["test", "-f","/tmp/update_helper.sh"]))

    # NOTE: can take too many time...
    test_bool("do update",
              build_cluster.do_update (node))
    repolist='''http://mirror.fuel-infra.org/mos-repos/centos/mos9.0-centos7/updates/x86_64/
    http://mirror.fuel-infra.org/mos-repos/centos/mos9.0-centos7/security/x86_64/
    '''

    test_bool("add repo",
              build_cluster.add_cent_repo(node,repolist))

    test_bool("add repo helper file",
              node.execute(["test", "-f","/tmp/repo_helper.sh"]))

    test_bool("add repo check repo file 1",
              node.execute(["test", "-f","/etc/yum.repos.d/add1.repo"]))

    test_bool("add repo rm repo file 1",
              node.execute(["rm", "-f","/etc/yum.repos.d/add1.repo"]))

    test_bool("add repo check repo file 2",
              node.execute(["test", "-f","/etc/yum.repos.d/add2.repo"]))

    test_bool("add repo rm repo file 2",
              node.execute(["rm", "-f","/etc/yum.repos.d/add2.repo"]))

if __name__ == "__main__":
    main()
