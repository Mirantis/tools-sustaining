#!/usr/bin/env python

import build_cluster
import netaddr


CONNECT_LINE = "root@test_admin"
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

    test_bool("add pub keys",
              node.put_ssh_pub_keys("""ssh-rsa AAAAB6NzaC1yc2EAAAADAQABAAABAQC8PWq76FFIKmxPGMdWErBMEFwtb2NZYeTxu1lMVacC1QemMMaoybNisvD+L4JyaiC+zFQzlHlCDgicCgw7TXkgFtoyttLMxbshcu+wx0uG8bMlQTZ5DZ7ywwBU7+OysSgBEvju1dlMF7wOKDcYLfJxbYoUYvq+tgVbBWBFm8q+PrMvZZGfPX5M6m/sdpiFc3/f1K6Hh+DeV+9hFx/2vES62Qwv76zzr7oGS3tAi2RyBFt6BWrJx9vqa25AAoqzRsHoj0+0iAi1reZQ3jvz3FIsfgVN+ymVv431X4Gr3H8+BMj56VpT5z8McXj9+o+qoK70YLrtg2z2IpSONOE7o3JX ac@achevychalov_

XXXXXJJJJJJJJJ ac@achevycahlov
ssh-rsa AAAAB7NzaC1yc2EAAAADAQABAAABAQC8PWq76FFIKmxPGMdWErBMEFwtb2NZYeTxu1lMVacC1QemMMaoybNisvD+L4JyaiC+zFQzlHlCDgicCgw7TXkgFtoyttLMxbshcu+wx0uG8bMlQTZ5DZ7ywwBU7+OysSgBEvju1dlMF7wOKDcYLfJxbYoUYvq+tgVbBWBFm8q+PrMvZZGfPX5M6m/sdpiFc3/f1K6Hh+DeV+9hFx/2vES62Qwv76zzr7oGS3tAi2RyBFt6BWrJx9vqa25AAoqzRsHoj0+0iAi1reZQ3jvz3FIsfgVN+ymVv431X4Gr3H8+BMj56VpT5z8McXj9+o+qoK70YLrtg2z2IpSONOE7o3JX ac@achevychalov_"""))

    test_bool("add pub keys CHECK1",
              node.execute(["egrep","-q","AAAAB6N", ".ssh/authorized_keys"]))

    test_bool("add pub keys CHECK2",
              node.execute(["egrep","-q","AAAAB7N", ".ssh/authorized_keys"]))

    test_bool("add pub keys CHECK3",
              not node.execute(["egrep","-q","XXXXXJ", ".ssh/authorized_keys"]))

if __name__ == "__main__":
    main()
