#!/usr/bin/env python

import build_cluster
import netaddr


CONNECT_LINE = "root@780_admin"
PSWD = "r00tme"


def test_bool(name, func):
    if func:
        print "\033[32mOK\033[00m   - "+name
    else:
        print "\033[31mOK\033[00m   - "+name


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


if __name__ == "__main__":
    main()
