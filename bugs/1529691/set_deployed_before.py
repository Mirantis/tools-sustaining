#!/usr/bin/env python

import json
import subprocess


class DockerUtils():
    def run_psql_in_container(self, sql, db):
        ret = []
        cmd = ["dockerctl",
               "shell",
               "postgres",
               "sudo",
               "-u",
               "postgres",
               "psql",
               db,
               "--tuples-only",
               "--no-align",
               "-c",
               sql]
        results = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE,
                                   universal_newlines=True)

        for l in results.stdout:
            ret.append(l.strip())

        return ret


class NailgunEditor(DockerUtils):
    db = "nailgun"

    def add_deployed_before_flag(self):
        values = []
        for line in self.run_psql_in_container(
                "select id, generated from attributes;", self.db):
            c_id, c_data = line.split("|", 1)
            data = json.loads(c_data)
            data["deployed_before"] = {"value": True}
            values.append("({0}, '{1}')".format(c_id, json.dumps(data)))

        if values:
            self.run_psql_in_container(
                'update attributes as a set generated = b.generated '
                'from (values {0}) as b(id, generated) '
                'where a.id = b.id;'.format(','.join(values)),
                self.db)


if __name__ == "__main__":
    ne = NailgunEditor()
    ne.add_deployed_before_flag()
    print("deployed_before flag successfully added")
