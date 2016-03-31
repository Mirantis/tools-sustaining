#!/usr/bin/env python
# coding: utf-8

import argparse
import collections
import hashlib
import logging
import os
import re
import requests
import subprocess
import sys
import urlparse
import yaml


LOG = logging.getLogger('codesync')

config_data = {}
commit_stats = {
    "total_commits": 0,
    "total_regexp_errors": 0
}
failed_projects_list = []
push_failures_list = []
merge_not_needed_list = []


class FailedToMerge(Exception):
    '''Raised when automatic merge fails due to conflicts.'''


def _clone_or_fetch(gerrit_uri):
    LOG.info('Cloning %s...', gerrit_uri)

    repo = os.path.basename(urlparse.urlsplit(gerrit_uri).path)

    retcode = subprocess.call(
        ['git', 'clone', '-q', gerrit_uri],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    if retcode:
        if not os.path.exists(repo):
            LOG.error('Failed to clone repo: %s', gerrit_uri)
            raise RuntimeError('Failed to clone repo: %s' % gerrit_uri)
        else:
            LOG.info('Repo already exists, fetching the latest state...')

            subprocess.check_call(
                ['git', 'reset', '--hard', 'HEAD'],
                cwd=repo,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            subprocess.check_call(
                ['git', 'remote', 'update'],
                cwd=repo,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )

    path = os.path.join(os.getcwd(), repo)
    LOG.info('Updated repo at: %s', path)
    return path


def _get_commit_id(repo, ref='HEAD'):
    return subprocess.check_output(
        ['git', 'show', ref],
        cwd=repo
    ).splitlines()[0].split()[1]


def _get_merge_commit_message(repo, downstream_branch, upstream_branch):
    downstream = _get_commit_id(repo, downstream_branch)
    upstream = _get_commit_id(repo, upstream_branch)

    LOG.info('Downstream commit id: %s', downstream)
    LOG.info('Upstream commit id: %s', upstream)

    commits_range = '%s..%s' % (downstream_branch, upstream_branch)
    commits = subprocess.check_output(
        ['git', 'log', '--no-merges', '--pretty=format:%h %s', commits_range],
        cwd=repo
    )

    hashsum = hashlib.sha1()
    hashsum.update(downstream)
    changeid = 'I' + hashsum.hexdigest()

    template = ('Merge the tip of %(upstream)s into %(downstream)s'
                '\n\n%(commits)s'
                '\n\nChange-Id: %(changeid)s')

    return template % {'upstream': upstream_branch,
                       'downstream': downstream_branch,
                       'changeid': changeid,
                       'commits': commits}


def personalize_committer(repo):
    result = subprocess.check_output(
        ['git', 'config', '--global', 'user.email',
         config_data[0]['options']['committer-email']],
        cwd=repo
    )
    result = subprocess.check_output(
        ['git', 'config', '--global', 'user.name',
         config_data[0]['options']['committer-name']],
        cwd=repo
    )
    return result


def local_branch_exists(repo, branch):
    branch_head = None
    try:
        branch_head = subprocess.check_output(
            ['git', 'show-ref', '--verify', 'refs/heads/{0}'.format(branch)],
            cwd=repo
        )
    except subprocess.CalledProcessError:
        pass
    return (branch_head is not None)


def _merge_tip(repo, downstream_branch, upstream_branch):
    LOG.info('Trying to merge the tip of %s into %s...',
             upstream_branch, downstream_branch)

    if not downstream_branch.startswith('origin/'):
        downstream_branch = 'origin/' + downstream_branch
    if not upstream_branch.startswith('origin/'):
        upstream_branch = 'origin/' + upstream_branch

    personalize_committer(repo)

    # print merge information for visibility purposes
    commits_range = '%s..%s' % (downstream_branch, upstream_branch)
    graph = subprocess.check_output(
        ['git', 'log', '--graph', '--pretty=format:%h %s', commits_range],
        cwd=repo
    )

    if graph:
        LOG.info('Commits graph to be merged:\n\n"%s"', graph)
    else:
        merge_not_needed_list.append(repo)
        raise FailedToMerge('Downstream branch is up-to-date/ahead of upstream branch, nothing to merge.')

    local_downstream_branch = '/'.join(downstream_branch.split('/')[1:])

    if local_branch_exists(repo, local_downstream_branch):
        # cleanup local branch
        subprocess.check_call(
            ['git', 'checkout', 'master'],
            cwd=repo,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        subprocess.check_call(
            ['git', 'branch', '-D', local_downstream_branch],
            cwd=repo,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )

    subprocess.check_call(
        ['git', 'checkout', '-b', local_downstream_branch,
         downstream_branch],
        cwd=repo,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )

    try:
        m = _get_merge_commit_message(repo, downstream_branch, upstream_branch)
        LOG.info('Commit message:\n\n%s\n\n', m)

        subprocess.check_call(
            ['git', 'merge', '--no-ff', '-m', m, upstream_branch],
            cwd=repo,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
    except subprocess.CalledProcessError as e:
        if graph:
            failed_projects_list.append(repo)
        raise FailedToMerge
    else:
        commit = _get_commit_id(repo)
        LOG.info('Merge commit id: %s', commit)
        return commit


def _upload_for_review(repo, commit, branch, topic=None):
    LOG.info('Uploading commit %s to %s for review...', commit, branch)

    pusharg = '%s:refs/for/%s' % (commit, branch)
    if topic:
        pusharg += '%topic=' + str(topic)

    process = subprocess.Popen(
        ['git', 'push', 'origin', pusharg],
        cwd=repo,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    stdout, stderr = process.communicate()

    if process.returncode:
        if 'no changes made' in stdout or 'no changes made' in stderr:
            LOG.info('No changes since the last sync. Skip.')
        else:
            LOG.error('Something went wrong!')
            LOG.error('stdout: {}'.format(stdout))
            LOG.error('stderr: {}'.format(stderr))
            push_failures_list.append(repo)
            LOG.error('Failed to push the commit %s to %s', commit, branch)


def _cleanup(repo):
    LOG.info('Running cleanups (hard reset + checkout of master + gc)...')

    subprocess.check_call(
        ['git', 'reset', '--hard', 'HEAD'],
        cwd=repo,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    subprocess.check_call(
        ['git', 'checkout', 'master'],
        cwd=repo,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    subprocess.check_call(
        ['git', 'gc'],
        cwd=repo,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )

    LOG.info('Cleanups done.')


def sync_project(gerrit_uri, downstream_branch, upstream_branch, topic=None,
                 cleanup=True, dry_run=False):
    '''Merge the tip of the tracked upstream branch and upload it for review.

    Tries to clone (fetch, if path already exists) the git repo and do a
    non-fastforward merge of the tip of the tracked upstream branch into
    downstream one, and then upload the resulting merge commit for review.

    If automatic merge fails due to conflicts, FailedToMerge exception is
    raised.

    :param gerrit_uri: gerrit git repo uri
    :param downstream_branch: name of the downstream branch
    :param upstream_branch: name of the corresponding upstream branch
    :param topic: a Gerrit topic to be used
    :param dry_run: don't actually upload commits to Gerrit, just try to merge
                    the branch locally

    :returns merge commit id

    '''

    repo = _clone_or_fetch(gerrit_uri)
    try:
        commit = _merge_tip(repo, downstream_branch, upstream_branch)

        if not dry_run:
            _upload_for_review(repo, commit, downstream_branch, topic=topic)
        else:
            LOG.info('Dry run, do not attempt to upload the merge commit')

        return commit
    finally:
        if cleanup:
            _cleanup(repo)
        else:
            LOG.info('!!! Explictly chosen *NOT* to cleanup. You must '
                     'perform all further stuff *MANUALLY*, uncluding '
                     'final cleanup !!!')


def merge_bug_fixes(gerrit_uri, downstream_branch, upstream_branch, topic=None,
                    cleanup=True, dry_run=False):
    LOG.info("Trying to cherry-pick only High/Critical bug fixes of %s into "
             "%s...", upstream_branch, downstream_branch)

    repo = _clone_or_fetch(gerrit_uri)

    personalize_committer(repo)

    if not downstream_branch.startswith("origin/"):
        downstream_branch = "origin/" + downstream_branch
    if not upstream_branch.startswith('origin/'):
        upstream_branch = "origin/" + upstream_branch

    # print difference information
    commits_range = '%s..%s' % (downstream_branch, upstream_branch)
    graph = subprocess.check_output(
        ["git", "log", "--no-merges", "--graph",
         "--pretty=format:'%Cred%h%Creset -%C(yellow)%d%Creset %s "
         "%Cgreen(%cr)%Creset'", "--abbrev-commit", "--date=relative",
         commits_range],
        cwd=repo
    )

    # possible output:
    # * a0ffd8c - Validate translations (7 days ago)
    # * 1f594f9 - Imported Translations from Zanata (3 days ago)
    # * 9ed4489 - Imported Translations from Zanata (5 days ago)
    # * 8ffca40 - Imported Translations from Zanata (9 days ago)
    if graph:
        LOG.info("Commits, that may contain needed bug fixes:\n\n%s\n", graph)

    commits_list = subprocess.check_output(
        ["git", "log", "--no-merges",
         "--pretty=format:'%Cred%h%Creset -%C(yellow)%d%Creset %s "
         "%Cgreen(%cr)%Creset'", "--abbrev-commit", "--date=relative",
         commits_range],
        cwd=repo
    )

    commit_lines = commits_list.split("\n")

    bugs = collections.OrderedDict()
    bug_suffixes = ["closes-bug:", "partial-bug:", "fixes-bug",
                    "partially-fixes-bug", "closes bug:", "partial bug:",
                    "fixes bug", "partially fixes bug"]
    commits_count = 0
    regexp_error_count = 0
    for ind, commit_line in enumerate(commit_lines):
        try:
            commit_line = re.sub('\x1b[^m]*m', '',
                                 commit_line).replace("'", "")
            commit_lines[ind] = commit_line
            if not commit_line:
                continue
            # commit_id = re.search('\* (.*) - *', commit_line).group(1)
            commit_id = commit_line.split('-')[0].strip()
            commit_msg = subprocess.check_output(
                ["git", "log", "--format=%B", "-n", "1", commit_id],
                cwd=repo
            )

            for bug_suffix in bug_suffixes:
                if bug_suffix in commit_msg.lower():
                    # line may looks like:
                    # Closes-Bug: #1536214
                    # We're setting the following values in bugs dict:
                    # bugs["a0ffd8c"] = "1536214"
                    bugs[commit_id] = re.search('%s #?(.+?)\\n' % bug_suffix,
                                                commit_msg.lower()).group(1)
                    break
            commits_count += 1
        except AttributeError as e:
            LOG.info("Encountered commit_line '{0}', skipping...".format(
                commit_line))
            regexp_error_count += 1
            continue
        except subprocess.CalledProcessError as e:
            LOG.info("Git returned error: '{0}', skipping...".format(
                e))
            LOG.info("Commit line was: '{0}'".format(
                commit_line))
            regexp_error_count += 1
            continue
    commit_stats["total_commits"] += commits_count
    LOG.info("Processed commits: {0}".format(commits_count))
    if regexp_error_count:
        commit_stats["total_regexp_errors"] += regexp_error_count
        LOG.info("Regexp failures encountered: {0}".format(
            regexp_error_count))
    if len(bugs.keys()):
        LOG.info("Commits, that are bug fixes:\n%s\n", bugs.keys())

    important_bugs = collections.OrderedDict()

    for commit_id, bug in bugs.iteritems():
        resp = requests.get("https://api.launchpad.net/devel/bugs/%s/bug_tasks"
                            % bug).json()
        for entry in resp["entries"]:
            if "liberty" in entry["bug_target_name"] and \
                            entry["importance"] in ["High", "Critical"]:
                important_bugs[commit_id] = bug

    if len(important_bugs.keys()):
        LOG.info("Commits, that are important bug fixes:\n%s\n",
                 important_bugs.keys())

    if important_bugs:
        subprocess.check_call(
            ['git', 'checkout', downstream_branch],
            cwd=repo,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        try:
            items = important_bugs.items()
            items.reverse()
            for bug in collections.OrderedDict(items):
                subprocess.check_call(
                    ['git', 'cherry-pick', '-x', bug],
                    cwd=repo,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE
                )
        except subprocess.CalledProcessError:
            raise FailedToMerge
        else:
            commit = _get_commit_id(repo)
            LOG.info('Current commit id: %s', commit)
            if not dry_run:
                _upload_for_review(repo, commit, downstream_branch,
                                   topic=topic)
            else:
                LOG.info('Dry run, do not attempt to upload the merge commit')
            return commit


def read_config(config_file):
    global config_data
    with open(config_file, 'r') as f:
        config_data = yaml.load(f)


def process_repos(action, downstream_branch, upstream_branch,
                  topic, cleanup=True, dry_run=True, repo_names=None):
    repos_list = config_data[0]['options']['project']
    gerrit_base_uri = config_data[0]['options']['gerrit-base-uri']
    upstream_branch = upstream_branch or \
        config_data[0]['options']['upstream-branch']
    downstream_branch = downstream_branch or \
        config_data[0]['options']['downstream-branch']
    topic = topic or config_data[0]['options']['gerrit-topic']
    print "Using gerrit URI: {0}".format(gerrit_base_uri)

    if action == 'merge_tip':
        func = sync_project
    elif action == 'merge_bug_fixes':
        func = merge_bug_fixes

    if not repo_names:
        repo_names = [repo[repo.keys()[0]]['repo'] for repo in repos_list]

    for repo_name in repo_names:
        LOG.info("========================================================")
        LOG.info("processing project: {0}".format(repo_name))
        try:
            commit = func(gerrit_uri=gerrit_base_uri + "/" + repo_name,
                          downstream_branch=downstream_branch,
                          upstream_branch=upstream_branch,
                          topic=topic,
                          cleanup=cleanup,
                          dry_run=dry_run)
            if commit:
                print(commit)
        except FailedToMerge as e:
            LOG.info("Automatic merge failed: {0}".format(e.message))
            LOG.info("Trying next repo from batch.")
            continue

    if func == merge_bug_fixes:
        LOG.info("======================TOTAL==================================")
        LOG.info("Commits found: {0}".format(commit_stats["total_commits"]))
        LOG.info("Regexp errors encountered: {0}".format(
            commit_stats["total_regexp_errors"]))
    elif func == sync_project:
        if failed_projects_list:
            LOG.info("Upstream changes failed to merge automatically for the following projects:")
            for project_repo in failed_projects_list:
                LOG.info("{0}".format(project_repo))
        if push_failures_list:
            LOG.info("Failed to push merge commit for the following projects:")
            for push_failure in push_failures_list:
                LOG.info("{0}".format(push_failure))
        if merge_not_needed_list:
            LOG.info("Failed to push merge commit for the following projects:")
            for project in merge_not_needed_list:
                LOG.info("{0}".format(project))


def main():
    logging.basicConfig(
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    LOG.setLevel(logging.INFO)

    parser = argparse.ArgumentParser(
        description=('Merge the tip of the upstream tracking branch and '
                     'upload it for review. Merge commit id is printed '
                     'to stdout on success. If automatic merge fails '
                     'the process ends with a special exit code - 1. '
                     'All other exit codes (except 0 and 1) are runtime '
                     'errors.')
    )

    parser.add_argument(
        'config', type=str,
        help="Name of file, containing the List of very basic parameter "
             "defaults and list of projects to process.",
        metavar="config"
    )

    parser.add_argument(
        '--action',
        help="What action is expected to happen. By default script will try"
             "to upload on review the merge commit of upstream branch to "
             "downstream branch. Also it's possible to merge only resolutions "
             "of High and Critical bugs from the upstream.",
        default='merge_tip',
        choices=['merge_tip', 'merge_bug_fixes'],
    )

    parser.add_argument(
        '--downstream-branch',
        help=('downstream branch to upload merge commit to '
              '(defaults to $SYNC_DOWNSTREAM_BRANCH)'),
        default=os.getenv('SYNC_DOWNSTREAM_BRANCH')
    )
    parser.add_argument(
        '--upstream-branch',
        help=('upstream branch to sync the state from '
              '(defaults to $SYNC_UPSTREAM_BRANCH)'),
        default=os.getenv('SYNC_UPSTREAM_BRANCH')
    )
    parser.add_argument(
        '--topic',
        help='a Gerrit topic to be used',
        default=os.getenv('SYNC_GERRIT_TOPIC')
    )
    parser.add_argument(
        '--cleanup',
        help="Clean up after merge attempt",
        action='store_true'
    )
    parser.add_argument(
        '--dry-run',
        help="do not upload a merge commit on review - just try local merge",
        action='store_true'
    )

    try:
        args = parser.parse_args()
        if not args.action:
            parser.print_usage()
            raise ValueError('Required arguments not passed')
        read_config(args.config)
        cleanup = bool(os.getenv('SYNC_CLEANUP') == 'true') or args.cleanup
        dry_run = bool(os.getenv('SYNC_DRY_RUN') == 'true') or args.dry_run
        repo_names = os.getenv('PROJECTS_LIST')
        if not repo_names:
            repo_names = None
        else:
            repo_names = repo_names.split('\n')
        process_repos(args.action,
                      args.downstream_branch,
                      args.upstream_branch,
                      args.topic,
                      repo_names=repo_names,
                      cleanup=cleanup,
                      dry_run=dry_run)
    except Exception:
        # unhandled runtime errors
        LOG.exception('Runtime error: ')
        sys.exit(1)


if __name__ == '__main__':
    main()
