#!/usr/bin/env python
# -*- coding: utf-8 -*-
import optparse
import sys
sys.path.insert(0, 'bin/python')

import os
import samba
import samba.getopt as options
import random
import tempfile
import shutil
import time

from samba.netcmd.main import cmd_sambatool

# We try to use the test infrastructure of Samba 4.3+, but if it
# doesn't work, we are probably in a back-ported patch and trying to
# run on 4.1 or something.
#
# Don't copy this horror into ordinary tests -- it is special for
# performance tests that want to apply to old versions.
try:
    from samba.tests.subunitrun import SubunitOptions, TestProgram
    ANCIENT_SAMBA = False
except ImportError:
    ANCIENT_SAMBA = True
    samba.ensure_external_module("testtools", "testtools")
    samba.ensure_external_module("subunit", "subunit/python")
    from subunit.run import SubunitTestRunner
    import unittest

from samba.samdb import SamDB
from samba.auth import system_session
from ldb import Message, MessageElement, Dn, LdbError
from ldb import FLAG_MOD_ADD, FLAG_MOD_REPLACE, FLAG_MOD_DELETE
from ldb import SCOPE_BASE, SCOPE_SUBTREE, SCOPE_ONELEVEL

parser = optparse.OptionParser("ad_dc_performance.py [options] <host>")
sambaopts = options.SambaOptions(parser)
parser.add_option_group(sambaopts)
parser.add_option_group(options.VersionOptions(parser))

if not ANCIENT_SAMBA:
    subunitopts = SubunitOptions(parser)
    parser.add_option_group(subunitopts)

# use command line creds if available
credopts = options.CredentialsOptions(parser)
parser.add_option_group(credopts)
opts, args = parser.parse_args()


if len(args) < 1:
    parser.print_usage()
    sys.exit(1)

host = args[0]

lp = sambaopts.get_loadparm()
creds = credopts.get_credentials(lp)

random.seed(1)


class PerfTestException(Exception):
    pass


BATCH_SIZE = 2000
N_GROUPS = 19


class GlobalState(object):
    next_user_id = 0
    n_groups = 0
    next_linked_user = 0
    next_relinked_user = 0
    next_linked_user_3 = 0
    next_removed_link_0 = 0
    test_number = 0

class UserTests(samba.tests.TestCase):

    def add_if_possible(self, *args, **kwargs):
        """In these tests sometimes things are left in the database
        deliberately, so we don't worry if we fail to add them a second
        time."""
        try:
            self.ldb.add(*args, **kwargs)
        except LdbError:
            pass

    def setUp(self):
        super(UserTests, self).setUp()
        self.state = GlobalState  # the class itself, not an instance
        self.lp = lp
        self.ldb = SamDB(host, credentials=creds,
                         session_info=system_session(lp), lp=lp)
        self.base_dn = self.ldb.domain_dn()
        self.ou = "OU=pid%s,%s" % (os.getpid(), self.base_dn)
        self.ou_users = "OU=users,%s" % self.ou
        self.ou_groups = "OU=groups,%s" % self.ou
        self.ou_computers = "OU=computers,%s" % self.ou

        for dn in (self.ou, self.ou_users, self.ou_groups,
                   self.ou_computers):
            self.add_if_possible({
                "dn": dn,
                "objectclass": "organizationalUnit"})

        self.state.test_number += 1
        random.seed(self.state.test_number)

    def tearDown(self):
        super(UserTests, self).tearDown()

    def test_00_00_do_nothing(self):
        # this gives us an idea of the overhead
        pass

    def test_00_01_do_nothing_relevant(self):
        # takes around 1 second on i7-4770
        j = 0
        for i in range(30000000):
            j += i

    def test_00_02_do_nothing_sleepily(self):
        time.sleep(1)

    def _prepare_n_groups(self, n):
        self.state.n_groups += n
        for i in range(n):
            self.add_if_possible({
                "dn": "cn=g%d,%s" % (i, self.ou_groups),
                "objectclass": "group"})

    def _add_users(self, start, end):
        for i in range(start, end):
            self.ldb.add({
                "dn": "cn=u%d,%s" % (i, self.ou_users),
                "objectclass": "user"})

    def _add_users_ldif(self, start, end):
        lines = []
        for i in range(start, end):
            lines.append("dn: cn=u%d,%s" % (i, self.ou_users))
            lines.append("objectclass: user")
            lines.append("")
        self.ldb.add_ldif('\n'.join(lines))

    def _test_join(self):
        tmpdir = tempfile.mkdtemp()
        if '://' in host:
            server = host.split('://', 1)[1]
        else:
            server = host
        cmd = cmd_sambatool.subcommands['domain'].subcommands['join']
        result = cmd._run("samba-tool domain join",
                          creds.get_realm(),
                          "dc", "-U%s%%%s" % (creds.get_username(),
                                              creds.get_password()),
                          '--targetdir=%s' % tmpdir,
                          '--server=%s' % server)

        shutil.rmtree(tmpdir)


    def _test_unindexed_search(self):
        expressions = [
            ('(&(objectclass=user)(description='
             'Built-in account for adminstering the computer/domain))'),
            '(description=Built-in account for adminstering the computer/domain)',
            '(objectCategory=*)',
            '(samaccountname=Administrator*)'
        ]
        for expression in expressions:
            t = time.time()
            for i in range(50):
                self.ldb.search(self.ou,
                                expression=expression,
                                scope=SCOPE_SUBTREE,
                                attrs=['cn'])
            print >> sys.stderr, '%d %s took %s' % (i, expression,
                                                    time.time() - t)

    def _test_indexed_search(self):
        expressions = ['(objectclass=group)',
                       '(samaccountname=Administrator)'
        ]
        for expression in expressions:
            t = time.time()
            for i in range(10000):
                self.ldb.search(self.ou,
                                expression=expression,
                                scope=SCOPE_SUBTREE,
                                attrs=['cn'])
            print >> sys.stderr, '%d runs %s took %s' % (i, expression,
                                                         time.time() - t)

    def search_expression_list(self, expressions, rounds,
                               attrs=['cn'],
                               scope=SCOPE_SUBTREE):
        for expression in expressions:
            t = time.time()
            for i in range(rounds):
                self.ldb.search(self.ou,
                                expression=expression,
                                scope=SCOPE_SUBTREE,
                                attrs=['cn'])
            print >> sys.stderr, '%d runs %s took %s' % (i, expression,
                                                         time.time() - t)

    def _test_complex_search(self, n=100):
        classes = ['samaccountname', 'objectCategory', 'dn', 'member']
        values = ['*', '*t*', 'g*', 'user']
        comparators = ['=', '<=', '>='] # '~=' causes error
        maybe_not = ['!(', '']
        joiners = ['&', '|']

        # The number of permuations is 18432, which is not huge but
        # would take hours to search. So we take a sample.
        all_permutations = list(itertools.product(joiners,
                                                  classes, classes,
                                                  values, values,
                                                  comparators, comparators,
                                                  maybe_not, maybe_not))

        expressions = []

        for (j, c1, c2, v1, v2,
             o1, o2, n1, n2) in random.sample(all_permutations, n):
            expression = ''.join(['(', j,
                                  '(', n1, c1, o1, v1,
                                  '))' if n1 else ')',
                                  '(', n2, c2, o2, v2,
                                  '))' if n2 else ')',
                                  ')'])
            expressions.append(expression)

        self.search_expression_list(expressions, 1)

    def _test_member_search(self, rounds=10):
        expressions = []
        for d in range(40):
            expressions.append('(member=cn=u%d,%s)' % (d + 500, self.ou_users))
            expressions.append('(member=u%d*)' % (d + 700,))

        self.search_expression_list(expressions, rounds)

    def _test_memberof_search(self, rounds=10):
        expressions = []
        for i in range(min(self.state.n_groups, 40)):
            expressions.append('(memberOf=cn=g%d,%s)' % (i, self.ou_groups))
            expressions.append('(memberOf=cn=g%d*)' % (i,))
            expressions.append('(memberOf=cn=*%s*)' % self.ou_groups)

        self.search_expression_list(expressions, rounds)

    def _test_add_many_users(self, n=BATCH_SIZE):
        s = self.state.next_user_id
        e = s + n
        self._add_users(s, e)
        self.state.next_user_id = e

    def _test_add_many_users_ldif(self, n=BATCH_SIZE):
        s = self.state.next_user_id
        e = s + n
        self._add_users_ldif(s, e)
        self.state.next_user_id = e

    test_00_01_join_empty_dc = _test_join

    test_00_02_adding_users_2000 = _test_add_many_users

    test_00_10_join_unlinked_2k_users = _test_join
    test_00_11_unindexed_search_2k_users = _test_unindexed_search
    test_00_12_indexed_search_2k_users = _test_indexed_search

    test_00_13_complex_search_2k_users = _test_complex_search
    test_00_14_member_search_2k_users = _test_member_search
    test_00_15_memberof_search_2k_users = _test_memberof_search

    def _link_user_and_group(self, u, g):
        m = Message()
        m.dn = Dn(self.ldb, "CN=g%d,%s" % (g, self.ou_groups))
        m["member"] = MessageElement("cn=u%d,%s" % (u, self.ou_users),
                                     FLAG_MOD_ADD, "member")
        self.ldb.modify(m)

    def _unlink_user_and_group(self, u, g):
        user = "cn=u%d,%s" % (u, self.ou_users)
        group = "CN=g%d,%s" % (g, self.ou_groups)
        m = Message()
        m.dn = Dn(self.ldb, group)
        m["member"] = MessageElement(user, FLAG_MOD_DELETE, "member")
        self.ldb.modify(m)

    def _test_link_many_users(self, n=BATCH_SIZE, offset=0):
        # this links unevenly, putting more users in the first group
        # and fewer in the last.
        self._prepare_n_groups(N_GROUPS)
        s = self.state.next_linked_user
        e = s + n
        ng = self.state.n_groups
        for i in range(s, e):
            g = (i) % (i % ng + 1)
            if offset:
                g = (g + offset) % ng
            self._link_user_and_group(i, g)
        self.state.next_linked_user = e

    test_01_01_link_2k_users = _test_link_many_users

    def test_01_02_link_2k_users_again(self):
        self._test_link_many_users(offset=1)

    test_02_10_join_2k_linked_dc = _test_join
    test_02_11_unindexed_search_2k_linked_dc = _test_unindexed_search
    test_02_12_indexed_search_2k_linked_dc = _test_indexed_search

    def _test_link_many_users_3_groups(self, n=BATCH_SIZE, groups=3):
        s = self.state.next_linked_user_3
        e = s + n
        ng = self.state.n_groups
        self.state.next_linked_user_3 = e
        for i in range(s, e):
            g = (i + 2) % groups
            if g not in (i % ng, (i + 1) % ng):
                self._link_user_and_group(i, g)

    test_03_01_link_users_2k_3_more_groups = _test_link_many_users_3_groups

    def _test_remove_links_0(self, n=BATCH_SIZE):
        s = self.state.next_removed_link_0
        e = s + n
        self.state.next_removed_link_0 = e
        ng = self.state.n_groups
        for i in range(s, e):
            g = i % ng
            self._unlink_user_and_group(i, g)

    test_04_01_remove_some_links_2k = _test_remove_links_0

    test_05_01_adding_users_after_links_4k_ldif = _test_add_many_users_ldif

    # reset the link count, to replace the original links
    def test_06_01_relink_users_2k(self):
        self.state.next_linked_user = 0
        self._test_link_many_users()

    test_06_04_link_users_4k = _test_link_many_users

    def test_01_02_link_4k_users_again(self):
        self._test_link_many_users(offset=1)

    test_03_01_link_users_4k_3_more_groups = _test_link_many_users_3_groups


    test_07_01_adding_users_after_links_6k = _test_add_many_users

    def _test_link_random_users_and_groups(self, n=BATCH_SIZE, groups=100):
        # slightly asymmeteric linking.
        self._prepare_n_groups(groups)
        ng = self.state.n_groups
        r = random.randrange
        for i in range(n):
            u = r(self.state.next_user_id)
            g = sum(r(groups // 3), r(groups // 3), r(groups // 3)) % groups
            try:
                self._link_user_and_group(u, g)
            except LdbError:
                pass

    test_08_01_random_links_6k_100_groups = _test_link_random_users_and_groups

    def _test_ldif_well_linked_group(self, link_chance=1.0):
        g = self.state.n_groups
        self.state.n_groups += 1
        lines = ["dn: CN=g%d,%s" % (g, self.ou_groups)]

        for i in xrange(self.state.next_user_id):
            if random.random() <= link_chance:
                lines.append("member: cn=u%d,%s" % (i, self.ou_users))

        lines.append("")
        self.ldb.add_ldif('\n'.join(lines))

    test_09_01_add_fully_linked_group =  _test_ldif_well_linked_group
    def test_09_02_add_half_linked_group(self):
        random.seed(1234)
        self._test_ldif_well_linked_group(0.5)

    def test_09_03_add_quarter_linked_group(self):
        random.seed(12345)
        self._test_ldif_well_linked_group(0.25)

    test_10_01_unindexed_search_6k_users = _test_unindexed_search
    test_10_02_indexed_search_6k_users = _test_indexed_search

    def test_10_03_complex_search_6k_users(self):
        self._test_complex_search(n=50)

    def test_10_04_member_search_6k_users(self):
        self._test_member_search(rounds=2)

    def test_10_05_memberof_search_6k_users(self):
        self._test_memberof_search(rounds=2)

    test_11_02_join_full_dc = _test_join

    test_12_01_remove_some_links_6k = _test_remove_links_0

    def test_20_01_delete_50_groups(self):
        for i in range(self.state.n_groups - 50, self.state.n_groups):
            self.ldb.delete("cn=g%d,%s" % (i, self.ou_groups))
        self.state.n_groups -= 50

    def _test_delete_many_users(self, n=BATCH_SIZE):
        e = self.state.next_user_id
        s = max(0, e - n)
        self.state.next_user_id = s
        for i in range(s, e):
            self.ldb.delete("cn=u%d,%s" % (i, self.ou_users))

    test_21_01_delete_users_6k = _test_delete_many_users
    test_21_02_delete_users_4k = _test_delete_many_users

    def test_22_01_delete_all_groups(self):
        for i in range(self.state.n_groups):
            self.ldb.delete("cn=g%d,%s" % (i, self.ou_groups))
        self.state.n_groups = 0

    #XXX assert the state is as we think, using searches

    test_23_01_delete_users_after_groups_2k = _test_delete_many_users

    test_24_02_join_after_cleanup = _test_join


if "://" not in host:
    if os.path.isfile(host):
        host = "tdb://%s" % host
    else:
        host = "ldap://%s" % host


if ANCIENT_SAMBA:
    runner = SubunitTestRunner()
    if not runner.run(unittest.makeSuite(UserTests)).wasSuccessful():
        sys.exit(1)
    sys.exit(0)
else:
    TestProgram(module=__name__, opts=subunitopts)
