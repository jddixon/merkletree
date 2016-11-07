#!/usr/bin/env python3
# testMakeExRE.py

""" Test the make_exre() function. """

import time
import unittest

from rnglib import SimpleRNG
from xlattice.util import make_ex_re


class TestMakeExRE(unittest.TestCase):
    """ Test the make_exre() function. """

    def setUp(self):
        self.rng = SimpleRNG(time.time())

    def tearDown(self):
        pass

    def do_test_for_expected_exclusions(self, ex_re):
        """ Verify that expected exclusions work for specific pattern. """
        self.assertIsNotNone(ex_re.match('junkEverywhere')
                             )  # begins with 'junk'
        self.assertIsNotNone(ex_re.match('.merkle'))          # a file
        self.assertIsNotNone(ex_re.match('.svn'))             # the directory
        self.assertIsNotNone(ex_re.match('.foo.swp'))         # vi backup file

    def do_test_for_expected_matches(self, match_re, names):
        """ Verify that expected matches work for specific pattern and names. """
        for name in names:
            self.assertIsNotNone(match_re.match(name))

    def do_test_for_expected_match_failures(self, match_re, names):
        """
        Verify that expected match failures occur for specific pattern
        and listed names.
        """
        for name in names:
            match_ = match_re.match(name)
            if match_:
                self.fail(("UNEXPECTED MATCH ON '%s'" % name))

    def test_new_make_ex_re(self):
        """
        Test utility for making excluded file name regexes.
        """

        # test the null pattern, which should not match anything
        ex_re = make_ex_re(None)
        self.assertIsNotNone(ex_re)
        self.assertIsNone(ex_re.match('bar'))
        self.assertIsNone(ex_re.match('foo'))

        exc = []
        exc.append('foo*')
        exc.append('*bar')
        exc.append('junk*')
        exc.append('.*.swp')
        exc.append('.merkle')
        exc.append('.svn')
        ex_re = make_ex_re(exc)
        self.do_test_for_expected_exclusions(ex_re)

        self.assertIsNotNone(ex_re.match('foobarf'))
        self.assertIsNone(ex_re.match(' foobarf'))

        self.assertIsNotNone(ex_re.match('ohMybar'))

        self.assertIsNone(ex_re.match('ohMybarf'))
        self.assertIsNotNone(ex_re.match('junky'))
        self.assertIsNone(ex_re.match(' junk'))      # not at beginning

    def test_new_make_match_re(self):
        """
        Test utility for making matched file name regexes.
        """
        match_re = make_ex_re(None)
        self.assertIsNotNone(match_re)

        matches = []
        matches.append('foo*')
        matches.append('*bar')
        matches.append('junk*')
        match_re = make_ex_re(matches)
        self.do_test_for_expected_matches(
            match_re, ['foo', 'foolish', 'roobar', 'junky'])
        self.do_test_for_expected_match_failures(
            match_re, [' foo', 'roobarf', 'myjunk'])

        matches = ['*.tgz']
        match_re = make_ex_re(matches)
        self.do_test_for_expected_matches(
            match_re, ['junk.tgz', 'notSoFoolish.tgz'])
        self.do_test_for_expected_match_failures(
            match_re, ['junk.tar.gz', 'foolish.tar.gz'])

        matches = ['*.tgz', '*.tar.gz']
        match_re = make_ex_re(matches)
        self.do_test_for_expected_matches(
            match_re, ['junk.tgz', 'notSoFoolish.tgz',
                       'junk.tar.gz', 'ohHello.tar.gz'])
        self.do_test_for_expected_match_failures(
            match_re, ['junk.gz', 'foolish.tar'])

if __name__ == '__main__':
    unittest.main()
