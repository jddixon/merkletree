#!/usr/bin/env python3
# testOldMakeExRE.py

""" Test old version of utility for making excluded file name regexes. """

import time
import unittest

from rnglib import SimpleRNG
from merkletree import MerkleDoc


class TestOldMakeExRE(unittest.TestCase):
    """ Test old version of utility for making excluded file name regexes. """

    def setUp(self):
        self.rng = SimpleRNG(time.time())

    def tearDown(self):
        pass

    def do_test_for_expected_exclusions(self, ex_re):
        """ Verify that regex finds expecsted matches. """
        self.assertTrue(ex_re.search('.'))
        self.assertTrue(ex_re.search('..'))
        self.assertTrue(ex_re.search('.merkle'))
        self.assertTrue(ex_re.search('.svn'))
        self.assertTrue(ex_re.search('.foo.swp'))          # vi backup file
        self.assertTrue(ex_re.search('junkEverywhere'))    # begins with 'junk'

    def do_test_for_expected_matches(self, match_re, names):
        """ Verify that regex finds listed names. """
        for name in names:
            self.assertTrue(match_re.search(name))

    def do_test_for_expected_match_failures(self, match_re, names):
        """ Verify that names do NOT match specified regex. """

        for name in names:
            match_ = match_re.search(name)
            if match_:
                print(("WE HAVE A MATCH ON '%s'" % name))
            # self.assertIsNone(where) # vestigial?

    def test_old_make_ex_re(self):
        """
        Test utility for making excluded file name regexes.

        ###################################################
        THIS TESTS THE OBSOLETE LOCAL VERSION OF makeExRE()
        ###################################################

        """
        ex_re = MerkleDoc.make_ex_re(None)
        self.assertTrue(ex_re is not None)
        self.do_test_for_expected_exclusions(ex_re)

        # should not be present
        self.assertTrue(ex_re.search('bar') is None)
        self.assertTrue(ex_re.search('foo') is None)

        exc = []
        exc.append('^foo')
        exc.append('bar$')
        exc.append('^junk*')
        ex_re = MerkleDoc.make_ex_re(exc)
        self.do_test_for_expected_exclusions(ex_re)

        self.assertTrue(ex_re.search('foobarf'))
        self.assertTrue(ex_re.search(' foobarf') is None)
        self.assertFalse(ex_re.search(' foobarf'))

        # bear in mind that match must be at the beginning
        self.assertFalse(ex_re.match('ohMybar'))
        self.assertTrue(ex_re.search('ohMybar'))

        self.assertFalse(ex_re.match('ohMybarf'))
        self.assertTrue(ex_re.search('junky'))
        self.assertFalse(ex_re.match(' junk'))

    def test_old_make_match_re(self):
        """
        Test utility for making matched file name regexes.

        ###################################################
        THIS TESTS THE OBSOLETE LOCAL VERSION OF makeExRE()
        ###################################################

        """
        match_re = MerkleDoc.make_match_re(None)
        self.assertEqual(None, match_re)

        matches = []
        matches.append('^foo')
        matches.append('bar$')
        matches.append('^junk*')
        match_re = MerkleDoc.make_match_re(matches)
        self.do_test_for_expected_matches(
            match_re, ['foo', 'foolish', 'roobar', 'junky'])
        self.do_test_for_expected_match_failures(
            match_re, [' foo', 'roobarf', 'myjunk'])

        matches = [r'\.tgz$']
        match_re = MerkleDoc.make_match_re(matches)
        self.do_test_for_expected_matches(
            match_re, ['junk.tgz', 'notSoFoolish.tgz'])
        self.do_test_for_expected_match_failures(
            match_re, ['junk.tar.gz', 'foolish.tar.gz'])

        matches = [r'\.tgz$', r'\.tar\.gz$']
        match_re = MerkleDoc.make_match_re(matches)
        self.do_test_for_expected_matches(
            match_re, ['junk.tgz', 'notSoFoolish.tgz',
                       'junk.tar.gz', 'ohHello.tar.gz'])
        self.do_test_for_expected_match_failures(
            match_re, ['junk.gz', 'foolish.tar'])

if __name__ == '__main__':
    unittest.main()
