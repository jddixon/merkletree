#!/usr/bin/env python3

# testMakeExRE.py

import hashlib
import os
import re
import shutil
import time
import unittest

from rnglib import SimpleRNG
from xlattice.util import makeExRE


class TestMakeExRE (unittest.TestCase):

    def setUp(self):
        self.rng = SimpleRNG(time.time())

    def tearDown(self):
        pass

    def doTestForExpectedExclusions(self, exRE):
        self.assertIsNotNone(exRE.match('junkEverywhere')
                             )   # begins with 'junk'
        self.assertIsNotNone(exRE.match('.merkle'))          # a file
        self.assertIsNotNone(exRE.match('.svn'))             # the directory
        self.assertIsNotNone(exRE.match('.foo.swp'))         # vi backup file

    def doTestForExpectedMatches(self, matchRE, names):
        for name in names:
            self.assertIsNotNone(matchRE.match(name))

    def doTestForExpectedMatchFailures(self, matchRE, names):
        for name in names:
            m = matchRE.match(name)
            if m:
                self.fail(("UNEXPECTED MATCH ON '%s'" % name))

    def testNewMakeExRE(self):
        """
        Test utility for making excluded file name regexes.
        """

        # test the null pattern, which should not match anything
        exRE = makeExRE(None)
        self.assertIsNotNone(exRE)
        self.assertIsNone(exRE.match('bar'))
        self.assertIsNone(exRE.match('foo'))

        exc = []
        exc.append('foo*')
        exc.append('*bar')
        exc.append('junk*')
        exc.append('.*.swp')
        exc.append('.merkle')
        exc.append('.svn')
        exRE = makeExRE(exc)
        self.doTestForExpectedExclusions(exRE)

        self.assertIsNotNone(exRE.match('foobarf'))
        self.assertIsNone(exRE.match(' foobarf'))

        self.assertIsNotNone(exRE.match('ohMybar'))

        self.assertIsNone(exRE.match('ohMybarf'))
        self.assertIsNotNone(exRE.match('junky'))
        self.assertIsNone(exRE.match(' junk'))      # not at beginning

    def testNewMakeMatchRE(self):
        """
        Test utility for making matched file name regexes.
        """
        matchRE = makeExRE(None)
        self.assertIsNotNone(matchRE)

        matches = []
        matches.append('foo*')
        matches.append('*bar')
        matches.append('junk*')
        matchRE = makeExRE(matches)
        self.doTestForExpectedMatches(matchRE,
                                      ['foo', 'foolish', 'roobar', 'junky'])
        self.doTestForExpectedMatchFailures(matchRE,
                                            [' foo', 'roobarf', 'myjunk'])

        matches = ['*.tgz']
        matchRE = makeExRE(matches)
        self.doTestForExpectedMatches(matchRE,
                                      ['junk.tgz', 'notSoFoolish.tgz'])
        self.doTestForExpectedMatchFailures(matchRE,
                                            ['junk.tar.gz', 'foolish.tar.gz'])

        matches = ['*.tgz', '*.tar.gz']
        matchRE = makeExRE(matches)
        self.doTestForExpectedMatches(matchRE,
                                      ['junk.tgz', 'notSoFoolish.tgz',
                                       'junk.tar.gz', 'ohHello.tar.gz'])
        self.doTestForExpectedMatchFailures(matchRE,
                                            ['junk.gz', 'foolish.tar'])
if __name__ == '__main__':
    unittest.main()
