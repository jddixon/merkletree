#!/usr/bin/python3

# testMakeExRE.py

import hashlib
import os
import re
import shutil
import time
import unittest

from rnglib import SimpleRNG
from merkletree import *
from xlattice import util


class TestMakeExRE (unittest.TestCase):

    def setUp(self):
        self.rng = SimpleRNG(time.time())

    def tearDown(self):
        pass

    def doTestForExpectedExclusions(self, exRE):
        # should always match
        self.assertTrue(exRE.search('.'))
        self.assertTrue(exRE.search('..'))
        self.assertTrue(exRE.search('.merkle'))
        self.assertTrue(exRE.search('.svn'))
        self.assertTrue(exRE.search('.foo.swp'))          # vi backup file
        self.assertTrue(exRE.search('junkEverywhere'))    # begins with 'junk'

    def doTestForExpectedMatches(self, matchRE, names):
        for name in names:
            self.assertTrue(matchRE.search(name))

    def doTestForExpectedMatchFailures(self, matchRE, names):
        for name in names:
            m = matchRE.search(name)
            if m:
                print(("WE HAVE A MATCH ON '%s'" % name))
            # self.assertEqual( None, where )

    def testOldMakeExRE(self):
        """
        Test utility for making excluded file name regexes.

        ###################################################
        THIS TESTS THE OBSOLETE LOCAL VERSION OF makeExRE()
        ###################################################

        """
        exRE = MerkleDoc.makeExRE(None)
        self.assertTrue(exRE is not None)
        self.doTestForExpectedExclusions(exRE)

        # should not be present
        self.assertTrue(None == exRE.search('bar'))
        self.assertTrue(None == exRE.search('foo'))

        exc = []
        exc.append('^foo')
        exc.append('bar$')
        exc.append('^junk*')
        exRE = MerkleDoc.makeExRE(exc)
        self.doTestForExpectedExclusions(exRE)

        self.assertTrue(exRE.search('foobarf'))
        self.assertTrue(None == exRE.search(' foobarf'))
        self.assertFalse(exRE.search(' foobarf'))

        # bear in mind that match must be at the beginning
        self.assertFalse(exRE.match('ohMybar'))
        self.assertTrue(exRE.search('ohMybar'))

        self.assertFalse(exRE.match('ohMybarf'))
        self.assertTrue(exRE.search('junky'))
        self.assertFalse(exRE.match(' junk'))

    def testOldMakeMatchRE(self):
        """
        Test utility for making matched file name regexes.

        ###################################################
        THIS TESTS THE OBSOLETE LOCAL VERSION OF makeExRE()
        ###################################################

        """
        matchRE = MerkleDoc.makeMatchRE(None)
        self.assertEqual(None, matchRE)

        matches = []
        matches.append('^foo')
        matches.append('bar$')
        matches.append('^junk*')
        matchRE = MerkleDoc.makeMatchRE(matches)
        self.doTestForExpectedMatches(matchRE,
                                      ['foo', 'foolish', 'roobar', 'junky'])
        self.doTestForExpectedMatchFailures(matchRE,
                                            [' foo', 'roobarf', 'myjunk'])

        matches = ['\.tgz$']
        matchRE = MerkleDoc.makeMatchRE(matches)
        self.doTestForExpectedMatches(matchRE,
                                      ['junk.tgz', 'notSoFoolish.tgz'])
        self.doTestForExpectedMatchFailures(matchRE,
                                            ['junk.tar.gz', 'foolish.tar.gz'])

        matches = ['\.tgz$', '\.tar\.gz$']
        matchRE = MerkleDoc.makeMatchRE(matches)
        self.doTestForExpectedMatches(matchRE,
                                      ['junk.tgz', 'notSoFoolish.tgz',
                                       'junk.tar.gz', 'ohHello.tar.gz'])
        self.doTestForExpectedMatchFailures(matchRE,
                                            ['junk.gz', 'foolish.tar'])

if __name__ == '__main__':
    unittest.main()
