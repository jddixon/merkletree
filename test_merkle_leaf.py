#!/usr/bin/env python3

""" Test MerkleLeaf functionality. """

# testMerkleLeaf.py
import time
import unittest
import hashlib

import sha3     # monkey-patches hashlib

from rnglib import SimpleRNG
from xlattice import QQQ, check_using_sha
from merkletree import MerkleLeaf

# This is the SHA1 test


class TestMerkleLeaf(unittest.TestCase):
    """ Test MerkleLeaf functionality. """

    def setUp(self):
        self.rng = SimpleRNG(time.time())

    def tearDown(self):
        pass

    # utility functions #############################################

    # actual unit tests #############################################
    def do_test_simple_constructor(self, using_sha):
        """ Test constructor for specific SHA type. """

        check_using_sha(using_sha)
        # pylint: disable=redefined-variable-type
        if using_sha == QQQ.USING_SHA1:
            sha = hashlib.sha1()
        elif using_sha == QQQ.USING_SHA2:
            sha = hashlib.sha256()
        elif using_sha == QQQ.USING_SHA3:
            sha = hashlib.sha3_256()

        file_name = self.rng.nextFileName(8)
        nnn = self.rng.someBytes(8)
        sha.update(nnn)
        hash0 = sha.digest()

        leaf0 = MerkleLeaf(file_name, using_sha, hash0)
        self.assertEqual(file_name, leaf0.name)
        self.assertEqual(hash0, leaf0.bin_hash)

        file_name2 = file_name
        while file_name2 == file_name:
            file_name2 = self.rng.nextFileName(8)
        nnn = self.rng.someBytes(8)
        self.rng.nextBytes(nnn)
        sha.update(nnn)
        hash1 = sha.digest()
        leaf1 = MerkleLeaf(file_name2, using_sha, hash1)
        self.assertEqual(file_name2, leaf1.name)
        self.assertEqual(hash1, leaf1.bin_hash)

        self.assertTrue(leaf0.equal(leaf0))
        self.assertFalse(leaf0.equal(leaf1))

        # XXX USE NLHTree instead
        #pair0    = leaf0.toPair()
        #leaf0bis = MerkleLeaf.createFromPair(pair0)
        #self.assertEqual(leaf0bis, leaf0)

        #pair1    = leaf1.toPair()
        #leaf1bis = MerkleLeaf.createFromPair(pair1)
        #self.assertEqual(leaf1bis, leaf1)

    def test_simple_constructor(self):
        """ Test constructor for various SHA types. """
        for using in [QQQ.USING_SHA1, QQQ.USING_SHA2, QQQ.USING_SHA3, ]:
            self.do_test_simple_constructor(using_sha=using)

if __name__ == '__main__':
    unittest.main()
