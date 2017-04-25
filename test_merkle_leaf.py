#!/usr/bin/env python3

""" Test MerkleLeaf functionality. """

# testMerkleLeaf.py
import sys
import time
import unittest
import hashlib

from rnglib import SimpleRNG
from xlattice import HashTypes, check_hashtype
from merkletree import MerkleLeaf

if sys.version_info < (3, 6):
    # pylint:disable=unused-import
    import sha3     # monkey-patches hashlib

# This is the SHA1 test


class TestMerkleLeaf(unittest.TestCase):
    """ Test MerkleLeaf functionality. """

    def setUp(self):
        self.rng = SimpleRNG(time.time())

    def tearDown(self):
        pass

    # utility functions #############################################

    # actual unit tests #############################################
    def do_test_simple_constructor(self, hashtype):
        """ Test constructor for specific SHA type. """

        check_hashtype(hashtype)
        # pylint: disable=redefined-variable-type
        if hashtype == HashTypes.SHA1:
            sha = hashlib.sha1()
        elif hashtype == HashTypes.SHA2:
            sha = hashlib.sha256()
        elif hashtype == HashTypes.SHA3:
            sha = hashlib.sha3_256()

        file_name = self.rng.next_file_name(8)
        nnn = self.rng.some_bytes(8)
        sha.update(nnn)
        hash0 = sha.digest()

        leaf0 = MerkleLeaf(file_name, hashtype, hash0)
        self.assertEqual(file_name, leaf0.name)
        self.assertEqual(hash0, leaf0.bin_hash)

        file_name2 = file_name
        while file_name2 == file_name:
            file_name2 = self.rng.next_file_name(8)
        nnn = self.rng.some_bytes(8)
        self.rng.next_bytes(nnn)
        sha.update(nnn)
        hash1 = sha.digest()
        leaf1 = MerkleLeaf(file_name2, hashtype, hash1)
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
        for hashtype in HashTypes:
            self.do_test_simple_constructor(hashtype=hashtype)


if __name__ == '__main__':
    unittest.main()
