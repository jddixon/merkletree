#!/usr/bin/python3

# testMerkleLeaf.py
import hashlib, time, unittest

from rnglib         import SimpleRNG
from merkletree     import *

# This is the SHA1 test
class TestMerkleLeaf (unittest.TestCase):

    def setUp(self):
        self.rng = SimpleRNG( time.time() )
    def tearDown(self):
        pass

    # utility functions #############################################
    
    # actual unit tests #############################################
    def doTestSimpleConstructor(self, usingSHA1):
        if usingSHA1:
            sha = hashlib.sha1()
        else:
            sha = hashlib.sha256()

        fileName = self.rng.nextFileName(8)
        n    = self.rng.someBytes(8)
        sha.update(n)
        hash0 = sha.digest()

        leaf0 = MerkleLeaf(fileName, usingSHA1, hash0)
        self.assertEqual( fileName, leaf0.name )
        self.assertEqual( hash0, leaf0.binHash)

        fileName2 = fileName
        while fileName2 == fileName:
            fileName2 = self.rng.nextFileName(8)
        n    = self.rng.someBytes(8)
        self.rng.nextBytes(n)
        sha.update(n)
        hash1 = sha.digest()
        leaf1 = MerkleLeaf(fileName2, usingSHA1, hash1)
        self.assertEqual( fileName2, leaf1.name )
        self.assertEqual( hash1, leaf1.binHash)

        self.assertTrue  ( leaf0.equal(leaf0) )
        self.assertFalse ( leaf0.equal(leaf1) )

        # XXX USE NLHTree instead
        #pair0    = leaf0.toPair()
        #leaf0bis = MerkleLeaf.createFromPair(pair0)
        #self.assertEqual(leaf0bis, leaf0)

        #pair1    = leaf1.toPair()
        #leaf1bis = MerkleLeaf.createFromPair(pair1)
        #self.assertEqual(leaf1bis, leaf1)

    def testSimplestConstructor(self):
        self.doTestSimpleConstructor(usingSHA1=True)   
        self.doTestSimpleConstructor(usingSHA1=False)

if __name__ == '__main__':
    unittest.main()