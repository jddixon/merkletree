#!/usr/bin/python3

# testMerkleLeaf.py
import time, unittest

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
        fileName = self.rng.nextFileName(8)
        leaf0 = MerkleLeaf(fileName, usingSHA1)
        self.assertEqual( fileName, leaf0.name )
        self.assertEqual( None, leaf0.binHash)

        fileName2 = fileName
        while fileName2 == fileName:
            fileName2 = self.rng.nextFileName(8)
        leaf1 = MerkleLeaf(fileName2, usingSHA1)
        self.assertEqual( fileName2, leaf1.name )

        self.assertTrue  ( leaf0.equals(leaf0) )
        self.assertFalse ( leaf0.equals(leaf1) )

    def testSimplestConstructor(self):
        self.doTestSimpleConstructor(True)          # using SHA1
        self.doTestSimpleConstructor(False)         # not using SHA1

if __name__ == '__main__':
    unittest.main()
