#!/usr/bin/python

# testMerkleLeaf.py
import time, unittest

from rnglib         import SimpleRNG
from merkletree     import *

class TestMerkleLeaf (unittest.TestCase):

    def setUp(self):
        self.rng = SimpleRNG( time.time() )
    def tearDown(self):
        pass

    # utility functions #############################################
    
    # actual unit tests #############################################
    def testSimplestConstructor(self):
        fileName = self.rng.nextFileName(8)
        leaf0 = MerkleLeaf(fileName)
        self.assertEquals( fileName, leaf0.name )
        self.assertEquals( None, leaf0.hash)

        fileName2 = fileName
        while fileName2 == fileName:
            fileName2 = self.rng.nextFileName(8)
        leaf1 = MerkleLeaf(fileName2)
        self.assertEquals( fileName2, leaf1.name )

        self.assertTrue  ( leaf0.equals(leaf0) )
        self.assertFalse ( leaf0.equals(leaf1) )

if __name__ == '__main__':
    unittest.main()
