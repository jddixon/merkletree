#!/usr/bin/env python3

# testMerkleDoc.py

import hashlib
import os
import re
import shutil
import time
import unittest

from rnglib import SimpleRNG
from merkletree import *
from xlattice import Q, checkUsingSHA, util

ONE = 1
FOUR = 4
MAX_NAME_LEN = 8


class TestMerkleDoc (unittest.TestCase):

    def setUp(self):
        self.rng = SimpleRNG(time.time())

    def tearDown(self):
        pass

    # utility functions #############################################
    def getTwoUniqueDirectoryNames(self):
        dirName1 = self.rng.nextFileName(MAX_NAME_LEN)
        dirName2 = dirName1
        while dirName2 == dirName1:
            dirName2 = self.rng.nextFileName(MAX_NAME_LEN)
        self.assertTrue(len(dirName1) > 0)
        self.assertTrue(len(dirName2) > 0)
        self.assertTrue(dirName1 != dirName2)
        return (dirName1, dirName2)

    def makeOneNamedTestDirectory(self, name, depth, width):
        dirPath = "tmp/%s" % name
        if os.path.exists(dirPath):
            print(("DEBUG: directory '%s' already exists; removing" % dirPath))
            shutil.rmtree(dirPath)
        self.rng.nextDataDir(dirPath, depth, width, 32)
        return dirPath

    def makeTwoTestDirectories(self, depth, width):
        dirName1 = self.rng.nextFileName(MAX_NAME_LEN)
        dirPath1 = self.makeOneNamedTestDirectory(dirName1, depth, width)

        dirName2 = dirName1
        while dirName2 == dirName1:
            dirName2 = self.rng.nextFileName(MAX_NAME_LEN)
        dirPath2 = self.makeOneNamedTestDirectory(dirName2, depth, width)

        return (dirName1, dirPath1, dirName2, dirPath2)

    def verifyLeafSHA(self, node, pathToFile, usingSHA):
        checkUsingSHA(usingSHA)
        self.assertTrue(os.path.exists(pathToFile))
        with open(pathToFile, "rb") as f:
            data = f.read()
        self.assertFalse(data is None)
        if usingSHA == Q.USING_SHA1:
            sha = hashlib.sha1()
        elif usingSHA == Q.USING_SHA2:
            sha = hashlib.sha256()
        elif usingSHA == Q.USING_SHA3:
            sha = hashlib.sha3_256()
        sha.update(data)
        hash = sha.digest()
        self.assertEqual(hash, node.binHash)

    def verifyTreeSHA(self, node, pathToTree, usingSHA):
        # we assume that the node is a MerkleTree
        checkUsingSHA(usingSHA)
        if node.nodes is None:
            self.assertEqual(None, node.binHash)
        else:
            hashCount = 0
            if usingSHA == Q.USING_SHA1:
                sha = hashlib.sha1()
            elif usingSHA == Q.USING_SHA2:
                sha = hashlib.sha256()
            elif usingSHA == Q.USING_SHA3:
                sha = hashlib.sha3_256()
            for n in node.nodes:
                pathToNode = os.path.join(pathToTree, n.name)
                if isinstance(n, MerkleLeaf):
                    self.verifyLeafSHA(n, pathToNode, usingSHA)
                elif isinstance(n, MerkleTree):
                    self.verifyTreeSHA(n, pathToNode, usingSHA)
                else:
                    print("DEBUG: unknown node type!")
                    self.fail("unknown node type!")
                if (n.binHash is not None):
                    hashCount += 1
                    sha.update(n.binHash)

            if hashCount == 0:
                self.assertEqual(None, node.binHash)
            else:
                self.assertEqual(sha.digest(), node.binHash)

    # actual unit tests #############################################

    def testBoundFlatDirs(self):
        """test directory is single level, with four data files"""
        for using in [Q.USING_SHA1, Q.USING_SHA2, Q.USING_SHA3, ]:
            self.doTestBoundFlatDirs(using)

    def doTestBoundFlatDirs(self, usingSHA):

        (dirName1, dirPath1, dirName2, dirPath2) = \
            self.makeTwoTestDirectories(ONE, FOUR)

        doc1 = MerkleDoc.createFromFileSystem(dirPath1, usingSHA)
        tree1 = doc1.tree
        self.assertEqual(dirName1, tree1.name)
        self.assertTrue(doc1.bound)
        self.assertEqual(("tmp/%s" % dirName1), dirPath1)
        nodes1 = tree1.nodes
        self.assertTrue(nodes1 is not None)
        self.assertEqual(FOUR, len(nodes1))
        self.verifyTreeSHA(tree1, dirPath1, usingSHA)

        doc2 = MerkleDoc.createFromFileSystem(dirPath2, usingSHA)
        tree2 = doc2.tree
        self.assertEqual(dirName2, tree2.name)
        self.assertTrue(doc2.bound)
        self.assertEqual(("tmp/%s" % dirName2), dirPath2)
        nodes2 = tree2.nodes
        self.assertTrue(nodes2 is not None)
        self.assertEqual(FOUR, len(nodes2))
        self.verifyTreeSHA(tree2, dirPath2, usingSHA)

        self.assertTrue(tree1.equal(tree1))
        self.assertFalse(tree1.equal(tree2))
        self.assertFalse(tree1.equal(None))

        doc1Str = doc1.toString()
        doc1Rebuilt = MerkleDoc.createFromSerialization(doc1Str, usingSHA)
        # DEBUG
        #print("flat doc:\n" + doc1Str)
        #print("rebuilt flat doc:\n" + doc1Rebuilt.toString())
        # END
        self.assertTrue(doc1.equal(doc1Rebuilt))  # MANGO

    def testBoundNeedleDirs(self):
        """test directories four deep with one data file at the lowest level"""
        for using in [Q.USING_SHA1, Q.USING_SHA2, Q.USING_SHA3, ]:
            self.doTestBoundNeedleDirs(using)

    def doTestBoundNeedleDirs(self, usingSHA):
        checkUsingSHA(usingSHA)
        (dirName1, dirPath1, dirName2, dirPath2) = \
            self.makeTwoTestDirectories(FOUR, ONE)
        doc1 = MerkleDoc.createFromFileSystem(dirPath1, usingSHA)
        tree1 = doc1.tree
        self.assertEqual(dirName1, tree1.name)
        self.assertTrue(doc1.bound)
        self.assertEqual(("tmp/%s" % dirName1), dirPath1)
        nodes1 = tree1.nodes
        self.assertTrue(nodes1 is not None)
        self.assertEqual(ONE, len(nodes1))
        self.verifyTreeSHA(tree1, dirPath1, usingSHA)

        doc2 = MerkleDoc.createFromFileSystem(dirPath2, usingSHA)
        tree2 = doc2.tree
        self.assertEqual(dirName2, tree2.name)
        self.assertTrue(doc2.bound)
        self.assertEqual(("tmp/%s" % dirName2), dirPath2)
        nodes2 = tree2.nodes
        self.assertTrue(nodes2 is not None)
        self.assertEqual(ONE, len(nodes2))
        self.verifyTreeSHA(tree2, dirPath2, usingSHA)

        self.assertTrue(doc1.equal(doc1))
        self.assertFalse(doc1.equal(doc2))

        doc1Str = doc1.toString()
        doc1Rebuilt = MerkleDoc.createFromSerialization(doc1Str, usingSHA)
#       # DEBUG
#       print "needle doc:\n" + doc1Str
#       print "rebuilt needle doc:\n" + doc1Rebuilt.toString()
#       # END
        self.assertTrue(doc1.equal(doc1Rebuilt))       # FOO

if __name__ == '__main__':
    unittest.main()
