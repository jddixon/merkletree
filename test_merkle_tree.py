#!/usr/bin/env python3

# testMerkleTree.py
import hashlib
import os
import re
import shutil
import sys
import time
import unittest

from rnglib import SimpleRNG
from xlattice import (Q, checkUsingSHA,
                      SHA1_HEX_NONE, SHA2_HEX_NONE, SHA3_HEX_NONE)
from merkletree import *

ONE = 1
FOUR = 4
MAX_NAME_LEN = 8


class TestMerkleTree (unittest.TestCase):

    def setUp(self):
        self.rng = SimpleRNG(time.time())

    def tearDown(self):
        pass

    # utility functions ---------------------------------------------

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

    def verifyTreeSHA(self, node, pathToNode, usingSHA):
        # we assume that the node is a MerkleTree
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
                pathToFile = os.path.join(pathToNode, n.name)
                if isinstance(n, MerkleLeaf):
                    self.verifyLeafSHA(n, pathToFile, usingSHA)
                elif isinstance(n, MerkleTree):
                    self.verifyTreeSHA(n, pathToFile, usingSHA)
                else:
                    self.fail("unknown node type!")
                if (n.binHash is not None):
                    hashCount += 1
                    sha.update(n.binHash)

            # take care to compare values of the same type;
            # node.binHash is binary, node.hexHash is hex
            if hashCount == 0:
                self.assertEqual(None, node.binHash)
            else:
                self.assertEqual(sha.digest(), node.binHash)

    # unit tests ----------------------------------------------------

    def testPathlessUnboundConstructor(self):
        for using in [Q.USING_SHA1, Q.USING_SHA2, Q.USING_SHA3, ]:
            self.doTestPathlessUnboundConstructor(using)

    def doTestPathlessUnboundConstructor(self, usingSHA):
        (dirName1, dirName2) = self.getTwoUniqueDirectoryNames()

        checkUsingSHA(usingSHA)
        tree1 = MerkleTree(dirName1, usingSHA)
        self.assertEqual(dirName1, tree1.name)
        if usingSHA == Q.USING_SHA1:
            self.assertEqual(SHA1_HEX_NONE, tree1.hexHash)
        elif usingSHA == Q.USING_SHA2:
            self.assertEqual(SHA2_HEX_NONE, tree1.hexHash)
        elif usingSHA == Q.USING_SHA3:
            self.assertEqual(SHA3_HEX_NONE, tree1.hexHash)

        tree2 = MerkleTree(dirName2, usingSHA)
        self.assertEqual(dirName2, tree2.name)

        # these tests remain skimpy
        self.assertTrue(tree1.equal(tree1))
        self.assertFalse(tree1.equal(tree2))
        self.assertFalse(tree1.equal(None))

        tree1Str = tree1.toString(0)

        # there should be no indent on the first line
        self.assertFalse(' ' == tree1Str[0])

        # no extra lines should be added
        lines = tree1Str.split('\n')
        # this split generates an extra blank line, because the serialization
        # ends with CR-LF
        if lines[-1] == '':
            lines = lines[:-1]
        self.assertEqual(1, len(lines))

        tree1Rebuilt = MerkleTree.createFromSerialization(tree1Str, usingSHA)
        self.assertTrue(tree1.equal(tree1Rebuilt))

    def testBoundFlatDirs(self):
        for using in [Q.USING_SHA1, Q.USING_SHA2, Q.USING_SHA3, ]:
            self.doTestBoundFlatDirs(using)

    def doTestBoundFlatDirs(self, usingSHA):
        """test directory is single level, with four data files"""

        checkUsingSHA(usingSHA)
        (dirName1, dirPath1, dirName2, dirPath2) = \
            self.makeTwoTestDirectories(ONE, FOUR)
        tree1 = MerkleTree.createFromFileSystem(dirPath1, usingSHA)
        self.assertEqual(dirName1, tree1.name)
        nodes1 = tree1.nodes
        self.assertTrue(nodes1 is not None)
        self.assertEqual(FOUR, len(nodes1))
        self.verifyTreeSHA(tree1, dirPath1, usingSHA)

        tree2 = MerkleTree.createFromFileSystem(dirPath2, usingSHA)
        self.assertEqual(dirName2, tree2.name)
        nodes2 = tree2.nodes
        self.assertTrue(nodes2 is not None)
        self.assertEqual(FOUR, len(nodes2))
        self.verifyTreeSHA(tree2, dirPath2, usingSHA)

        # XXX COMMENTED OUT FOR DEBUGGING XXX
        #self.assertTrue  ( tree1.equal(tree1) )
        self.assertFalse(tree1.equal(tree2))
        self.assertFalse(tree1.equal(None))

        tree1Str = tree1.toString(0)
        tree1Rebuilt = MerkleTree.createFromSerialization(tree1Str, usingSHA)
        self.assertTrue(tree1.equal(tree1Rebuilt))

    def testBoundNeedleDirs(self):
        for using in [Q.USING_SHA1, Q.USING_SHA2, Q.USING_SHA3, ]:
            self.doTestBoundNeedleDirs(using)

    def doTestBoundNeedleDirs(self, usingSHA):
        """test directories four deep with one data file at the lowest level"""
        (dirName1, dirPath1, dirName2, dirPath2) = \
            self.makeTwoTestDirectories(FOUR, ONE)
        tree1 = MerkleTree.createFromFileSystem(dirPath1, usingSHA)

        self.assertEqual(dirName1, tree1.name)
        nodes1 = tree1.nodes
        self.assertTrue(nodes1 is not None)
        self.assertEqual(ONE, len(nodes1))
        self.verifyTreeSHA(tree1, dirPath1, usingSHA)

        tree2 = MerkleTree.createFromFileSystem(dirPath2, usingSHA)
        self.assertEqual(dirName2, tree2.name)
        nodes2 = tree2.nodes
        self.assertTrue(nodes2 is not None)
        self.assertEqual(ONE, len(nodes2))
        self.verifyTreeSHA(tree2, dirPath2, usingSHA)

        self.assertTrue(tree1.equal(tree1))
        self.assertFalse(tree1.equal(tree2))

        tree1Str = tree1.toString(0)
        tree1Rebuilt = MerkleTree.createFromSerialization(tree1Str, usingSHA)
#       # DEBUG
#       print "NEEDLEDIR TREE1:\n" + tree1Str
#       print "REBUILT TREE1:\n" + tree1Rebuilt.toString("")
#       # END
        self.assertTrue(tree1.equal(tree1Rebuilt))   # GEEP

    # tests of bugs previously found --------------------------------

    def testGrayBoxesBug1(self):
        serialization = \
            '721a08022dd26e7be98b723f26131786fd2c0dc3 grayboxes.com/\n'       + \
            ' fcd3973c66230b9078a86a5642b4c359fe72d7da images/\n'            + \
            '  15e47f4eb55197e1bfffae897e9d5ce4cba49623 grayboxes.gif\n'    + \
            ' 2477b9ea649f3f30c6ed0aebacfa32cb8250f3df index.html\n'

        # create from string array ----------------------------------
        s = serialization.split('\n')
        s = s[:-1]
        self.assertEqual(4, len(s))

        tree2 = MerkleTree.createFromStringArray(s, Q.USING_SHA1)

        ser2 = tree2.toString(0)
        self.assertEqual(serialization, ser2)

        # create from serialization ---------------------------------
        tree1 = MerkleTree.createFromSerialization(serialization, Q.USING_SHA1)

        ser1 = tree1.toString(0)
        self.assertEqual(serialization, ser1)

        self.assertTrue(tree1.equal(tree2))

        # 2014-06-26 tagged this on here to test firstLineRE_1()
        firstLine = s[0]
        m = MerkleTree.firstLineRE_1().match(firstLine)
        self.assertTrue(m is not None)
        self.assertEqual(m.group(1), '')               # indent
        treeHash = m.group(2)
        dirName = m.group(3)
        self.assertEqual(treeHash + ' ' + dirName, firstLine)

    def testXLatticeBug1(self):
        """
        this test relies on dat.xlattice.org being locally present
        and an internally consistent merkleization
        """
        with open('testData/dat.xlattice.org', 'rb') as f:
            serialization = str(f.read(), 'utf-8')

        # create from serialization ---------------------------------
        tree1 = MerkleTree.createFromSerialization(serialization, Q.USING_SHA1)

#       # DEBUG
#       print "tree1 has %d nodes" % len(tree1.nodes)
#       with open('junk.tree1', 'w') as t:
#           t.write( tree1.toString(0) )
#       # END

        ser1 = tree1.toString(0)
        self.assertEqual(serialization, ser1)

        # create from string array ----------------------------------
        s = serialization.split('\n')
        s = s[:-1]
        self.assertEqual(2511, len(s))

        tree2 = MerkleTree.createFromStringArray(s, Q.USING_SHA1)

        ser2 = tree2.toString(0)
        self.assertEqual(serialization, ser2)

        self.assertTrue(tree1.equal(tree2))

    def testGrayBoxesBug3(self):
        serialization = \
            '088d0e391e1a4872329e0f7ac5d45b2025363e26c199a74ea39901d109afd6ba grayboxes.com/\n' + \
            ' 24652ddc14687866e6b1251589aee7e1e3079a87f80cd7775214f6d837612a90 images/\n' + \
            '  1eb774eef9be1e696f69a2f95711be37915aac283bb4b34dcbaf7d032233e090 grayboxes.gif\n' + \
            ' 6eacebda9fd55b59c0d2e48e2ed59ce9fd683379592f8e662b1de88e041f53c9 index.html\n'

        # create from string array ----------------------------------
        s = serialization.split('\n')
        s = s[:-1]
        self.assertEqual(4, len(s))

        tree2 = MerkleTree.createFromStringArray(s, Q.USING_SHA2)

        ser2 = tree2.toString(0)
        self.assertEqual(serialization, ser2)

        # create from serialization ---------------------------------
        tree1 = MerkleTree.createFromSerialization(serialization, Q.USING_SHA2)

        ser1 = tree1.toString(0)
        self.assertEqual(serialization, ser1)

        self.assertTrue(tree1.equal(tree2))            # GEEP

        # 2014-06-26 tagged this on here to test firstLineRE_1()
        firstLine = s[0]
        m = MerkleTree.firstLineRE_2().match(firstLine)
        self.assertTrue(m is not None)
        self.assertEqual(m.group(1), '')               # indent
        treeHash = m.group(2)
        dirName = m.group(3)
        self.assertEqual(treeHash + ' ' + dirName, firstLine)

    def testXLatticeBug3(self):
        """
        this test relies on dat2.xlattice.org being locally present
        and an internally consistent merkleization
        """
        with open('testData/dat2.xlattice.org', 'rb') as f:
            serialization = str(f.read(), 'utf-8')

        # create from serialization ---------------------------------
        tree1 = MerkleTree.createFromSerialization(serialization, Q.USING_SHA2)

        ser1 = tree1.toString(0)
        self.assertEqual(serialization, ser1)

        # create from string array ----------------------------------
        s = serialization.split('\n')
        s = s[:-1]
        self.assertEqual(2511, len(s))

        tree2 = MerkleTree.createFromStringArray(s, Q.USING_SHA2)

        ser2 = tree2.toString(0)
        self.assertEqual(serialization, ser2)

        self.assertTrue(tree1.equal(tree2))

if __name__ == '__main__':
    unittest.main()
