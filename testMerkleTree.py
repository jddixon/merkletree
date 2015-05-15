#!/usr/bin/python3

# testMerkleTree.py
import hashlib, os, re, shutil, sys, time, unittest

from rnglib         import SimpleRNG
from xlattice       import SHA1_HEX_NONE, SHA2_HEX_NONE
from merkletree     import *

ONE          = 1
FOUR         = 4
MAX_NAME_LEN = 8

class TestMerkleTree (unittest.TestCase):

    def setUp(self):
        self.rng = SimpleRNG( time.time() )
    def tearDown(self):
        pass

    # utility functions #############################################
    def getTwoUniqueDirectoryNames(self):
        dirName1 = self.rng.nextFileName(MAX_NAME_LEN)
        dirName2 = dirName1
        while dirName2 == dirName1:
            dirName2 = self.rng.nextFileName(MAX_NAME_LEN)
        self.assertTrue( len(dirName1) > 0 )
        self.assertTrue( len(dirName2) > 0 )
        self.assertTrue( dirName1 != dirName2 )
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

    def verifyLeafSHA1(self, node, pathToFile):
        self.assertTrue( os.path.exists(pathToFile) )
        with open(pathToFile, "rb") as f:
            data = f.read()
        self.assertFalse( data == None )
        sha1 = hashlib.sha1()
        sha1.update(data)
        hash = sha1.digest()
        self.assertEqual( hash, node.binHash )

    def verifyTreeSHA1(self, node, pathToNode):
        # we assume that the node is a MerkleTree
        if node.nodes == None:
            self.assertEqual(None, node.binHash)
        else:
            hashCount = 0
            sha1 = hashlib.sha1()
            for n in node.nodes:
                pathToFile = os.path.join(pathToNode, n.name)
                if isinstance(n, MerkleLeaf):
                    self.verifyLeafSHA1(n, pathToFile)
                elif isinstance(n, MerkleTree):
                    self.verifyTreeSHA1(n, pathToFile)
                else:
                    self.fail ("unknown node type!")
                if (n.binHash != None):
                    hashCount += 1
                    sha1.update(n.binHash)

            # take care to compare values of the same type;
            # node.binHash is binary, node.asciiHash is hex
            if hashCount == 0:
                self.assertEqual(None, node.binHash)
            else:
                self.assertEqual(sha1.digest(), node.binHash)

    def verifyLeafSHA2(self, node, pathToFile):
        self.assertTrue( os.path.exists(pathToFile) )
        with open(pathToFile, "rb") as f:
            data = f.read()
        self.assertFalse( data == None )
        sha = hashlib.sha256()
        sha.update(data)
        hash = sha.digest()
        self.assertEqual( hash, node.binHash )

    def verifyTreeSHA2(self, node, pathToNode):
        # we assume that the node is a MerkleTree
        if node.nodes == None:
            self.assertEqual(None, node.binHash)
        else:
            hashCount = 0
            sha = hashlib.sha256()
            for n in node.nodes:
                pathToFile = os.path.join(pathToNode, n.name)
                if isinstance(n, MerkleLeaf):
                    self.verifyLeafSHA2(n, pathToFile)
                elif isinstance(n, MerkleTree):
                    self.verifyTreeSHA2(n, pathToFile)
                else:
                    self.fail ("unknown node type!")
                if (n.binHash != None):
                    hashCount += 1
                    sha.update(n.binHash)

            # take care to compare values of the same type;
            # node.binHash is binary, node.asciiHash is hex
            if hashCount == 0:
                self.assertEqual(None, node.binHash)
            else:
                self.assertEqual(sha.digest(), node.binHash)

    #################################################################
    # SHA1 UNIT TESTS
    #################################################################

    def testPathlessUnboundConstructor1(self):
        (dirName1, dirName2) = self.getTwoUniqueDirectoryNames()

        tree1 = MerkleTree(dirName1, True)
        self.assertEqual( dirName1, tree1.name )
        self.assertEqual(SHA1_HEX_NONE, tree1.asciiHash)

        tree2 = MerkleTree(dirName2, True)
        self.assertEqual( dirName2, tree2.name )

        # these tests remain skimpy
        self.assertTrue  ( tree1.equal(tree1) )
        self.assertFalse ( tree1.equal(tree2) )
        self.assertFalse ( tree1.equal(None)  )

        tree1Str     = tree1.toString('')

        # there should be no indent on the first line
        self.assertFalse( ' ' == tree1Str[0] )

        # no extra lines should be added
        lines = tree1Str.split('\r\n')
        # this split generates an extra blank line, because the serialization
        # ends with CR-LF
        if lines[-1] == '':
            lines = lines[:-1]
        self.assertEqual( 1, len(lines) )

        tree1Rebuilt = MerkleTree.createFromSerialization(tree1Str)
        self.assertTrue( tree1.equal(tree1Rebuilt) )

    def testBoundFlatDirs1(self):
        """test directory is single level, with four data files"""
        (dirName1, dirPath1, dirName2, dirPath2) = \
                                    self.makeTwoTestDirectories(ONE, FOUR)
        tree1 = MerkleTree.createFromFileSystem(dirPath1, usingSHA1=True)
        self.assertEqual( dirName1, tree1.name, True )
        nodes1 = tree1.nodes
        self.assertTrue (nodes1 is not None)
        self.assertEqual(FOUR, len(nodes1))
        self.verifyTreeSHA1(tree1, dirPath1)

        tree2 = MerkleTree.createFromFileSystem(dirPath2, True)
        self.assertEqual( dirName2, tree2.name )
        nodes2 = tree2.nodes
        self.assertTrue (nodes2 is not None)
        self.assertEqual(FOUR, len(nodes2))
        self.verifyTreeSHA1(tree2, dirPath2)

        # XXX COMMENTED OUT FOR DEBUGGING XXX
        #self.assertTrue  ( tree1.equal(tree1) )
        self.assertFalse ( tree1.equal(tree2) )
        self.assertFalse ( tree1.equal(None)  )

        tree1Str     = tree1.toString('')
        tree1Rebuilt = MerkleTree.createFromSerialization(tree1Str)
        self.assertTrue( tree1.equal(tree1Rebuilt) )

    def testBoundNeedleDirs1(self):
        """test directories four deep with one data file at the lowest level"""
        (dirName1, dirPath1, dirName2, dirPath2) = \
                                    self.makeTwoTestDirectories(FOUR, ONE)
        tree1 = MerkleTree.createFromFileSystem(dirPath1, True)

        self.assertEqual( dirName1, tree1.name )
        nodes1 = tree1.nodes
        self.assertTrue (nodes1 is not None)
        self.assertEqual(ONE, len(nodes1))
        self.verifyTreeSHA1(tree1, dirPath1)

        tree2 = MerkleTree.createFromFileSystem(dirPath2, True)
        self.assertEqual( dirName2, tree2.name )
        nodes2 = tree2.nodes
        self.assertTrue (nodes2 is not None)
        self.assertEqual(ONE, len(nodes2))
        self.verifyTreeSHA1(tree2, dirPath2)

        self.assertTrue  ( tree1.equal(tree1) )
        self.assertFalse ( tree1.equal(tree2) )

        tree1Str     = tree1.toString('')
        tree1Rebuilt = MerkleTree.createFromSerialization(tree1Str)
#       # DEBUG
#       print "NEEDLEDIR TREE1:\n" + tree1Str
#       print "REBUILT TREE1:\n" + tree1Rebuilt.toString("")
#       # END
        self.assertTrue( tree1.equal(tree1Rebuilt) )   # GEEP

    def testGrayBoxesBug1(self):
        serialization = \
        '721a08022dd26e7be98b723f26131786fd2c0dc3 grayboxes.com/\r\n'       + \
        '  fcd3973c66230b9078a86a5642b4c359fe72d7da images/\r\n'            + \
        '    15e47f4eb55197e1bfffae897e9d5ce4cba49623 grayboxes.gif\r\n'    + \
        '  2477b9ea649f3f30c6ed0aebacfa32cb8250f3df index.html\r\n'

        # create from string array ----------------------------------
        s = serialization.split('\r\n')
        s = s[:-1]
        self.assertEqual(4, len(s))

        tree2 = MerkleTree.createFromStringArray(s, '  ')

        ser2  = tree2.toString('', '  ')
        self.assertEqual(serialization, ser2)

        # create from serialization ---------------------------------
        tree1 = MerkleTree.createFromSerialization(serialization, '  ')

        ser1  = tree1.toString('', '  ')
        self.assertEqual(serialization, ser1)

        self.assertTrue(tree1.equal(tree2))

        # 2014-06-26 tagged this on here to test firstLineRE_1()
        firstLine = s[0]
        m = MerkleTree.firstLineRE_1().match(firstLine)
        self.assertTrue(m is not None)
        self.assertEqual(m.group(1), '')               # indent
        treeHash = m.group(2)
        dirName  = m.group(3)
        self.assertEqual(treeHash + ' ' + dirName, firstLine)

    def testXLatticeBug1(self):
        """
        this test relies on dat.xlattice.org being locally present
        and an internally consistent merkleization
        """
        with open('testData/dat.xlattice.org', 'rb') as f:
            serialization = str(f.read(), 'utf-8')

        # create from serialization ---------------------------------
        tree1 = MerkleTree.createFromSerialization(serialization, '  ')

#       # DEBUG
#       print "tree1 has %d nodes" % len(tree1.nodes)
#       with open('junk.tree1', 'w') as t:
#           t.write( tree1.toString('') )
#       # END

        ser1  = tree1.toString('', '  ')
        self.assertEqual(serialization, ser1)

        # create from string array ----------------------------------
        s = serialization.split('\r\n')
        s = s[:-1]
        self.assertEqual(2511, len(s))

        tree2 = MerkleTree.createFromStringArray(s, '  ')

        ser2  = tree2.toString('', '  ')
        self.assertEqual(serialization, ser2)

        self.assertTrue(tree1.equal(tree2))

    #################################################################
    # SHA2 UNIT TESTS
    #################################################################
    def testPathlessUnboundConstructor3(self):
        (dirName1, dirName2) = self.getTwoUniqueDirectoryNames()

        tree1 = MerkleTree(dirName1)
        self.assertEqual( dirName1, tree1.name )
        self.assertEqual(SHA2_HEX_NONE, tree1.asciiHash)

        tree2 = MerkleTree(dirName2)
        self.assertEqual( dirName2, tree2.name )

        # these tests remain skimpy
        self.assertTrue  ( tree1.equal(tree1) )
        self.assertFalse ( tree1.equal(tree2) )
        self.assertFalse ( tree1.equal(None)  )

        tree1Str     = tree1.toString('')

        # there should be no indent on the first line
        self.assertFalse( ' ' == tree1Str[0] )

        # no extra lines should be added
        lines = tree1Str.split('\r\n')
        # this split generates an extra blank line, because the serialization
        # ends with CR-LF
        if lines[-1] == '':
            lines = lines[:-1]
        self.assertEqual( 1, len(lines) )

        tree1Rebuilt = MerkleTree.createFromSerialization(tree1Str)
        self.assertTrue( tree1.equal(tree1Rebuilt) )

    def testBoundFlatDirs3(self):
        """test directory is single level, with four data files"""
        (dirName1, dirPath1, dirName2, dirPath2) = \
                                    self.makeTwoTestDirectories(ONE, FOUR)
        tree1 = MerkleTree.createFromFileSystem(dirPath1)
        self.assertEqual( dirName1, tree1.name )
        nodes1 = tree1.nodes
        self.assertTrue (nodes1 is not None)
        self.assertEqual(FOUR, len(nodes1))
        self.verifyTreeSHA2(tree1, dirPath1)

        tree2 = MerkleTree.createFromFileSystem(dirPath2)
        self.assertEqual( dirName2, tree2.name )
        nodes2 = tree2.nodes
        self.assertTrue (nodes2 is not None)
        self.assertEqual(FOUR, len(nodes2))
        self.verifyTreeSHA2(tree2, dirPath2)

        self.assertTrue  ( tree1.equal(tree1) )
        self.assertFalse ( tree1.equal(tree2) )
        self.assertFalse ( tree1.equal(None)  )

        tree1Str     = tree1.toString('')
        tree1Rebuilt = MerkleTree.createFromSerialization(tree1Str)
        self.assertTrue( tree1.equal(tree1Rebuilt) )

    def testBoundNeedleDirs3(self):
        """test directories four deep with one data file at the lowest level"""
        (dirName1, dirPath1, dirName2, dirPath2) = \
                                    self.makeTwoTestDirectories(FOUR, ONE)
        tree1 = MerkleTree.createFromFileSystem(dirPath1)

        self.assertEqual( dirName1, tree1.name )
        nodes1 = tree1.nodes
        self.assertTrue (nodes1 is not None)
        self.assertEqual(ONE, len(nodes1))
        self.verifyTreeSHA2(tree1, dirPath1)

        tree2 = MerkleTree.createFromFileSystem(dirPath2)
        self.assertEqual( dirName2, tree2.name )
        nodes2 = tree2.nodes
        self.assertTrue (nodes2 is not None)
        self.assertEqual(ONE, len(nodes2))
        self.verifyTreeSHA2(tree2, dirPath2)

        self.assertTrue  ( tree1.equal(tree1) )
        self.assertFalse ( tree1.equal(tree2) )

        tree1Str     = tree1.toString('')
        tree1Rebuilt = MerkleTree.createFromSerialization(tree1Str)
#       # DEBUG
#       print "NEEDLEDIR TREE1:\n" + tree1Str
#       print "REBUILT TREE1:\n" + tree1Rebuilt.toString("")
#       # END
        self.assertTrue( tree1.equal(tree1Rebuilt) )   # GEEP

    def testGrayBoxesBug3(self):
        serialization = \
        '088d0e391e1a4872329e0f7ac5d45b2025363e26c199a74ea39901d109afd6ba grayboxes.com/\r\n' + \
        ' 24652ddc14687866e6b1251589aee7e1e3079a87f80cd7775214f6d837612a90 images/\r\n' + \
        '  1eb774eef9be1e696f69a2f95711be37915aac283bb4b34dcbaf7d032233e090 grayboxes.gif\r\n' + \
        ' 6eacebda9fd55b59c0d2e48e2ed59ce9fd683379592f8e662b1de88e041f53c9 index.html\r\n'

        # create from string array ----------------------------------
        s = serialization.split('\r\n')
        s = s[:-1]
        self.assertEqual(4, len(s))

        tree2 = MerkleTree.createFromStringArray(s)

        ser2  = tree2.toString('')
        self.assertEqual(serialization, ser2)

        # create from serialization ---------------------------------
        tree1 = MerkleTree.createFromSerialization(serialization)

        ser1  = tree1.toString('')
        self.assertEqual(serialization, ser1)

        self.assertTrue(tree1.equal(tree2))            # GEEP

        # 2014-06-26 tagged this on here to test firstLineRE_1()
        firstLine = s[0]
        m = MerkleTree.firstLineRE_2().match(firstLine)
        self.assertTrue(m is not None)
        self.assertEqual(m.group(1), '')               # indent
        treeHash = m.group(2)
        dirName  = m.group(3)
        self.assertEqual(treeHash + ' ' + dirName, firstLine)

    def testXLatticeBug3(self):
        """
        this test relies on dat2.xlattice.org being locally present
        and an internally consistent merkleization
        """
        with open('testData/dat2.xlattice.org', 'rb') as f:
            serialization = str(f.read(), 'utf-8')

        # create from serialization ---------------------------------
        tree1 = MerkleTree.createFromSerialization(serialization, '  ')

#       # DEBUG
#       print "tree1 has %d nodes" % len(tree1.nodes)
#       with open('junk.tree1', 'w') as t:
#           t.write( tree1.toString('') )
#       # END

        ser1  = tree1.toString('', '  ')
        self.assertEqual(serialization, ser1)

        # create from string array ----------------------------------
        s = serialization.split('\r\n')
        s = s[:-1]
        self.assertEqual(2511, len(s))

        tree2 = MerkleTree.createFromStringArray(s, '  ')

        ser2  = tree2.toString('', '  ')
        self.assertEqual(serialization, ser2)

        self.assertTrue(tree1.equal(tree2))

if __name__ == '__main__':
    unittest.main()
