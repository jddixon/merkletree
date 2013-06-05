#!/usr/bin/python

# testMerkleTree.py
import hashlib, os, re, shutil, time, unittest

from rnglib         import SimpleRNG
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
        self.assertEquals( hash, node.hash )

    def verifyTreeSHA1(self, node, pathToNode):
        # we assume that the node is a MerkleTree
        if node.nodes == None:
            self.assertEquals(None, node.hash)
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
                if (n.hash != None):
                    hashCount += 1
                    sha1.update(n.hash)

            # take care to compare values of the same type;
            # node._hash is binary, node.hash is hex
            if hashCount == 0:
                self.assertEquals(None, node._hash)
            else:
                self.assertEquals(sha1.digest(), node._hash)

    # actual unit tests #############################################
    def testPathlessUnboundConstructor(self):
        (dirName1, dirName2) = self.getTwoUniqueDirectoryNames()

        tree1 = MerkleTree(dirName1)
        self.assertEquals( dirName1, tree1.name )
        self.assertEquals('0000000000000000000000000000000000000000',
                           tree1.hash)

        tree2 = MerkleTree(dirName2)
        self.assertEquals( dirName2, tree2.name )

        # these tests remain skimpy
        self.assertTrue  ( tree1.equals(tree1) )
        self.assertFalse ( tree1.equals(tree2) )
        self.assertFalse ( tree1.equals(None)  )

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
        self.assertTrue( tree1.equals(tree1Rebuilt) )

    def testBoundFlatDirs(self):
        """test directory is single level, with four data files"""
        (dirName1, dirPath1, dirName2, dirPath2) = \
                                    self.makeTwoTestDirectories(ONE, FOUR)
        tree1 = MerkleTree.createFromFileSystem(dirPath1)
        self.assertEquals( dirName1, tree1.name )
        nodes1 = tree1.nodes
        self.assertTrue (nodes1 is not None)
        self.assertEquals(FOUR, len(nodes1))
        self.verifyTreeSHA1(tree1, dirPath1)

        tree2 = MerkleTree.createFromFileSystem(dirPath2)
        self.assertEquals( dirName2, tree2.name )
        nodes2 = tree2.nodes
        self.assertTrue (nodes2 is not None)
        self.assertEquals(FOUR, len(nodes2))
        self.verifyTreeSHA1(tree2, dirPath2)

        self.assertTrue  ( tree1.equals(tree1) )
        self.assertFalse ( tree1.equals(tree2) )
        self.assertFalse ( tree1.equals(None)  )

        tree1Str     = tree1.toString('')
        tree1Rebuilt = MerkleTree.createFromSerialization(tree1Str)
        self.assertTrue( tree1.equals(tree1Rebuilt) )

    def testBoundNeedleDirs(self):
        """test directories four deep with one data file at the lowest level"""
        (dirName1, dirPath1, dirName2, dirPath2) = \
                                    self.makeTwoTestDirectories(FOUR, ONE)
        tree1 = MerkleTree.createFromFileSystem(dirPath1)

        self.assertEquals( dirName1, tree1.name )
        nodes1 = tree1.nodes
        self.assertTrue (nodes1 is not None)
        self.assertEquals(ONE, len(nodes1))
        self.verifyTreeSHA1(tree1, dirPath1)

        tree2 = MerkleTree.createFromFileSystem(dirPath2)
        self.assertEquals( dirName2, tree2.name )
        nodes2 = tree2.nodes
        self.assertTrue (nodes2 is not None)
        self.assertEquals(ONE, len(nodes2))
        self.verifyTreeSHA1(tree2, dirPath2)

        self.assertTrue  ( tree1.equals(tree1) )
        self.assertFalse ( tree1.equals(tree2) )

        tree1Str     = tree1.toString('')
        tree1Rebuilt = MerkleTree.createFromSerialization(tree1Str)
#       # DEBUG
#       print "NEEDLEDIR TREE1:\n" + tree1Str
#       print "REBUILT TREE1:\n" + tree1Rebuilt.toString("")
#       # END
        self.assertTrue( tree1.equals(tree1Rebuilt) )   # GEEP
 
    def testGrayBoxesBug(self):
        serialization = \
        '721a08022dd26e7be98b723f26131786fd2c0dc3 grayboxes.com/\r\n'       + \
        '  fcd3973c66230b9078a86a5642b4c359fe72d7da images/\r\n'            + \
        '    15e47f4eb55197e1bfffae897e9d5ce4cba49623 grayboxes.gif\r\n'    + \
        '  2477b9ea649f3f30c6ed0aebacfa32cb8250f3df index.html\r\n'

        # create from string array ----------------------------------
        s = serialization.split('\r\n')
        s = s[:-1]
        self.assertEquals(4, len(s))

        tree2 = MerkleTree.createFromStringArray(s)

        ser2  = tree2.toString('')
        self.assertEquals(serialization, ser2)

        # create from serialization ---------------------------------
        tree1 = MerkleTree.createFromSerialization(serialization)

        ser1  = tree1.toString('')
        self.assertEquals(serialization, ser1)

        self.assertTrue(tree1.equals(tree2))            # GEEP

    def testXLatticeBug(self):
        """ 
        this test relies on dat.xlattice.org being locally present
        and an internally consistent merkleization
        """
        with open('./dat.xlattice.org', 'r') as f:
            serialization = f.read()

        # create from serialization ---------------------------------
        tree1 = MerkleTree.createFromSerialization(serialization)

#       # DEBUG
#       print "tree1 has %d nodes" % len(tree1.nodes)
#       with open('junk.tree1', 'w') as t:
#           t.write( tree1.toString('') )
#       # END

        ser1  = tree1.toString('')
        self.assertEquals(serialization, ser1)          # XXX FAILS

        # create from string array ----------------------------------
        s = serialization.split('\r\n')
        s = s[:-1]
        self.assertEquals(2511, len(s))

        tree2 = MerkleTree.createFromStringArray(s)

        ser2  = tree2.toString('')
        self.assertEquals(serialization, ser2)          # XXX FAILS

        self.assertTrue(tree1.equals(tree2))            # GEEP

if __name__ == '__main__':
    unittest.main()
