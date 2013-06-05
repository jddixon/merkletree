#!/usr/bin/python

# testMerkleDoc.py
import hashlib, os, re, shutil, time, unittest

from rnglib     import SimpleRNG
from merkletree import *

ONE          = 1
FOUR         = 4
MAX_NAME_LEN = 8

class TestMerkleDoc (unittest.TestCase):

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
            print("DEBUG: directory '%s' already exists" % dirPath)
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

    def verifyTreeSHA1(self, node, pathToTree):
        # we assume that the node is a MerkleTree
        if node.nodes == None:
            self.assertEquals(None, node.hash)
        else:
            hashCount = 0
            sha1 = hashlib.sha1()
            for n in node.nodes:
                pathToNode = os.path.join(pathToTree, n.name)
                if isinstance(n, MerkleLeaf):
                    self.verifyLeafSHA1(n, pathToNode)
                elif isinstance(n, MerkleTree):
                    self.verifyTreeSHA1(n, pathToNode)
                else:
                    print "DEBUG: unknown node type!"
                    self.fail ("unknown node type!")
                if (n.hash != None):
                    hashCount += 1
                    sha1.update(n.hash)

            if hashCount == 0:
                self.assertEquals(None, node._hash)
            else:
                self.assertEquals(sha1.digest(), node._hash)

    # actual unit tests #############################################

    def testBoundFlatDirs(self):
        """test directory is single level, with four data files"""
        (dirName1, dirPath1, dirName2, dirPath2) = \
                            self.makeTwoTestDirectories(ONE, FOUR)

        doc1   = MerkleDoc.createFromFileSystem(dirPath1)
        tree1  = doc1.tree
        self.assertEquals( dirName1, tree1.name )
        self.assertTrue  ( doc1.bound )
        self.assertEquals( ("tmp/%s" % dirName1), dirPath1)
        nodes1 = tree1.nodes
        self.assertTrue (nodes1 is not None)
        self.assertEquals(FOUR, len(nodes1))
        self.verifyTreeSHA1(tree1, dirPath1)

        doc2  = MerkleDoc.createFromFileSystem(dirPath2)
        tree2 = doc2.tree
        self.assertEquals( dirName2, tree2.name )
        self.assertTrue  ( doc2.bound )
        self.assertEquals( ("tmp/%s" % dirName2), dirPath2)
        nodes2 = tree2.nodes
        self.assertTrue (nodes2 is not None)
        self.assertEquals(FOUR, len(nodes2))
        self.verifyTreeSHA1(tree2, dirPath2)

        self.assertTrue  ( tree1.equals(tree1) )
        self.assertFalse ( tree1.equals(tree2) )
        self.assertFalse ( tree1.equals(None)  )

        doc1Str     = doc1.toString()
        doc1Rebuilt = MerkleDoc.createFromSerialization(doc1Str)
#       # DEBUG
#       print "flat doc:\n" + doc1Str
#       print "rebuilt flat doc:\n" + doc1Rebuilt.toString()
#       # END
        self.assertTrue( doc1.equals(doc1Rebuilt) )       #  MANGO

    def testBoundNeedleDirs(self):
        """test directories four deep with one data file at the lowest level"""
        (dirName1, dirPath1, dirName2, dirPath2) = \
                                    self.makeTwoTestDirectories(FOUR, ONE)
        doc1   = MerkleDoc.createFromFileSystem(dirPath1)
        tree1  = doc1.tree
        self.assertEquals( dirName1, tree1.name )
        self.assertTrue  ( doc1.bound )
        self.assertEquals( ("tmp/%s" % dirName1), dirPath1)
        nodes1 = tree1.nodes
        self.assertTrue (nodes1 is not None)
        self.assertEquals(ONE, len(nodes1))
        self.verifyTreeSHA1(tree1, dirPath1)

        doc2   = MerkleDoc.createFromFileSystem(dirPath2)
        tree2  = doc2.tree
        self.assertEquals( dirName2, tree2.name )
        self.assertTrue  ( doc2.bound )
        self.assertEquals( ("tmp/%s" % dirName2), dirPath2)
        nodes2 = tree2.nodes
        self.assertTrue (nodes2 is not None)
        self.assertEquals(ONE, len(nodes2))
        self.verifyTreeSHA1(tree2, dirPath2)

        self.assertTrue  ( doc1.equals(doc1) )
        self.assertFalse ( doc1.equals(doc2) )

        doc1Str     = doc1.toString()
        doc1Rebuilt = MerkleDoc.createFromSerialization(doc1Str)
#       # DEBUG
#       print "needle doc:\n" + doc1Str
#       print "rebuilt needle doc:\n" + doc1Rebuilt.toString()
#       # END
        self.assertTrue( doc1.equals(doc1Rebuilt) )       # FOO

    def doTestForExpectedExclusions(self, exRE):
        # should always match
        self.assertTrue( exRE.search('.') )
        self.assertTrue( exRE.search('..') )
        self.assertTrue( exRE.search('.merkle') )
        self.assertTrue( exRE.search('.svn') )
        self.assertTrue( exRE.search('.foo.swp') )          # vi backup file
        self.assertTrue( exRE.search('junkEverywhere') )    # begins with 'junk'

    def doTestForExpectedMatches(self, matchRE, names):
        for name in names:
            self.assertTrue( matchRE.search(name) )

    def doTestForExpectedMatchFailures(self, matchRE, names):
        for name in names:
            m = matchRE.search(name)
            if m:
                print "WE HAVE A MATCH ON '%s'" % name
            # self.assertEquals( None, where )

    def testMakeExRE(self):
        """test utility for making excluded file name regexes"""
        exRE = MerkleDoc.makeExRE(None)
        self.assertTrue (exRE is not None)
        self.doTestForExpectedExclusions(exRE)

        # should not be present
        self.assertTrue( None == exRE.search('bar') )
        self.assertTrue( None == exRE.search('foo') )

        exc = []
        exc.append('^foo')
        exc.append('bar$')
        exc.append('^junk*')
        exRE = MerkleDoc.makeExRE(exc)
        self.doTestForExpectedExclusions(exRE)

        self.assertTrue ( exRE.search('foobarf') )
        self.assertTrue ( None == exRE.search(' foobarf') )
        self.assertFalse( exRE.search(' foobarf') )

        # bear in mind that match must be at the beginning
        self.assertFalse( exRE.match('ohMybar') )
        self.assertTrue ( exRE.search('ohMybar') )

        self.assertFalse( exRE.match('ohMybarf') )
        self.assertTrue ( exRE.search('junky') )
        self.assertFalse( exRE.match(' junk') )

    def testMakeMatchRE(self):
        """test utility for making matched file name regexes"""
        matchRE = MerkleDoc.makeMatchRE(None)
        self.assertEquals (None, matchRE)

        matches = []
        matches.append('^foo')
        matches.append('bar$')
        matches.append('^junk*')
        matchRE = MerkleDoc.makeMatchRE(matches)
        self.doTestForExpectedMatches(matchRE,
                ['foo', 'foolish', 'roobar', 'junky'])
        self.doTestForExpectedMatchFailures(matchRE,
                [' foo', 'roobarf', 'myjunk'])

        matches = [ '\.tgz$' ]
        matchRE = MerkleDoc.makeMatchRE(matches)
        self.doTestForExpectedMatches(matchRE,
                ['junk.tgz', 'notSoFoolish.tgz'])
        self.doTestForExpectedMatchFailures(matchRE,
                ['junk.tar.gz', 'foolish.tar.gz'])

        matches = [ '\.tgz$', '\.tar\.gz$' ]
        matchRE = MerkleDoc.makeMatchRE(matches)
        self.doTestForExpectedMatches(matchRE,
                ['junk.tgz', 'notSoFoolish.tgz',
                 'junk.tar.gz', 'ohHello.tar.gz'])
        self.doTestForExpectedMatchFailures(matchRE,
                ['junk.gz', 'foolish.tar'])                 # GEEP

if __name__ == '__main__':
    unittest.main()
