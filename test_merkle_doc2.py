#!/usr/bin/env python3
# testMerkleDoc2.py

""" Test MerkleTree functionality at the document level. """

import hashlib
import os
import shutil
import time
import unittest

from rnglib import SimpleRNG
from merkletree import MerkleDoc, MerkleTree, MerkleLeaf

ONE = 1
FOUR = 4
MAX_NAME_LEN = 8


class TestMerkleDoc(unittest.TestCase):
    """ Test MerkleTree functionality at the document level. """

    def setUp(self):
        self.rng = SimpleRNG(time.time())

    def tearDown(self):
        pass

    def get_two_unique_directory_names(self):
        """
        Get two candidate directory names, making sure that they differ.
        """
        dir_name1 = self.rng.nextFileName(MAX_NAME_LEN)
        dir_name2 = dir_name1
        while dir_name2 == dir_name1:
            dir_name2 = self.rng.nextFileName(MAX_NAME_LEN)
        self.assertTrue(len(dir_name1) > 0)
        self.assertTrue(len(dir_name2) > 0)
        self.assertTrue(dir_name1 != dir_name2)
        return (dir_name1, dir_name2)

    def make_one_named_test_directory(self, name, depth, width):
        """
        Create a test directory with the name, depth, and width specified.
        The directory is under tmp/ ; subdirectories have random names
        and contents.
        """
        dir_path = "tmp/%s" % name
        if os.path.exists(dir_path):
            shutil.rmtree(dir_path)
        self.rng.nextDataDir(dir_path, depth, width, 32)
        return dir_path

    def make_two_test_directories(self, depth, width):
        """
        Create two test directories under tmp/ with distinct names but the
        depth and width specified.
        """
        dir_name1 = self.rng.nextFileName(MAX_NAME_LEN)
        dir_path1 = self.make_one_named_test_directory(dir_name1, depth, width)

        dir_name2 = dir_name1
        while dir_name2 == dir_name1:
            dir_name2 = self.rng.nextFileName(MAX_NAME_LEN)
        dir_path2 = self.make_one_named_test_directory(dir_name2, depth, width)

        return (dir_name1, dir_path1, dir_name2, dir_path2)

    def verify_leaf_sha256(self, node, path_to_file):
        """
        Verify that the content keys of the named file match the SHA
        hash of its contents.
        """
        self.assertTrue(os.path.exists(path_to_file))
        with open(path_to_file, "rb") as file:
            data = file.read()
        self.assertFalse(data is None)
        sha = hashlib.sha256()
        sha.update(data)
        hash_ = sha.digest()
        self.assertEqual(hash_, node.bin_hash)

    def verify_tree_sha256(self, node, path_to_tree):
        """
        Verify that the names (content keys) of files below the node
        (a Merkletree) have correct content keys, matching the SHA
        hash of the files.
        """
        if node.nodes is None:
            self.assertEqual(None, node.bin_hash)
        else:
            hash_count = 0
            sha = hashlib.sha256()
            for node_ in node.nodes:
                path_to_node = os.path.join(path_to_tree, node_.name)
                if isinstance(node_, MerkleLeaf):
                    self.verify_leaf_sha256(node_, path_to_node)
                elif isinstance(node_, MerkleTree):
                    self.verify_tree_sha256(node_, path_to_node)
                else:
                    print("DEBUG: unknown node type!")
                    self.fail("unknown node type!")
                if node_.bin_hash is not None:
                    hash_count += 1
                    sha.update(node_.bin_hash)

            if hash_count == 0:
                self.assertEqual(None, node.bin_hash)
            else:
                self.assertEqual(sha.digest(), node.bin_hash)

    # actual unit tests #############################################

    def test_bound_flat_dirs(self):
        """test directory is single level, with four data files"""

        dir_name1, dir_path1, dir_name2, dir_path2 = \
            self.make_two_test_directories(ONE, FOUR)
        doc1 = MerkleDoc.create_from_file_system(dir_path1)
        # pylint: disable=no-member
        tree1 = doc1.tree
        # XXX This succeeds BUT pylint doesn't get this right: it sees
        # doc1.tree as a function
        self.assertTrue(isinstance(tree1, MerkleTree))

        # pylint: disable=no-member
        self.assertEqual(dir_name1, tree1.name)
        self.assertTrue(doc1.bound)
        self.assertEqual(("tmp/%s" % dir_name1), dir_path1)
        # pylint: disable=no-member
        nodes1 = tree1.nodes
        self.assertTrue(nodes1 is not None)
        self.assertEqual(FOUR, len(nodes1))
        self.verify_tree_sha256(tree1, dir_path1)

        doc2 = MerkleDoc.create_from_file_system(dir_path2)
        tree2 = doc2.tree
        # pylint: disable=no-member
        self.assertEqual(dir_name2, tree2.name)
        self.assertTrue(doc2.bound)
        self.assertEqual(("tmp/%s" % dir_name2), dir_path2)
        # pylint: disable=no-member
        nodes2 = tree2.nodes
        self.assertTrue(nodes2 is not None)
        self.assertEqual(FOUR, len(nodes2))
        self.verify_tree_sha256(tree2, dir_path2)

        # pylint: disable=no-member
        self.assertTrue(tree1.equal(tree1))
        # pylint: disable=no-member
        self.assertFalse(tree1.equal(tree2))
        # pylint: disable=no-member
        self.assertFalse(tree1.equal(None))

        doc1_str = doc1.to_string()
        doc1_rebuilt = MerkleDoc.create_from_serialization(doc1_str)
        self.assertTrue(doc1.equal(doc1_rebuilt))  # MANGO

    def test_bound_needle_dirs(self):
        """test directories four deep with one data file at the lowest level"""
        (dir_name1, dir_path1, dir_name2, dir_path2) =\
            self.make_two_test_directories(FOUR, ONE)
        doc1 = MerkleDoc.create_from_file_system(dir_path1)
        tree1 = doc1.tree
        # XXX This succeeds BUT pylint doesn't get this right: it sees
        # doc1.tree as a function
        self.assertTrue(isinstance(tree1, MerkleTree))

        # pylint: disable=no-member
        self.assertEqual(dir_name1, tree1.name)
        self.assertTrue(doc1.bound)
        self.assertEqual(("tmp/%s" % dir_name1), dir_path1)
        # pylint: disable=no-member
        nodes1 = tree1.nodes
        self.assertTrue(nodes1 is not None)
        self.assertEqual(ONE, len(nodes1))
        self.verify_tree_sha256(tree1, dir_path1)

        doc2 = MerkleDoc.create_from_file_system(dir_path2)
        tree2 = doc2.tree
        # pylint: disable=no-member
        self.assertEqual(dir_name2, tree2.name)
        self.assertTrue(doc2.bound)
        self.assertEqual(("tmp/%s" % dir_name2), dir_path2)
        # pylint: disable=no-member
        nodes2 = tree2.nodes
        self.assertTrue(nodes2 is not None)
        self.assertEqual(ONE, len(nodes2))
        self.verify_tree_sha256(tree2, dir_path2)

        self.assertTrue(doc1.equal(doc1))
        self.assertFalse(doc1.equal(doc2))

        doc1_str = doc1.to_string()
        doc1_rebuilt = MerkleDoc.create_from_serialization(doc1_str)
#       # DEBUG
#       print "needle doc:\n" + doc1Str
#       print "rebuilt needle doc:\n" + doc1Rebuilt.toString()
#       # END
        self.assertTrue(doc1.equal(doc1_rebuilt))       # FOO

# 2016-11-21: These FRAGMENTS are unused ----------------------------

#   def do_test_for_expected_exclusions(self, ex_re):
#       """ Verify that exclusion regexes work for these examples. """
#       self.assertTrue(ex_re.search('.'))
#       self.assertTrue(ex_re.search('..'))
#       self.assertTrue(ex_re.search('.merkle'))
#       self.assertTrue(ex_re.search('.svn'))
#       self.assertTrue(ex_re.search('.foo.swp'))          # vi backup file
#       self.assertTrue(ex_re.search('junkEverywhere'))    # begins with 'junk'

#   def do_test_for_expected_matches(self, match_re, names):
#       """ Verify the match regex works for the names listed. """
#       for name in names:
#           self.assertTrue(match_re.search(name))

#   def do_test_for_expected_match_failures(self, match_re, names):
#       """ Verify match regexes FAIL for the names listed. """
#       for name in names:
#           match_ = match_re.search(name)
#           if match_:
#               print("WE HAVE A MATCH ON '%s'" % name)
#           self.assertIsNone( where )


if __name__ == '__main__':
    unittest.main()
