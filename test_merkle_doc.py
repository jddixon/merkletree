#!/usr/bin/env python3

# testMerkleDoc.py

import hashlib
import os
import shutil
import time
import unittest

from rnglib import SimpleRNG
from merkletree import MerkleDoc, MerkleTree, MerkleLeaf
from xlattice import QQQ, check_using_sha, util

ONE = 1
FOUR = 4
MAX_NAME_LEN = 8


class TestMerkleDoc(unittest.TestCase):

    def setUp(self):
        self.rng = SimpleRNG(time.time())

    def tearDown(self):
        pass

    # utility functions #############################################
    def get_two_unique_directory_names(self):
        dir_name1 = self.rng.nextFileName(MAX_NAME_LEN)
        dir_name2 = dir_name1
        while dir_name2 == dir_name1:
            dir_name2 = self.rng.nextFileName(MAX_NAME_LEN)
        self.assertTrue(len(dir_name1) > 0)
        self.assertTrue(len(dir_name2) > 0)
        self.assertTrue(dir_name1 != dir_name2)
        return (dir_name1, dir_name2)

    def make_one_named_test_directory(self, name, depth, width):
        dir_path = "tmp/%s" % name
        if os.path.exists(dir_path):
            shutil.rmtree(dir_path)
        self.rng.nextDataDir(dir_path, depth, width, 32)
        return dir_path

    def make_two_test_directories(self, depth, width):
        dir_name1 = self.rng.nextFileName(MAX_NAME_LEN)
        dir_path1 = self.make_one_named_test_directory(dir_name1, depth, width)

        dir_name2 = dir_name1
        while dir_name2 == dir_name1:
            dir_name2 = self.rng.nextFileName(MAX_NAME_LEN)
        dir_path2 = self.make_one_named_test_directory(dir_name2, depth, width)

        return (dir_name1, dir_path1, dir_name2, dir_path2)

    def verify_leaf_sha(self, node, path_to_file, using_sha):
        check_using_sha(using_sha)
        self.assertTrue(os.path.exists(path_to_file))
        with open(path_to_file, "rb") as file:
            data = file.read()
        self.assertFalse(data is None)
        # pylint: disable=redefined-variable-type
        if using_sha == QQQ.USING_SHA1:
            sha = hashlib.sha1()
        elif using_sha == QQQ.USING_SHA2:
            sha = hashlib.sha256()
        elif using_sha == QQQ.USING_SHA3:
            sha = hashlib.sha3_256()
        sha.update(data)
        hash_ = sha.digest()
        self.assertEqual(hash_, node.bin_hash)

    def verify_tree_sha(self, node, path_to_tree, using_sha):
        # we assume that the node is a MerkleTree
        check_using_sha(using_sha)
        if node.nodes is None:
            self.assertEqual(None, node.bin_hash)
        else:
            hash_count = 0
            # pylint: disable=redefined-variable-type
            if using_sha == QQQ.USING_SHA1:
                sha = hashlib.sha1()
            elif using_sha == QQQ.USING_SHA2:
                sha = hashlib.sha256()
            elif using_sha == QQQ.USING_SHA3:
                # pylint: disable=no-member
                sha = hashlib.sha3_256()
            for node_ in node.nodes:
                path_to_node = os.path.join(path_to_tree, node_.name)
                if isinstance(node_, MerkleLeaf):
                    self.verify_leaf_sha(node_, path_to_node, using_sha)
                elif isinstance(node_, MerkleTree):
                    self.verify_tree_sha(node_, path_to_node, using_sha)
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
        for using in [QQQ.USING_SHA1, QQQ.USING_SHA2, QQQ.USING_SHA3, ]:
            self.do_test_bound_flat_dirs(using)

    def do_test_bound_flat_dirs(self, using_sha):

        (dir_name1, dir_path1, dir_name2, dir_path2) =\
            self.make_two_test_directories(ONE, FOUR)

        doc1 = MerkleDoc.create_from_file_system(dir_path1, using_sha)
        tree1 = doc1.tree
        self.assertTrue(isinstance(tree1, MerkleTree))
        self.assertEqual(dir_name1, tree1.name)
        self.assertTrue(doc1.bound)
        self.assertEqual(("tmp/%s" % dir_name1), dir_path1)
        nodes1 = tree1.nodes
        self.assertTrue(nodes1 is not None)
        self.assertEqual(FOUR, len(nodes1))
        self.verify_tree_sha(tree1, dir_path1, using_sha)

        doc2 = MerkleDoc.create_from_file_system(dir_path2, using_sha)
        tree2 = doc2.tree
        self.assertEqual(dir_name2, tree2.name)
        self.assertTrue(doc2.bound)
        self.assertEqual(("tmp/%s" % dir_name2), dir_path2)
        nodes2 = tree2.nodes
        self.assertTrue(nodes2 is not None)
        self.assertEqual(FOUR, len(nodes2))
        self.verify_tree_sha(tree2, dir_path2, using_sha)

        self.assertEqual(tree1, tree1)
        self.assertFalse(tree1 == tree2)
        self.assertFalse(tree1 is None)

        doc1_str = doc1.to_string()
        doc1_rebuilt = MerkleDoc.create_from_serialization(doc1_str, using_sha)
        # DEBUG
        #print("flat doc:\n" + doc1Str)
        #print("rebuilt flat doc:\n" + doc1Rebuilt.toString())
        # END
        self.assertTrue(doc1.equal(doc1_rebuilt))  # MANGO

    def test_bound_needle_dirs(self):
        """test directories four deep with one data file at the lowest level"""
        for using in [QQQ.USING_SHA1, QQQ.USING_SHA2, QQQ.USING_SHA3, ]:
            self.do_test_bound_needle_dirs(using)

    def do_test_bound_needle_dirs(self, using_sha):
        check_using_sha(using_sha)
        (dir_name1, dir_path1, dir_name2, dir_path2) =\
            self.make_two_test_directories(FOUR, ONE)
        doc1 = MerkleDoc.create_from_file_system(dir_path1, using_sha)
        tree1 = doc1.tree
        self.assertEqual(dir_name1, tree1.name)
        self.assertTrue(doc1.bound)
        self.assertEqual(("tmp/%s" % dir_name1), dir_path1)
        nodes1 = tree1.nodes
        self.assertTrue(nodes1 is not None)
        self.assertEqual(ONE, len(nodes1))
        self.verify_tree_sha(tree1, dir_path1, using_sha)

        doc2 = MerkleDoc.create_from_file_system(dir_path2, using_sha)
        tree2 = doc2.tree
        self.assertEqual(dir_name2, tree2.name)
        self.assertTrue(doc2.bound)
        self.assertEqual(("tmp/%s" % dir_name2), dir_path2)
        nodes2 = tree2.nodes
        self.assertTrue(nodes2 is not None)
        self.assertEqual(ONE, len(nodes2))
        self.verify_tree_sha(tree2, dir_path2, using_sha)

        self.assertTrue(doc1.equal(doc1))
        self.assertFalse(doc1.equal(doc2))

        doc1_str = doc1.to_string()
        doc1_rebuilt = MerkleDoc.create_from_serialization(doc1_str, using_sha)
#       # DEBUG
#       print "needle doc:\n" + doc1Str
#       print "rebuilt needle doc:\n" + doc1Rebuilt.toString()
#       # END
        self.assertTrue(doc1.equal(doc1_rebuilt))       # FOO

if __name__ == '__main__':
    unittest.main()
