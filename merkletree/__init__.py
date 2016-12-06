# merkletree/__init__.py

import binascii
import hashlib
import os
import re
import sys
from stat import S_ISDIR

from xlattice import (SHA1_BIN_LEN, SHA2_BIN_LEN, SHA3_BIN_LEN,
                      SHA1_BIN_NONE, SHA2_BIN_NONE, SHA3_BIN_NONE,
                      SHA1_HEX_NONE, SHA2_HEX_NONE, SHA3_HEX_NONE,
                      QQQ, check_using_sha, util)
from xlattice.crypto import SP   # for getSpaces()
from xlattice.u import file_sha1bin, file_sha2bin, file_sha3bin

if sys.version_info < (3, 6):
    import sha3     # monkey-patches hashlib

__all__ = ['__version__', '__version_date__',
           # classes
           'MerkleDoc', 'MerkleLeaf', 'MerkleTree', 'MerkleParseError', ]

__version__ = '5.2.3'
__version_date__ = '2016-12-06'

# -------------------------------------------------------------------


class MerkleParseError(RuntimeError):
    pass


class MerkleNode(object):

    #__slots__ = [ A PERFORMANCE ENHANCER ]

    def __init__(self, name, is_leaf=False, using_sha=QQQ.USING_SHA2):
        check_using_sha(using_sha)
        self._bin_hash = None
        if name is None:
            raise RuntimeError("MerkleNode: null MerkleNode name")
        self._name = name.strip()
        if len(self._name) == 0:
            raise RuntimeError("MerkleNode: null or empty name")

        self._is_leaf = is_leaf
        self._using_sha = using_sha

    @property
    def hex_hash(self):
        if self._bin_hash is None:
            if self._using_sha == QQQ.USING_SHA1:
                return SHA1_HEX_NONE
            elif self._using_sha == QQQ.USING_SHA2:
                return SHA2_HEX_NONE
            elif self._using_sha == QQQ.USING_SHA3:
                return SHA3_HEX_NONE
        else:
            return str(binascii.b2a_hex(self._bin_hash), 'ascii')

    @hex_hash.setter
    def hex_hash(self, value):
        if self._bin_hash:
            raise RuntimeError('attempt to set non-null hash')
        self._bin_hash = bytes(binascii.a2b_hex(value))

#   def bind(self):             pass

    @property
    def bin_hash(self):
        return self._bin_hash

    @bin_hash.setter
    def bin_hash(self, value):
        if self._bin_hash:
            raise RuntimeError('attempt to set non-null hash')
        self._bin_hash = value

#   def bound(self):
#       raise RuntimeError('not implemented')

    def __eq__(self, other):
        raise RuntimeError('subclass must implement')

    # XXX CONSIDER THIS DEPRECATED
    def equal(self, other):
        return self.__eq__(other)
    # END DEPRECATED

    @property
    def is_leaf(self):
        return self._is_leaf

    @property
    def name(self):
        return self._name

#   def path(self):
#       raise RuntimeError('not implemented')

    def __str__(self):
        raise RuntimeError('subclass must implement')

    def using_sha(self):
        return self._using_sha

# -------------------------------------------------------------------


class MerkleDoc(MerkleNode):
    """
    The path to a tree, and the SHA hash of the path and the treehash.
    """

    __slots__ = ['_bound', '_ex_re', '_match_re', '_path',
                 '_tree', '_using_sha', ]

    # notice the terminating forward slash and lack of newlines or CR-LF
    # THIS PATTERN WON"T CATCH SOME ERRORS; eg it permits '///' in paths
    FIRST_LINE_RE_1 = re.compile(r'^([0-9a-f]{40}) ([a-z0-9_\-\./!:]+/)$',
                                 re.IGNORECASE)
    FIRST_LINE_RE_2 = re.compile(r'^([0-9a-f]{64}) ([a-z0-9_\-\./!:]+/)$',
                                 re.IGNORECASE)

    # XXX MUST ADD matchRE and exRE and test on their values at this level
    def __init__(self, path, using_sha=QQQ.USING_SHA2, binding=False,
                 tree=None,
                 ex_re=None,    # exclusions, which are Regular Expressions
                 match_re=None):   # matches, also Regular Expressions

        check_using_sha(using_sha)
        if path is None:
            raise RuntimeError("null MerkleDoc path")
        if tree:
            if not isinstance(tree, MerkleTree):
                raise RuntimeError('tree is not a MerkleTree')
            self._name = name = tree.name
        elif not binding:
            raise RuntimeError('null MerkleTree and not binding')
        else:
            raise RuntimeError("MerkleDoc binding not yet implemented")
        super().__init__(name, is_leaf=False, using_sha=using_sha)

        path = path.strip()
        if len(path) == 0:
            raise RuntimeError("empty path")
        if not path.endswith('/'):
            path += '/'
        self._path = path
        self._tree = tree
        if tree:
            # DEBUG
            #print("MerkleDoc.__init__: usingSHA = %s" % str(usingSHA))
            # END
            # pylint:disable=redefined-variable-type
            if using_sha == QQQ.USING_SHA1:
                sha = hashlib.sha1()
            elif using_sha == QQQ.USING_SHA2:
                sha = hashlib.sha256()
            elif using_sha == QQQ.USING_SHA3:
                # pylint: disable=no-member
                sha = hashlib.sha3_256()
            sha.update(bytes(tree.bin_hash))
            sha.update(path.encode('utf-8'))
            self._bin_hash = bytes(sha.digest())      # a binary value

        self._ex_re = ex_re
        self._match_re = match_re

        if binding:
            path_to_dir = os.path.join(path, tree.name)
            if not os.path.exists(path_to_dir):
                raise RuntimeError('no directory found at ' + path_to_dir)
            else:
                # XXX STUB: BIND THE TREE
                self._bound = True

    def __eq__(self, other):
        """ignore boundedness"""
        return isinstance(other, MerkleDoc)      and \
            self._path == other.path         and \
            self._bin_hash == other.bin_hash and \
            self._tree == other.tree

    # XXX DEPRECATED
    def equal(self, other):
        return self.__eq__(other)

    @property
    def path(self):
        """should return doc's path"""
        return self._path

    @path.setter
    def path(self, value):
        # XXX CHECK value
        self._path = value

    @property
    def tree(self):
        return self._tree

    @tree.setter
    def tree(self, value):
        # XXX CHECKS
        self._tree = value

    @property
    def bound(self):
        return self._bound

    @bound.setter
    def bound(self, value):
        # XXX validate
        self._bound = value

    @property
    def using_sha(self):
        return self._using_sha

    # QUASI-CONSTRUCTORS ############################################
    @staticmethod
    def create_from_file_system(path_to_dir, using_sha=QQQ.USING_SHA2,
                                exclusions=None, matches=None):
        """
        Create a MerkleDoc based on the information in the directory
        at pathToDir.  The name of the directory will be the last component
        of pathToDir.  Return the MerkleTree.
        """
        check_using_sha(using_sha)
        if not path_to_dir:
            raise RuntimeError("cannot create a MerkleTree, no path set")
        if not os.path.exists(path_to_dir):
            raise RuntimeError(
                "MerkleTree: directory '%s' does not exist" % path_to_dir)
        path, _, _ = path_to_dir.rpartition('/')
        if path == '':
            raise RuntimeError("cannot parse inclusive path " + path_to_dir)
        path += '/'
        ex_re = None
        if exclusions:
            ex_re = util.make_ex_re(exclusions)
        match_re = None
        if matches:
            match_re = util.make_match_re(matches)
        tree = MerkleTree.create_from_file_system(path_to_dir, using_sha,
                                                  ex_re, match_re)
        # creates the hash
        doc = MerkleDoc(path, using_sha, False, tree, ex_re, match_re)
        doc.bound = True
        return doc

    @staticmethod
    def create_from_serialization(string, using_sha=QQQ.USING_SHA2):
        check_using_sha(using_sha)
        if string is None:
            raise RuntimeError("MerkleDoc.createFromSerialization: no input")
        s_array = string.split('\n')                # note CR-LF
        return MerkleDoc.create_from_string_array(s_array, using_sha)

    @staticmethod
    def create_from_string_array(string, using_sha=QQQ.USING_SHA2):
        """
        The string array is expected to follow conventional indentation
        rules, with zero indentation on the first line and some number
        of leading spaces on all successive lines.
        """
        check_using_sha(using_sha)
        if string is None:
            raise RuntimeError('null argument')
        # XXX check TYPE - must be array of strings
        if len(string) == 0:
            raise RuntimeError("empty string array")

        (doc_hash, doc_path) =\
            MerkleDoc.parse_first_line(string[0].rstrip())
        len_hash = len(doc_hash)
        if len_hash == SHA1_BIN_LEN:
            if using_sha != QQQ.USING_SHA1:
                raise RuntimeError("hash length %d inconsistent with %s" % (
                    len_hash, using_sha))
        elif len_hash != SHA2_BIN_LEN:
            raise RuntimeError("hash length %d inconsistent with %s" % (
                len_hash, using_sha))

        # DEBUG
        # print("MerkleDoc.createFromStringArray:")
        #print("    docHash = %s" % str(binascii.b2a_hex(docHash),'ascii'))
        #print("    docPath = %s" % docPath)
        #print("    usingSHA=%s" % str(usingSHA))
        # END

        tree = MerkleTree.create_from_string_array(string[1:], using_sha)

        # def __init__ (self, path, binding = False, tree = None,
        #    exRE    = None,    # exclusions, which are Regular Expressions
        #    matchRE = None):   # matches, also Regular Expressions
        doc = MerkleDoc(doc_path, using_sha=using_sha, tree=tree)
        return doc

    # CLASS METHODS #################################################
    @classmethod
    def first_line_re_1(cls):
        """
        Returns a reference to the regexp for SHA1 first lines.  A
        match finds (indent, treeHash, dirName), where indent is an
        integer, the treeHash is a hex string, and dirName may have a
        terminating slash.
        """
        return MerkleDoc.FIRST_LINE_RE_1

    @classmethod
    def first_line_re_2(cls):
        """
        Returns a reference to the regexp for SHA256 first lines.  A
        match finds (indent, treeHash, dirName), where indent is an
        integer, the treeHash is a hex string, and dirName may have a
        terminating slash.
        """
        return MerkleDoc.FIRST_LINE_RE_2

    @staticmethod
    def parse_first_line(line):
        """ returns binary docHash and string docPath"""
        line = line.rstrip()
        match_ = MerkleDoc.FIRST_LINE_RE_1.match(line)
        if match_ is None:
            match_ = MerkleDoc.FIRST_LINE_RE_2.match(line)
        if match_ is None:
            raise RuntimeError(
                "MerkleDoc first line <%s> does not match expected pattern" % line)
        doc_hash = bytes(binascii.a2b_hex(match_.group(1)))
        doc_path = match_.group(2)          # includes terminating slash
        return (doc_hash, doc_path)

    @staticmethod
    def make_ex_re(exclusions):
        """
        #############################################################
        THIS FUNCTION IS OBSOLETE AND SHOULD BE REPLACED WHEREVER USED
        WITH xlattice.util::makeExRE(), WHICH USES GLOBS.  This
        function uses regular expressions instead of globs.
        #############################################################

        Compile a regular expression which ORs exclusion patterns.
        """
        if exclusions is None:
            exclusions = []
        exclusions.append(r'^\.$')
        exclusions.append(r'^\.\.$')
        exclusions.append(r'^\.merkle$')
        exclusions.append(r'^\.svn$')            # subversion control data
        # some might disagree with these:
        exclusions.append(r'^junk')
        exclusions.append(r'^\..*\.swp$')        # vi editor files
        ex_pat = '|'.join(exclusions)
        return re.compile(ex_pat)

    @staticmethod
    def make_match_re(match_list):
        """
        #############################################################
        THIS FUNCTION IS OBSOLETE AND SHOULD BE REPLACED WHEREVER USED
        WITH xlattice.util::makeMatchRE(), WHICH USES GLOBS.  This
        function uses regular expressions instead of globs.
        #############################################################

        Compile a regular expression which ORs match patterns.
        """
        if match_list and len(match_list) > 0:
            match_pat = '|'.join(match_list)
            return re.compile(match_pat)
        else:
            return None

    # SERIALIZATION #################################################
    def __str__(self):
        return self.to_string()

    # XXX indent is not used
    def to_string(self, indent=0):
        return ''.join([
            "%s %s\n" % (self.hex_hash, self.path),
            self._tree.to_string(indent)
        ])

# -------------------------------------------------------------------


class MerkleLeaf(MerkleNode):

    __slots__ = ['_name', '_using_sha', ]

    def __init__(self, name, using_sha=QQQ.USING_SHA1, hash_=None):
        super().__init__(name, is_leaf=True, using_sha=using_sha)

        # JUNK
        if name is None:
            raise RuntimeError("MerkleLeaf: null MerkleLeaf name")
        self._name = name.strip()
        if len(self._name) == 0:
            raise RuntimeError("MerkleLeaf: null or empty name")
        # END JUNK

        # XXX VERIFY HASH IS WELL-FORMED
        if hash_:
            self._bin_hash = hash_
        else:
            self._bin_hash = None

    # IMPLEMENTATIONS OF ABSTRACT METHODS ###########################

    def __eq__(self, other):
        return isinstance(other, MerkleLeaf)     and \
            self._name == other.name         and \
            self._bin_hash == other.bin_hash

    # XXX DEPRECATED
    def equal(self, other):
        return self.__eq__(other)
    # END DEPRECATED

    def __str__(self):
        return self.to_string(0)        # that is, no indent

    # OTHER METHODS AND PROPERTIES ##################################

    @staticmethod
    def create_from_file_system(path_to_file, name, using_sha=QQQ.USING_SHA2):
        """
        Returns a MerkleLeaf.  The name is part of pathToFile, but is
        passed to simplify the code.
        """
        def reportIOError(exc):
            # path = os.path.join(path_to_file, name)
            print("error reading file %s: %s" % (
                path_to_file, exc), file=sys.stderr)

        if not os.path.exists(path_to_file):
            print(("INTERNAL ERROR: file does not exist: " + path_to_file))
        # XXX we convert from binary to hex and then right back to binary !!
        if using_sha == QQQ.USING_SHA1:
            try:
                hash_ = file_sha1bin(path_to_file)
            except OSError as exc:
                reportIOError(exc)
                hash_ = SHA1_BIN_NONE
        elif using_sha == QQQ.USING_SHA2:
            try:
                hash_ = file_sha2bin(path_to_file)
            except OSError as exc:
                reportIOError(exc)
                hash_ = SHA2_BIN_NONE
        elif using_sha == QQQ.USING_SHA3:
            try:
                hash_ = file_sha3bin(path_to_file)
            except OSError as exc:
                reportIOError(exc)
                hash_ = SHA3_BIN_NONE
        return MerkleLeaf(name, using_sha, hash_)

    def to_string(self, indent=0):
        if self._bin_hash is None:
            if self._using_sha == QQQ.USING_SHA1:
                hash_ = SHA1_HEX_NONE
            elif self._using_sha == QQQ.USING_SHA2:
                hash_ = SHA2_HEX_NONE
            elif self._using_sha == QQQ.USING_SHA3:
                hash_ = SHA3_HEX_NONE
        else:
            hash_ = self.hex_hash
        string = "%s%s %s\n" % (SP.get_spaces(indent), hash_, self.name)
        return string

    # THIS GETS REPLACED BY NLHTree XXX

    # PAIRLIST FUNCTIONS ############################################
    # def toPair(leaf):
    #     """
    #     Given a MerkleLeaf, return its name and binary hash as a pair
    #     """
    #     # DEBUG
    #     print("MerkleLeaf.toPair: %s %s" % (leaf.name, leaf.binHash))
    #     # END
    #     return (leaf.name, leaf.binHash)

    # @staticmethod
    # def createFromPair(p):
    #     """
    #     Given p, a name/hash pair, return a MerkleLeaf.
    #     """
    #     name = p[0];    hash = p[1]
    #     if len(hash) == SHA1_BIN_LEN:
    #         usingSHA = True
    #     elif len(hash) == SHA2_BIN_LEN:
    #         usingSHA = False
    #     else:
    #         raise RuntimeError('invalid SHA hash len')
    #     return MerkleLeaf(name, hash, usingSHA)

# -------------------------------------------------------------------


class MerkleTree(MerkleNode):

    __slots__ = ['_bound', '_name', '_ex_re', '_bin_hash', '_match_re',
                 '_nodes', '_using_sha', ]

    # notice the terminating forward slash and lack of newlines or CR-LF
    FIRST_LINE_RE_1 = re.compile(r'^( *)([0-9a-f]{40}) ([a-z0-9_\-\.:]+/)$',
                                 re.IGNORECASE)
    OTHER_LINE_RE_1 = re.compile(r'^([ XYZ]*)([0-9a-f]{40}) ([a-z0-9_\$\+\-\.:~]+/?)$',
                                 re.IGNORECASE)
    FIRST_LINE_RE_2 = re.compile(r'^( *)([0-9a-f]{64}) ([a-z0-9_\-\.:]+/)$',
                                 re.IGNORECASE)
    OTHER_LINE_RE_2 = re.compile(r'^([ XYZ]*)([0-9a-f]{64}) ([a-z0-9_\$\+\-\.:_]+/?)$',
                                 re.IGNORECASE)

    #################################################################
    # exRE and matchRE must have been validated by the calling code
    #################################################################
    def __init__(self, name, using_sha=False,
                 ex_re=None,     # exclusions Regular Expression
                 match_re=None):    # matches Regular Expression

        super().__init__(name, is_leaf=False, using_sha=using_sha)

        self._ex_re = ex_re
        self._match_re = match_re
        self._nodes = []

    # IMPLEMENTATIONS OF ABSTRACT METHODS ###########################

    def __eq__(self, other):
        """
        This is quite wasteful.  Given the nature of the merkletree,
        it should only be necessary to compare top-level hashes.
        """
        if other is None:
            return False

        if (not isinstance(other, MerkleTree)) or (self._name != other.name):
            return False
        if self.hex_hash != other.hex_hash:
            return False
        if self.using_sha != other.using_sha:
            return False

        my_nodes = self.nodes
        other_nodes = other.nodes
        if len(my_nodes) != len(other_nodes):
            return False
        for ndx, my_node in enumerate(my_nodes):
            other_node = other_nodes[ndx]
            if not my_node.__eq__(other_node):    # RECURSES
                return False
        return True

    # DEPRECATED
    def equal(self, other):
        return self.__eq__(other)
    # END DEPRECATED

    def __str__(self):
        return self.to_string(0)

    @property
    def using_sha(self):
        return self._using_sha

    #################################################################
    # METHODS LIFTED FROM bindmgr/bindlib/MerkleTree.py
    #################################################################
    @staticmethod
    def parse_first_line(line):
        """ returns indent, binary treeHash, and str dirName """
        line = line.rstrip()
        match_ = MerkleTree.FIRST_LINE_RE_1.match(line)
        if match_ is None:
            match_ = MerkleTree.FIRST_LINE_RE_2.match(line)
        if match_ is None:
            raise RuntimeError(
                "MerkleTree first line \"%s\" does not match expected pattern" % line)
        indent = len(match_.group(1))         # count of leading spaces
        tree_hash = bytes(binascii.a2b_hex(match_.group(2)))
        dir_name = match_.group(3)          # includes terminating slash
        dir_name = dir_name[0:len(dir_name) - 1]
        return (indent, tree_hash, dir_name)

    @staticmethod
    def parse_other_line(line):
        match_ = re.match(MerkleTree.OTHER_LINE_RE_1, line)
        if match_ is None:
            match_ = re.match(MerkleTree.OTHER_LINE_RE_2, line)
        if match_ is None:
            raise RuntimeError(
                "MerkleTree other line <%s> does not match expected pattern" % line)
        node_depth = len(match_.group(1))
        node_hash = bytes(binascii.a2b_hex(match_.group(2)))
        node_name = match_.group(3)
        if node_name.endswith('/'):
            node_name = node_name[0:len(node_name) - 1]
            is_dir = True
        else:
            is_dir = False
        return (node_depth, node_hash, node_name, is_dir)

    @staticmethod
    def create_from_string_array(string, using_sha=QQQ.USING_SHA2):
        """
        The string array is expected to follow conventional indentation
        rules, with zero indentation on the first line and some number
        of leading spaces on all successive lines.
        """
        if string is None:
            raise RuntimeError('null argument')

        # XXX should check TYPE - must be array of strings

        if len(string) == 0:
            raise RuntimeError("empty string array")
        (indent, tree_hash, dir_name) =\
            MerkleTree.parse_first_line(string[0].rstrip())
        len_hash = len(tree_hash)
        if len_hash == SHA1_BIN_LEN:
            if using_sha != QQQ.USING_SHA1:
                raise RuntimeError("hash length %d inconsistent with %s" % (
                    len_hash, using_sha))
        elif len_hash != SHA2_BIN_LEN:
            raise RuntimeError("hash length %d inconsistent with %s" % (
                len_hash, using_sha))

        root_tree = MerkleTree(dir_name, using_sha)    # an empty tree
        root_tree.bin_hash = tree_hash

        if indent != 0:
            print(("INTERNAL ERROR: initial line indent %d" % indent))

        stack = []
        stk_depth = 0
        cur_tree = root_tree
        stack.append(cur_tree)           # rootTree
        stk_depth += 1                  # always step after pushing tree
        last_was_dir = False

        for nnn in range(1, len(string)):
            line = string[nnn].rstrip()
            if len(line) == 0:
                nnn += 1
                continue
            # XXX SHOULD/COULD CHECK THAT HASHES ARE OF THE RIGHT TYPE
            line_indent, hash_, name, is_dir = MerkleTree.parse_other_line(
                line)
            if line_indent < stk_depth:
                while line_indent < stk_depth:
                    stk_depth -= 1
                    stack.pop()
                cur_tree = stack[-1]
                if not stk_depth == line_indent:
                    print("ERROR: stkDepth != lineIndent")

            if is_dir:
                # create and set attributes of new node
                new_tree = MerkleTree(name, using_sha)  # , curTree)
                new_tree.bin_hash = hash_
                # add the new node into the existing tree
                cur_tree.add_node(new_tree)
                stack.append(new_tree)
                stk_depth += 1
                cur_tree = new_tree
            else:
                # create and set attributes of new node
                new_node = MerkleLeaf(name, using_sha, hash_)
                # add the new node into the existing tree
                cur_tree.add_node(new_node)
            nnn += 1
        return root_tree

    @staticmethod
    def create_from_serialization(string, using_sha=QQQ.USING_SHA2):
        """
        Create a MerkleTree by parsing its serialization (a single string),
        given the SHA hash type used to create the MerkleTree.
        """
        if string is None:
            raise RuntimeError("MerkleTree.createFromSerialization: no input")
        if not isinstance(string, str):
            string = str(string, 'utf-8')
        s_array = string.split('\n')                # note CR-LF
        return MerkleTree.create_from_string_array(s_array, using_sha)

    @staticmethod
    def create_from_file(path_to_file, using_sha=QQQ.USING_SHA2):
        """
        Create a MerkleTree by parsing its on-disk serialization,
        given the SHA hash type used to create the MerkleTree.
        """
        if not os.path.exists(path_to_file):
            raise RuntimeError(
                "MerkleTree.createFromFile: file '%s' does not exist" % path_to_file)
        with open(path_to_file, 'r') as file:
            text = file.read()
        return MerkleTree.create_from_serialization(text, using_sha)

    @staticmethod
    def create_from_file_system(path_to_dir, using_sha=QQQ.USING_SHA2,
                                ex_re=None, match_re=None):
        """
        Create a MerkleTree based on the information in the directory
        at pathToDir.  The name of the directory will be the last component
        of pathToDir.  Return the MerkleTree.
        """
        check_using_sha(using_sha)
        if not path_to_dir:
            raise RuntimeError("cannot create a MerkleTree, no path set")
        if not os.path.exists(path_to_dir):
            raise RuntimeError(
                "MerkleTree: directory '%s' does not exist" % path_to_dir)
        (path, _, name) = path_to_dir.rpartition('/')
        if path == '':
            raise RuntimeError("cannot parse inclusive path " + path_to_dir)

        tree = MerkleTree(name, using_sha, ex_re, match_re)
        tree.bin_hash = None
        # pylint: disable=redefined-variable-type
        if using_sha == QQQ.USING_SHA1:
            sha = hashlib.sha1()
        elif using_sha == QQQ.USING_SHA2:
            sha = hashlib.sha256()
        elif using_sha == QQQ.USING_SHA3:
            # pylint: disable=no-member
            sha = hashlib.sha3_256()

        # Create data structures for constituent files and subdirectories
        # These MUST BE SORTED by the bare name to meet specs.
        files = sorted(os.listdir(path_to_dir))
        if files:
            sha_count = 0
            for file in files:
                # exclusions take priority over matches
                if ex_re and ex_re.search(file):
                    continue
                if match_re and not match_re.search(file):
                    continue
                node = None
                path_to_file = os.path.join(path_to_dir, file)
                string = os.lstat(path_to_file)        # ignores symlinks
                mode = string.st_mode
                # os.path.isdir(path) follows symbolic links
                if S_ISDIR(mode):
                    node = MerkleTree.create_from_file_system(
                        path_to_file, using_sha, ex_re, match_re)
                # S_ISLNK(mode) is true if symbolic link
                # isfile(path) follows symbolic links
                elif os.path.isfile(path_to_file):        # S_ISREG(mode):
                    # pylint: disable=redefined-variable-type
                    node = MerkleLeaf.create_from_file_system(
                        path_to_file, file, using_sha)
                # otherwise, just ignore it ;-)

                if node:
                    # update tree-level hash
                    if node.bin_hash is not None:
                        # note empty file has null hash  XXX NOT TRUE
                        sha_count += 1
                        sha.update(node.bin_hash)
                    # SKIP NEXT TO EASE GARBAGE COLLECTION ??? XXX
                    # but that won't be a good idea if we are
                    # invoking toString()
                    tree.nodes.append(node)
            if sha_count:
                tree.bin_hash = bytes(sha.digest())

        return tree

    # OTHER METHODS AND PROPERTIES ##################################
    @classmethod
    def first_line_re_1(cls):
        """
        Returns a reference to the regexp for SHA1 first lines.  A
        match finds (indent, treeHash, dirName), where indent is an
        integer, the treeHash is a hex string, and dirName may have a
        terminating slash.
        """
        return MerkleTree.FIRST_LINE_RE_1

    @classmethod
    def first_line_re_2(cls):
        """
        Returns a reference to the regexp for SHA3 first lines.  A
        match finds (indent, treeHash, dirName), where indent is an
        integer, the treeHash is a hex string, and dirName may have a
        terminating slash.
        """
        return MerkleTree.FIRST_LINE_RE_2

    @property
    def nodes(self):
        """
        DANGEROUS: returns a reference to the MerkleTree's node list.
        """
        return self._nodes

    def add_node(self, node):
        """ Add a MerkleNode to a MerkleTree. """
        if node is None:
            raise RuntimeError("attempt to add null node")
        if not isinstance(node, MerkleTree)\
                and not isinstance(node, MerkleLeaf):
            raise RuntimeError("node being added not MerkleTree or MerkleLeaf")
        self._nodes.append(node)

    # SERIALIZATION #################################################
    def to_string_not_top(self, indent=0):
        """ indent is the indentation to be used for the top node"""
        string = []                             # a list of strings
        spaces = SP.get_spaces(indent)
        if self._bin_hash is None:
            if self._using_sha == QQQ.USING_SHA1:
                top = "%s%s %s/\n" % (spaces, SHA1_HEX_NONE, self.name)
            elif self._using_sha == QQQ.USING_SHA2:
                top = "%s%s %s/\n" % (spaces, SHA2_HEX_NONE, self.name)
            elif self._using_sha == QQQ.USING_SHA3:
                top = "%s%s %s/\n" % (spaces, SHA3_HEX_NONE, self.name)
        else:
            top = "%s%s %s/\n" % (spaces, self.hex_hash, self.name)
        string.append(top)
        indent += 1              # <--- LEVEL 2+ NODE
        for node in self.nodes:
            if isinstance(node, MerkleLeaf):
                string.append(node.to_string(indent))
            else:
                # recurse
                string.append(node.to_string_not_top(indent))

        return ''.join(string)

    def to_string(self, indent=0):
        """
        indent is the initial indentation of the serialized list, NOT the
        extra indentation added at each recursion.
        Using code should take into account that the last line is CR-LF
        terminated, and so a split on CRLF will generate an extra blank line
        """
        string = []                             # a list of strings
        spaces = SP.get_spaces(indent)
        if self._bin_hash is None:
            if self._using_sha == QQQ.USING_SHA1:
                top = "%s%s %s/\n" % (spaces, SHA1_HEX_NONE, self.name)
            elif self._using_sha == QQQ.USING_SHA2:
                top = "%s%s %s/\n" % (spaces, SHA2_HEX_NONE, self.name)
            elif self._using_sha == QQQ.USING_SHA3:
                top = "%s%s %s/\n" % (spaces, SHA3_HEX_NONE, self.name)
        else:
            top = "%s%s %s/\n" % (spaces, self.hex_hash, self.name)
        string.append(top)                       # <--- LEVEL 0 NODE
        my_indent = indent + 1               # <--- LEVEL 1 NODE
        for node in self.nodes:
            if isinstance(node, MerkleLeaf):
                string.append(node.to_string(my_indent))
            else:
                # recurse
                string.append(node.to_string_not_top(my_indent))

        return ''.join(string)
