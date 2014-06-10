# merkletree/__init__.py

from abc import ABCMeta, abstractmethod, abstractproperty
import binascii, hashlib, os, re, sys
if sys.version_info < (3,4):
    import sha3
from stat import *

__all__ = [ '__version__',  '__version_date__', 
            'SHA1_NONE',    'SHA3_NONE', 
            # classes
            'MerkleDoc', 'MerkleLeaf', 'MerkleNode',  'MerkleTree',
          ]

__version__      = '2.0.0'
__version_date__ = '2012-06-10'

#            ....x....1....x....2....x....3....x....4....x....5....x....6....
SHA1_NONE = '0000000000000000000000000000000000000000'
SHA3_NONE = '0000000000000000000000000000000000000000000000000000000000000000'

# -------------------------------------------------------------------
class MerkleNode():
    __metaclass__ = ABCMeta

    @abstractproperty
    def __str__(self):          pass

#   @abstractmethod
#   def bind(self):             pass

#   @abstractproperty
#   def bound(self):            pass

    @abstractmethod
    def equals(self, other):    pass

    @abstractproperty
    def hash(self):             pass

    @abstractproperty
    def isLeaf(self):           pass

    @abstractproperty
    def name(self):             pass

#   @abstractproperty
#   def path(self):             pass

    @abstractproperty
    def usingSHA1(self):        pass

# -------------------------------------------------------------------
class MerkleDoc():
    """
    The path to a tree, and the SHA hash of the path and the treehash.
    """

    __slots__ = ['_bound', '_exRE', '_hash', '_matchRE', '_path', '_tree', '_usingSHA1', ]

    # notice the terminating forward slash and lack of newlines or CR-LF
    # THIS PATTERN WON"T CATCH SOME ERRORS; eg it permits '///' in paths
    FIRST_LINE_PAT_1 = re.compile(r'^([0-9a-f]{40}) ([a-z0-9_\-\./]+/)$',
                                re.IGNORECASE)
    FIRST_LINE_PAT_3 = re.compile(r'^([0-9a-f]{64}) ([a-z0-9_\-\./]+/)$',
                                re.IGNORECASE)

    # XXX MUST ADD matchRE and exRE and test on their values at this level
    def __init__ (self, path, usingSHA1 = False, binding = False, 
                        tree = None,
            exRE    = None,    # exclusions, which are Regular Expressions
            matchRE = None):   # matches, also Regular Expressions
        if path == None:
            raise RunTimeError("null MerkleDoc path")
        path = path.strip()
        if len(path) == 0:
            raise RuntimeError("empty path")
        if not path.endswith('/'):
            path += '/'
        self._path      = path
        self._usingSHA1 = usingSHA1
        self._tree      = tree
        if tree:
            if not isinstance(tree, MerkleTree):
                raise RuntimeError('tree is not a MerkleTree')
            if usingSHA1:
                sha1 = hashlib.sha1()
                sha1.update(tree.hash)
                sha1.update(path)
                self._hash = sha1.digest()
            else:
                # sha3 = sha3.SHA3256()
                sha3 = hashlib.sha3_256()
                sha3.update(tree.hash)
                sha3.update(path)
                self._hash = sha3.digest()
        elif not binding:
            raise RuntimeError('null MerkleTree and not binding')

        self._exRE    = exRE
        self._matchRE = matchRE

        if (binding):
            pathToDir = os.path.join(path, tree.name)
            if not os.path.exists(pathToDir):
                raise RuntimeError('no directory found at ' + pathToDir)
            else:
                # XXX STUB: BIND THE TREE
                self._bound = True
                pass

    def equals(self, other):
        """ignore boundedness"""
        if isinstance(other, MerkleDoc)         and \
                self._path   == other._path     and \
                self._hash   == other._hash     and \
                self._tree.equals(other._tree)  :
            return True
        else:
            return False

    @property
    def hash(self):
        return binascii.b2a_hex(self._hash)

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

    @property
    def usingSHA1(self):
        return self._usingSHA1

    # QUASI-CONSTRUCTORS ############################################
    @staticmethod
    def createFromFileSystem(pathToDir, usingSHA1 = False,
                             exclusions = None, matches = None):
        """
        Create a MerkleDoc based on the information in the directory
        at pathToDir.  The name of the directory will be the last component
        of pathToDir.  Return the MerkleTree.
        """
        if not pathToDir:
            raise RuntimeError("cannot create a MerkleTree, no path set")
        if not os.path.exists(pathToDir):
            raise RuntimeError(
                "MerkleTree: directory '%s' does not exist" % self._path)
        (path, delim, name) = pathToDir.rpartition('/')
        if path == '':
            raise RuntimeError("cannot parse inclusive path " + pathToDir)
        path += '/'
        exRE = None
        if exclusions:
            exRE    = MerkleDoc.makeExRE(exclusions)
        matchRE = None
        if matches:
            matchRE = MerkleDoc.makeMatchRE(matches)
        tree = MerkleTree.createFromFileSystem(pathToDir, usingSHA1,
                                            exRE, matchRE)
        # creates the hash
        doc  = MerkleDoc(path, usingSHA1, False, tree, exRE, matchRE)  
        doc.bound = True
        return doc

    @staticmethod
    def createFromSerialization(s):
        if s == None:
            raise RuntimeError ("MerkleDoc.createFromSerialization: no input")
        sArray = s.split('\r\n')                # note CR-LF
        return MerkleDoc.createFromStringArray(sArray)

    @staticmethod
    def createFromStringArray(s):
        """
        The string array is expected to follow conventional indentation
        rules, with zero indentation on the first line and some multiple
        of two spaces on all successive lines.
        """
        if s == None:
            raise RuntimeError('null argument')
        # XXX check TYPE - must be array of strings
        if len(s) == 0:
            raise RuntimeError("empty string array")

        (docHash, docPath) = \
                            MerkleDoc.parseFirstLine(s[0].rstrip())
#       print "DEBUG: doc first line: hash = %s, path = %s" % (
#                               docHash, docPath)
        usingSHA1 = (40 == len(docHash))

        tree = MerkleTree.createFromStringArray( s[1:] )

        #def __init__ (self, path, binding = False, tree = None,
        #    exRE    = None,    # exclusions, which are Regular Expressions
        #    matchRE = None):   # matches, also Regular Expressions
        doc = MerkleDoc( docPath, usingSHA1, False, tree )
        doc.hash = docHash
        return doc

    # CLASS METHODS #################################################
    @staticmethod
    def parseFirstLine(line):
        line = line.rstrip()
        m = re.match(MerkleDoc.FIRST_LINE_PAT_1, line)
        if m == None:
            m = re.match(MerkleDoc.FIRST_LINE_PAT_3, line)
        if m == None:
            raise RuntimeError(
                    "MerkleDoc first line <%s> does not match expected pattern" %  line)
        docHash  = m.group(1)
        docPath  = m.group(2)          # includes terminating slash
        return (docHash, docPath)

    @staticmethod
    def makeExRE(exclusions):
        """compile a regular expression which ORs exclusion patterns"""
        if exclusions == None:
            exclusions = []
        exclusions.append('^\.$')
        exclusions.append('^\.\.$')
        exclusions.append('^\.merkle$')
        exclusions.append('^\.svn$')            # subversion control data
        # some might disagree with these:
        exclusions.append('^junk')
        exclusions.append('^\..*\.swp$')        # vi editor files
        exPat = '|'.join(exclusions)
        return re.compile(exPat)

    @staticmethod
    def makeMatchRE(matchList):
        """compile a regular expression which ORs match patterns"""
        if matchList and len(matchList) > 0:
            matchPat = '|'.join(matchList)
            return re.compile(matchPat)
        else:
            return None

    # SERIALIZATION #################################################
    def __str__(self):
        return self.toString()

    def toString(self):
        return ''.join([
            "%s %s\r\n" % ( self.hash, self.path),
            self._tree.toString('')
            ])

# -------------------------------------------------------------------
class MerkleLeaf(MerkleNode):

    __slots__ = ['_name', '_hash', '_usingSHA1', ]

    def __init__ (self, name, usingSHA1 = False, hash = None):
        if name == None:
            raise RunTimeError("MerkleLeaf: null MerkleLeaf name")
        self._name = name.strip()
        if len(self._name) == 0:
            raise RuntimeError("MerkleLeaf: null or empty name")
        self._usingSHA1 = usingSHA1

        # XXX VERIFY HASH IS WELL-FORMED
        if hash:
            self._hash = binascii.a2b_hex(hash)
        else:
            self._hash = None

    # IMPLEMENTATIONS OF ABSTRACT METHODS ###########################
    def __str__(self):
        return self.toString('')        # that is, no indent

    def equals(self, other):
        if isinstance(other, MerkleLeaf)        and \
                self._name   == other._name     and \
                self._hash   == other._hash:
            return True
        else:
            return False

    @property
    def hash(self):         return self._hash

    def setHash(self, value):
        if self._hash != None:
            raise RuntimeError('attempt to change MerkleLeaf hash')
        # XXX SHOULD CHECK whether well-formed
        self._hash = binascii.a2b_hex(value)

    @property
    def isLeaf(self):       return True

    @property
    def name(self):         return self._name

    @property
    def usingSHA1(self):    return self._usingSHA1

    # OTHER METHODS AND PROPERTIES ##################################
    @staticmethod
    def sha1File(pathToFile):
        """XXX no checks on file existence, etc"""
        with open(pathToFile, "rb") as f:
            # XXX should use buffer
            data = f.read()
        if data == None:
            # DEBUG
            print "sha1File(%s) returning None" % pathToFile
            # END
            return None
        sha1 = hashlib.sha1()
        sha1.update(data)
        d    = sha1.digest()        # a binary number
        return d

    @staticmethod
    def sha3File(pathToFile):
        """XXX no checks on file existence, etc"""
        with open(pathToFile, "rb") as f:
            # XXX should use buffer
            data = f.read()
        if data == None:
            return None
        # sha3 = sha3.SHA3256()
        sha3 = hashlib.sha3_256()
        sha3.update(data)
        return sha3.digest()            # a binary number

    @staticmethod
    def createFromFileSystem(pathToFile, name, usingSHA1 = False):
        """
        Returns a MerkleLeaf.  The name is part of pathToFile, but is
        passed to simplify the code.
        """
        if not os.path.exists(pathToFile):
            print "INTERNAL ERROR: file does not exist: " + pathToFile
        # XXX we convert from binary to hex and then right back to binary !!
        if usingSHA1:
            hash = binascii.b2a_hex(MerkleLeaf.sha1File(pathToFile))
        else:
            hash = binascii.b2a_hex(MerkleLeaf.sha3File(pathToFile))
        return MerkleLeaf(name, usingSHA1, hash)

    def toString(self, indent):
        if self._hash == None:
            if self._usingSHA1:     h = SHA1_NONE
            else:                   h = SHA3_NONE
        else:
            h = binascii.b2a_hex(self._hash)
        s = "%s%s %s\r\n" % (indent, h, self.name)
        return s

# -------------------------------------------------------------------
class MerkleTree(MerkleNode):

    __slots__ = ['_bound', '_name', '_exRE', '_hash', '_matchRE', '_nodes', '_usingSHA1', ]

    # notice the terminating forward slash and lack of newlines or CR-LF
    FIRST_LINE_PAT_1 = re.compile(r'^( *)([0-9a-f]{40}) ([a-z0-9_\-\.]+/)$',
                                re.IGNORECASE)
    OTHER_LINE_PAT_1 = re.compile(r'^([ XYZ]*)([0-9a-f]{40}) ([a-z0-9_\-\.]+/?)$',
                                re.IGNORECASE)
    FIRST_LINE_PAT_3 = re.compile(r'^( *)([0-9a-f]{64}) ([a-z0-9_\-\.]+/)$',
                                re.IGNORECASE)
    OTHER_LINE_PAT_3 = re.compile(r'^([ XYZ]*)([0-9a-f]{64}) ([a-z0-9_\-\.]+/?)$',
                                re.IGNORECASE)
    

    #################################################################
    # exRE and matchRE must have been validated by the calling code
    #################################################################
    def __init__ (self, name, usingSHA1 = False,
            exRE    = None,     # exclusions Regular Expression
            matchRE = None):    # matches Regular Expression

        if name == None:
            raise RunTimeError("MerkleTree: null MerkleTree name")
        self._name = name.strip()
        if len(self._name) == 0:
            raise RuntimeError("MerkleTree: null or empty name")

        self._usingSHA1 = usingSHA1
        self._exRE      = exRE
        self._hash      = None
        self._matchRE   = matchRE
        self._nodes     = []

#       if (binding):
#           if not pathTo:
#               raise RuntimeError("cannot bind, no path set")
#           self._path = "%s/%s" % (pathTo, name)
#           if not os.path.exists(self._path):
#               raise RuntimeError(
#                   "MerkleTree: directory '%s' does not exist" % self._path)

#           # Create data structures for constituent files and subdirectories
#           # These are sorted by the bare name
#           files = os.listdir(self._path)  # empty if you just append .sort()
#           files.sort()                    # sorts in place
#           self._hash = None
#           sha1 = hashlib.sha1()
#           if files:
#               sha1Count = 0
#               # empty directories will still contain . and ..
#               for file in files:
#                   # exclusions take priority over matches
#                   if exRE and exRE.search(file):
#                       continue
#                   if matchRE and not matchRE.search(file):
#                       continue
#                   node = None
#                   pathToFile = os.path.join(self._path, file)
#                   s = os.lstat(pathToFile)        # ignores symlinks
#                   mode = s.st_mode
#                   if S_ISDIR(mode):
#                       node = MerkleTree (file, self, True, self._path)
#                   elif S_ISREG(mode):
#                       fSize = s.st_size
#                       node = MerkleLeaf(file, self, True) # calculates hash
#                   # otherwise, just ignore it ;-)

#                   if node:
#                       # update tree-level hash
#                       if node.hash:
#                           # note empty file has null hash
#                           sha1Count = sha1Count + 1
#                           sha1.update(node.hash)
#                       # SKIP NEXT TO EASE GARBAGE COLLECTION ??? XXX
#                       # but that won't be a good idea if we are
#                       # invoking toString()
#                       self._nodes.append(node)
#               if sha1Count:
#                   self._hash = sha1.digest()
#           else:
#               # this must be an error; . and .. are always present
#               msg = "directory '%s' contains no files" % self._path
#               raise RuntimeError(msg) GEEP

    # IMPLEMENTATIONS OF ABSTRACT METHODS ###########################
    @property
    def __str__(self):
        return self.toString('')

    def equals(self, other):
        """considerably hacked about during debugging"""
        if other == None:
            return False
        if self == other:
            return True

        if (not isinstance(other, MerkleTree)) or \
           (self._name != other._name ):
            return False
        # tests at the binary level sometimes fail
#       if (self._hash != other._hash):
        if (self.hash != other.hash):
            print "my hash:    " + self.hash
            print "other hash: " + other.hash
            return False
        myNodes    = self.nodes
        otherNodes = other.nodes
        if len(myNodes) != len(otherNodes):
            return False
        for i in range(len(myNodes)):
            myNode    = myNodes[i]
            otherNode = otherNodes[i]
            if not myNode.equals(otherNode):    # RECURSES
                print "DEBUG nodes %s and %s differ" % (        # DEBUG
                        myNode._name, otherNode._name)          # DEBUG
                return False
        return True

    @property
    def hash(self):
        if self._hash == None:
            if self._usingSHA1:
                return SHA1_NONE;
            else:
                return SHA3_NONE;
        else:
            return binascii.b2a_hex(self._hash);

    def setHash(self, value):
        if self._hash:
            raise RuntimeError('attempt to set non-null hash')
        self._hash = binascii.a2b_hex(value)

    @property
    def isLeaf(self):       return False

    @property
    def name(self):         return self._name

    @property
    def usingSHA1(self):    return self._usingSHA1

    #################################################################
    # METHODS LIFTED FROM bindmgr/bindlib/MerkleTree.py
    #################################################################
    @staticmethod
    def parseFirstLine(line):
        line = line.rstrip()
        m = re.match(MerkleTree.FIRST_LINE_PAT_1, line)
        if m == None:
            m = re.match(MerkleTree.FIRST_LINE_PAT_3, line)
        if m == None:
            raise RuntimeError(
                    "MerkleTree first line <%s> does not match expected pattern" %  line)
        indent    = len(m.group(1))/2
        treeHash  = m.group(2)
        dirName   = m.group(3)          # includes terminating slash
        dirName   = dirName[0:len(dirName) - 1]
        return (indent, treeHash, dirName)

    @staticmethod
    def parseOtherLine(line):
        m = re.match(MerkleTree.OTHER_LINE_PAT_1, line)
        if m == None:
            m = re.match(MerkleTree.OTHER_LINE_PAT_3, line)
        if m == None:
            raise RuntimeError(
                    "MerkleTree other line <%s> does not match expected pattern" %  line)
        nodeDepth = len(m.group(1))/2
        nodeHash  = m.group(2)
        nodeName  = m.group(3)
        if nodeName.endswith('/'):
            nodeName = nodeName[0:len(nodeName) - 1]
            isDir = True
        else:
            isDir = False
        return (nodeDepth, nodeHash, nodeName, isDir)

#   # DEBUG
#   @staticmethod
#   def showStack(stack):
#       """ a stack of trees """
#       s = []
#       s.append( '     %d ' % len(stack) )
#       for tree in stack:
#           s.append( '[%s] ' % tree.name )
#       print ''.join(s)
#   # END
    @staticmethod
    def createFromStringArray(s):
        """
        The string array is expected to follow conventional indentation
        rules, with zero indentation on the first line and some multiple
        of two spaces on all successive lines.
        """
        if s == None:
            raise RuntimeError('null argument')

        # XXX should check TYPE - must be array of strings

        if len(s) == 0:
            raise RuntimeError("empty string array")
        (indent, treeHash, dirName) = \
                            MerkleTree.parseFirstLine(s[0].rstrip())
        usingSHA1   = (40 == len(treeHash))
        rootTree    = MerkleTree(dirName, usingSHA1)    # an empty tree
        rootTree.setHash(treeHash)

        if indent != 0:
            print "INTERNAL ERROR: initial line indent %d" % indent

        stack      = []
        stkDepth   = 0
        curTree    = rootTree
        stack.append(curTree)           # rootTree
        stkDepth  += 1                  # always step after pushing tree
        lastWasDir = False

        # REMEMBER THAT PYTHON HANDLES LARGE RANGES BADLY
        for n in range(1, len(s)):
            line = s[n].rstrip()
#           print "LINE: " + line       # DEBUG
            if len(line) == 0:
                n += 1
                continue
            # XXX SHOULD/COULD CHECK THAT HASHES ARE OF THE RIGHT TYPE
            (lineIndent, hash, name, isDir) = MerkleTree.parseOtherLine(line)
#           print "DEBUG: item %d, lineIndent %d, stkDepth %d, name %s" % (
#                           n, lineIndent, stkDepth, name)    # DEBUG
            if lineIndent < stkDepth:
                while lineIndent < stkDepth:
                    stkDepth -= 1
                    stack.pop()
                curTree = stack[-1]

#               print "DEBUG: item %d, lineIndent %d, stkDepth %d BEYOND LOOP curTree is %s" % (
#                           n, lineIndent, stkDepth, curTree.name)    # DEBUG

#               MerkleTree.showStack(stack)         # DEBUG

                if not stkDepth == lineIndent:
                    print "ERROR: stkDepth != lineIndent"

            if isDir:
                # create and set attributes of new node
                newTree = MerkleTree(name, usingSHA1)  # , curTree)
                newTree.setHash(hash)
                # add the new node into the existing tree
                curTree.addNode(newTree)
                stack.append(newTree)
                stkDepth += 1
                curTree   = newTree
#               # DEBUG
#               MerkleTree.showStack( stack )
#               # END
            else:
                # create and set attributes of new node
                newNode = MerkleLeaf(name, usingSHA1, hash)
                # add the new node into the existing tree
                curTree.addNode(newNode)
#               print "DEBUG: added node %s to tree %s" % (newNode.name,
#                                                          curTree.name)
            n += 1
        return rootTree         # BAR

    @staticmethod
    def createFromSerialization(s):
        if s == None:
            raise RuntimeError ("MerkleTree.createFromSerialization: no input")
        sArray = s.split('\r\n')                # note CR-LF
        return MerkleTree.createFromStringArray(sArray)

    @staticmethod
    def createFromFile(pathToFile):
        if not os.path.exists(pathToFile):
            raise RuntimeError(
                "MerkleTree.createFromFile: file '%s' does not exist" % pathToFile)
        with open(pathToFile, 'r') as f:
            line = f.readline()
            line = line.rstrip()
            m = re.match(MerkleTree.FIRST_LINE_PAT_1, line)
            if m == None:
                m = re.match(MerkleTree.FIRST_LINE_PAT_3, line)
                usingSHA1 = False
            else:
                usingSHA1 = True
            if m == None:
                raise RuntimeError(
                        "line '%s' does not match expected pattern" %  line)
            dirName = m.group(3)
            tree = MerkleTree(dirName, usingSHA1)
#           if m.group(3) != 'bind':
#               raise RuntimeError(
#                       "expected 'bind' in first line, found %s" % m.group(3))
            tree.setHash(m.group(2))
            line = f.readline()
            while line:
                line = line.rstrip()
                if line == '':
                    continue
                if self._usingSHA1:
                    m = re.match(MerkleTree.OTHER_LINE_PAT_1, line)
                else:
                    m = re.match(MerkleTree.OTHER_LINE_PAT_3, line)
                    
                if m == None:
                    raise RuntimeError(
                            "line '%s' does not match expected pattern" %  line)
                tree._add(m.group(3), m.group(2))
                line = f.readline()

        return tree

    @staticmethod
    def createFromFileSystem(pathToDir, usingSHA1 = False,
                                        exRE = None, matchRE = None):
        """
        Create a MerkleTree based on the information in the directory
        at pathToDir.  The name of the directory will be the last component
        of pathToDir.  Return the MerkleTree.
        """
        if not pathToDir:
            raise RuntimeError("cannot create a MerkleTree, no path set")
        if not os.path.exists(pathToDir):
            raise RuntimeError(
                "MerkleTree: directory '%s' does not exist" % self._path)
        (path, junk, name) = pathToDir.rpartition('/')
        if path == '':
            raise RuntimeError("cannot parse inclusive path " + pathToDir)

        tree = MerkleTree(name, usingSHA1, exRE, matchRE)

        # Create data structures for constituent files and subdirectories
        # These are sorted by the bare name
        files = os.listdir(pathToDir)  # empty if you just append .sort()
        files.sort()                    # sorts in place
        tree._hash = None
        if usingSHA1:
            shaX = hashlib.sha1()
        else:
            shaX = hashlib.sha3_256()
        if files:
            shaXCount = 0
            for file in files:
                # exclusions take priority over matches
                if exRE and exRE.search(file):
                    continue
                if matchRE and not matchRE.search(file):
                    continue
                node = None
                pathToFile = os.path.join(pathToDir, file)
                s = os.lstat(pathToFile)        # ignores symlinks
                mode = s.st_mode
                # os.path.isdir(path) follows symbolic links
                if S_ISDIR(mode):
                    node = MerkleTree.createFromFileSystem(
                                    pathToFile, usingSHA1, exRE, matchRE)
                # S_ISLNK(mode) is true if symbolic link
                # isfile(path) follows symbolic links
                elif os.path.isfile(pathToFile):        # S_ISREG(mode):
                    node = MerkleLeaf.createFromFileSystem(
                                            pathToFile, file, usingSHA1)
                # otherwise, just ignore it ;-)

                if node:
                    # update tree-level hash
                    if node.hash:
                        # note empty file has null hash
                        shaXCount += 1
                        shaX.update(node.hash)
                    # SKIP NEXT TO EASE GARBAGE COLLECTION ??? XXX
                    # but that won't be a good idea if we are
                    # invoking toString()
                    tree._nodes.append(node)
            if shaXCount:
                tree._hash = shaX.digest()
#       else:           # WE SEE THIS ERROR
#           # this must be an error; . and .. are always present
#           msg = "directory '%s' contains no files" % pathToDir
#           raise RuntimeError(msg)

        return tree

    # XXX THIS SHOULD BE SOMEWHAT OLDER THAN THE CODE ABOVE
#   @staticmethod
#   def createFromFileSystem(pathToDir, exRE, matchRE):
#       """
#       Create a MerkleTree based on the information in the directory
#       at pathToDir.  The name of the directory will be the last component
#       of pathToDir.  It is also
#       """
#       if not pathToDir:
#           raise RuntimeError("cannot create a MerkleTree, no path set")
#       if not os.path.exists(pathToDir):
#           raise RuntimeError(
#               "MerkleTree: directory '%s' does not exist" % self._path)
#       # XXX SHOULD VALIDATE exRE, matchRE

#       # Create data structures for constituent files and subdirectories
#       # These are sorted by the bare name
#       files = os.listdir(self._path)  # empty if you just append .sort()
#       files.sort()                    # sorts in place
#       treeHash = None
#       sha1     = hashlib.sha1()
#       if files:
#           sha1Count = 0
#           # empty directories will still contain . and ..
#           for file in files:
#               # exclusions take priority over matches
#               if exRE and exRE.search(file):
#                   continue
#               if matchRE and not matchRE.search(file):
#                   continue
#               node = None
#               pathToFile = os.path.join(self._path, file)
#               s = os.lstat(pathToFile)        # ignores symlinks
#               mode = s.st_mode
#               if S_ISDIR(mode):
#                   node = MerkleTree (file, self, True, self._path)
#               elif S_ISREG(mode):
#                   fSize = s.st_size
#                   node = MerkleLeaf(file, self, True) # calculates hash
#               # otherwise, just ignore it ;-)

#               if node:
#                   # update tree-level hash
#                   if node.hash:
#                       # note empty file has null hash
#                       sha1Count = sha1Count + 1
#                       sha1.update(node.hash)
#                   # SKIP NEXT TO EASE GARBAGE COLLECTION ??? XXX
#                   # but that won't be a good idea if we are
#                   # invoking toString()
#                   self._nodes.append(node)
#           if sha1Count:
#               treeHash = sha1.digest()
#       else:
#           # this must be an error; . and .. are always present
#           msg = "directory '%s' contains no files" % self._path
#           raise RuntimeError(msg)

#   # FOO

    # OTHER METHODS AND PROPERTIES ##################################
    @property
    def nodes(self):        return self._nodes

    def addNode(self, node):
        if node == None:
            raise RuntimeError("attempt to add null node")
        if not isinstance(node, MerkleTree) \
                and not isinstance(node, MerkleLeaf):
            raise RuntimeError("node being added not MerkleTree or MerkleLeaf")
        self._nodes.append(node)

    # SERIALIZATION #################################################
    def toStringNotTop(self, indent):
        """ indent is the indentation to be used for the top node"""
        s      = []                             # a list of strings
        if self._hash == None:
            if self._usingSHA1:
                top = "%s%s %s/\r\n" % (indent, SHA1_NONE, self.name)
            else:
                top = "%s%s %s/\r\n" % (indent, SHA3_NONE, self.name)
        else:
            top = "%s%s %s/\r\n" % (indent, binascii.b2a_hex(self._hash),
                              self.name)
        s.append(top)
        # DEBUG
        # print "toStringNotTop appends: %s" % top
        # END
        indent = indent + '  '              # <--- LEVEL 2+ NODE
        for node in self.nodes:
            if isinstance(node, MerkleLeaf):
                s.append( node.toString(indent) )
            else:
                s.append( node.toStringNotTop(indent) )     # recurses

        return ''.join(s)

    def toString(self, indent):
        """
        indent is the initial indentation of the serialized list, NOT the
        extra indentation added at each recursion, which is fixed at 2 spaces.
        Using code should take into account that the last line is CR-LF
        terminated, and so a split on CRLF will generate an extra blank line
        """
        s      = []                             # a list of strings
        if self._hash == None:
            if self._usingSHA1:
                top = "%s%s %s/\r\n" % (indent, SHA1_NONE, self.name)
            else:
                top = "%s%s %s/\r\n" % (indent, SHA3_NONE, self.name)
        else:
            top = "%s%s %s/\r\n" % (indent, binascii.b2a_hex(self._hash),
                              self.name)    # <--- LEVEL 0 NODE
        s.append(top)
        myIndent = indent + '  '            # <--- LEVEL 1 NODE
        for node in self.nodes:
            if isinstance (node, MerkleLeaf):
                s.append(node.toString(myIndent))
            else:
                s.append( node.toStringNotTop(myIndent) )     # recurses

        return ''.join(s)
