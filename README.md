# merkletree


## What It Does

**merkletree** is a Python package for creating a
[Merkle tree](https://en.wikipedia.org/wiki/Merkle_tree)
for a
directory structure.  A **Merkle tree** is a representation of the contents
of the directory and its subdirectories in terms of *hashes*.  In this case,
the hashes used are those specified in various versions of the
[Secure Hash Algorithm](https://en.wikipedia.org/wiki/Secure_Hash_Algorithm),
a Federal cryptographic standard for securely deriving a (relatively) short
number which can be used to uniquely identify a document.

A file is represented by the hash of its
contents.  A directory is represented by the hash of the hashes
of its members, sorted by file name.  This makes it very easy to verify the
contents of a directory:

	merkleize -x -i  .

outputs a single hash, a hexadecimal number.  If any file in the
directory structure has been changed, the output from the above
command will also change.

## SHA, the Secure Hash Algorithm

This package uses hash algorithms specified in the
[Secure Hash Standard](http://csrc.nist.gov/publications/fips/fips180-4/fips-180-4.pdf)
for hashing.  This is a standard published by the US National Institute of
Standards and Techology (**NIST**).

SHA is a cryptographically secure hash, meaning that for all
practical purposes it is impossible to find two documents with the same hash.
In other words, the SHA hashes are meant to be **one-way**: given a document,
it is very easy to determine its SHA hash, but given such a hash the only
practical way to find out what document it corresponds to is to hash all
candidate matches and compare the resultant hash with the one you are searching
for.

**merkletree** currently uses either the older 160 bit/20 byte **SHA-1**
or the more recent and more secure **SHA-256** or **SHA-3**, where the latter
two are 256 bit/32 byte hashes.

## What It's Used For

Verifying the integrity of file systems, of directory structures.

## Command Line

    usage: merkleize [-h] [-d OUT_DIR] [-I INDENT] [-i IN_DIR] [-j] [-m]
                     [-o OUT_FILE] [-P MATCH_PAT] [-t] [-V] [-x] [-X EXCLUDE] [-1]
                     [-2] [-3] [-u U_PATH] [-v]

    generate the merkletree corresponding to a directory

    optional arguments:
      -h, --help            show this help message and exit
      -d OUT_DIR, --out_dir OUT_DIR
                            write serialized merkletree here
      -I INDENT, --indent INDENT
                            number of spaces to indent list (default=1)
      -i IN_DIR, --in_dir IN_DIR
                            write serialized merkletree here
      -j, --just_show       show options and exit
      -m, --show_tree       output the merkletree hash+filename lines
      -o OUT_FILE, --out_file OUT_FILE
                            write output to this file (default = timestamp)
      -P MATCH_PAT, --match_pat MATCH_PAT
                            include only files with matching names
      -t, --showTimestamp   output UTC time
      -V, --show_version    output the version number of this program
      -x, --hash_output     output the top level hash
      -X EXCLUDE, --exclude EXCLUDE
                            ignore files matching this pattern
      -1, --using_sha1      using the 160-bit SHA1 hash
      -2, --using_sha2      using the 256-bit SHA2 (SHA256) hash
      -3, --using_sha3      using the 256-bit SHA3 (Keccak-256) hash
      -u U_PATH, --u_path U_PATH
                            path to uDir
      -v, --verbose         be chatty
	
The default output file name is the UTC timestamp, the number of seconds
since the epoch (1970-01-01), where 'UTC' is more or less the same of
GMT, Greenwich Mean Time.

## Relationships

Merkletree was implemented as part of the [XLattice](http://www.xlattice.org)
project.  A Go language implementation forms part of
[xlattice_go](https://jddixon.github.io/xlattice_go).

## Project Status

Merkletree has been in use for several years.  There are no known bugs.

## On-line Documentation

More information on the **merkletree** project can be found
[here](https://jddixon.github.io/merkletree)
