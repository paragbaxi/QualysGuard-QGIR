#!/usr/bin/env python
"""Tools for QGIR.

Functions used in multiple classes of QGIR.
Prerequisites:
QGIR
"""

__author__ = "Parag Baxi"
__copyright__ = "Copyright 2012"
__credits__ = ["Parag Baxi"]
__license__ = "GPLv3"
__version__ = "2011.10.20.1"
__maintainer__ = "Parag Baxi"
__email__ = "parag.baxi@gmail.com"
__status__ = "Production"


import re

def index_of_first_digit(s):
    m = re.search('\d', s)
    if m:
        return m.start()
    #No digit in that string.
    return False


def is_positive_integer(s):
    """Returns whether a value passed is a positive integer."""
    try:
        return (int(s) > 0)
    except ValueError:
        return False


def parse_int_set(nputstr = ''):
    """Return a set of selected values when a string in the form:
    1-4,6
    would return:
    1,2,3,4,6
    as expected.
    http://stackoverflow.com/questions/712460/interpreting-number-ranges-in-python """
    selection = set()
    invalid = set()
    # tokens are comma seperated values
    tokens = [x.strip() for x in nputstr.split(',')]
    for i in tokens:
        if len(i) > 0:
            if i[:1] == "<":
                i = "1-%s" % (i[1:])
        try:
            # typically tokens are plain old integers
            selection.add(int(i))
        except:
            # if not, then it might be a range
            try:
                token = [int(k.strip()) for k in i.split('-')]
                if len(token) > 1:
                    token.sort()
                    # we have items seperated by a dash
                    # try to build a valid range
                    first = token[0]
                    last = token[len(token) - 1]
                    for x in range(first, last + 1):
                        selection.add(x)
            except:
                # not an int and not a range...
                invalid.add(i)
    # Report invalid tokens before returning valid selection
    if len(invalid) > 0:
        print "Invalid set: " + str(invalid)
    return selection

def sort_naturally(l, key):
    """ Sort the given iterable in the way that humans expect."""
    if not l:
        return l
    convert = lambda text: int(text) if text.isdigit() else text
    alphanum_key = lambda item: [ convert(c) for c in re.split('([0-9]+)', key(item)) ]
    return sorted(l, key = alphanum_key)

def natural_sort(l):
    """ Sort the given list in the way that humans expect. 
    """
    convert = lambda text: int(text) if text.isdigit() else text.lower()
    alphanum_key = lambda key: [ convert(c) for c in re.split('([0-9]+)', key) ]
    return sorted(l, key = alphanum_key)


def unique(seq):
    """Return seq list after removing duplicates whilst preserving order."""
    seen = set()
    seen_add = seen.add
    return [ x for x in seq if x not in seen and not seen_add(x)]


