import pickle
import os
from os import listdir
from os.path import isfile, join


class PickleStatesMixin:
    def get_good_disclosure_state_dumps(self):
        mypath = './'
        tmpfiles = [f for f in listdir(mypath) if isfile(join(mypath, f))]
        files = [f for f in tmpfiles if 'good_disclosure_state' in f]
        return files