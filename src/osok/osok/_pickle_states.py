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

    def dump_good_bloom_state(self):
        for good_bloom_gadget in self.good_bloom_gadget:
            print good_bloom_gadget
        print 'there are %d good bloom gadget verified by symbolic execution' % (len(self.good_bloom_gadget))
        if not os.path.isfile('good_bloom_gadget.cache'):  # dump bloom gadget
            with open('good_bloom_gadget.cache', 'wb') as f:
                pickle.dump(self.good_bloom_gadget, f, -1)

    def dump_good_bloom_state_2nd(self):
        for good_bloom_gadget in self.good_bloom_gadget:
            print good_bloom_gadget
        print 'there are %d good two level bloom gadget verified by symbolic execution' % (len(self.good_bloom_gadget))
        if not os.path.isfile('good_bloom_gadget_2nd.cache'):  # dump bloom gadget
            with open('good_bloom_gadget_2nd.cache', 'wb') as f:
                pickle.dump(self.good_bloom_gadget, f, -1)

    def dump_good_bloom_state_2nd_discretely(self, idx):
        for good_bloom_gadget in self.good_bloom_gadget:
            print good_bloom_gadget
        subdir = './double_bloom/'
        filepath = subdir+'good_bloom_gadget_2nd_'+str(idx)+'.cache'
        if not os.path.isfile(filepath):
            with open(filepath, 'wb') as f:
                pickle.dump(self.good_bloom_pairs, f, -1)

    def load_good_bloom_gadgets_from_disk(self):
        if not os.path.isfile('good_bloom_gadget_2nd.cache'):
            with open('good_bloom_gadget.cache', 'rb') as f:
                print '[+] loading good bloom gadget'
                self.good_bloom_gadget = pickle.load(f)
        else:
            with open('good_bloom_gadget_2nd.cache', 'rb') as f:
                print '[+] loading double bloomed good bloom state'
