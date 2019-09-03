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
                self.good_bloom_gadget = pickle.load(f)

    def dump_initial_state_to_disk(self, s):
        state_name='initial_state.cache'
        if not os.path.isfile(state_name):
            with open(state_name, 'wb') as f:
                print 'pickling current initial state to disk'
                pickle.dump(s, f, -1)
                print 'successfully pickle initial state to disk'

    def dump_hyper_parameters(self):
        """
        save some critical information to pickle dump
        :return:
        """
        critical_information = {}
        critical_information['extra_module_base'] = self.extra_module_base
        critical_information['extra_module_size'] = self.extra_module_size
        critical_information['start_addr'] = self.start_addr
        critical_information['expected_start_rip'] = self.expected_start_rip
        #if not os.path.isfile('critical_info.cache'):
        with open('critical_info.cache', 'wb') as f:
            pickle.dump(critical_information, f, -1)

    def load_hyper_parameters(self):
        """
        :return:
        """
        if os.path.isfile('critical_info.cache'):
            with open('critical_info.cache', 'rb') as f:
                crit_info = pickle.load(f)
                self.extra_module_base = crit_info['extra_module_base']
                self.extra_module_size = crit_info['extra_module_size']
                self.start_addr = crit_info['start_addr']
                self.expected_start_rip = crit_info['expected_start_rip']
        else:
            print 'not found hyper parameters, run savevm.py first to get a start machine state'
            assert 0



