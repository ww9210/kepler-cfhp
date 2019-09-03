"""
osok version 3
Principles:
1. modularize the phases, maybe refactor the workflow into invocation of different classes
2. figure out the input and output of each phase
"""
import angr
from capstone import *
from angr import concretization_strategies
import claripy
import traceback
from pwn import *
import sys
sys.path.append('/home/ww9210/develop/concolic_execution')
import statebroker
import colorama
import pickle
import os
from os import listdir
from os.path import isfile, join
import datetime
import time
import state_filters
import _concrete_state
import _pickle_states
import _gadget_analysis
import _bloom_gadget
import _disclosure_gadget
import _forking_gadget
import _prologue_gadget
import _smash_gadget
import _symbolic_tracing
import _exploit_routine


class OneShotExploit(object, _concrete_state.ConcreteStateMixin\
                     , _pickle_states.PickleStatesMixin\
                     , _gadget_analysis.GadgetAnalysisMixin\
                     , _bloom_gadget.BloomGadgetMixin\
                     , _forking_gadget.ForkingGadgetMixin\
                     , _prologue_gadget.PrologueGadgetMixin\
                     , _disclosure_gadget.DisclosureGadgetMixin\
                     , _smash_gadget.SmashGadgetMixin\
                     , _symbolic_tracing.SymbolicTracingMixin\
                     , _exploit_routine.ExploitRoutineMixin\
                     ):
    def __init__(self, kernel_path=None):
        '''
        :param kernel_path: the vmlinux path to the kernel
        '''
        self.kernel_path=kernel_path
        #self.b = angr.Project(kernel_path, support_selfmodifying_code=True)
        if os.path.isfile('angr_project.cache'):
            with open('angr_project.cache','rb') as f:
                print '[+] deserilizing vmlinux from pickle dump'
                self.b = pickle.load(f)
        else:
            self.b = angr.Project(kernel_path)
            with open('angr_project.cache','wb') as f:
                pickle.dump(self.b, f)
        self.r = None
        self.statebroker = statebroker.StateBroker()
        self.claripy = claripy
        self.sol = claripy.Solver()
        self.md = Cs(CS_ARCH_X86, CS_MODE_64)
        self.md.detail = True

    def do_nothing(self, state):
        pass

    def setup(self, gadget_path=None \
            , start_addr=None \
            , debug_qemu_backend=True\
            , function_call_to_disable=None\
            , qemu_port=9210\
            , limit_loop=False\
            , pause_on_each_step=False\
            , add_bloom_instrumentation=True\
            , add_forking_instrumentation=True\
            , add_prologue_instrumentation=True\
            , execution_time_limit=99999\
            , debug_irsb=True\
            , pause_on_read_from_symbolic_address=False\
            , resolve_uninit=True\
            , pause_on_failed_memory_resolving=True\
            , pause_on_finish_memory_loading=False\
            , pause_on_enforce_fork_on_bloom=False\
            , pause_on_prologue_on_fork=False\
            , expected_start_rip=None\
            , extra_module_base=None\
            , extra_module_size=None\
            , first_constraint_func=None\
            , controlled_memory_base=None\
            , controlled_memory_size=None\
            , start_bloom_gadget_index=0\
            , boost_via_reconstraining_with_old_state=True\
            , require_perfect_bloom_gadget=True\
            , serilize_good_bloom_fork_gadget_pair=True\
            , use_controlled_data_concretization=True\
            , has_custom_concretization_strategy=True\
            , explore_smash_gadget=False\
            , dump_good_disclosure_state_discretely=True\
            , dump_good_disclosure_state_together=False\
            , dump_good_smash_state_together=True\
            , use_precomputed_disclosure_state=False\
            , use_precomputed_good_bloom_and_fork_pair=False\
            , fast_path_for_disclosure_state=False\
            , not_saving_unsatisfiable_states=True\
            , consider_rbp_disclosure_prologue_pair=True\
            , inspect_phase_2=False\
            ):
        self.start_addr=start_addr
        self._gadget_path=gadget_path
        self.load_gadgets()  # load gadget from result of IDA-Python
        self.function_call_to_disable = function_call_to_disable
        self.debug_qemu_backend=debug_qemu_backend
        self.qemu_port = qemu_port
        self.limit_loop = limit_loop
        self.pause_on_each_step = pause_on_each_step
        self.add_bloom_instrumentation = add_bloom_instrumentation
        self.add_forking_instrumentation = add_forking_instrumentation
        self.add_prologue_instrumentation = add_prologue_instrumentation
        self.execution_time_limit = execution_time_limit
        self.debug_irsb = debug_irsb
        self.pause_on_read_from_symbolic_address = pause_on_read_from_symbolic_address
        self.resolve_uninit = resolve_uninit
        self.pause_on_failed_memory_resolving = pause_on_failed_memory_resolving
        self.pause_on_finish_memory_loading = pause_on_finish_memory_loading
        self.pause_on_enforce_fork_on_bloom = pause_on_enforce_fork_on_bloom
        self.expected_start_rip = expected_start_rip
        self.extra_module_base = extra_module_base
        self.extra_module_size = extra_module_size
        self.first_constraint_func = first_constraint_func
        self.controlled_memory_base = controlled_memory_base
        self.controlled_memory_size = controlled_memory_size
        self.reach_current_bloom_site = None
        self.reach_current_fork_gadget = None
        self.reach_current_first_fork_site = None
        self.reach_current_second_fork_site = None
        self.good_bloom_gadget = []  # good bloom filter
        self.good_bloom_fork_gadget_pair = []
        self.current_bloom_gadget = None
        self.current_forking_gadget = None
        self.current_prologue_gadget = None
        self.current_smash_gadget = None
        self.current_prologue_signature = None
        self.current_firstly_reached_fork_site = None
        self.start_bloom_gadget_index = start_bloom_gadget_index
        self.boost_via_reconstraining_with_old_state = boost_via_reconstraining_with_old_state
        self.require_perfect_bloom_gadget = require_perfect_bloom_gadget
        self.prologue_disclosure_pairs = None
        self.unsatisfiable_state = []
        self.serilize_good_bloom_fork_gadget_pair = serilize_good_bloom_fork_gadget_pair
        self.first_fork_site_bp = None
        self.pause_on_prologue_on_fork = pause_on_prologue_on_fork
        self.use_controlled_data_concretization = use_controlled_data_concretization
        self.bp_enforce_prologue_to_copy_to_user = None
        self.initial_state = None
        self.has_custom_concretization_strategy = has_custom_concretization_strategy
        self.good_disclosure_state = []
        self.explore_smash_gadget = explore_smash_gadget
        self.dump_good_disclosure_state_discretely = dump_good_disclosure_state_discretely
        self.dump_good_disclosure_state_together = dump_good_disclosure_state_together
        self.use_precomputed_disclosure_state = use_precomputed_disclosure_state
        self.good_smash_states = [ ]
        self.fast_path_for_disclosure_state = fast_path_for_disclosure_state
        self.tmp_good_disclosure_state_number = 0
        self.dump_good_smash_state_together = dump_good_smash_state_together
        self.use_precomputed_good_bloom_and_fork_pair = use_precomputed_good_bloom_and_fork_pair
        self.not_saving_unsatisfiable_states = not_saving_unsatisfiable_states
        self.consider_rbp_disclosure_prologue_pair = consider_rbp_disclosure_prologue_pair
        self.inspect_phase_2 = inspect_phase_2

    def getInstructionLengthByAddr(self, addr):
        tmpbb = self.b.factory.block(addr)
        if tmpbb.size > 5:
            print 'wtf tmpbb size >  5'
            import IPython;
            IPython.embed()
        # call __x86_indirect_thunk_rax
        assert tmpbb.size <= 5
        return tmpbb.size

    def is_stack_address(self, addr):
        if (addr & 0xffffc90000000000) == 0xffffc90000000000:
            return True
        else:
            return False

    def add_concretization_strategy_controlled_data(self, state):
        """
        add conrolled_data concretization strategy to read strategies
        :param state:
        :return:
        """
        if self.has_custom_concretization_strategy:
            state.memory.read_strategies.insert(0, \
                angr.concretization_strategies.mycontrolled_data.MySimConcretizationStrategyControlledData(\
                    1, [ ]))
        else:
            #state.memory.read_strategies.insert(2, \
            state.memory.read_strategies.insert(0, \
                            angr.concretization_strategies.controlled_data.SimConcretizationStrategyControlledData( \
                            1, [0xffff880066800000]))
        return