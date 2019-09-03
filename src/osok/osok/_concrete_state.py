from pwn import *
import time
import angr
import traceback
from IPython import embed

class ConcreteStateMixin:
    def get_complete_initial_state(self
                                   , control_memory_base=0xfff880066800000
                                   , control_memory_size=0x1000
                                   , switch_cpu=True
                                   , extra_options=None
                                   , save_to_file=True):
        """
        Get a complete memory state from qemu backend, and pickle to disk
        :return:
        """
        s = self.get_initial_state(control_memory_base, control_memory_size, switch_cpu, extra_options)
        self.install_section(s, '.__init_rodata')
        self.install_section(s, '.__ksymtab')
        self.install_section(s, '.rodata')
        self.install_current(s)

        self.dump_initial_state_to_disk(s)
        return s

    def load_qemu_snapshot(self):
        """
        Load qemu snapshot and pause the execution
        :return:
        """
        tmp_r = pwnlib.tubes.remote.remote('127.0.0.1', self.qemu_port)
        self.statebroker.load_snapshot(tmp_r, 'initstate'+self.snapshot_prefix)
        sleep(5)
        tmp_r.close()

    def take_qemu_snapshot(self):
        tmp_r = pwnlib.tubes.remote.remote('127.0.0.1', self.qemu_port)
        self.statebroker.take_snapshot(tmp_r, 'initstate'+self.snapshot_prefix)
        sleep(5)
        tmp_r.close()

    def get_initial_state(self
                          , control_memory_base=0xffff880066800000
                          , control_memory_size=0x1000
                          , switch_cpu=True
                          , extra_options=None
                          ):
        """
        Get a initial state by getting concrete value from the qemu instance
        :param control_memory_base:
        :param control_memory_size:
        :param switch_cpu:
        :param extra_options:
        :return:
        """
        start_addr = self.start_addr

        extras = {angr.options.REVERSE_MEMORY_NAME_MAP, \
              angr.options.TRACK_ACTION_HISTORY, \
              # angr.options.CONSERVATIVE_READ_STRATEGY, \
              # angr.options.AVOID_MULTIVALUED_READS, \
              angr.options.KEEP_IP_SYMBOLIC, \
              angr.options.CONSTRAINT_TRACKING_IN_SOLVER}
        if extra_options:
            extras.add(extra_options)

        # create new state
        s = self.b.factory.blank_state(addr=self.start_addr, add_options=extras)

        if self.function_call_to_disable is not None:
            for addr in self.function_call_to_disable:
                self.b.hook(addr, self.do_nothing, 5)

        if self.debug_qemu_backend:
            print 'connecting to qemu console'
            self.r = pwnlib.tubes.remote.remote('127.0.0.1', self.qemu_port)
            self.install_context(s)
            self.install_gs(s)  # install the gs
            self.debug_state(s)
            if switch_cpu:
                self.statebroker.set_cpu_number(self.r, 1)
                self.install_context(s)
                self.debug_state(s)

            if self.expected_start_rip is not None:
                # has 4 cpu cores
                if self.vm._cpu_number == 4:
                    for i in range(4):
                        if self.sol.eval(s.regs.rip, 1)[0] == self.expected_start_rip:
                            break
                        else:
                            self.statebroker.set_cpu_number(self.r, i)
                            s = self.install_context(s)

                elif self.sol.eval(s.regs.rip, 1)[0] != self.expected_start_rip:
                    self.statebroker.set_cpu_number(self.r, 0)
                    s = self.install_context(s)
                    self.debug_state(s)

            else:
                print self.expected_start_rip
                opt = raw_input('switch cpu?[N/y]')
                if 'y' in opt or 'Y' in opt:
                    self.statebroker.set_cpu_number(self.r, 0)
                    s = self.install_context(s)
                    self.debug_state(s)

        self.start_time_of_symbolic_execution = time.time()

        s = self.install_context(s)
        self.fix_a_section(s, '.text')
        self.install_section(s, '.data')
        self.install_section(s, '.bss')
        self.install_section(s, '.brk')
        self.install_extra_module(s)  # install the vulnerable module
        self.install_stack(s)  # install the stack
        self.install_gs(s)  # install the gs
        self.r.close()

        # setting symbolic memory
        self.physmap_bytes = []
        for i in range(control_memory_size):
            symbolic_byte = s.se.BVS("exp_mem" + str(i), 8)
            self.physmap_bytes.append(symbolic_byte)
            s.memory.store(control_memory_base + i, symbolic_byte, inspect=False)
            s.memory.store(control_memory_base - 0x1000 + i, symbolic_byte, inspect=False)
            s.memory.store(control_memory_base + 0x1000 + i, symbolic_byte, inspect=False)

        return s

    def install_extra_module(self, s):
        if self.extra_module_base is not None:
            try:
                extra_module_base = self.extra_module_base
                extra_module_size = self.extra_module_size
                num_of_pages = extra_module_size / 4096 + 1
                print 'extra module is at memory location %x of size %x' % (extra_module_base, extra_module_size)
                for i in range(num_of_pages):
                    addr = extra_module_base + i * 4096
                    con = self.statebroker.get_a_page(self.r, addr)
                    if con is not None:
                        print 'successfully get a page at:', hex(addr)
                        self.set_loader_concret_memory_region(s, addr, con, 4096)
                    else:
                        raw_input('failed to get a page')
                print 'Finished installing extra modules'
            except TypeError as e:
                print e
                traceback.print_exc()
                embed()
        else:
            print 'do not need to print extra module'
        return

    def init_reg_concrete(self, s):
        # assert self.r != None
        s.regs.rax = s.se.BVV(self.statebroker.get_register(self.r, "rax"), 64)
        s.regs.rbx = s.se.BVV(self.statebroker.get_register(self.r, "rbx"), 64)
        s.regs.rcx = s.se.BVV(self.statebroker.get_register(self.r, "rcx"), 64)
        s.regs.rdx = s.se.BVV(self.statebroker.get_register(self.r, "rdx"), 64)
        s.regs.rsi = s.se.BVV(self.statebroker.get_register(self.r, "rsi"), 64)
        s.regs.rdi = s.se.BVV(self.statebroker.get_register(self.r, "rdi"), 64)
        s.regs.rsp = s.se.BVV(self.statebroker.get_register(self.r, "rsp"), 64)
        s.regs.rbp = s.se.BVV(self.statebroker.get_register(self.r, "rbp"), 64)
        s.regs.r8 = s.se.BVV(self.statebroker.get_register(self.r, "r8"), 64)
        s.regs.r9 = s.se.BVV(self.statebroker.get_register(self.r, "r9"), 64)
        s.regs.r10 = s.se.BVV(self.statebroker.get_register(self.r, "r10"), 64)
        s.regs.r11 = s.se.BVV(self.statebroker.get_register(self.r, "r11"), 64)
        s.regs.r12 = s.se.BVV(self.statebroker.get_register(self.r, "r12"), 64)
        s.regs.r13 = s.se.BVV(self.statebroker.get_register(self.r, "r13"), 64)
        s.regs.r14 = s.se.BVV(self.statebroker.get_register(self.r, "r14"), 64)
        s.regs.r15 = s.se.BVV(self.statebroker.get_register(self.r, "r15"), 64)
        s.regs.rip = s.se.BVV(self.statebroker.get_register(self.r, "rip"), 64)
        # s.regs.fs = s.se.BVV(self.statebroker.get_register(self.r,"fs"), 64)
        s.regs.gs = s.se.BVV(self.statebroker.get_register(self.r, "gs"), 64)
        # s.regs.es = s.se.BVV(self.statebroker.get_register(self.r,"es"), 16)
        # s.regs.cs = s.se.BVV(self.statebroker.get_register(self.r,"cs"), 16)
        # s.regs.ss = s.se.BVV(self.statebroker.get_register(self.r,"ss"), 16)
        # s.regs.ds = s.se.BVV(self.statebroker.get_register(self.r,"ds"), 16)
        return s

    def install_section(self, s, name):
        r = self.r
        b = self.b
        section = b.loader.main_object.sections_map[name]
        section_offset = section.vaddr
        section_length = section.memsize
        if section_length % 4096 != 0:
            section_length = ((section_length / 4096) + 1) * 4096
        num_of_page = section_length / 4096
        print 'installing', num_of_page, 'pages of section:', name
        for i in range(num_of_page):
            # print i
            addr = section_offset + i * 4096
            con = self.statebroker.get_a_page(r, addr)
            if con is not None:
                self.set_concret_memory_region(s, addr, con, 4096)
            else:
                raw_input('failed to get_a_page')
        print 'Finished installing section:', name
        return



    def set_loader_concret_memory_region(self, s, addr, buf, length):
        aligned_addr = addr & 0xfffffffffffff000
        # self.b.loader.memory.write_bytes(aligned_addr,buf)
        try:
            self.b.loader.memory.add_backer(aligned_addr, buf)
        except ValueError:
            print('ValueError: Address is already backed!')
            embed()
            pass

    def set_concret_memory_region(self, s, addr, buf, length):
        aligned_addr = addr & 0xfffffffffffff000
        s.memory.store(aligned_addr, buf, inspect=False)
        return

    def install_context(self, s):
        s = self.init_reg_concrete(s)
        return s

    def install_gs(self, s):
        r = self.r
        gs_addr = self.sol.eval(s.regs.gs, 1)[0]
        print 'install gs %x...' % (gs_addr)
        for idx in range(2):
            con = self.statebroker.get_a_page(r, gs_addr + idx * 4096)
            if con is not None:
                self.set_concret_memory_region(s, gs_addr + idx * 4096, con, 4096)
            else:
                raw_input('failed to get gs')
        print 'finished installing gs'

    def install_stack(self, s):
        r = self.r
        rsp_addr = self.sol.eval(s.regs.rsp, 1)[0]
        print 'install rsp...'
        con = self.statebroker.get_a_page(r, rsp_addr)
        if con is not None:
            self.set_concret_memory_region(s, rsp_addr, con, 4096)
        else:
            raw_input('failed to get stack')
        print 'finished installing stack'

    def track_reads(self, state):
        b = self.b
        sol = self.sol
        # print '='*78
        # print 'Read', state.inspect.mem_read_expr, 'from', state.inspect.mem_read_address,\
        #                                'Size', state.inspect.mem_read_length
        if type(state.inspect.mem_read_address) != long:
            try:
                if self.debug_irsb:
                    # irsb = b.factory.block(state.addr).vex
                    # irsb.pp()
                    pass
                # cap = b.factory.block(state.addr).capstone
                # cap.pp()
                # self.dump_reg(state)
                # print 'uninit: ', state.inspect.mem_read_address.uninitialized,\
                # 'symbolic:', state.inspect.mem_read_address.symbolic
                if state.inspect.mem_read_address.symbolic:
                    # print 'read from symbolic address, primitive found!'
                    if self.pause_on_read_from_symbolic_address:
                        raw_input('wtf read from symbolic address')
                # print 'checking whether memory is uninitialized...'
                t = state.memory.load(state.inspect.mem_read_address, size=1, inspect=False)
                if t.uninitialized and not state.inspect.mem_read_address.symbolic:
                    print 'memory content uninit: ', t.uninitialized, \
                        'memory content symbolic: ', t.symbolic
                    print '[+] uninitialized memory read found:', state.inspect.mem_read_address
                    print '[+] the uninitialized memory read is at:', hex(state.addr)

                    # eliminate SMAP violation read
                    if self.sol.eval(state.inspect.mem_read_address.get_bytes(0, 8), 1)[0] < 0xffff880000000000:
                        print 'SMAP vialation, not going to resolving'
                        state.regs.ip = 0
                        return

                    if self.resolve_uninit:
                        r = None
                        try:
                            r = remote('127.0.0.1', self.qemu_port)
                        except PwnlibException as e:
                            print e
                            print 'fail to connect to vm, try restarting'
                            print 'sleeping 30 seconds'
                            sleep(30)
                            self.vm.run(test_connection=False)
                            self.load_qemu_snapshot()
                            sleep(5)
                            r = remote('127.0.0.1', self.qemu_port)
                        try:
                            addr = self.sol.eval(state.inspect.mem_read_address.get_bytes(0, 8), 1)[0]
                            if self.controlled_memory_base <= addr < (self.controlled_memory_base +
                                                                      self.controlled_memory_size):
                                r.close()
                                pass
                            else:
                                print '[+] resolving a page containing the address:', hex(addr)
                                con = self.statebroker.get_a_page(r, addr)
                                r.close()
                                if con is not None:  # success memory resolving
                                    self.set_concret_memory_region(state, addr, con, 4096)
                                    print '[+] resolved the uninit with concrete page'
                                else:
                                    print('[!] failed to resolve the uninit memory')

                                    if self.pause_on_failed_memory_resolving:
                                        for addr in state.history_iterator:
                                            print addr
                                        # import IPython; IPython.embed()
                                    state.regs.ip = 0
                                    return
                            if self.pause_on_finish_memory_loading:
                                raw_input('do the read now(continue) <-')
                        except PwnlibException as e:  # catch options
                            print e
                            traceback.print_exc()
                            if r is not None:
                                r.close()
                            print 'failed in resolving, we do not handle here~'
                            pass
                else:
                    # print 'Memory content does not appear uninitialized'
                    pass

            except (AttributeError, angr.errors.SimMemoryAddressError) as e:
                print e.args, e.message
                print 'wtf track reads'
                self.unsatisfiable_state.append(state.copy())
                # import IPython; IPython.embed()
                # assert(0)

    def track_writes(self, state):
        return
