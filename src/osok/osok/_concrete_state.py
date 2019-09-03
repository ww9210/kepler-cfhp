from pwn import *
import time
import angr

class ConcreteStateMixin:
    def get_initial_state(self \
                      , control_memory_base=0xffff880066800000 \
                      , control_memory_size=0x1000 \
                      , switch_cpu=True \
                      , extra_options=None \
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
            self.debug_state(s)
            if switch_cpu:
                self.statebroker.set_cpu_number(self.r, 1)
                self.install_context(s)
                self.debug_state(s)

            if self.expected_start_rip is not None:
                if self.sol.eval(s.regs.rip, 1)[0] != self.expected_start_rip:
                    self.statebroker.set_cpu_number(self.r, 0)
                    s = self.install_context(s)
                    self.debug_state(s)
            else:
                opt = raw_input('switch cpu?[N/y]')
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

    def install_extra_module(self, s):
        extra_module_base = self.extra_module_base
        extra_module_size = self.extra_module_size
        num_of_pages = extra_module_size / 4096 + 1
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
            if con != None:
                self.set_concret_memory_region(s, addr, con, 4096)
            else:
                raw_input('failed to get_a_page')
        print 'Finished installing section:', name
        return

    def debug_state(self, state, save_memory=True):
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
        print 'rax:', state.regs.rax, 'r8', state.regs.r8
        print 'rbx:', state.regs.rbx, 'r9', state.regs.r9
        print 'rcx:', state.regs.rcx, 'r10', state.regs.r10
        print 'rdx:', state.regs.rdx, 'r11', state.regs.r11
        print 'rsi:', state.regs.rsi, 'r12', state.regs.r12
        print 'rdi:', state.regs.rdi, 'r13', state.regs.r13
        print 'rsp:', state.regs.rsp, 'r14', state.regs.r14
        print 'rbp:', state.regs.rbp, 'r15', state.regs.r15
        print 'gs:', state.regs.gs
        return

    def debug_simgr(self, simgr, save_memory=True):
        print 'dumping active'
        if not save_memory:
            for state in simgr.stashes['active']:
                self.debug_state(state, save_memory)

    def set_loader_concret_memory_region(self, s, addr, buf, length):
        aligned_addr = addr & 0xfffffffffffff000
        # self.b.loader.memory.write_bytes(aligned_addr,buf)
        try:
            self.b.loader.memory.add_backer(aligned_addr, buf)
        except ValueError:
            print('ValueError: Address is already backed!')
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
        con = self.statebroker.get_a_page(r, gs_addr)
        if con != None:
            self.set_concret_memory_region(s, gs_addr, con, 4096)
        else:
            raw_input('failed to get gs')
        print 'finished installing gs'

    def install_stack(self, s):
        r = self.r
        rsp_addr = self.sol.eval(s.regs.rsp, 1)[0]
        print 'install rsp...'
        con = self.statebroker.get_a_page(r, rsp_addr)
        if con != None:
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
                                    print('[!] failed to resolve the uninit memory')
                                    if self.pause_on_failed_memory_resolving:
                                        for addr in state.history_iterator:
                                            print addr
                                        # import IPython; IPython.embed()
                            if self.pause_on_finish_memory_loading:
                                raw_input('do the read now(continue) <-')
                        except:
                            if r is not None:
                                r.close()
                            print 'failed in resolving'
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
