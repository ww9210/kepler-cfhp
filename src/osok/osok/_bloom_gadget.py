import angr
import traceback
import time
import datetime
from state_filters import *
from IPython import embed


class BloomGadgetMixin:
    def get_number_of_bloomed_regs(self, state):
        """
        Check state to see how many registers are under our control
        :param state:
        :return:
        """
        num = 0
        reg_names = ['rax', 'rbx', 'rcx', 'rdx', 'rdi', 'rsi', 'r8', 'r9']
        bloomed_regs = []
        for reg_name in reg_names:
            # print reg_name
            val = state.registers.load(reg_name)
            if val.symbolic:  # symbolic registers are considered under control
                # print reg_name, val
                bloomed_regs.append(reg_name)
            elif val.concrete:
                try:
                    if type(val) == angr.state_plugins.sim_action_object.SimActionObject:
                        val = val.to_claripy()
                    val_number = self.sol.eval(val, 1)[0]
                    if self.controlled_memory_base <= val_number < self.controlled_memory_base + self.controlled_memory_size:
                        # print reg_name, val
                        bloomed_regs.append(reg_name)  # registers pointing to symbolic memory region are also considered under control
                except:
                    traceback.print_exc()
                    import IPython; IPython.embed()

            # import IPython; IPython.embed()
        # return len(bloomed_regs)
        return bloomed_regs

    def get_blooming_gadget_entry_and_site(self, bloom_gadget):
        """
        get entry and site of a blooming gadget
        :param bloom_gadget:
        :return:  entry of bloom gadget, bloom_site
        """
        return bloom_gadget[0], bloom_gadget[2]  # entry, site


    def check_bloom_regs(self, state):
        print('=' * 78)
        print('Call instruction at:', state.inspect.function_address)
        print 'lalala'

        current_gadget = self.current_bloom_gadget

        if self.sol.eval(state.ip, 1)[0] == current_gadget[2]:  # TODO: isn't check redundant
            self.reach_current_bloom_site = True

        # calculating bloomed registers
        bloomed_regs = self.get_number_of_bloomed_regs(state)
        number_of_bloomed_regs = len(bloomed_regs)
        print('[+] there are %d bloomed regsiters' % (number_of_bloomed_regs))

        if number_of_bloomed_regs >= 3:
            self.good_bloom_gadget.append([self.current_bloom_gadget, state.copy(), bloomed_regs])
            print 'blooming: %s!!!' % (self.current_bloom_gadget[1])
            print bloomed_regs
            # import IPython; IPython.embed()

        if state.regs.rdi.symbolic and state.regs.rsi.symbolic and state.regs.rdx.symbolic:
            self.good_bloom_gadget.append([self.current_bloom_gadget, state.copy(), bloomed_regs])
            print 'perfect blooming! %s' % (self.current_bloom_gadget[1])
            print bloomed_regs
            # import IPython; IPython.embed()
        return

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

    def run_bloom_gadget(self, state, bloom_gadget, first_constraint_func=None, previous_blooming_gadget=None):
        """
        symbolically execute the blooming gadget, and find the blooming site
        :param state:
        :param bloom_gadget:
        :param first_constraint_func:
        :return:
        """
        print bloom_gadget
        self.current_bloom_gadget = bloom_gadget
        self.reach_current_bloom_site=False
        bloom_entry, bloom_site = self.get_blooming_gadget_entry_and_site(bloom_gadget)

        if self.add_bloom_instrumentation:
            print 'add bloom instrumentation'
            self.instrument_bloom(state, bloom_entry, bloom_site, bloom_gadget)

        if first_constraint_func is not None:
            first_constraint_func(state, bloom_entry)

        if self.use_controlled_data_concretization:  # use controlled_data_concretization
            print 'add concretization strategy'
            self.add_concretization_strategy_controlled_data(state)


        b = self.b
        sol = self.sol
        print 'initilizing sim group'
        simgr = b.factory.simgr(state, save_unconstrained=True)
        if self.limit_loop:
            #llimiter = angr.exploration_techniques.LoopLimiter(count=5)
            #simgr.use_technique(llimiter)
            pass
        loop_idx = 0
        seen_bloom_state = False
        print 'inspecting simgr...'
        print simgr.active
        while True:
            print '[+] '+str(loop_idx)+' step()'
            #self.debug_simgr(simgr)
            try:
                simgr.step(stash='active')
                print 'inspecting simgr...'
                print simgr.active
                simgr.move(from_stash='active', to_stash='deadended', filter_func=filter_bad_rip)
                #import IPython; IPython.embed()
            except:
                print 'wtf simgr error'
                traceback.print_exc()
                #raw_input()
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
                    x = xxx.next()
                    second_to_last_history = xx.addr
                    third_to_last_history = x.addr
                    if third_to_last_history is None:
                        #embed()
                        third_to_last_history = second_to_last_history
                    if bloom_site in self.b.factory.block(ucstate.history.addr).instruction_addrs:
                        # if the unconstrained state is generated from the bloom_site
                        print 'reached current bloom site'
                        self.reach_current_bloom_site = True
                        bloomed_regs = self.get_number_of_bloomed_regs(ucstate)
                        number_of_bloomed_regs = len(bloomed_regs)
                        print('[+] there are %d bloomed regsiters' % (number_of_bloomed_regs))
                        if self.require_perfect_bloom_gadget:
                            if ucstate.regs.rdi.symbolic and ucstate.regs.rsi.symbolic and ucstate.regs.rdx.symbolic:
                                if previous_blooming_gadget is not None:
                                    self.good_bloom_gadget.append([self.current_bloom_gadget, ucstate.copy(), \
                                                                   bloomed_regs, previous_blooming_gadget])
                                    if self.track_good_bloom_pairs:
                                        self.good_bloom_pairs.append([previous_blooming_gadget, self.current_bloom_gadget, bloomed_regs])
                                else:
                                    self.good_bloom_gadget.append([self.current_bloom_gadget, ucstate.copy(), \
                                                                   bloomed_regs, previous_blooming_gadget])
                                print 'perfect blooming! %s' % (self.current_bloom_gadget[1])
                                seen_bloom_state = True
                                print bloomed_regs
                            else:  # not perfect blooming
                                continue
                        else:
                            #if number_of_bloomed_regs >= 3:
                            if number_of_bloomed_regs >= 4:
                                self.good_bloom_gadget.append([self.current_bloom_gadget, ucstate.copy(), bloomed_regs])
                                seen_bloom_state = True
                                print 'blooming: %s!!!' % (self.current_bloom_gadget[1])
                            else:
                                continue
                    elif bloom_site in self.b.factory.block(second_to_last_history).instruction_addrs or \
                            bloom_site in self.b.factory.block(third_to_last_history).instruction_addrs:
                        # if the unconstrained state is generated from the bloom_site and a call stub
                        print 'reached current bloom site with a call stub'
                        self.reach_current_bloom_site = True
                        bloomed_regs = self.get_number_of_bloomed_regs(ucstate)
                        number_of_bloomed_regs = len(bloomed_regs)
                        print('[+] there are %d bloomed regsiters' % number_of_bloomed_regs)
                        if self.require_perfect_bloom_gadget:
                            """
                            perfect bloom gadget means rdi, rsi, rdx is all symbolic
                            """
                            if ucstate.regs.rdi.symbolic and ucstate.regs.rsi.symbolic and ucstate.regs.rdx.symbolic:
                                if previous_blooming_gadget is not None:
                                    self.good_bloom_gadget.append([self.current_bloom_gadget, ucstate.copy(),
                                                               bloomed_regs, previous_blooming_gadget])
                                    if self.track_good_bloom_pairs:
                                        self.good_bloom_pairs.append([previous_blooming_gadget, self.current_bloom_gadget, bloomed_regs])
                                else:
                                    self.good_bloom_gadget.append([self.current_bloom_gadget, ucstate.copy(),
                                                                   bloomed_regs, previous_blooming_gadget])
                                print 'perfect blooming! %s' % (self.current_bloom_gadget[1])
                                seen_bloom_state = True
                                print bloomed_regs
                                if self.debug_bloom_verbose:
                                    import IPython; IPython.embed()
                        else:
                            if number_of_bloomed_regs >= 3:
                                self.good_bloom_gadget.append([self.current_bloom_gadget, ucstate.copy(), bloomed_regs])
                                seen_bloom_state = True
                                print 'blooming: %s!!!' % (self.current_bloom_gadget[1])
                                if self.debug_bloom_verbose:
                                    import IPython; IPython.embed()
                    else:  # maybe the function has multiple sites of indirect call, let's just ignore these states.
                        print 'unexpected unconstrained state, inspecting...'
                        for his_addr in ucstate.history_iterator:
                            print his_addr
                        if self.debug_bloom_verbose:
                            #import IPython; IPython.embed()
                            pass
                        #import IPython; IPython.embed()
                        print 'unexpected unconstrained state, removing...'
                        simgr.unconstrained.remove(ucstate)

                print '[+] end of dumping unconstrained states'
                print '[+] wtf has unconstrained states'
                # import IPython; IPython.embed()
                if seen_bloom_state:
                    del simgr
                    return seen_bloom_state

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
                if len(simgr.errored) > 0:
                    pass
                    # import IPython; IPython.embed()
                del simgr
                return

            if self.pause_on_each_step:
                raw_input('step?<-')

        del simgr
        return seen_bloom_state

    def multiple_runs_blooming_gadget(self):
        """
        iterate over all blooming gadget and try to find the good blooming state
        :return: good_bloom_gadget containing the bloom state
        """
        initial_state = self.get_initial_state(switch_cpu=True, control_memory_base=self.controlled_memory_base)
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
        print '[+] symbolic execution of blooming gadget takes up to %f seconds' % executed_time

        self.dump_good_bloom_state()

    def multiple_runs_two_stage_blooming_gadgets(self, skip_first=False, start_idx_for_second_phase=None\
                                                 , save_memory=True):
        """
        iterate over all blooming gadgets in a double loop to find the good blooming state
        :return:
        """
        if not skip_first:
            initial_state = self.get_initial_state(switch_cpu=True)
            total = len(self.bloom_gadgets)
            # first stage
            self.require_perfect_bloom_gadget = False  # temporarily turn off perfect requirement
            for i, bloom_gadget in enumerate(self.bloom_gadgets):
                print '[+] ===== checking %d/%d th bloom gadget... =====' % (i, total)
                tmp_state = initial_state.copy()
                if bloom_gadget[1] == 'udp_v6_early_demux':  # skip black list gadget
                    continue
                self.run_bloom_gadget(tmp_state, bloom_gadget, first_constraint_func=self.first_constraint_func)
                del tmp_state
            print 'identified %d good bloom states in first stage...' % len(self.good_bloom_gadget)
            self.dump_good_bloom_state()

        tmp_good_bloom_gadgets = list(self.good_bloom_gadget)
        self.good_bloom_gadget = []

        # Second stage
        print 'start second stage'
        self.require_perfect_bloom_gadget = True  # turn on our perfect requirement
        for i, good_bloom_gadget in enumerate(tmp_good_bloom_gadgets):
            if start_idx_for_second_phase is not None:
                if i < start_idx_for_second_phase:
                    continue
            print '[+] checking %d/%d good bloom state for second bloom' % (i, len(tmp_good_bloom_gadgets))
            ts = time.time()
            st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
            print st,
            print '[+] now we have found %d good bloom state via double blooming' % len(self.good_bloom_gadget)
            old_good_bloom_states = len(good_bloom_gadget)
            for ii, bloom_gadget in enumerate(self.bloom_gadgets):
                if save_memory:  # improve the memory efficiency of the program
                    for item in self.good_bloom_gadget:
                        del item
                    del self.good_bloom_gadget
                    self.good_bloom_gadget = []
                if bloom_gadget[1] == 'udp_v6_early_demux':  # skip black list gadget
                    continue
                print '[+] double checking %d/%d th bloom gadget...' % (ii, len(self.bloom_gadgets))
                bloom_entry, bloom_site = self.get_blooming_gadget_entry_and_site(bloom_gadget)
                tmp_state = good_bloom_gadget[1].copy()
                # constraining rip to second bloom gadget
                tmp_state.add_constraints(tmp_state.regs.rip == bloom_entry)
                if not tmp_state.satisfiable():
                    print "[-] can not set bloom target to second blooming gadget"
                    # we want to debug the problem here
                    if self.debug_bloom_verbose:
                        import IPython; IPython.embed()
                    return
                self.run_bloom_gadget(tmp_state, bloom_gadget, first_constraint_func=None, previous_blooming_gadget=good_bloom_gadget[0])
                del tmp_state
                new_good_bloom_states = len(good_bloom_gadget) - old_good_bloom_states
                # quick return path, return if we have enough good bloom state
                if new_good_bloom_states > 25:
                    break
            self.dump_good_bloom_state_2nd_discretely(i)
            if len(self.good_bloom_gadget) > 2000:  # we do not need too many good bloom gadget
                break
        del tmp_good_bloom_gadgets
        # dump good bloom state to disk
        self.dump_good_bloom_state_2nd()

    def multiple_runs_second_stage_blooming_gadgets(self, start_idx_for_second_phase=None):
        self.multiple_runs_two_stage_blooming_gadgets(skip_first=True, start_idx_for_second_phase=start_idx_for_second_phase)
