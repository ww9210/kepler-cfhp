import traceback


class SmashGadgetMixin:
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
