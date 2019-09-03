import colorama
import angr
import traceback
from state_filters import *
from IPython import embed

class PrologueGadgetMixin:
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
        # import IPython; IPython.embed()
        return signature

    def enter_prologue_callback(self, state):
        """
        this is a bp on the first instruction of the prologue gadget
        we add a bp over call instruction to handle future indirect call
        TODO: BUG here: we did not consider the indirect jump
        :param state:
        :return:
        """
        self.reach_current_prologue_entry = True
        print colorama.Fore.RED + 'enter prologue gadget' + colorama.Style.RESET_ALL
        if not self.is_dfs_search_routine:
            state.inspect.remove_breakpoint("call", self.first_fork_site_bp)
            print '[+] removed the call bp at the first fork site..'
        #
        self.bp_enforce_prologue_to_copy_to_user = state.inspect.b("call", when=angr.BP_BEFORE
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

    def enforce_indirect_jump_to_disclosure_gadget(self, state):
        """
        this function is actually a callback or bp over unconstrained jmp instruction
        :param state:
        :return:
        """
        if state.regs.rip.symbolic:
            print 'trying to extract signature at prologue indirect jump to copy_from_user'
            print colorama.Fore.RED +'jmp instruction at:', hex(state.history.addr) + colorama.Style.RESET_ALL
            self.dump_reg(state)
            print(colorama.Fore.RED + '[+] extracting runtime data flow signature for pairing with disclosure gadget'
                  + colorama.Style.RESET_ALL)
            data_signatures = self.extract_prologue_call_site_signature(state)
            self.current_prologue_signature = data_signatures
            print (colorama.Fore.RED + '[!] removing bp_enforce_prologue_to_copy_to_user)' + colorama.Style.RESET_ALL)
            state.inspect.remove_breakpoint('call', self.bp_enforce_prologue_to_copy_to_user)
            # embed()
        else:
            print 'rip is not symbolic, this should never happen'
            embed()
        return

    def enforce_prologue_to_copy_to_user(self, state):
        """
        this function is actually a callback or bp over unconstrained call instructions
        :param state:
        :return:
        """
        if state.regs.rip.symbolic:
            print 'trying to extract signature at prologue indirect call to copy_from_user'
            print 'Call target address :', state.inspect.function_address
            self.dump_reg(state)  # dump registers for debug purpose
            print(colorama.Fore.RED + '[+] extracting runtime data flow signature for pairing with disclosure gadget'
                  + colorama.Style.RESET_ALL)
            data_signatures = self.extract_prologue_call_site_signature(state)
            self.current_prologue_signature = data_signatures
            print (colorama.Fore.RED + '[!] removing bp_enforce_prologue_to_copy_to_user)' + colorama.Style.RESET_ALL)
            state.inspect.remove_breakpoint('call', self.bp_enforce_prologue_to_copy_to_user)
            # embed()
        else:
            print 'rip is not symbolic, we are not removing this enforcement until we finding one'
            # embed()
        return

    def enforce_prologue_on_first_fork(self, state):
        """
        callback at the first_fork site, will set indirect call target as the prologue gadget
        :param state:
        :return:
        """
        prologue_gadget = self.current_prologue_gadget
        prologue_entry = prologue_gadget[6]
        print '='*78
        print 'Call instruction at:', state.inspect.function_address
        self.reach_current_first_fork_site = True
        print('reached current first fork site')
        if state.regs.rip.symbolic:
            print(colorama.Fore.RED + '[+] connecting first_fork with prologue %x by adding constraint' % prologue_entry
                  + colorama.Style.RESET_ALL)
            state.add_constraints(state.regs.rip == prologue_entry)  # add constraint
            if state.satisfiable():
                print '[+] constraint satisfiable'
                pass
            else:
                print('state is not satisfiable')
                # embed()
                self.unsatisfiable_state.append(state.copy())
            if self.pause_on_prologue_on_fork:
                opt = raw_input('ipython shell? [y/N]')
                if opt == 'y\n':
                    embed()
        else:
            print 'rip is not symbolic wtf'
            # embed()
        return

    def instrument_prologue_gadget(self, state, bloom_gadget, forking_gadget, prologue_gadget, disclosure_gadget \
                                   , first_reached_fork_site):
        """
        instrument state, add callbacks to enforce indirect jump to instrument prologue
        the instrumented callbacks include:
        1. disclosure site callback
        2. entering prologue callback
        3. track memory reads
        4. first fork site callback (optional)
        :param state: the state that already reach the basic block of the first fork stie
        :param bloom_gadget: the bloom gadget information
        :param forking_gadget: the forking gadget information
        :param prologue_gadget: the prologue gadget
        :param disclosure_gadget:  the disclosure gadget
        :param first_reached_fork_site: 1 or 2
        :return:
        """
        # init some parameters
        self.reach_current_bloom_site = False
        self.reach_current_fork_gadget = False
        self.reach_current_first_fork_site = False
        self.reach_current_second_fork_site = False
        self.reach_current_prologue_entry = False
        self.reach_current_prologue_site = False
        self.current_prologue_gadget = prologue_gadget  # set current prologue gadget
        self.current_disclosure_gadget = disclosure_gadget  # set current disclosure gadget
        self.current_prologue_signature = None
        self.bp_enforce_prologue_to_copy_to_user = None

        # register the state plugin to store path sensitive state information
        state.register_plugin('osokplugin', angr.state_plugins.OsokPlugin(False, False, False))

        bloom_entry, bloom_site = self.get_blooming_gadget_entry_and_site(bloom_gadget)
        fork_entry, first_fork_site, second_fork_site = self.get_forking_gadget_entry_and_sites(forking_gadget)

        #get disclosure site(e.g. site of copy from user)xxx this is dirty hack
        try:
            address_near_to_copy_from_user = disclosure_gadget[4][0]['addr']
        except all:
            print 'wtf'
            # embed()

        tmp_bbl = self.b.factory.block(address_near_to_copy_from_user)
        disclosure_site = tmp_bbl.instruction_addrs[-1]  # a dirty way to get the disclosure site

        if first_reached_fork_site == 2:
            first_fork_site, second_fork_site = second_fork_site, first_fork_site  # swap order if we first see second site
        if first_reached_fork_site == 3:
            second_fork_site = first_fork_site
        if first_reached_fork_site == 4:
            first_fork_site = second_fork_site
        prologue_entry = prologue_gadget[6]

        #for constraint in constraints_at_first_fork_site:
        #state.add_constraints(constraint)

        # call breakpoint for first fork site
        if not self.is_dfs_search_routine:
            print 'first fork site: %x' % first_fork_site
            self.first_fork_site_bp = state.inspect.b('call', when=angr.BP_BEFORE
                                                      , instruction=first_fork_site
                                                      , action=self.enforce_prologue_on_first_fork)
        else:
            pass  # in this case, we have already set the indirect jump target of first indirect jump in fork gadget

        # call breakpoint for disclosure site
        print 'copy_to_user site: %x' % disclosure_site
        state.inspect.b('call', when=angr.BP_BEFORE, instruction=disclosure_site
                        , action=self.disclosure_site_callback)
        # state.inspect.remove_breakpoint("call", self.first_fork_site_bp)
        state.inspect.b('mem_read', when=angr.BP_BEFORE, action=self.track_reads)
        state.inspect.b('instruction', when=angr.BP_BEFORE, instruction=prologue_entry
                        , action=self.enter_prologue_callback)
        # state.inspect.b('address_concretization', when=angr.BP_BEFORE, instruction = first_fork_site,
                        #action = self.track_prologue_address_concretization
                        #)

    def run_prologue_and_disclosure_gadget(self, state, bloom_gadget, forking_gadget, prologue_disclosure_pair
                                           , first_reached_fork_site, first_constraint_func=None):
        """
        run symbolic execution from the start of first forking site and disclosure gadget
        We set a set of bps so that we can guide the symbolic execution to find good disclosure state
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
        seen_good_disclosure_site = False
        if len(disclosure_gadget[4]) == 0:
            return
        if self.add_prologue_instrumentation:
            # add instrumentation to reach prologue gadget
            self.instrument_prologue_gadget(state, bloom_gadget, forking_gadget, prologue_gadget
                                            , disclosure_gadget, first_reached_fork_site)

        if first_constraint_func is not None:
            first_constraint_func(state, bloom_entry)

        b = self.b

        simgr = b.factory.simgr(state, save_unconstrained=True)
        print simgr.active
        self.loop_idx_prologue_state = 0
        seen_unconstrained_state = False
        while True:
            if not self.reach_current_prologue_site:  # have not reach the prologue entry
                print '[+] ' + str(self.loop_idx_prologue_state) + ' step()'
                try:
                    # embed()
                    print 'stepping...'
                    simgr.step(stash='active')  # step()
                    print simgr.active
                    for act_state in simgr.active:
                        if filter_bad_rip(act_state):
                            print 'found wtf state:', act_state
                            #embed()
                        if act_state.osokplugin.should_get_killed is True:
                            print "removing state:", act_state
                            simgr.active.remove(act_state)
                    print 'removing bad state to deadended'
                    simgr.move(from_stash='active', to_stash='deadended', filter_func=filter_bad_rip)
                except Exception as e:
                    print e
                    print 'wtf simgr error'
                    traceback.print_exc()
                    raw_input()
                    del simgr
                    return

                self.loop_idx_prologue_state += 1  # increase the loop idx

                if len(simgr.deadended) > 0:
                    print 'has deadended states, inspecting..'
                    # embed()
                    for deadend_state in simgr.deadended:
                        simgr.deadended.remove(deadend_state)  # save memory usage

                if len(simgr.active) == 0 and len(simgr.unconstrained) == 0:
                    print('no active states and unconstrained states left, wtf..')
                    del simgr
                    return

                if self.reach_current_bloom_site is True:  # reach the bloom site
                    print('reached bloom site')
                    if self.reach_current_prologue_site:  # reach the current prologue site
                        print('reached prologue entry in the step')
                        embed()

                if not self.has_indirect_call_thunk:  # the system does not have indirect call stub
                    if not self.use_extended_auxiliary_gadget and self.loop_idx_prologue_state == 3:
                        print 'we should be able to finish the analysis in *three* steps'
                        print 'lets save the good states'
                        for active_state in simgr.stashes['active']:
                            if active_state.osokplugin.has_good_disclosure_site:  # is good disclosure site
                                print active_state, 'is a good disclosure site'
                                # embed()

                                if self.reproduce_mode:  # in reproduce mode add our constraint now
                                    print '[+] reproduce mode: add constraint to ensure successful disclosure'

                                    """
                                    * * adding constraint here, should be very careful with constraint added * *
                                    """
                                    minimal_rdx_disclosure = self.current_disclosure_gadget[1] + 8
                                    active_state.add_constraints(active_state.regs.rdx >= minimal_rdx_disclosure)
                                    active_state.add_constraints(active_state.regs.rdi == 0x41414000 + 0x1000 - minimal_rdx_disclosure)
                                    """
                                    * * end of adding constraint 
                                    """

                                    if not active_state.satisfiable():
                                        print '[!] can not successfully generate good disclosure state'
                                        continue

                                self.tmp_good_disclosure_state_number += 1
                                self.good_disclosure_state.append([active_state.copy()
                                                                  , self.current_bloom_gadget
                                                                  , self.current_forking_gadget
                                                                  , self.current_prologue_gadget
                                                                  , self.current_disclosure_gadget
                                                                  , self.current_firstly_reached_fork_site]
                                                                  )
                        del simgr
                        return
                    if self.use_extended_auxiliary_gadget:
                        # todo
                        pass
                else:  # handling indirect_call_thunk
                    '''
                    when we handle kernel with a lot of call stub such as x86_indirect_thunk_rax, there are more 
                    then three steps
                    '''

                    # checking all active states to see whether we have a good disclosure site
                    for active_state in simgr.stashes['active']:
                        if active_state.osokplugin.has_good_disclosure_site:  # is good disclosure site
                            seen_good_disclosure_site = True
                            print active_state, 'is a good disclosure site'
                            # embed()
                            self.tmp_good_disclosure_state_number += 1
                            # append current state to global good list
                            self.good_disclosure_state.append([active_state.copy()
                                                              , self.current_bloom_gadget
                                                              , self.current_forking_gadget
                                                              , self.current_prologue_gadget
                                                              , self.current_disclosure_gadget
                                                              , self.current_firstly_reached_fork_site]
                                                              )
                    if seen_good_disclosure_site or self.loop_idx_prologue_state > 7:
                        if seen_good_disclosure_site:
                            print 'already found good disclosure site, clean up and return'
                        else:
                            print 'too much steps, abort..'
                        del simgr
                        return

                if simgr.unconstrained:  # having unconstrained states
                    if self.current_prologue_signature is None:
                        for uc_state in simgr.unconstrained:
                            if uc_state.history.jumpkind == 'Ijk_Boring':
                                print 'Previous jumpkind is ', 'Ijk_Boring', 'symbolic indirect jump'
                                # extract prologue signature
                                self.enforce_indirect_jump_to_disclosure_gadget(uc_state)
                                # lets remove the bp at the callsite now

                            else:
                                print 'we already found unconstrained states but no prologue signatures, wtf...'
                                print 'this should never happen...'
                                embed()
                    else:  # already have prologue signature
                        print(colorama.Fore.RED+'[+] found %d unconstrained states' % (len(simgr.unconstrained))
                              + colorama.Style.RESET_ALL)
                        print 'how to handle unconstrained state?'
                        for ucstate in simgr.unconstrained:
                            for addr in ucstate.history_iterator:
                                print addr
                            hotmap, sub_gadget_entry = self.analyze_disclosure_gadget(self.current_disclosure_gadget)
                            if len(sub_gadget_entry) == 0 or sub_gadget_entry == [0, 0, 0]:
                                print 'There is not good sub disclosure gadget entry site, abort this simgr...'
                                del simgr
                                return
                            target_addrs = self.decide_disclosure_landing_site(self.current_prologue_signature
                                                                               , hotmap, sub_gadget_entry)
                            if target_addrs is None:
                                print 'There is not good target landing disclosure gadget site, abort this simgr...'
                                del simgr
                                return
                            else:
                                print 'there are %d candidates of landing targets' % (len(target_addrs))
                                for i, target_addr in enumerate(target_addrs):
                                    print 'generating state for %dth landing target' % i
                                    new_state = ucstate.copy()
                                    print 'constraining the rip to %x' % target_addr
                                    new_state.add_constraints(ucstate.regs.rip == target_addr)
                                    if new_state.satisfiable():
                                        print 'appending the cloned state to active stash'
                                        simgr.stashes['active'].insert(1, new_state)
                                    else:
                                        print 'found unsatisfiable states'
                                        self.unsatisfiable_state.append(new_state)
                                # embed()

                        print 'remove unconstrained state'
                        simgr.stashes['unconstrained'] = []
                        #embed()
                    pass
                # TODO what if we can not reach the first fork site

                pass
            else:  # already reached the current prologue site
                print('already reached prologue entry')
                embed()
                pass
                # TODO

    def multiple_runs_prologue_and_disclosure_gadgets(self, good_bloom_and_fork_gadget):
        """
        firstly run symbolic tracing using histroy bbl_addrs, then start symbolic exploration from the bloom state,
        :param good_bloom_and_fork_gadget: a good pair of bloom gadget and fork gadget
        :return: None
        """
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
            fork_site_state = self.run_symbolic_tracing_to_first_fork_site(tmp_state, bloom_gadget,
                forking_gadget, history_bbl_addrs, first_constraint_func=self.first_constraint_func)
            del tmp_state
            trial_number += 1
        if fork_site_state is None:
            print('failed symbolic tracing attempt')
            embed()
            return
        print 'finished symbolic tracing'
        for i, prologue_disclosure_pair in enumerate(self.prologue_disclosure_pairs):
            print '====== checking ' + colorama.Fore.RED\
                  + '%d/%d ' % (i, len(self.prologue_disclosure_pairs)) + colorama.Style.RESET_ALL\
                  + 'pair of prologue and disclosure gadget'

            # embed()
            tmp_state = fork_site_state.copy()
            self.run_prologue_and_disclosure_gadget(tmp_state, bloom_gadget, forking_gadget, prologue_disclosure_pair
                , first_reached_fork_site, first_constraint_func=None)
            del tmp_state
            # fast path: if we get several states, just return
            if self.fast_path_for_disclosure_state and self.tmp_good_disclosure_state_number > 10:
                print colorama.Fore.CYAN + 'we already get enough states, just return' + colorama.Style.RESET_ALL
                del fork_site_state
                return
        del fork_site_state