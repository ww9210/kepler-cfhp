import colorama
import traceback
import angr
from state_filters import *
class ForkingGadgetMixin:
    def enforce_fork_on_bloom(self, state):
        fork_gadget = self.current_forking_gadget
        fork_entry = fork_gadget[0]
        print('=' * 78)
        print('Call instruction at:', state.inspect.function_address)
        self.reach_current_bloom_site = True
        state.osokplugin.reach_bloom_site = True
        # import IPython; IPython.embed()
        if state.regs.rip.symbolic:
            print(colorama.Fore.RED + '[+] connecting bloom and fork by adding constraint' \
                  + colorama.Style.RESET_ALL)
            state.add_constraints(state.regs.rip == fork_entry)  # add constraint
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
            # import IPython; IPython.embed()
            # assert(0)
        return

    def get_forking_gadget_entry_and_sites(self, fork_gadget):
        #  return entry and first site  and second site
        return fork_gadget[0], fork_gadget[2][0][1], fork_gadget[2][1][1]

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
        callback function at the 2nd fork site (2nd is only an index, does not mean the site is reached first
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
                        , constraints
                        , list(state.osokplugin.constraints_at_firstly_reached_site)
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
            self.good_bloom_fork_gadget_pair.append([list(self.current_bloom_gadget), list(self.current_forking_gadget)
                    , constraints
                    , list(state.osokplugin.constraints_at_firstly_reached_site)
                    , list(state.osokplugin.history_bbls_to_firstly_reached_fork_site), 1])
        #import IPython; IPython.embed()
        return

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

        #state.inspect.b('mem_read', when=angr.BP_BEFORE, action=self.track_reads)
        #state.inspect.b('mem_write', when=angr.BP_BEFORE, action=self.track_writes)

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
        bloom_state = good_bloom_gadget[1]  # the bloom state is stored in good_bloom_gadget
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
            #self.debug_simgr(simgr)
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

            if self.reach_current_bloom_site is True:
                print('reached the bloom site, next going to reach forking site')

            if self.reach_current_bloom_site is True:
                print('reached bloom site')
                if self.reach_current_fork_gadget is True:
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