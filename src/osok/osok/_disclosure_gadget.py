import colorama
class DisclosureGadgetMixin:
    def decide_disclosure_landing_site(self, prologue_signature, hotmap, sub_gadget_entry):
        """
        TODO: heurisitic to decide disclosure landing site, would be useful to speed up the osok
        :param prologue_signature:
        :param hotmap:
        :param sub_gadget_entry:
        :return:
        """
        print 'hotmap', hotmap
        if str(hotmap) == '[1, 2, 3]':  # 1
            # todo
            pass
        elif str(hotmap) == '[1, 3, 2]':  # 2
            # todo
            pass
        elif str(hotmap) == '[2, 1, 3]':  # 3
            # todo
            pass
        elif str(hotmap) == '[3, 1, 2]':  # 4
            # todo
            pass
        elif str(hotmap) == '[3, 2, 1]':  # 5
            # todo
            pass
        elif str(hotmap) == '[2, 3, 1]':  # 6
            # todo
            pass
        elif str(hotmap) == '[2, 1, 0]':  # 7
            # todo
            pass
        elif str(hotmap) == '[1, 2, 0]':  # 8
            # todo
            pass
        elif str(hotmap) == '[0, 2, 1]':  # 9
            # todo
            pass
        elif str(hotmap) == '[0, 1, 2]':  # 10
            # todo
            pass
        elif str(hotmap) == '[0, 1, 0]':  # 11
            # todo
            pass
        elif str(hotmap) == '[0, 0, 0]':  # 12
            # todo
            pass
        return [x for x in sub_gadget_entry if x != 0]

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