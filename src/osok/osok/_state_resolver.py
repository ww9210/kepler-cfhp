"""
In the dream we hope angr load the kernel correctly but unfortunately it does not.
We need to update the kernel image to fix text section content, there are several different sites in such kernel images,
by comparing QEMU state and the state load by angr.
To do that we will iterate over the angr state, load those pages from QEMU, if there is any difference, we will fix that.
"""
import hashlib
from IPython import embed


class StateResolverMixin:
    def reset_backer_memory(self, addr, buf):
        aligned_addr = addr & 0xfffffffffffff000
        try:
            self.b.loader.memory.write_bytes(aligned_addr, buf)
        except ValueError as e:
            print e
            embed()
            pass
        except TypeError as e:
            print e
            embed()
            pass

    def fix_a_section(self, s, name='.text', white_list=[0xffffffff81c03000]):
        # get text section
        r = self.r
        section = self.b.loader.main_object.sections_map[name]
        section_offset = section.vaddr
        section_length = section.memsize
        if section_length % 4096 != 0:
            section_length = ((section_length / 4096) + 1) * 4096
        num_of_page = section_length / 4096
        print 'installing', num_of_page, 'pages of section:', name
        for i in range(num_of_page):
            # print i
            addr = section_offset + i * 4096

            # skip page in white_list
            if addr in white_list:
                print 'skip addr: %x' % addr
                continue

            qemu_con = self.statebroker.get_a_page(r, addr)
            if qemu_con is not None:
                # get old content of that page from backer
                cle_con = ''.join(self.b.loader.memory.read_bytes(addr, 4096))
                # calculate the md5 of cle memory and qemu memory content
                cle_md5 = hashlib.md5(cle_con).hexdigest()
                qemu_md5 = hashlib.md5(qemu_con).hexdigest()
                if cle_md5 != qemu_md5:
                    self.reset_backer_memory(addr, qemu_con)
                else:
                    if self.reproduce_mode:
                        pass
                    else:
                        #print 'same content for cle and qemu at page %x, skip' % addr
                        pass
            else:
                raw_input('failed to get_a_page')
        print 'Finished fixing section:', name
        return
