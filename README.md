# kepler-cfhp
## What is Kepler
Kepler is a set of tools to facilitate exploitability evaluation of control-flow hijacking primitives in linux kernel , here is the baisc idea of how it works:

1. **Gadget identification** it scans the kernel binary image for several types of pre-defined gadgets
2. **Gadget chain identification** Following a code-reuse template (we called it single-shot exploitation), kepler enumerate all possible combination of gadgets and use symbolic execution to verify whether the exploit chain works.

The proposed technique could enhance an exploit primitive and bypass the following mitigations:
1. **SMEP**
2. **SMAP**
3. **stack canary**
4. **STATIC_USERMODEHELPER_PATH**
5. **non-executable physmap**
6. **hypervisor based cr4 protection**

## Dependency
angr, qemu-system-x86_64, ROPGadget, pwntools, GDB, gef, capstone, fuze

## Cite
```
@inproceedings{wu2019kepler,
  title={$\{$KEPLER$\}$: Facilitating Control-flow Hijacking Primitive Evaluation for Linux Kernel Vulnerabilities},
  author={Wu, Wei and Chen, Yueqi and Xing, Xinyu and Zou, Wei},
  booktitle={28th $\{$USENIX$\}$ Security Symposium ($\{$USENIX$\}$ Security 19)},
  pages={1187--1204},
  year={2019}
}
```
