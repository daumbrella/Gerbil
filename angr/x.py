# coding: utf-8
import angr
p = angr.Project('../../binaries/tests/i386/test_arrays.exe')
p.loader.memory[p.entry] = '\xcd'
p.loader.memory[p.entry+1] = '\x80'

s = p.factory.simgr()
s.one_active.regs.eax = 4
s.one_active.options.add(angr.options.BYPASS_UNSUPPORTED_SYSCALL)
import IPython; IPython.embed()
