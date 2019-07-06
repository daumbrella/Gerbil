import angr
import string
from angr.state_plugins.sim_action import SimAction, SimActionConstraint

class miio_memcpy(angr.SimProcedure):
    def run(self):
        '''memcpy = angr.SIM_PROCEDURES['libc']['memcpy']
        self.inline_call(memcpy, self.state.regs.r0,self.state.regs.r1,self.state.regs.r2)'''
        self.state.memory.store(self.state.se.eval(self.state.regs.r0),self.state.memory.load(self.state.se.eval(self.state.regs.r1),self.state.se.eval(self.state.regs.r2)))
        #print "src addr: ",hex(self.state.se.eval(self.state.regs.r0))
        #print "dst addr: ",hex(self.state.se.eval(self.state.regs.r1))
        #print self.state.se.eval(self.state.regs.r2)
        operations="<Operation {0} ({1}, {2}, {3})>".format("miio_memcpy",hex(self.state.se.eval(self.state.regs.r0)),hex(self.state.se.eval(self.state.regs.r1)),self.state.se.eval(self.state.regs.r2))
        print operations
        sac = SimActionConstraint(self.state,operations)
        self.state.history.add_action(sac)
        self.state.regs.ip=self.state.regs.lr
        return
