import angr
import string
from angr.state_plugins.sim_action import SimAction, SimActionConstraint

class memcmp(angr.SimProcedure):
    def run(self):
        key_str=self.load_str(self.state.se.eval(self.state.regs.r1,cast_to=int))
        if key_str == "":
            operations="<Operation {0} ({1}, {2}, {3})>".format("memcmp",self.state.regs.r0,self.state.regs.r1,self.state.regs.r2)
        else:
            operations="<Operation {0} ({1}, {2}, {3})>".format("memcmp",self.state.regs.r0,key_str,self.state.regs.r2)
        print operations
        sac = SimActionConstraint(self.state,operations)
        self.state.history.add_action(sac)
        r0=self.state.solver.BVS('memcmp_r0',4*8)
        self.state.regs.r0=r0
        self.state.regs.ip=self.state.regs.lr
        return

    def load_str(self,addr):
        memory = self.project.loader.memory
        stn = ""
        offset = 0
        if addr+offset in memory:
            current_char =memory[addr + offset]
            while current_char in string.printable:
                stn += current_char
                offset += 1
                current_char = memory[addr + offset]

        # check that the string was a null terminated string with minimum length
        return stn
