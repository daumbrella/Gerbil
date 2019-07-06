import angr
import string
from angr.state_plugins.sim_action import SimAction, SimActionConstraint

class miio_jsonq(angr.SimProcedure):
    def run(self):
        key_str=self.load_str(self.state.se.eval(self.state.regs.r2,cast_to=int))
        operations="<Operation {0} ({1}, {2}, {3})>".format("miio_jsonq",self.state.regs.r0,self.state.regs.r1,key_str)
        print operations
        sac = SimActionConstraint(self.state,operations)
        self.state.history.add_action(sac)
        self.state.regs.ip=self.state.regs.lr

    def load_str(self,addr):
        memory = self.project.loader.memory
        stn = ""
        if addr not in memory:
            return stn
        offset = 0
        current_char =memory[addr + offset]
        while current_char in string.printable:
            stn += current_char
            offset += 1
            current_char = memory[addr + offset]

        # check that the string was a null terminated string with minimum length
        return stn

