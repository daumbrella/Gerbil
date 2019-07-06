import angr

class netbuf_data(angr.SimProcedure):
    def run(self):
        global recv_data_sm
        recv_data_sm=self.state.solver.BVS('recv_data',100*8)
        self.state.solver.register_variable(recv_data_sm,('recv_data', 9, 800))
        r2=self.state.solver.BVS('r2',8)
        r0=self.state.solver.BVS('r0',8)
        self.state.memory.store(0x33333333,recv_data_sm)
        self.state.memory.store(self.state.regs.r1,0x33333333)
        self.state.memory.store(self.state.regs.r2,r2)
        self.state.regs.r0=r0
        self.state.regs.ip=self.state.regs.lr
