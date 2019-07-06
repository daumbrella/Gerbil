import angr
import string
from angr.state_plugins.sim_action import SimAction, SimActionConstraint

class miio_json_str_to_int(angr.SimProcedure):
    def run(self):
        operations="<Operation> miio_json_str_to_int"
        print operations
