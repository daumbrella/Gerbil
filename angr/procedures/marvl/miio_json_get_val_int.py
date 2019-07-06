import angr
import string
from angr.state_plugins.sim_action import SimAction, SimActionConstraint

class miio_json_get_val_int(angr.SimProcedure):
    def run(self):
        operations="<Operation {0} >".format("miio_json_get_val_int")
        #print operations

