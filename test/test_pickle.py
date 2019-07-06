import angr
import claripy
import re
from angr.state_plugins.sim_action import SimAction, SimActionConstraint
from cle.address_translator import AT
import cPickle as pickle
import time
import logging


def get_all_call_addr(callgraph,target_addr):
    call_addr=list()
    target_list=list()
    traced_list=list()
    target_list.append(target_addr)
    traced_list.append(target_addr)
    for target in target_list:
        call_list=list(callgraph.predecessors(target))
        if len(call_list)>0:
            for call in call_list:
                if call not in traced_list:
                    target_list.append(call)
                traced_list.append(call)
        else:
            call_addr.append(hex(target))
    return call_addr

def test_pickle_cfg():
    proj = angr.Project("gateway2.bin",load_options={'auto_load_libs':False},main_opts={'backend':'blob','custom_base_addr':0x1f003740,'custom_arch':'arm','segments':[(0x0,0x1f003740,0x827e0)]})
    cfg_start=time.time()
    cfg = proj.analyses.CFG(force_complete_scan=True)
    cfg_end=time.time()
    callgraph=cfg.kb.functions.callgraph
    print "construct the cfg costs ",cfg_end-cfg_start
    pickle_start=time.time()
    f_cfg=file('callgraph_all', 'wb')
    pickle.dump(callgraph, f_cfg, -1)
    f_cfg.close()
    pickle_end=time.time()
    print "write the cfg costs ",pickle_start-pickle_end
    
    f_cfg=file('callgraph_all', 'rb')
    pickle_start=time.time()
    callgraph=pickle.load(f_cfg)
    pickle_end=time.time()
    print "get the cfg costs ",pickle_start-pickle_end 
    print get_all_call_addr(callgraph,0x1F005363)

def pickle_fm():
    proj = angr.Project("gateway2.bin",load_options={'auto_load_libs':False},main_opts={'backend':'blob','custom_base_addr':0x1f003740,'custom_arch':'arm','segments':[(0x0,0x1f003740,0x827e0)]})
    start_addr=0x1F059781
    start_state=proj.factory.blank_state(addr=start_addr,add_options={"TRACK_CONSTRAINT_ACTIONS"})
    cfg_start=time.time()
    cfg=proj.analyses.CFGAccurate(starts=[start_state.addr])
    cfg_end=time.time()
    fm=cfg.kb.functions
    print "get funcyion manager costs ",cfg_end-cfg_start
    f_fm=file('fm_0x1F059781','wb')
    pickle.dump(fm,f_fm,-1)
    f_fm.close()
    f_fm2=file('fm_0x1F059781','rb')
    fm2=pickle.load(f_fm2)
    print fm2.sig
    find_func=fm2.function(addr=0x1F059781)
    print find_func.byteStr32
    print find_func.identify_lib_func

def pickle_load_fm(filename):
    f_fm=file(filename,'rb')
    fm=pickle.load(f_fm)
    f_fm.close()
    return fm

def pickle_load_cfg_fast():
    f_cfg=file('cfg_all','rb')
    cfg_fast=pickle.load(f_cfg)
    f_cfg.close()
    return cfg_fast

def test_loop_function():
    proj = angr.Project("gateway2.bin",load_options={'auto_load_libs':False},main_opts={'backend':'blob','custom_base_addr':0x1f003740,'custom_arch':'arm','segments':[(0x0,0x1f003740,0x827e0)]})
    start_addr=0x1F040CF1
    '''add_constraints=angr.SIM_PROCEDURES['marvl']['add_constraints']
    proj.hook(0x1F06DA09,add_constraints(func_name="copy"))
    proj.hook(0x1F04B10D,add_constraints(func_name="sub_1F04B10D"))
    proj.hook(0x1F059E61,add_constraints(func_name="sub_1F059E60"))
    proj.hook(0x1F05B30D,add_constraints(func_name="netbuf_alloc")) dead loop 
    proj.hook(0x1F06DC05,add_constraints(func_name="sub_1F06DC04"))
    proj.hook(0x1F041649,add_constraints(func_name="call_networksendto"))
    proj.hook(0x1F059F59,add_constraints(func_name="sub_1F059F58"))'''
    function_manager=pickle_load_fm("fm_all")
    functions=function_manager.itervalues()
    start_state=proj.factory.blank_state(addr=start_addr,add_options={"TRACK_CONSTRAINT_ACTIONS"})
    start_state.register_plugin('loop_data', angr.state_plugins.SimStateLoopData())
    function_manager=pickle_load_fm("fm_0x1F0402E5")
    sm=proj.factory.simulation_manager(start_state,function_manager=function_manager,category='marvl',filter_constraints=True)
    cfg=pickle_load_cfg_fast()
    logging.getLogger("angr.exploration_techniques.loop_seer").setLevel("DEBUG")
    sm.use_technique(angr.exploration_techniques.LoopSeer(cfg=cfg, functions=functions, bound=1))
    sm.run()
    for state in sm.deadended:
        print hex(state.addr)

test_loop_function()
