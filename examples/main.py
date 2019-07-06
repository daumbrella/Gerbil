import angr
import claripy
import re
from angr.state_plugins.sim_action import SimAction, SimActionConstraint
from cle.address_translator import AT
import cPickle as pickle
import time
import logging
import binascii
import os
import string


def pickle_load_cfg_fast(filename):
    f_cfg=file(filename,'rb')
    cfg_fast=pickle.load(f_cfg)
    f_cfg.close()
    return cfg_fast

def pickle_dump_cfg_fast(filename,cfg):
    f_cfg=file(filename,'wb')
    cfg_fast=pickle.dump(cfg,f_cfg,-1)
    f_cfg.close()

def pickle_load_callgraph(start_addr):
    f_cfg=file('callgraph_'+hex(start_addr), 'rb')
    callgraph=pickle.load(f_cfg)
    f_cfg.close()
    return callgraph

def pickle_dump_fm_fast(filename,fm):
    f_fm=file(filename,'wb')
    pickle.dump(fm,f_fm,-1)
    f_fm.close()

def pickle_load_fm_fast(filename):
    f_fm=file(filename,'rb')
    fm=pickle.load(f_fm)
    f_fm.close()
    return fm

def pickle_dump_fm_accurate(filename,fm):
    f_fm=file(filename,'wb')
    pickle.dump(fm,f_fm,-1)
    f_fm.close()

def pickle_load_fm_accurate(filename):
    f_fm=file(filename,'rb')
    fm=pickle.load(f_fm)
    f_fm.close()
    return fm

def get_sym_variables(state,key):
    variables=list(state.solver.get_variables(key))
    symbol_vars=list()
    for var in variables:
        symbol_vars.append(var[1])
    return symbol_vars

def getSegments(filepath):
    segments=[]
    firmware=open(filepath,'rb')
    segment_header=firmware.read(0xc8)
    segment_header= segment_header.encode('hex')
    num_segment=int(convertBE(segment_header[24:28]))
    for i in range(num_segment):
        offset=int(convertBE(segment_header[40*(i+1)+8:40*(i+1)+16]),16)
        length=int(convertBE(segment_header[40*(i+1)+16:40*(i+1)+24]),16)
        base_addr=int(convertBE(segment_header[40*(i+1)+24:40*(i+1)+32]),16)
        segment_each=(offset,base_addr,length)
        segments.append(segment_each)
    firmware.close()
    return segments

def convertBE(hexstr):
    return hexstr.decode('hex')[::-1].encode('hex_codec') 

def search_target_func(proj,target_regex):
    target_pattern=re.compile(target_regex)
    target_list=list()
    binary=proj.loader.main_object
    strides = binary.memory.stride_repr
    for start_, _, bytes_ in strides:
        for mo in target_pattern.finditer(bytes_):
            #print str(binascii.b2a_hex(bytes_))[2:-1]
            position = mo.start() + start_
            if position % proj.arch.instruction_alignment == 0:
                func_addr=AT.from_rva(position, binary).to_mva()
                if func_addr%2==0:
                    func_addr+=1
                target_list.append(func_addr)
    return target_list

def getMainSegment(segments):
    main_segment=(0,0,0)
    main_list=list()
    for seg in segments:
        if seg[2] > main_segment[2]:
             main_segment=seg
    main_list.append(main_segment)
    return main_list

def get_all_call_addr(callgraph,target_addr):
    call_addr=list()
    target_list=list()
    traced_list=list()
    target_list.append(target_addr)
    traced_list.append(target_addr)
    for target in target_list:
        call_list=list(callgraph.predecessors(target))
        print call_list
        if len(call_list)>0:
            for call in call_list:
                if call not in traced_list:
                    target_list.append(call)
                traced_list.append(call)
        else:
            call_addr.append(target)
    return call_addr

def fiter_constraints(proj,start_addr):
    start_time=time.time()
    start_addr_hex=hex(start_addr)
    fm_name="fm_"+start_addr_hex
    function_manager=None
    if os.path.exists(fm_name):
        print "The function manager has existed, load it...."
        function_manager=pickle_load_fm_accurate(fm_name)
    else:
        print "The function manager not exists, pickle it...."
        start_state=proj.factory.blank_state(addr=start_addr)
        cfg=proj.analyses.CFGAccurate(keep_state=True,starts=[start_state.addr],initial_state=start_state)
        function_manager=cfg.kb.functions
        pickle_dump_fm_accurate(fm_name,function_manager)
    functions=function_manager.itervalues()
    start_state=proj.factory.blank_state(addr=start_addr,add_options={"TRACK_CONSTRAINT_ACTIONS"},remove_options={angr.options.LAZY_SOLVES})
    start_state.register_plugin('loop_data', angr.state_plugins.SimStateLoopData())
    sm=proj.factory.simulation_manager(start_state,function_manager=function_manager,category='marvl',filter_constraints=True)
    logging.getLogger("angr.exploration_techniques.loop_seer").setLevel("DEBUG")
    print "Start filter the contraints..."
    #avoid=0x1F03E1AF,
    #find=0x1F0412E9
    #find=0x1F0387F1
    sm.use_technique(angr.exploration_techniques.FilterContraints(find=0x1F041395,functions=functions, bound=2,loop_limit=True,num_find=1))
    sm.run()
    for found in sm.found:
        constraints=found.history.constraints_since(start_state)
        print len(constraints)
        print found.solver.constraints
        for con in constraints:
            if "Operation" in str(con):
                print con
        recv_data_list=get_sym_variables(found,"recv_data")
        for recv_data in recv_data_list:
            print hex(found.solver.eval(recv_data,cast_to=int))
    end_time=time.time()
        #print found.solver.constraints
    print "This filter cost time :  ",end_time-start_time

def analyses_mrvl():
    filepath=''
    segments=getSegments(filepath)
    print segments
    main_segment=getMainSegment(segments)
    print main_segment
    base_addr=main_segment[0][1]
    proj = angr.Project(filepath,load_options={'auto_load_libs':False},main_opts={'backend':'blob','custom_base_addr':base_addr,'custom_entry_point':base_addr,'custom_arch':'arm','segments':main_segment})
    target_regex=br"\x08\xB5\x08\xB9\x0C\x48\x04\xE0\x09\xB9\x0C\x48\x01\xE0\x3A\xB9\x0B\x48"
    target_addr=search_target_func(proj,target_regex)[0]
    print "Find target function at addr : ",hex(target_addr)
    cfg_fast=None
    fm_fast=None
    fm_accurate=None
    cfg_file="cfg_all_"+filename
    fm_fast_file="fm_fast_"+filename
    if not os.path.exists(cfg_file):
        print "The cfg_file not exists, construct it..."
        cfg_start_time=time.time()
        cfg_fast= proj.analyses.CFG(force_complete_scan=True)
        fm_fast=cfg_fast.kb.functions
        pickle_dump_cfg_fast(cfg_file,cfg_fast)
        pickle_dump_fm_fast(fm_fast_file,fm_fast)
        cfg_end_time=time.time()
        print "Construct the cfg all costs ",cfg_end_time-cfg_start_time
    else:
        print "The cfg_file has existed, load it..."
        cfg_fast=pickle_load_cfg_fast(cfg_file)
        fm_fast=pickle_load_fm_fast(fm_fast_file)
    start_addr=list()
    start_addr=get_all_call_addr(fm_fast.callgraph,target_addr)
    print "Get all start addrs : "
    #for sa in start_addr:
        #print hex(sa)
    for sa in start_addr:
        fiter_constraints(proj,sa)


def get_cmds():
    filepath='upd_lumi.gateway.v3.1.4.1_161.bin'
    filename='upd_lumi.gateway.v3.1.4.1_161.bin'
    base_addr=0x1f000000
    proj=angr.Project(filepath,load_options={'auto_load_libs':False},main_opts={'backend':'blob','custom_base_addr':base_addr,'custom_entry_point':base_addr,'custom_arch':'arm'})
    memory=proj.loader.memory
    start_map_addr=0x1F003260
    end_map_addr=0x1F003764
    cmd_func=dict()
    cmd_map_state=proj.factory.blank_state(addr=start_map_addr)
    while start_map_addr<end_map_addr:
        func_addr=memory.read_addr_at(start_map_addr, 4)
        cmd_addr=memory.read_addr_at(start_map_addr+4, 4)
        cmd_str = ""
        offset = 0
        current_char = memory[cmd_addr + offset]
        while current_char in string.printable:
            cmd_str += current_char
            offset += 1
            current_char = memory[cmd_addr + offset]
        cmd_func.update({cmd_str:func_addr})
        start_map_addr+=8
    for cmd in cmd_func.keys():
        print(cmd)
        start_state=proj.factory.blank_state(addr=cmd_func[cmd],add_options={"TRACK_CONSTRAINT_ACTIONS"},remove_options={angr.options.LAZY_SOLVES})
        start_state.register_plugin('loop_data', angr.state_plugins.SimStateLoopData())
        function_manager=None
        fm_name="fm_"+hex(cmd_func[cmd])
        if os.path.exists(fm_name):
            print "The function manager has existed, load it...."
            function_manager=pickle_load_fm_accurate(fm_name)
        else:
            print "The function manager not exists, pickle it...."
            cfg=proj.analyses.CFGAccurate(keep_state=True,starts=[start_state.addr],initial_state=start_state)
            function_manager=cfg.kb.functions
            pickle_dump_fm_accurate(fm_name,function_manager)
        functions=function_manager.itervalues()
        sm=proj.factory.simulation_manager(start_state,function_manager=function_manager,category='marvl',filter_constraints=True)
        logging.getLogger("angr.exploration_techniques.loop_seer").setLevel("DEBUG")
        print "Start filter the contraints..."
        #avoid=0x1F03E1AF,
        #find=0x1F0412E9
        #find=0x1F0387F1
        sm.use_technique(angr.exploration_techniques.FilterContraints(find=0x1F04AFF5,avoid=0x1F013A91,functions=functions, bound=1,loop_limit=True,num_find=1))
        sm.run()
        for found in sm.found:
            constraints=found.history.constraints_since(start_state)
            print len(constraints)
            print found.solver.constraints
            for con in constraints:
                if "Operation" in str(con):
                    print con
        print

analyses_mrvl()
'''filepath='upd_lumi.gateway.v3.1.4.1_161.bin'
filename='upd_lumi.gateway.v3.1.4.1_161.bin'
base_addr=0x1f000000
proj=angr.Project(filepath,load_options={'auto_load_libs':False},main_opts={'backend':'blob','custom_base_addr':base_addr,'custom_entry_point':base_addr,'custom_arch':'arm'})
cfg_fast=None
fm_fast=None
cfg_accurate=None
fm_accurate=None
cfg_file="cfg_all_"+filename
fm_fast_file="fm_fast_"+filename
if not os.path.exists(cfg_file):
    print "The cfg_file not exists, construct it..."
    cfg_start_time=time.time()
    cfg_fast= proj.analyses.CFG(force_complete_scan=True)
    fm_fast=cfg_fast.kb.functions
    pickle_dump_cfg_fast(cfg_file,cfg_fast)
    pickle_dump_fm_fast(fm_fast_file,fm_fast)
    cfg_end_time=time.time()
    print "Construct the cfg all costs ",cfg_end_time-cfg_start_time
else:
    print "The cfg_file has existed, load it..."
    cfg_fast=pickle_load_cfg_fast(cfg_file)
    fm_fast=pickle_load_fm_fast(fm_fast_file)'''
