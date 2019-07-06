lib_nums_file=open('hf-mc300_results.txt','r')
results_lib=dict()
lines=lib_nums_file.readlines()
for line in lines:
    line=line.split(' ')
    print (line)
    fw_name=line[0]
    total_num=int(line[1])
    lib_num=int(line[2])
    total_size=int(line[3])
    lib_size=int(line[4])
    if fw_name in results_lib.keys():
        old_nums=results_lib[fw_name]
        old_total_num=old_nums[0]
        old_lib_num=old_nums[1]
        old_total_size=old_nums[2]
        old_lib_size=old_nums[3]
        new_nums=(old_total_num+total_num,old_lib_num+lib_num,old_total_size+total_size,old_lib_size+lib_size)
        results_lib.update({fw_name:new_nums})
    else:
        new_nums=(total_num,lib_num,total_size,lib_size)
        results_lib.update({fw_name:new_nums})
lib_nums_file.close()
for fw_name in results_lib.keys():
    print (str(fw_name)+","+str(results_lib[fw_name])+","+str(results_lib[fw_name][1]*1.0/results_lib[fw_name][0])+","+str(results_lib[fw_name][3]*1.0/results_lib[fw_name][2]))



