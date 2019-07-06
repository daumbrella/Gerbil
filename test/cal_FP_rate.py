


gerbil_FP_file=open('gerbil_FP.txt','r')
angr_FP_file=open('angr_FP.txt','r')

total_num=0
FPR=0
count=0
for line in angr_FP_file.readlines():
    if 'total num' in line:
        total_num=float(line[12:])
        print total_num
    if 'wrong num' in line:
        wrong_num=int(line[11:])
        count=count+1
        print wrong_num
        if total_num==0:
            continue
        FPR=FPR+(wrong_num/total_num)
FPR=FPR/count
print(FPR)
