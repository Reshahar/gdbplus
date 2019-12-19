import gdb
import re

class ToIDA(gdb.Command):
    """Get Offset of Process Base

    Usage:
        ti address (defalut address=$pc)
    Example:
        ti
        ti 0x55a63002bb68
    """
    def __init__(self):
        super(self.__class__,self).__init__("ti",gdb.COMMAND_USER)
        self.arch = 'amd64'

    def get_arch(self):
        result = gdb.execute("info r",to_string=True)
        if 'rax' in result:
            self.arch = 'amd64'
        elif 'eax' in result:
            self.arch = 'i386'

    def invoke(self,args,from_tty):
        #msg(gdb.objfiles()[0].filename)
        argv = gdb.string_to_argv(args)
        try:
            result = gdb.execute("info proc",to_string=True)
            result = re.findall("exe = '(.*)'",result)
            if len(result) == 0:
                msg("ti: the proc name is worng!")
                return -1
            proc_name = result[0]
            result = gdb.execute("vmmap",to_string=True)
            result = re.findall("(0x.+)(0x[0-9a-fA-F]+).*"+proc_name,result)
            result = [y for x in result for y in x]
            if len(result) == 0:
                msg("ti: get process base address error!")
                return -1
            proc_addr_start = int(min(result,key=lambda x:int(x,16)),16)
            proc_addr_end = int(max(result,key=lambda x:int(x,16)),16)
            self.get_arch()
            if len(argv) == 0:
                if self.arch =='amd64':
                    value = '$rip'
                elif self.arch == 'i386':
                    value = '$eip'
            elif len(argv) == 1:
                value = argv[0]
            else:
                return -1;
            if '$' in value:
                value = gdb.execute('i r '+value,to_string=True).split("\t")[0].split(" ")[-1]
            value = int(value,16)
            if value < proc_addr_start or value > proc_addr_end:
                msg("ti: input addr or $pc is not in process space!")
                return -1;
            msg('offset: '+hex(value-proc_addr_start))
        except Exception as e:
            #msg(e)
            msg("ti: The program is not being run!")
            return -1

def start(event):
    msg("test")


#gdb.events.cont.connect(start)
ToIDA()
