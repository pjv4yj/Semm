from semm_ops.disassembly import Disassembler
from semm_ops.assembly import Assembler
from semm_ops.transform import Transform
import pefile

d = Disassembler() # instantiate Disassembler Object
operation_arr = d.get_instruction_list('../sample_files/sample1.exe', num_bytes=100) # operation list from first instruction for 100 bytes

t = Transform(operation_arr)
t.transform_registers()

a = Assembler() # instantiate Assembler Object
assembly_code = a.get_assembly_code(operation_arr[0:15])
byte_code = a.reassemble(assembly_code)
#print(byte_code)
