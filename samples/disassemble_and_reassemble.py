from semm_ops.disassembly import Disassembler
from semm_ops.transform import Transform

d = Disassembler() # instantiate Disassembler Object
operation_arr = d.get_instruction_list('../sample_files/sample1.exe', num_bytes=100) # operation list from first instruction for 100 bytes

t = Transform(operation_arr[0:20]) # Initiate Transform Object
byte_codes = t.transform_registers() # Transform registers

for code in byte_codes: # Print out each byte code permutation
    print(code)
