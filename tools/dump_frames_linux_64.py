#!/usr/bin/env python

import r2pipe
import json
import re
import os
import sys
from getopt import getopt, GetoptError

################################################################################
#
# RELEVENT RADARE2 COMMANDS
#
# is                 - list all symbols
# s sym.<symbol>     - seek to symbol
# s <nothing>        - print position in executable file
# pa <inst>          - assemble instruction
# pi <count>         - print the next <count> instructions
# so <count>         - seek forward <count> instructions
#
################################################################################

mov_edi_re = re.compile("mov edi, (0x[0-9a-fA-F]+|[0-9]+)")
mov_esi_re = re.compile("mov esi, (0x[0-9a-fA-F]+|[0-9]+)")

# TODO: does this pick up the function calls that don't get demangled by r2?
call_create_func = re.compile("call sym\.create_([a-zA-Z0-9]+_[0-9]+)")

set_width_re = re.compile("mov dword \[rdi \+ 8\], (0x[0-9a-fA-f]+)")
set_height_re = re.compile("mov dword \[rdi \+ 0x10\], (0x[0-9a-fA-f]+)")

class FpObjClass:
    def __init__(self, name, func, func_len, vaddr, paddr):
        self.name = name
        self.func = func
        self.func_len = func_len
        self.vaddr = vaddr
        self.paddr = paddr

    def __str__(self):
        return "%s\t%s\t0x%x\t0x%x" % (self.name,
                                       self.func,
                                       self.vaddr,
                                       self.paddr)

def list_object_classes():
    """
    iterate throught the elf symbols and come up with a map
    of all object classes and the addresses and names of the functions
    that create them.
    """
    obj_classes = {}
    symbols = r2.cmd("is | grep -E \"create_[a-zA-Z0-9]+_[0-9]+\"").splitlines()
    for entry in symbols:
        cols = entry.split()
        vaddr = cols[0].split('=')[1]
        paddr = cols[1].split('=')[1]
        create_func = cols[7].split('=')[1]
        func_len = int(cols[4].split('=')[1])
        if create_func[:17] == "_GLOBAL__sub_I__Z":
            # radare2 doesn't demangle the symbols where bind=LOCAL, IDK why
            class_name = create_func[26:-2]
        else:
            class_name = create_func[7:]
        obj_class = FpObjClass(name = class_name,
                               func = create_func,
                               vaddr = int(vaddr, 16),
                               paddr = int(paddr, 16),
                               func_len = func_len)
        obj_classes[class_name] = obj_class
    return obj_classes

def find_first_image(obj_class):
    """
    seeks to the create function and returns the image id sent to
    the first get_internal_image call.  This will return None if
    it doesn't find an image id.
    """

    r2.cmd("s sym.%s" % obj_class.func)

    end_address = int(r2.cmd("s"), 16) + obj_class.func_len
    img_id = None

    # go forward and find the last mov into %edi before the first
    # get_internal_image call.  This will fuck up if Chowdren uses
    # any other opcode to write to %edi, but it doesn't look like
    # it ever does.
    while int(r2.cmd("s"), 16) < end_address:
        inst = r2.cmd("pi 1")

        re_match = mov_edi_re.match(inst)
        if re_match is not None:
            img_id = re_match.group(1)
        elif inst == "call sym.get_internal_image":
            if img_id is None:
                print "ERROR: Unable to find get_internal_image parameter " + \
                    "in %s" % obj_class.func
            else:
                return int(img_id, 16)
        r2.cmd("so 1")
    return None

def parse_frame(frame_no):
    """
    seek to the given frame and return a list of all the objects it
    instantiates.  Eventually this will get the coordinates, too.
    """

    frame_init_func = "Frames::on_frame_%d_init" % frame_no
    r2.cmd("s sym.%s" % frame_init_func)

    # TODO: I'm not sure if there are any special characters in function names
    #       that grep might interpret as regexp special characters
    frame_symbol = r2.cmd("is | grep %s$" % frame_init_func).split()
    func_len = int(frame_symbol[4].split('=')[1])
    end_address = int(r2.cmd("s"), 16) + func_len

    last_x_val = None
    last_y_val = None
    frame_w = None
    frame_h = None
    last_x_val_addr = None
    last_y_val_addr = None

    objs = []
    obj_classes = list_object_classes()

    while int(r2.cmd("s"), 16) < end_address:
        inst = r2.cmd("pi 1")

        re_match = set_width_re.match(inst)
        if re_match is not None:
            frame_w = re_match.group(1)

        re_match = set_height_re.match(inst)
        if re_match is not None:
            frame_h = re_match.group(1)

        re_match = call_create_func.match(inst)
        if re_match is not None:
            new_obj = { "obj_class" : re_match.group(1),
                        "pos_x" : last_x_val,
                        "pos_y" : last_y_val,
                        "addr_pos_x" : last_x_val_addr,
                        "addr_pos_y" : last_y_val_addr,
                        "images" : [],
                        "error" : 0}
            if (last_x_val is None or last_y_val is None):
                  new_obj['error'] = 1
            last_x_val = None
            last_y_val = None
            objs.append(new_obj)

        re_match = mov_edi_re.match(inst)
        if re_match is not None:
            last_x_val = int(re_match.group(1), 16)
            last_x_val_addr = int(r2.cmd("s"), 0)
            if last_x_val > 0x7fffffff:
                last_x_val -= 0x100000000

        re_match = mov_esi_re.match(inst)
        if re_match is not None:
            last_y_val = int(re_match.group(1), 16)
            last_y_val_addr = int(r2.cmd("s"), 0)
            if last_y_val > 0x7fffffff:
                last_y_val -= 0x100000000
        r2.cmd("so 1")

    for idx, obj in enumerate(objs):
        img_id = find_first_image(obj_classes[obj['obj_class']])
        if img_id is not None:
            objs[idx]['image'] = img_id;

    return {"width" : int(frame_w, 0),
            "height" : int(frame_h, 0),
            "frame_no" : frame_no,
            "objects" : objs}

def dump_all_levels(engine_path, out_dir):
    global r2
    os.mkdir(out_dir)

    r2 = r2pipe.open(engine_path)

    for frame_no in range(1, 88):
        lvl_path = os.path.join(out_dir, "%d.lvl" % frame_no)
        print "dumping frame %d to %s..." % (frame_no, lvl_path)

        frame = parse_frame(frame_no)
        json.dump(obj=frame, fp = open(lvl_path, "w"), indent=4)
    r2.quit()

if __name__ == "__main__":
    engine_path = "Chowdren"
    out_dir = "."

    try:
        opt_val, params = getopt(sys.argv[1:], "i:o:", ["in=", "out="])
        for option, value in opt_val:
            if option == "-i" or option == "--in":
                engine_path = value
            elif option == "-o" or option == "--out":
                out_dir = value
    except GetoptError:
        print usage_string
        exit(1)

        dump_all_levels(engine_path, out_dir)
