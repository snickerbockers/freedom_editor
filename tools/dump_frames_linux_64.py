#!/usr/bin/env python

import r2pipe
import json
import re
import os
import sys
import threading
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

usage_string = "%s -i|--in <path-to-Chowdren> -o|--out <path-to-lvl-files>" % \
               sys.argv[0]

mov_edi_re = re.compile("mov edi, (0x[0-9a-fA-F]+|[0-9]+)")
mov_esi_re = re.compile("mov esi, (0x[0-9a-fA-F]+|[0-9]+)")

# TODO: does this pick up the function calls that don't get demangled by r2?
call_create_func = re.compile("call sym\.create_([a-zA-Z0-9]+_[0-9]+)")

set_width_re = re.compile("mov dword \[rdi \+ 8\], (0x[0-9a-fA-f]+)")
set_height_re = re.compile("mov dword \[rdi \+ 0x10\], (0x[0-9a-fA-f]+)")

def do_log(msg):
    print msg

class FpObjClass:
    def __init__(self, name, func, func_len, vaddr, paddr, all_img_ids):
        self.name = name
        self.func = func
        self.func_len = func_len
        self.vaddr = vaddr
        self.paddr = paddr

        self.all_img_ids = all_img_ids

    def __str__(self):
        return "%s\t%s\t0x%x\t0x%x" % (self.name,
                                       self.func,
                                       self.vaddr,
                                       self.paddr)

def list_object_classes(r2, log_fn = do_log):
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
        all_img_ids = find_all_images(r2 = r2, func = create_func,
                                      func_len = func_len, log_fn = log_fn)
        obj_class = FpObjClass(name = class_name,
                               func = create_func,
                               vaddr = int(vaddr, 16),
                               paddr = int(paddr, 16),
                               func_len = func_len,
                               all_img_ids = all_img_ids)
        obj_classes[class_name] = obj_class
    return obj_classes

def find_all_images(r2, func, func_len, log_fn = do_log):
    """
    seeks to the create function and returns the image id sent to
    the first get_internal_image call.  This will return None if
    it doesn't find an image id.
    """

    r2.cmd("s sym.%s" % func)

    end_address = int(r2.cmd("s"), 16) + func_len
    all_img_ids = []
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
                log_fn("WARNING: Unable to find get_internal_image " + \
                       "parameter in %s" % func)
            else:
                all_img_ids.append(int(img_id, 16))
                img_id = None
        r2.cmd("so 1")
    return all_img_ids

def parse_frame(r2, frame_no, obj_classes, log_fn = do_log):
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
    frame_w_addr = None
    frame_h_addr = None
    last_x_val_addr = None
    last_y_val_addr = None

    objs = []

    while int(r2.cmd("s"), 16) < end_address:
        inst = r2.cmd("pi 1")

        re_match = set_width_re.match(inst)
        if re_match is not None:
            frame_w_addr = int(r2.cmd("s"), 0)
            frame_w = re_match.group(1)

        re_match = set_height_re.match(inst)
        if re_match is not None:
            frame_h_addr = int(r2.cmd("s"), 0)
            frame_h = re_match.group(1)

        re_match = call_create_func.match(inst)
        if re_match is not None:
            new_obj = { "obj_class" : re_match.group(1),
                        "pos_x" : last_x_val,
                        "pos_y" : last_y_val,
                        "addr_pos_x" : last_x_val_addr,
                        "addr_pos_y" : last_y_val_addr,
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
        all_img_ids = obj_classes[obj['obj_class']].all_img_ids
        objs[idx]['all_images'] = all_img_ids

    # Unlike with objects, having an error in a frame doesn't mean we ignore
    # the entire frame, it just means that we shouldn't edit the frame
    # attributes
    frame_error = 0
    if frame_w is None or frame_w_addr is None or \
       frame_h is None or frame_h_addr is None:
        frame_error = 1

    return {"width" : int(frame_w, 0),
            "width_addr" : frame_w_addr,
            "height" : int(frame_h, 0),
            "height_addr" : frame_h_addr,
            "frame_no" : frame_no,
            "objects" : objs,
            "error" : frame_error}

def do_dump_levels(engine_path, out_dir, n_jobs = 1, start_idx = 1,
                   log_fn = do_log):
    r2 = r2pipe.open(engine_path)

    # TODO: IF I ever get the multi-threading *really* working, then I'm going
    # to want to move the call to list_object_classes up another level into the
    # callee so that they can all share the same obj_classes list instead of
    # having every thread call list_object_classes
    obj_classes = list_object_classes(r2, log_fn = log_fn)

    for frame_no in range(start_idx, 88, n_jobs):
        lvl_path = os.path.join(out_dir, "%d.lvl" % frame_no)
        log_fn("dumping frame %d to %s..." % (frame_no, lvl_path))

        frame = parse_frame(r2, frame_no, obj_classes = obj_classes,
                            log_fn = log_fn)
        json.dump(obj=frame, fp = open(lvl_path, "w"), indent=4)
    r2.quit()

def dump_all_levels(engine_path, out_dir, n_jobs = 1, log_fn = do_log,
                    join_threads = True):
    """
    launch a bunch of threads that all call do_dump_levels.
    If join_threads is False, this function will not wait until the levels have
    been dumped to return.

    returns a list of all active_threads
    """
    os.mkdir(out_dir)

    thread_list = []
    for i in range(n_jobs):
        t = threading.Thread(target = do_dump_levels,
                             args = (engine_path, out_dir, n_jobs, i + 1, log_fn))
        t.start()
        thread_list.append(t)

    if join_threads:
        for t in thread_list:
            t.join()
        return []
    else:
        return thread_list

if __name__ == "__main__":
    engine_path = "Chowdren"
    out_dir = "."
    n_jobs = 1

    try:
        opt_val, params = getopt(sys.argv[1:], "i:o:j:", ["in=", "out=", "jobs="])
        for option, value in opt_val:
            if option == "-i" or option == "--in":
                engine_path = value
            elif option == "-o" or option == "--out":
                out_dir = value
            elif option == "-j" or option == "--jobs":
                n_jobs = int(value)
    except GetoptError:
        print usage_string
        exit(1)

    dump_all_levels(engine_path, out_dir, n_jobs)
