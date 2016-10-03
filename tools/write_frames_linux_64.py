#!/usr/bin/env python

import os
import sys
import json
import r2pipe
from getopt import getopt, GetoptError

r2 = None

usage_string = "%s -i|--in <path-to-Chowdren> -o|--out <path-to-lvl-files>" % \
               sys.argv[0]

def do_log(msg):
    print msg

def write_frame(frame_no, lvl_prefix, log_fn = do_log):
    lvl_path = os.path.join(lvl_prefix, "%d.lvl" % frame_no)
    log_fn("writing frame %d from %s..." % (frame_no, lvl_path))
    lvl_frame = json.load(fp = open(lvl_path, "r"))

    # write frame width and height if they were obtained error-free.
    if lvl_frame["error"] == 0:
        r2.cmd("s %d" % lvl_frame["width_addr"])
        r2.cmd("s+ 3")
        r2.cmd("wv4 %d" % lvl_frame["width"])

        r2.cmd("s %d" % lvl_frame["height_addr"])
        r2.cmd("s+ 3")
        r2.cmd("wv4 %d" % lvl_frame["height"])

    for obj in lvl_frame['objects']:
        if obj["error"] != 0:
            continue

        r2.cmd("s %d" % obj["addr_pos_x"])
        r2.cmd("s+ 1")
        r2.cmd("wv4 %d" % obj["pos_x"])

        r2.cmd("s %d" % obj["addr_pos_y"])
        r2.cmd("s+ 1")
        r2.cmd("wv4 %d" % obj["pos_y"])

def write_all_frames(source_dir, engine_path, log_fn = do_log):
    global r2

    r2 = r2pipe.open(engine_path)
    r2.cmd("oo+")

    for frame_no in range(1, 88):
        lvl_path = os.path.join(source_dir, "%d.lvl" % frame_no)
        write_frame(frame_no, source_dir, log_fn = log_fn)

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

    write_all_frames(source_dir = out_dir, engine_path = engine_path)
