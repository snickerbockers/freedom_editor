#!/usr/bin/env python

# fp_render
# A tool for rendering images from .lvl files

import os
import sys
import json
import cairo
from getopt import getopt, GetoptError

class FpObj:
    def __init__(self, obj_dict, proj_path):
        self.addr_pos_x = obj_dict["addr_pos_x"]
        self.addr_pos_y = obj_dict["addr_pos_y"]

        self.pos_x = obj_dict["pos_x"]
        self.pos_y = obj_dict["pos_y"]

        self.image = None
        if "image" in obj_dict:
            img_path = os.path.join(proj_path, "assets", "images",
                                    "img_%d.png" % obj_dict["image"])
            self.image = cairo.ImageSurface.create_from_png(img_path)
        self.obj_class = obj_dict["obj_class"]
        self.error = obj_dict["error"]

class FpFrame:
    def __init__(self, proj_path, frame_no):
        frame_path = os.path.join(proj_path, "levels", "%d.lvl" % frame_no)
        fr = json.load(open(frame_path, "r"))

        self.frame_no = fr["frame_no"]
        self.width = fr["width"]
        self.height = fr["height"]

        self.objs = []
        for obj in fr["objects"]:
            self.objs.append(FpObj(obj, proj_path))

    def draw(self, cr):
        for obj in self.objs:
            if obj.image is not None and obj.error == 0:
                cr.set_source_surface(obj.image, float(obj.pos_x), float(obj.pos_y))
                cr.paint()

    def get_min_point(self):
        for obj in self.objs:
            if obj.error == 0 and obj.image is not None:
                min_x = obj.pos_x
                min_y = obj.pos_y
                break

        for obj in self.objs:
            if obj.error == 0 and obj.image is not None:
                if obj.pos_x < min_x:
                    min_x = obj.pos_x
                    if obj.pos_y < min_y:
                        min_y = obj.pos_y
        return (min_x, min_y)

    def get_max_point(self):
        for obj in self.objs:
            if obj.error == 0 and obj.image is not None:
                max_x = obj.pos_x + obj.image.get_width()
                max_y = obj.pos_y + obj.image.get_height()
                break

        for obj in self.objs:
            if obj.error == 0 and obj.image is not None:
                x = obj.pos_x + obj.image.get_width()
                y = obj.pos_y + obj.image.get_height()
                if obj.pos_x > max_x:
                    max_x = x
                if obj.pos_y > max_y:
                    max_y = y
        return (max_x, max_y)

def render_frame_to_png(proj_path, frame_no, img_path):
    fr = FpFrame(proj_path, frame_no)

    if len(fr.objs) <= 0:
        print "Error: skipping frame %d due to lack of objects" % frame_no
        return

    min_x, min_y = fr.get_min_point()
    max_x, max_y = fr.get_max_point()

    surface = cairo.ImageSurface(cairo.FORMAT_ARGB32,
                                 max_x - min_x + 1,
                                 max_y - min_y + 1)
    cr = cairo.Context(surface)
    cr.translate(-min_x, -min_y)
    fr.draw(cr)

    surface.write_to_png(img_path)



usage_string = """ \
%s -p|--proj <project path> -f|--frame <frame number> -o|--out <image path>
""" % sys.argv[0]

if __name__ == "__main__":
    proj = None
    frame = None
    out = None
    opt_val, params = getopt(sys.argv[1:], "p:f:o:", ["proj=", "frame=", "out="])

    try:
        for option, value in opt_val:
            if option == "-p" or option == "--proj":
                proj = value
            elif option == "-f" or option == "--proj":
                frame = int(value)
            elif option == "-o" or option == "--out":
                out = value
    except GetoptError:
        print usage_string
        exit(1)

    if proj is None or frame is None or out is None:
        print usage_string
        exit(1)

    render_frame_to_png(proj, frame, out)
