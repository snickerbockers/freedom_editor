#!/usr/bin/env python

import os
import json
import cairo

class FpObj:
    def __init__(self, obj_dict, proj_path):
        self.addr_pos_x = obj_dict["addr_pos_x"]
        self.addr_pos_y = obj_dict["addr_pos_y"]

        self.pos_x = obj_dict["pos_x"]
        self.pos_y = obj_dict["pos_y"]

        self.image = None
        self.image_handle = None
        if "image" in obj_dict:
            img_path = os.path.join(proj_path, "assets", "images",
                                    "img_%d.png" % obj_dict["image"])
            self.image = cairo.ImageSurface.create_from_png(img_path)
            self.image_handle = obj_dict["image"]
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

    def convert_to_json(self):
        dat = {}
        obj_dict_list = []

        dat["frame_no"] = self.frame_no
        dat["width"] = self.width
        dat["height"] = self.height

        for obj in self.objs:
            obj_dict = {
                "addr_pos_x" : obj.addr_pos_x,
                "addr_pos_y" : obj.addr_pos_y,
                "pos_x" : obj.pos_x,
                "pos_y" : obj.pos_y,
                "obj_class" : obj.obj_class,
                "error" : obj.error
                }
            if obj.image_handle is not None:
                obj_dict["image"] = obj.image_handle
            obj_dict_list.append(obj_dict)
        dat["objects"] = obj_dict_list
        return json.dumps(obj = dat, indent = 4)
