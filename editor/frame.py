#!/usr/bin/env python

import os
import json
import cairo

import freedom_editor

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
        self.width_addr = fr["width_addr"]
        self.height_addr = fr["height_addr"]
        self.error = fr["error"]

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
        dat["width_addr"] = self.width_addr
        dat["height_addr"] = self.height_addr
        dat["error"] = self.error

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

def set_builder(builder):
    global frame_attrs_treeview, frame_attrs_liststore

    frame_attrs_treeview = builder.get_object("frame_attrs_treeview")
    frame_attrs_liststore = builder.get_object("frame_attrs_liststore")

def edit_frame_width(frame_width):
    """
    This updates the frame_width in the UI, but it does not actually change the
    frame_width of the frame.
    """
    tree_model = frame_attrs_treeview.get_model()
    tree_iter = tree_model.get_iter(0)

    frame_attrs_liststore.set_value(tree_iter, 1, str(frame_width))

def edit_frame_height(frame_height):
    """
    This updates the frame_height in the UI, but it does not actually change the
    frame_width of the frame.
    """
    tree_model = frame_attrs_treeview.get_model()
    tree_iter = tree_model.get_iter(1)

    frame_attrs_liststore.set_value(tree_iter, 1, str(frame_height))

def edit_frame_width_addr(frame_width_addr):
    """
    This updates the frame_width_addr in the UI, but it does not actually
    change the frame_width_addr of the frame.
    """
    tree_model = frame_attrs_treeview.get_model()
    tree_iter = tree_model.get_iter(2)

    frame_attrs_liststore.set_value(tree_iter, 1, str(frame_width_addr))

def edit_frame_height_addr(frame_height_addr):
    """
    This updates the frame_height_addr in the UI, but it does not actually
    change the frame_height_addr of the frame.
    """
    tree_model = frame_attrs_treeview.get_model()
    tree_iter = tree_model.get_iter(3)

    frame_attrs_liststore.set_value(tree_iter, 1, str(frame_height_addr))

def edit_frame_error(frame_error):
    """
    This updates the frame_error in the UI, but it does not actually
    change the frame_error of the frame.
    """
    tree_model = frame_attrs_treeview.get_model()
    tree_iter = tree_model.get_iter(4)

    frame_attrs_liststore.set_value(tree_iter, 1, str(frame_error))

def text_is_float(txt):
    if len(txt) <= 0:
        return False

    if type(txt) != str:
        return False

    dot_count = 0
    for c in txt:
        if c.isdigit():
            continue
        elif c == '.':
            dot_count += 1
            if dot_count >= 2:
                return False
        else:
            return False
    return True

def on_frame_attr_edit(widget, path, val):
    if int(path) == 0:
        # frame_width
        if text_is_float(val):
            freedom_editor.set_frame_width(float(val))
    elif int(path) == 1:
        # frame height
        if text_is_float(val):
            freedom_editor.set_frame_height(float(val))
    elif int(path) == 2:
        # frame_width_addr
        return
    elif int(path) == 3:
        # frame_width_height
        return
    elif int(path) == 4:
        # frame_error
        return
    else:
        raise RuntimeError("unrecognized path %d in frame_attrs_treeview" % \
                           int(path))
