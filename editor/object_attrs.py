#!/usr/bin/env python

import gi
gi.require_version('Gtk', '3.0')
from gi.repository import Gtk, GLib, GObject

selected_obj = None

def set_builder(builder):
    global obj_attr_pos_x, obj_attr_pos_y, \
        obj_attr_addr_pos_x, obj_attr_addr_pos_y, obj_attr_class, obj_attr_error

    obj_attr_pos_x = builder.get_object("obj_attr_pos_x")
    obj_attr_pos_y = builder.get_object("obj_attr_pos_y")
    obj_attr_addr_pos_x = builder.get_object("obj_attr_addr_pos_x")
    obj_attr_addr_pos_y = builder.get_object("obj_attr_addr_pos_y")
    obj_attr_class = builder.get_object("obj_attr_class")
    obj_attr_error = builder.get_object("obj_attr_error")

def select_obj(obj):
    global selected_obj

    selected_obj = obj

    if selected_obj is not None:
        obj_attr_pos_x.set_text(str(selected_obj.pos_x))
        obj_attr_pos_y.set_text(str(selected_obj.pos_y))
        obj_attr_addr_pos_x.set_text(str(selected_obj.addr_pos_x))
        obj_attr_addr_pos_y.set_text(str(selected_obj.addr_pos_y))
        obj_attr_class.set_text(selected_obj.obj_class)
        obj_attr_error.set_text(str(selected_obj.error))
