#!/usr/bin/env python

import gi
gi.require_version('Gtk', '3.0')
from gi.repository import Gtk, GLib, GObject

import freedom_editor

selected_obj = None

def set_builder(builder):
    global obj_attr_pos_x, obj_attr_pos_y, \
        obj_attr_addr_pos_x, obj_attr_addr_pos_y, obj_attr_class, \
        obj_attr_error, obj_list_treeview, obj_list_liststore

    obj_attr_pos_x = builder.get_object("obj_attr_pos_x")
    obj_attr_pos_y = builder.get_object("obj_attr_pos_y")
    obj_attr_addr_pos_x = builder.get_object("obj_attr_addr_pos_x")
    obj_attr_addr_pos_y = builder.get_object("obj_attr_addr_pos_y")
    obj_attr_class = builder.get_object("obj_attr_class")
    obj_attr_error = builder.get_object("obj_attr_error")
    obj_list_treeview = builder.get_object("obj_list_treeview")
    obj_list_liststore = builder.get_object("obj_list_liststore")


def select_frame(new_frame):
    obj_list_liststore.clear()

    for idx, obj in enumerate(new_frame.objs):
        # The index of the object is appended to the second column to be used
        # as a unique ID so we know which object was clicked in new_obj_selected
        new_obj = obj_list_liststore.append()
        obj_list_liststore.set_value(new_obj, 0, obj.obj_class)
        obj_list_liststore.set_value(new_obj, 1, idx)

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

def new_obj_selected(widget):
    """
    called when the user moves the cursor in the object list treeview
    """
    treemodel, treeiter = widget.get_selection().get_selected()

    obj_idx = treemodel.get(treeiter, 1)[0]

    freedom_editor.select_object(obj_idx)

def obj_attr_pos_x_activate(widget):
    """
    called when the user presses enter while the x-position text entry
    is in-focus on the object attributes tab.
    """
    if selected_obj is not None:
        freedom_editor.set_obj_pos(selected_obj, (float(widget.get_text()),
                                                  selected_obj.pos_y))

def obj_attr_pos_y_activate(widget):
    """
    called when the user presses enter while the y-position text entry
    is in-focus on the object attributes tab.
    """
    if selected_obj is not None:
        freedom_editor.set_obj_pos(selected_obj, (selected_obj.pos_x,
                                                  float(widget.get_text())))
