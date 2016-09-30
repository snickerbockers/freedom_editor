#!/usr/bin/env python

import gi
gi.require_version('Gtk', '3.0')
from gi.repository import Gtk, GLib, GObject

import freedom_editor

selected_obj = None

def set_builder(builder):
    global obj_attr_pos_x, obj_attr_pos_y, \
        obj_attr_addr_pos_x, obj_attr_addr_pos_y, obj_attr_class, \
        obj_attr_error, obj_list_treeview, obj_list_liststore, obj_attrs_box, \
        obj_attrs_liststore, obj_attrs_treeview

    obj_list_treeview = builder.get_object("obj_list_treeview")
    obj_list_liststore = builder.get_object("obj_list_liststore")
    obj_attrs_liststore = builder.get_object("obj_attrs_liststore")
    obj_attrs_treeview = builder.get_object("obj_attrs_treeview")

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
        edit_obj_class(selected_obj.obj_class)
        edit_pos_x(selected_obj.pos_x)
        edit_pos_y(selected_obj.pos_y)
        edit_addr_pos_x(selected_obj.addr_pos_x)
        edit_addr_pos_y(selected_obj.addr_pos_y)
        edit_error(obj.error)

        obj_attrs_treeview.set_sensitive(True)
    else:
        obj_attrs_treeview.set_sensitive(False)

def new_obj_selected(widget):
    """
    called when the user moves the cursor in the object list treeview
    """
    treemodel, treeiter = widget.get_selection().get_selected()

    obj_idx = treemodel.get(treeiter, 1)[0]

    freedom_editor.select_object(obj_idx)

def text_is_float(txt):
    if len(txt) <= 0:
        return False

    if type(txt) != str:
        return False

    dot_count = 0
    for c in txt:
        if c.isdigit():
            continue
        if c == '.':
            dot_count += 1
            if dot_count >= 2:
                return False
    return True

def edit_obj_class(new_class):
    """
    Call this to set the obj class in the object attributes
    """
    tree_model = obj_attrs_treeview.get_model()
    tree_iter = tree_model.get_iter(0)

    obj_attrs_liststore.set_value(tree_iter, 1, new_class)

def edit_pos_x(new_x_pos):
    """
    Call this when the x-position of the currently selected object should be
    updated in the UI.  This does not actually move the object.
    """
    tree_model = obj_attrs_treeview.get_model()
    tree_iter = tree_model.get_iter(1)

    obj_attrs_liststore.set_value(tree_iter, 1, str(new_x_pos))

def edit_pos_y(new_y_pos):
    """
    Call this when the y-position of the currently selected object should be
    updated in the UI.  This does not actually move the object.
    """
    tree_model = obj_attrs_treeview.get_model()
    tree_iter = tree_model.get_iter(2)

    obj_attrs_liststore.set_value(tree_iter, 1, str(new_y_pos))

def edit_addr_pos_x(new_addr_pos_x):
    """
    Call this to set the address of pos_x in the object attributes
    """
    tree_model = obj_attrs_treeview.get_model()
    tree_iter = tree_model.get_iter(3)

    obj_attrs_liststore.set_value(tree_iter, 1, str(new_addr_pos_x))

def edit_addr_pos_y(new_addr_pos_y):
    """
    Call this to set the address of pos_x in the object attributes
    """
    tree_model = obj_attrs_treeview.get_model()
    tree_iter = tree_model.get_iter(4)

    obj_attrs_liststore.set_value(tree_iter, 1, str(new_addr_pos_y))

def edit_error(new_error):
    """
    Call this to set the address of pos_x in the object attributes
    """
    tree_model = obj_attrs_treeview.get_model()
    tree_iter = tree_model.get_iter(5)

    obj_attrs_liststore.set_value(tree_iter, 1, str(new_error))

def on_obj_attr_edit(widget, path, val):
    """
    Called when the user tries to edit one of the attributes in the obj attr
    tab
    """

    if int(path) == 0:
        # obj_class
        return
    elif int(path) == 1:
        # pos_x
        if text_is_float(val):
            idx = freedom_editor.get_selected_object()
            if idx is None:
                return
            obj = freedom_editor.get_object_by_index(idx)
            if obj is None:
                return
            freedom_editor.set_obj_pos(obj, (float(val), obj.pos_y))
    elif int(path) == 2:
        # pos_y
        if text_is_float(val):
            idx = freedom_editor.get_selected_object()
            if idx is None:
                return
            obj = freedom_editor.get_object_by_index(idx)
            if obj is None:
                return
            freedom_editor.set_obj_pos(obj, (obj.pos_x, float(val)))
    elif int(path) == 3:
        # addr_pos_x
        return
    elif int(path) == 4:
        # addr_pos_y
        return
    elif int(path) == 5:
        # error
        return
    else:
        raise RuntimeError("unrecognized path %d in obj_attrs_treeview" % \
                           int(path))
