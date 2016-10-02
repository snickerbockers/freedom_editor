#!/usr/bin/env python

import gi
gi.require_version('Gtk', '3.0')
from gi.repository import Gtk, GLib, GObject

import freedom_editor

class ObjectAttrs:
    def __init__(self, builder, freedomEditor):
        self.selected_obj = None

        self.obj_list_treeview = builder.get_object("obj_list_treeview")
        self.obj_list_liststore = builder.get_object("obj_list_liststore")
        self.obj_attrs_liststore = builder.get_object("obj_attrs_liststore")
        self.obj_attrs_treeview = builder.get_object("obj_attrs_treeview")

        self.freedomEditor = freedomEditor

    def select_frame(self, new_frame):
        self.obj_list_liststore.clear()

        for idx, obj in enumerate(new_frame.objs):
            # The index of the object is appended to the second column to be used
            # as a unique ID so we know which object was clicked in new_obj_selected
            new_obj = self.obj_list_liststore.append()
            self.obj_list_liststore.set_value(new_obj, 0, obj.obj_class)
            self.obj_list_liststore.set_value(new_obj, 1, idx)

    def select_obj(self, obj):
        self.selected_obj = obj

        if self.selected_obj is not None:
            self.edit_obj_class(self.selected_obj.obj_class)
            self.edit_pos_x(self.selected_obj.pos_x)
            self.edit_pos_y(self.selected_obj.pos_y)
            self.edit_addr_pos_x(self.selected_obj.addr_pos_x)
            self.edit_addr_pos_y(self.selected_obj.addr_pos_y)
            self.edit_error(self.selected_obj.error)

            self.obj_attrs_treeview.set_sensitive(True)
        else:
            self.obj_attrs_treeview.set_sensitive(False)

    def new_obj_selected(self, widget):
        """
        called when the user moves the cursor in the object list treeview
        """
        treemodel, treeiter = widget.get_selection().get_selected()

        obj_idx = treemodel.get(treeiter, 1)[0]

        self.freedomEditor.select_object(obj_idx)

    def text_is_float(self, txt):
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

    def edit_obj_class(self, new_class):
        """
        Call this to set the obj class in the object attributes
        """
        tree_model = self.obj_attrs_treeview.get_model()
        tree_iter = tree_model.get_iter(0)

        self.obj_attrs_liststore.set_value(tree_iter, 1, new_class)

    def edit_pos_x(self, new_x_pos):
        """
        Call this when the x-position of the currently selected object should be
        updated in the UI.  This does not actually move the object.
        """
        tree_model = self.obj_attrs_treeview.get_model()
        tree_iter = tree_model.get_iter(1)

        self.obj_attrs_liststore.set_value(tree_iter, 1, str(new_x_pos))

    def edit_pos_y(self, new_y_pos):
        """
        Call this when the y-position of the currently selected object should be
        updated in the UI.  This does not actually move the object.
        """
        tree_model = self.obj_attrs_treeview.get_model()
        tree_iter = tree_model.get_iter(2)

        self.obj_attrs_liststore.set_value(tree_iter, 1, str(new_y_pos))

    def edit_addr_pos_x(self, new_addr_pos_x):
        """
        Call this to set the address of pos_x in the object attributes
        """
        tree_model = self.obj_attrs_treeview.get_model()
        tree_iter = tree_model.get_iter(3)

        self.obj_attrs_liststore.set_value(tree_iter, 1, str(new_addr_pos_x))

    def edit_addr_pos_y(self, new_addr_pos_y):
        """
        Call this to set the address of pos_x in the object attributes
        """
        tree_model = self.obj_attrs_treeview.get_model()
        tree_iter = tree_model.get_iter(4)

        self.obj_attrs_liststore.set_value(tree_iter, 1, str(new_addr_pos_y))

    def edit_error(self, new_error):
        """
        Call this to set the address of pos_x in the object attributes
        """
        tree_model = self.obj_attrs_treeview.get_model()
        tree_iter = tree_model.get_iter(5)

        self.obj_attrs_liststore.set_value(tree_iter, 1, str(new_error))

    def edit_width(self, new_width):
        """
        Call this when the width of the currently selected object should be
        updated in the UI.
        """
        tree_model = self.obj_attrs_treeview.get_model()
        tree_iter = tree_model.get_iter(6)

        self.obj_attrs_liststore.set_value(tree_iter, 1, str(new_width))

    def edit_height(self, new_height):
        """
        Call this when the height of the currently selected object should be
        updated in the UI.
        """
        tree_model = self.obj_attrs_treeview.get_model()
        tree_iter = tree_model.get_iter(7)

        self.obj_attrs_liststore.set_value(tree_iter, 1, str(new_height))

    def on_obj_attr_edit(self, widget, path, val):
        """
        Called when the user tries to edit one of the attributes in the obj attr
        tab
        """

        if int(path) == 0:
            # obj_class
            return
        elif int(path) == 1:
            # pos_x
            if self.text_is_float(val):
                idx = self.freedomEditor.get_selected_object()
                if idx is None:
                    return
                obj = self.freedomEditor.get_object_by_index(idx)
                if obj is None:
                    return
                self.freedomEditor.set_obj_pos(obj, (float(val), obj.pos_y))
        elif int(path) == 2:
            # pos_y
            if self.text_is_float(val):
                idx = self.freedomEditor.get_selected_object()
                if idx is None:
                    return
                obj = self.freedomEditor.get_object_by_index(idx)
                if obj is None:
                    return
                self.freedomEditor.set_obj_pos(obj, (obj.pos_x, float(val)))
        elif int(path) == 3:
            # addr_pos_x
            return
        elif int(path) == 4:
            # addr_pos_y
            return
        elif int(path) == 5:
            # error
            return
        elif int(path) == 6:
            # width
            return
        elif int(path) == 7:
            # height
            return
        else:
            raise RuntimeError("unrecognized path %d in obj_attrs_treeview" % \
                               int(path))
