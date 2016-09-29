#!/usr/bin/env python

import os
import sys
import subprocess

import gi
gi.require_version('Gtk', '3.0')
from gi.repository import Gtk, GLib, GObject
import cairo

import frame

sys.path.append("../tools/")
import fp_project

import level_display
import project_menu
import object_attrs

project_path = None
cur_frame = None

selected_obj_idx = None

def main_window_delete_event(self, *args):
    Gtk.main_quit(*args)

def set_frame(frame_no):
    global cur_frame
    """
    loads frame_no
    """
    cur_frame = frame.FpFrame(project_path, frame_no)
    if len(cur_frame.objs) >= 1:
        select_object(0)
    object_attrs.select_frame(cur_frame)
    level_display.invalidate()

def select_object(obj_idx):
    """
    This method should be called to select the object
    indicated by object_idx.
    """
    global selected_obj_idx

    if obj_idx is not None:
        object_attrs.select_obj(cur_frame.objs[obj_idx])
    selected_obj_idx = obj_idx

def get_selected_object():
    """
    returns the index of the currently selected object, or None
    """
    return selected_obj_idx

def set_obj_pos(obj, new_pos):
    """
    Instead of setting an object's pos_x and pos_y members yourself, call this
    method.  This method will set the position and notify any subsystems that
    need to be notified.
    """
    obj.pos_x = float(new_pos[0])
    obj.pos_y = float(new_pos[1])

    # queue a redraw of the level display so that it draws obj in the new pos
    level_display.invalidate()

def get_object_by_index(idx):

    # TODO: find a better way to handle the possibility that cur_frame could
    #       be none, the way this is implemented is a mess and I would be
    #       seriously worried about fucking up the heap if I was writing this
    #       in C.
    if cur_frame is None:
        return None
    return cur_frame.objs[idx]

def get_object_at_pos(pos):
    """
    iterate through all objects in cur_frame and return the first object which
    contains pos within it (or None if there is no such object).
    """
    if cur_frame is None:
        return None

    for idx, obj in enumerate(cur_frame.objs):
        if obj.error != 0:
            continue
        if obj.image is None:
            continue
        obj_x = obj.pos_x
        obj_y = obj.pos_y
        obj_w = obj.image.get_width()
        obj_h = obj.image.get_height()

        if pos[0] >= obj_x and pos[0] < (obj_x + obj_w) and \
           pos[1] >= obj_y and pos[1] < (obj_y + obj_h):
            return idx
    return None

def main():
    global builder

    builder = Gtk.Builder()
    builder.add_from_file("freedom_editor_gui.glade")

    level_display.set_builder(builder)
    project_menu.set_builder(builder)
    object_attrs.set_builder(builder)

    callbacks = {
        "main_window_delete_event" : main_window_delete_event,
        "on_level_display_click" : level_display.on_click,
        "on_level_display_unclick" : level_display.on_unclick,
        "on_level_display_drag" : level_display.on_mouse_motion,
        "on_level_display_draw" : level_display.on_draw,
        "on_project_new" : project_menu.on_project_new,
        "on_new_project_game_path_browse" : project_menu.on_new_project_game_path_browse,
        "on_new_project_project_path_browse" : project_menu.on_new_project_project_path_browse,
        "on_project_open" : project_menu.on_project_open,
        "on_project_launch" : project_menu.on_project_launch,
        "on_project_open_frame" : project_menu.on_project_open_frame,
        "new_obj_selected" : object_attrs.new_obj_selected,
        "obj_attr_pos_x_activate" : object_attrs.obj_attr_pos_x_activate,
        "obj_attr_pos_y_activate" : object_attrs.obj_attr_pos_y_activate
    }

    main_window = builder.get_object("main_window")
    builder.connect_signals(callbacks)
    main_window.show_all()

    Gtk.main()

if __name__ == "__main__":
    main()
