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
    object_attrs.select_obj(cur_frame.objs[obj_idx])

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
        "on_level_display_drag" : level_display.on_mouse_motion,
        "on_level_display_draw" : level_display.on_draw,
        "on_project_new" : project_menu.on_project_new,
        "on_new_project_game_path_browse" : project_menu.on_new_project_game_path_browse,
        "on_new_project_project_path_browse" : project_menu.on_new_project_project_path_browse,
        "on_project_open" : project_menu.on_project_open,
        "on_project_launch" : project_menu.on_project_launch,
        "on_project_open_frame" : project_menu.on_project_open_frame,
        "new_obj_selected" : object_attrs.new_obj_selected
    }

    main_window = builder.get_object("main_window")
    builder.connect_signals(callbacks)
    main_window.show_all()

    Gtk.main()

if __name__ == "__main__":
    main()
