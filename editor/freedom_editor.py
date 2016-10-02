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

# When you open a project or create a new one, it immediately loads the
# DEFAULT_FRAME, which is Dragon Valley Act 1
DEFAULT_FRAME = 21

# The width and height of the grid nodes.  This is used both by the
# "snap-to-grid" feature (when you're moving objects) and the grid that gets
# drawn in the level_display's draw_grid method
GRID_WIDTH = 32
GRID_HEIGHT = 32

freedomEditor = None

class FreedomEditor:
    def __init__(self, builder):
        self.builder = builder

        self.levelDisplay = level_display.LevelDisplay(builder, self)
        self.projectMenu = project_menu.ProjectMenu(builder, self)
        self.objectAttrs = object_attrs.ObjectAttrs(builder, self)
        self.frameAttrs = frame.FrameAttrs(builder, self)

        self.main_window = builder.get_object("main_window")
        self.snap_to_grid_toggle = builder.get_object("snap_to_grid_toggle")

        # if true, objects will be snapped to the grid when they are moved
        self.do_snap_to_grid = False
        self.project_path = None
        self.cur_frame = None

    def load_project(self, proj_path):
        self.project_path = proj_path

        try:
            # We default to Dragon Valley act 1
            self.set_frame(DEFAULT_FRAME)
        except IOError as err:
            self.project_path = None
            dialog = Gtk.MessageDialog(None, 0, Gtk.MessageType.INFO,
                                       Gtk.ButtonsType.OK,
                                       "Invalid project path")
            dialog.run()
            dialog.hide()

    def main_window_delete_event(self, *args):
        Gtk.main_quit(*args)

    def set_frame(self, frame_no):
        """
        loads frame_no
        """
        self.cur_frame = frame.FpFrame(self.project_path, frame_no)
        self.select_object(None)
        self.objectAttrs.select_frame(self.cur_frame)
        self.levelDisplay.set_trans(0, 0)
        self.levelDisplay.invalidate()

        # update the frame attrs ui
        self.frameAttrs.edit_frame_width(self.cur_frame.width)
        self.frameAttrs.edit_frame_height(self.cur_frame.height)
        self.frameAttrs.edit_frame_width_addr(self.cur_frame.width_addr)
        self.frameAttrs.edit_frame_height_addr(self.cur_frame.height_addr)
        self.frameAttrs.edit_frame_error(self.cur_frame.error)

    def set_frame_width(self, frame_width):
        self.cur_frame.width = frame_width
        self.frameAttrs.edit_frame_width(self.cur_frame.width)

    def set_frame_height(self, frame_height):
        self.cur_frame.height = frame_height
        self.frameAttrs.edit_frame_height(self.cur_frame.height)

    def select_object(self, obj_idx):
        """
        This method should be called to select the object
        indicated by object_idx.
        """
        if obj_idx is None:
            self.objectAttrs.select_obj(None)
        else:
            self.objectAttrs.select_obj(self.cur_frame.objs[obj_idx])
        self.selected_obj_idx = obj_idx

    def get_selected_object(self):
        """
        returns the index of the currently selected object, or None
        """
        return self.selected_obj_idx

    def obj_snap(self, obj_pos, obj_len):
        """
        1-dimensional snap-to-grid .
        obj_pos should be the object's x or y coordinate
        obj_len should be the object's width or height
        """
        snap_min = (int(obj_pos) / 32) * 32
        snap_max = (int(obj_pos + obj_len) / 32) * 32 - obj_pos

        if abs(obj_pos - snap_min) < abs(obj_pos - snap_max):
            snap_best = snap_min
        else:
            snap_best = snap_max

        if abs(snap_best - obj_pos) < 8:
            return snap_best
        return obj_pos

    def set_obj_pos(self, obj, new_pos):
        """
        Instead of setting an object's pos_x and pos_y members yourself, call
        this method.  This method will set the position and notify any
        subsystems that need to be notified.
        """

        if self.do_snap_to_grid:
            obj.pos_x = float(self.obj_snap(new_pos[0], obj.get_width()))
            obj.pos_y = float(self.obj_snap(new_pos[1], obj.get_height()))
        else:
            obj.pos_x = float(new_pos[0])
            obj.pos_y = float(new_pos[1])

        # queue a redraw of the level display so that it draws obj in the new pos
        self.levelDisplay.invalidate()

        self.objectAttrs.edit_obj_class(obj.obj_class)
        self.objectAttrs.edit_pos_x(obj.pos_x)
        self.objectAttrs.edit_pos_y(obj.pos_y)
        self.objectAttrs.edit_addr_pos_x(obj.addr_pos_x)
        self.objectAttrs.edit_addr_pos_y(obj.addr_pos_y)
        self.objectAttrs.edit_error(obj.error)
        self.objectAttrs.edit_width(obj.get_width())
        self.objectAttrs.edit_height(obj.get_height())

    def get_object_by_index(self, idx):
        # TODO: find a better way to handle the possibility that cur_frame could
        #       be none, the way this is implemented is a mess and I would be
        #       seriously worried about fucking up the heap if I was writing
        #       this in C.
        if self.cur_frame is None:
            return None
        return self.cur_frame.objs[idx]

    def get_object_at_pos(self, pos):
        """
        iterate through all objects in cur_frame and return the first object
        which contains pos within it (or None if there is no such object).
        """
        if self.cur_frame is None:
            return None

        for idx, obj in enumerate(self.cur_frame.objs):
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

    def save_current_frame(self):
        """
        save the current frame to its json (.lvl) file
        """
        if self.cur_frame is None:
            return
        dat = self.cur_frame.convert_to_json()
        frame_path = os.path.join(self.project_path, "levels", "%d.lvl" %
                                  self.cur_frame.frame_no)

        open(frame_path, "w").write(dat)

    def on_toggle_snap_to_grid_button(self, widget):
        """
        Called when the user toggles the "Snap to Grid" togglebutton on the toolbar
        """
        self.do_snap_to_grid = widget.get_active()


def main():
    global freedomEditor
    builder = Gtk.Builder()
    builder.add_from_file("freedom_editor_gui.glade")

    freedomEditor = FreedomEditor(builder)

    callbacks = {
        "main_window_delete_event" : freedomEditor.main_window_delete_event,
        "on_level_display_click" : freedomEditor.levelDisplay.on_click,
        "on_level_display_unclick" : freedomEditor.levelDisplay.on_unclick,
        "on_level_display_drag" : freedomEditor.levelDisplay.on_mouse_motion,
        "on_level_display_draw" : freedomEditor.levelDisplay.on_draw,
        "on_project_new" : freedomEditor.projectMenu.on_project_new,
        "on_new_project_game_path_browse" : freedomEditor.projectMenu.on_new_project_game_path_browse,
        "on_new_project_project_path_browse" : freedomEditor.projectMenu.on_new_project_project_path_browse,
        "on_project_open" : freedomEditor.projectMenu.on_project_open,
        "on_project_launch" : freedomEditor.projectMenu.on_project_launch,
        "on_project_open_frame" : freedomEditor.projectMenu.on_project_open_frame,
        "on_project_save_frame" : freedomEditor.projectMenu.on_project_save_frame,
        "on_project_build" : freedomEditor.projectMenu.on_project_build,
        "new_obj_selected" : freedomEditor.objectAttrs.new_obj_selected,
        "on_obj_attr_edit" : freedomEditor.objectAttrs.on_obj_attr_edit,
        "on_frame_attr_edit" : freedomEditor.frameAttrs.on_frame_attr_edit,
        "on_toggle_snap_to_grid_button" : freedomEditor.on_toggle_snap_to_grid_button
    }

    builder.connect_signals(callbacks)

    freedomEditor.main_window.show_all()

    Gtk.main()

if __name__ == "__main__":
    main()
