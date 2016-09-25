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

project_path = None

class EditorCallbacks:
    def __init__(self):
        self.frame = None

        self.level_display_trans_x = 0.0
        self.level_display_trans_y = 0.0

    def kill_me_now(self, *args):
        Gtk.main_quit(*args)
    def on_draw(self, widget, cr):
        cr.translate(self.level_display_trans_x, self.level_display_trans_y)
        if self.frame is not None:
            self.frame.draw(cr)
            cr.paint()

    def on_level_display_click(self, widget, event):
        """
        called when the user clicks on the level_display drawing area
        """
        self.cursor_x_pos = event.x
        self.cursor_y_pos = event.y

    def on_level_display_drag(self, widget, event):
        """
        called when the user drags the level_display drawing area
        """
        rel_x = event.x - self.cursor_x_pos
        rel_y = event.y - self.cursor_y_pos

        self.cursor_x_pos = event.x
        self.cursor_y_pos = event.y

        self.level_display_trans_x += rel_x
        self.level_display_trans_y += rel_y

        widget.queue_draw()

    def on_project_new(self, *args):
        new_project_dialog = builder.get_object("new_project_dialog")
        new_project_dialog.set_transient_for(main_window)
        new_project_dialog.show_all()
        response_id = new_project_dialog.run()

        game_path_box = builder.get_object("new_project_game_path_text")
        proj_path_box = builder.get_object("new_project_project_path_text")

        game_path = game_path_box.get_text()
        proj_path = proj_path_box.get_text()

        new_project_dialog.destroy()

        if response_id == 1:
            # User clicked OK
            progress_dialog = builder.get_object("progress_dialog")
            progress_dialog.set_transient_for(main_window)
            progress_dialog.show_all()

            self.fp_proj_sub = subprocess.Popen(["../tools/fp_project.py",
                                                 "create", "-i", game_path,
                                                 proj_path],
                                                stdout = subprocess.PIPE)
            GLib.io_add_watch(self.fp_proj_sub.stdout,
                              GLib.IO_IN,
                              self.update_progress_dialog,
                              priority = GLib.PRIORITY_HIGH)
            GLib.idle_add(self.check_up_on_fp_proj_sub)
            progress_dialog.run()
            progress_dialog.destroy()
            project_path = proj_path

    def check_up_on_fp_proj_sub(self):
        self.fp_proj_sub.poll()
        if self.fp_proj_sub.returncode is not None:
            builder.get_object("progress_dialog_ok_button").set_sensitive(True)
            return False
        return True

    def update_progress_dialog(self, fd, condition):
        textview = builder.get_object("progress_dialog_textview")
        if condition == GLib.IO_IN:
            buf = textview.get_buffer()

            # XXX: since this isn't quite atomic, a compulsive clicker might be
            # able to fuck this up (but only a little since it prints one char
            # at a time)
            end_iter = buf.get_end_iter()
            buf.place_cursor(end_iter)
            buf.insert_at_cursor(fd.read(1))

            # FIXME: This is supposed to make it scroll to the end, but it doesn't do that
            end_iter = buf.get_end_iter()
            textview.scroll_to_iter(end_iter, 0.0, False, 0, 1.0)
            return True
        return False

    def on_new_project_game_path_browse(self, *args):
        """
        Called when the user clicks the "Browse" button next to
        "Game Installation Path" in the "New Project" dialog
        """
        dialog_buttons = (Gtk.STOCK_CANCEL, Gtk.ResponseType.CANCEL,
                          Gtk.STOCK_OPEN, Gtk.ResponseType.ACCEPT)

        # TODO: I found it triggering that this is more than 80 columns wide
        dialog = Gtk.FileChooserDialog(name = "Open Project",
                                       parent = builder.get_object("new_project_dialog"),
                                       action = Gtk.FileChooserAction.SELECT_FOLDER,
                                       buttons = dialog_buttons)
        dialog.show_all()
        if dialog.run() == Gtk.ResponseType.ACCEPT:
            game_path = dialog.get_filename()
            builder.get_object("new_project_game_path_text").set_text(game_path)
        dialog.destroy()

    def on_new_project_project_path_browse(self, *args):
        """
        Called when the user clicks the "Browse" button next to "Project Path"
        in the "New Project" dialog
        """
        dialog_buttons = (Gtk.STOCK_CANCEL, Gtk.ResponseType.CANCEL,
                          Gtk.STOCK_OPEN, Gtk.ResponseType.ACCEPT)

        # TODO: I found it triggering that this is more than 80 columns wide
        dialog = Gtk.FileChooserDialog(name = "Open Project",
                                       parent = builder.get_object("new_project_dialog"),
                                       action = Gtk.FileChooserAction.CREATE_FOLDER,
                                       buttons = dialog_buttons)
        dialog.show_all()
        if dialog.run() == Gtk.ResponseType.ACCEPT:
            game_path = dialog.get_filename()
            builder.get_object("new_project_project_path_text").set_text(game_path)
        dialog.destroy()

    def on_project_open(self, *args):
        global project_path

        dialog_buttons = (Gtk.STOCK_CANCEL, Gtk.ResponseType.CANCEL,
                          Gtk.STOCK_OPEN, Gtk.ResponseType.ACCEPT)

        # TODO: I found it triggering that this is more than 80 columns wide
        dialog = Gtk.FileChooserDialog(name = "Open Project", parent = main_window,
                                       action = Gtk.FileChooserAction.SELECT_FOLDER,
                                       buttons = dialog_buttons)
        dialog.show_all()
        dialog.run()
        project_path = dialog.get_filename()
        dialog.destroy()

        self.frame = frame.FpFrame(project_path, 21)

    def on_project_launch(self, *args):
        if project_path is None:
            return

        fp_project.launch_project(project_path, False)

    def on_project_open_frame(self, *args):
        if project_path is None:
            return
        choose_frame_dialog = builder.get_object("choose_frame_dialog")
        choose_frame_dialog_liststore = builder.get_object("choose_frame_dialog_liststore")
        treeview = builder.get_object("choose_frame_dialog_treeview")

        for lvl_file in os.listdir(os.path.join(project_path, "levels")):
            new_obj = choose_frame_dialog_liststore.append()
            choose_frame_dialog_liststore.set_value(new_obj, 0, lvl_file)

        choose_frame_dialog.set_transient_for(main_window)
        choose_frame_dialog.show_all()

        if choose_frame_dialog.run() == 1:
            # user clicked Ok
            treemodel, treeiter = treeview.get_selection().get_selected()
            selected_frame = treemodel.get(treeiter, 0)[0]
            selected_frame = int(selected_frame[:selected_frame.find('.')])

            self.frame = frame.FpFrame(project_path, selected_frame)
        choose_frame_dialog.destroy()

builder = Gtk.Builder()
builder.add_from_file("freedom_editor_gui.glade")

main_window = builder.get_object("main_window")
builder.connect_signals(EditorCallbacks())
main_window.show_all()

Gtk.main()
