#!/usr/bin/env python

import os
import sys
import subprocess

import gi
gi.require_version('Gtk', '3.0')
from gi.repository import Gtk, GLib
import cairo

sys.path.append("../tools/")
import fp_project

project_path = None

class EditorCallbacks:
    def kill_me_now(self, *args):
        Gtk.main_quit(*args)
    def on_draw(self, widget, cr):
        cr.set_source_rgb(255, 0, 0)
        cr.set_line_width(0.5)

        # draw a red X
        cr.move_to(0, 0)
        cr.line_to(640, 480)
        cr.move_to(0, 480)
        cr.line_to(640, 0)

        cr.stroke()


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

    def on_project_launch(self, *args):
        if project_path is None:
            return

        fp_project.launch_project(project_path, False)

builder = Gtk.Builder()
builder.add_from_file("freedom_editor_gui.glade")

main_window = builder.get_object("main_window")
builder.connect_signals(EditorCallbacks())
main_window.show_all()

Gtk.main()
