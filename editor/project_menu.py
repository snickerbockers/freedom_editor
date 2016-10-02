#!/usr/bin/env python

import os
import sys
import subprocess

import gi
gi.require_version('Gtk', '3.0')
from gi.repository import Gtk, GLib, GObject

sys.path.append("../tools/")
import fp_project

import freedom_editor

class ProjectMenu:
    def __init__(self, builder, freedomEditor):
        self.new_project_dialog = builder.get_object("new_project_dialog")
        self.game_path_box = builder.get_object("new_project_game_path_text")
        self.proj_path_box = builder.get_object("new_project_project_path_text")
        self.progress_dialog = builder.get_object("progress_dialog")
        self.progress_dialog_ok_button = builder.get_object("progress_dialog_ok_button")
        self.choose_frame_dialog = builder.get_object("choose_frame_dialog")
        self.choose_frame_dialog_liststore = builder.get_object("choose_frame_dialog_liststore")
        self.choose_frame_dialog_treeview = builder.get_object("choose_frame_dialog_treeview")
        self.main_window = builder.get_object("main_window")
        self.progress_dialog_textview = builder.get_object("progress_dialog_textview")

        self.fp_proj_sub = None

        self.freedomEditor = freedomEditor

    def on_project_new(self, *args):
        self.new_project_dialog.set_transient_for(self.main_window)
        self.new_project_dialog.show_all()
        response_id = self.new_project_dialog.run()

        game_path = self.game_path_box.get_text()
        proj_path = self.proj_path_box.get_text()

        self.new_project_dialog.hide()

        if response_id == 1:
            # User clicked OK
            self.clear_progress_dialog()
            self.progress_dialog.set_transient_for(self.main_window)
            self.progress_dialog.show_all()

            self.fp_proj_sub = subprocess.Popen(["../tools/fp_project.py",
                                                 "create", "-i", game_path,
                                                 proj_path],
                                                stdout = subprocess.PIPE)
            GLib.io_add_watch(self.fp_proj_sub.stdout,
                              GLib.IO_IN,
                              self.update_progress_dialog,
                              priority = GLib.PRIORITY_HIGH)
            GLib.idle_add(self.check_up_on_fp_proj_sub)
            self.progress_dialog.run()
            self.progress_dialog.hide()

            self.freedomEditor.load_project(proj_path)

    def check_up_on_fp_proj_sub(self):
        self.fp_proj_sub.poll()
        if self.fp_proj_sub.returncode is not None:
            self.progress_dialog_ok_button.set_sensitive(True)
            return False
        return True

    def clear_progress_dialog(self):
        """
        deletes all the text from the progress_dialog_textview
        """
        self.progress_dialog_textview.get_buffer().set_text("")

    def update_progress_dialog(self, fd, condition):
        if condition == GLib.IO_IN:
            buf = self.progress_dialog_textview.get_buffer()

            # XXX: since this isn't quite atomic, a compulsive clicker might be
            # able to fuck this up (but only a little since it prints one char
            # at a time)
            end_iter = buf.get_end_iter()
            buf.place_cursor(end_iter)
            buf.insert_at_cursor(fd.read(1))

            # FIXME: This is supposed to make it scroll to the end,
            #        but it doesn't do that
            end_iter = buf.get_end_iter()
            self.progress_dialog_textview.scroll_to_iter(end_iter,
                                                         0.0, False, 0, 1.0)
            return True
        return False

    def on_project_build(self, *args):
        """
        Called when the user clicks Project=>Build.
        """
        proj_path = self.freedomEditor.project_path

        if proj_path is None:
            return

        self.clear_progress_dialog()
        self.progress_dialog.set_transient_for(self.main_window)
        self.progress_dialog.show_all()

        self.fp_proj_sub = subprocess.Popen(["../tools/fp_project.py",
                                             "build", proj_path],
                                            stdout = subprocess.PIPE)
        GLib.io_add_watch(self.fp_proj_sub.stdout,
                          GLib.IO_IN,
                          self.update_progress_dialog,
                          priority = GLib.PRIORITY_HIGH)
        GLib.idle_add(self.check_up_on_fp_proj_sub)
        self.progress_dialog.run()
        self.progress_dialog.hide()
        self.freedomEditor.project_path = proj_path

    def on_new_project_game_path_browse(self, *args):
        """
        Called when the user clicks the "Browse" button next to
        "Game Installation Path" in the "New Project" dialog
        """
        dialog_buttons = (Gtk.STOCK_CANCEL, Gtk.ResponseType.CANCEL,
                          Gtk.STOCK_OPEN, Gtk.ResponseType.ACCEPT)

        dialog = Gtk.FileChooserDialog(name = "Open Project",
                                       parent = self.new_project_dialog,
                                       action = Gtk.FileChooserAction.SELECT_FOLDER,
                                       buttons = dialog_buttons)
        dialog.show_all()
        if dialog.run() == Gtk.ResponseType.ACCEPT:
            game_path = dialog.get_filename()
            self.game_path_box.set_text(game_path)
        dialog.destroy()

    def on_new_project_project_path_browse(self, *args):
        """
        Called when the user clicks the "Browse" button next to "Project Path"
        in the "New Project" dialog
        """
        dialog_buttons = (Gtk.STOCK_CANCEL, Gtk.ResponseType.CANCEL,
                          Gtk.STOCK_OPEN, Gtk.ResponseType.ACCEPT)

        dialog = Gtk.FileChooserDialog(name = "Open Project",
                                       parent = self.new_project_dialog,
                                       action = Gtk.FileChooserAction.CREATE_FOLDER,
                                       buttons = dialog_buttons)
        dialog.show_all()
        if dialog.run() == Gtk.ResponseType.ACCEPT:
            game_path = dialog.get_filename()
            self.proj_path_box.set_text(game_path)
        dialog.destroy()

    def on_project_open(self, *args):
        dialog_buttons = (Gtk.STOCK_CANCEL, Gtk.ResponseType.CANCEL,
                          Gtk.STOCK_OPEN, Gtk.ResponseType.ACCEPT)

        dialog = Gtk.FileChooserDialog(name = "Open Project",
                                       parent = self.main_window,
                                       action = Gtk.FileChooserAction.SELECT_FOLDER,
                                       buttons = dialog_buttons)
        dialog.show_all()
        action = dialog.run()

        if action == Gtk.ResponseType.ACCEPT:
            self.freedomEditor.load_project(dialog.get_filename())

        dialog.destroy()

    def on_project_launch(self, *args):
        if self.freedomEditor.project_path is None:
            return

        fp_project.launch_project(self.freedomEditor.project_path, False)

    def on_project_open_frame(self, *args):
        if self.freedomEditor.project_path is None:
            return

        lvl_dir = os.path.join(self.freedomEditor.project_path, "levels")
        for lvl_file in os.listdir(lvl_dir):
            new_obj = self.choose_frame_dialog_liststore.append()
            self.choose_frame_dialog_liststore.set_value(new_obj, 0, lvl_file)

        self.choose_frame_dialog.set_transient_for(self.main_window)
        self.choose_frame_dialog.show_all()

        if self.choose_frame_dialog.run() == 1:
            # user clicked Ok
            treemodel, treeiter = self.choose_frame_dialog_treeview.get_selection().get_selected()
            selected_frame = treemodel.get(treeiter, 0)[0]
            selected_frame = int(selected_frame[:selected_frame.find('.')])

            self.freedomEditor.set_frame(selected_frame)
        self.choose_frame_dialog.hide()

    def on_project_save_frame(self, *args):
        self.freedomEditor.save_current_frame()
