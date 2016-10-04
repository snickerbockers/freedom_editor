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

            idle_threads = fp_project.create_project(project_name = os.path.basename(proj_path),
                                                     project_path = proj_path,
                                                     game_path = game_path,
                                                     n_jobs = 1,
                                                     log_fn = self.update_progress_dialog,
                                                     join_threads = False)
            GLib.idle_add(self.check_up_on_fp_proj_threads, idle_threads)
            self.progress_dialog.run()
            self.progress_dialog.hide()

            self.freedomEditor.load_project(proj_path)

    def check_up_on_fp_proj_threads(self, idle_threads):
        for td in idle_threads:
            if td.is_alive():
                return True
        self.progress_dialog_ok_button.set_sensitive(True)
        return False

    def clear_progress_dialog(self):
        """
        Call this every time you're about to show the progress_dialog to make
        sure it is in a pristine state.
        """
        self.progress_dialog_textview.get_buffer().set_text("")
        self.progress_dialog_ok_button.set_sensitive(False)

    def actually_update_progress_dialog(self, txt):
        buf = self.progress_dialog_textview.get_buffer()
        buf.insert(buf.get_end_iter(), "%s\n" % txt)

    def update_progress_dialog(self, txt):
        GLib.idle_add(self.actually_update_progress_dialog, txt)

    def on_project_build_everything(self, *args):
        """
        Called when the user clicks "Project=>Build Everything".
        """
        self.on_project_build(only_new = False)

    def on_project_build_changes(self, *args):
        """
        Called when the user clicks "Project=>Build Changes".
        """
        self.on_project_build(only_new = True)

    def on_project_build(self, only_new):
        proj_path = self.freedomEditor.project_path

        if proj_path is None:
            return

        self.clear_progress_dialog()
        self.progress_dialog.set_transient_for(self.main_window)
        self.progress_dialog.show_all()

        engine_threads = fp_project.build_project_engine(project_path = proj_path,
                                                         log_fn = self.update_progress_dialog,
                                                         join_threads = False,
                                                         new_frames_only = only_new)
        assets_threads = fp_project.build_project_assets(project_path = proj_path,
                                                         log_fn = self.update_progress_dialog,
                                                         join_threads = False)
        GLib.idle_add(self.check_up_on_fp_proj_threads, engine_threads + assets_threads)
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
