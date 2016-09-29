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

def set_builder(builder):
    global new_project_dialog, game_path_box, proj_path_box, progress_dialog, \
        progress_dialog_ok_button, choose_frame_dialog, \
        choose_frame_dialog_liststore, choose_frame_dialog_treeview, \
        main_window, progress_dialog_textview

    new_project_dialog = builder.get_object("new_project_dialog")
    game_path_box = builder.get_object("new_project_game_path_text")
    proj_path_box = builder.get_object("new_project_project_path_text")
    progress_dialog = builder.get_object("progress_dialog")
    progress_dialog_ok_button = builder.get_object("progress_dialog_ok_button")
    choose_frame_dialog = builder.get_object("choose_frame_dialog")
    choose_frame_dialog_liststore = builder.get_object("choose_frame_dialog_liststore")
    choose_frame_dialog_treeview = builder.get_object("choose_frame_dialog_treeview")
    main_window = builder.get_object("main_window")
    progress_dialog_textview = builder.get_object("progress_dialog_textview")

def on_project_new(*args):
    global fp_proj_sub

    new_project_dialog.set_transient_for(main_window)
    new_project_dialog.show_all()
    response_id = new_project_dialog.run()

    game_path = game_path_box.get_text()
    proj_path = proj_path_box.get_text()

    new_project_dialog.hide

    if response_id == 1:
        # User clicked OK
        progress_dialog.set_transient_for(main_window)
        progress_dialog.show_all()

        fp_proj_sub = subprocess.Popen(["../tools/fp_project.py",
                                        "create", "-i", game_path,
                                        proj_path],
                                       stdout = subprocess.PIPE)
        GLib.io_add_watch(fp_proj_sub.stdout,
                          GLib.IO_IN,
                          update_progress_dialog,
                          priority = GLib.PRIORITY_HIGH)
        GLib.idle_add(check_up_on_fp_proj_sub)
        progress_dialog.run()
        progress_dialog.hide()
        freedom_editor.project_path = proj_path

def check_up_on_fp_proj_sub():
    fp_proj_sub.poll()
    if fp_proj_sub.returncode is not None:
        progress_dialog_ok_button.set_sensitive(True)
        return False
    return True

def update_progress_dialog(fd, condition):
    textview = progress_dialog_textview
    if condition == GLib.IO_IN:
        buf = progress_dialog_textview.get_buffer()

        # XXX: since this isn't quite atomic, a compulsive clicker might be
        # able to fuck this up (but only a little since it prints one char
        # at a time)
        end_iter = buf.get_end_iter()
        buf.place_cursor(end_iter)
        buf.insert_at_cursor(fd.read(1))

        # FIXME: This is supposed to make it scroll to the end, but it doesn't do that
        end_iter = buf.get_end_iter()
        progress_dialog_textview.scroll_to_iter(end_iter, 0.0, False, 0, 1.0)
        return True
    return False



def on_new_project_game_path_browse(*args):
    """
    Called when the user clicks the "Browse" button next to
    "Game Installation Path" in the "New Project" dialog
    """
    dialog_buttons = (Gtk.STOCK_CANCEL, Gtk.ResponseType.CANCEL,
                      Gtk.STOCK_OPEN, Gtk.ResponseType.ACCEPT)

    dialog = Gtk.FileChooserDialog(name = "Open Project",
                                   parent = new_project_dialog,
                                   action = Gtk.FileChooserAction.SELECT_FOLDER,
                                   buttons = dialog_buttons)
    dialog.show_all()
    if dialog.run() == Gtk.ResponseType.ACCEPT:
        game_path = dialog.get_filename()
        game_path_box.set_text(game_path)
    dialog.destroy()

def on_new_project_project_path_browse(*args):
    """
    Called when the user clicks the "Browse" button next to "Project Path"
    in the "New Project" dialog
    """
    dialog_buttons = (Gtk.STOCK_CANCEL, Gtk.ResponseType.CANCEL,
                      Gtk.STOCK_OPEN, Gtk.ResponseType.ACCEPT)

    dialog = Gtk.FileChooserDialog(name = "Open Project",
                                   parent = new_project_dialog,
                                   action = Gtk.FileChooserAction.CREATE_FOLDER,
                                   buttons = dialog_buttons)
    dialog.show_all()
    if dialog.run() == Gtk.ResponseType.ACCEPT:
        game_path = dialog.get_filename()
        proj_path_box.set_text(game_path)
    dialog.destroy()

def on_project_open(*args):
    dialog_buttons = (Gtk.STOCK_CANCEL, Gtk.ResponseType.CANCEL,
                      Gtk.STOCK_OPEN, Gtk.ResponseType.ACCEPT)

    dialog = Gtk.FileChooserDialog(name = "Open Project", parent = main_window,
                                   action = Gtk.FileChooserAction.SELECT_FOLDER,
                                   buttons = dialog_buttons)
    dialog.show_all()
    action = dialog.run()

    if action == Gtk.ResponseType.ACCEPT:
        freedom_editor.project_path = dialog.get_filename()
        freedom_editor.set_frame(21)

    dialog.destroy()

def on_project_launch(*args):
    if freedom_editor.project_path is None:
        return

    fp_project.launch_project(freedom_editor.project_path, False)

def on_project_open_frame(*args):
    if freedom_editor.project_path is None:
        return

    lvl_dir = os.path.join(freedom_editor.project_path, "levels")
    for lvl_file in os.listdir(lvl_dir):
        new_obj = choose_frame_dialog_liststore.append()
        choose_frame_dialog_liststore.set_value(new_obj, 0, lvl_file)

    choose_frame_dialog.set_transient_for(main_window)
    choose_frame_dialog.show_all()

    if choose_frame_dialog.run() == 1:
        # user clicked Ok
        treemodel, treeiter = choose_frame_dialog_treeview.get_selection().get_selected()
        selected_frame = treemodel.get(treeiter, 0)[0]
        selected_frame = int(selected_frame[:selected_frame.find('.')])

        freedom_editor.set_frame(selected_frame)
    choose_frame_dialog.hide()

def on_project_save_frame(*args):
    freedom_editor.save_current_frame()
