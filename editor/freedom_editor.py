#!/usr/bin/env python

import sys

import gi
gi.require_version('Gtk', '3.0')
from gi.repository import Gtk
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
