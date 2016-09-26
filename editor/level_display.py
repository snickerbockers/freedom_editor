#!/usr/bin/env python

import freedom_editor

drawing_area = None
level_display_trans_x = 0.0
level_display_trans_y = 0.0

cursor_x_pos = cursor_y_pos = None

def set_builder(builder):
    global drawing_area, level_display_trans_X, level_display_trans_y

    drawing_area = builder.get_object("level_display")
    level_display_trans_x = 0.0
    level_display_trans_y = 0.0

def on_click(widget, event):
    """
    called when the user clicks on the level_display drawing area
    """
    global cursor_x_pos, cursor_y_pos

    cursor_x_pos = event.x
    cursor_y_pos = event.y

def on_mouse_motion(widget, event):
    """
    called when the user drags the level_display drawing area
    """
    global cursor_x_pos, cursor_y_pos, \
        level_display_trans_x, level_display_trans_y

    if cursor_x_pos is None:
        rel_x = rel_y = 0
    else:
        rel_x = event.x - cursor_x_pos
        rel_y = event.y - cursor_y_pos

    cursor_x_pos = event.x
    cursor_y_pos = event.y

    level_display_trans_x += rel_x
    level_display_trans_y += rel_y

    invalidate()
    # widget.queue_draw()

def invalidate():
    drawing_area.queue_draw()

def on_draw(widget, cr):
    cr.translate(level_display_trans_x, level_display_trans_y)
    if freedom_editor.cur_frame is not None:
        freedom_editor.cur_frame.draw(cr)
        cr.paint()
