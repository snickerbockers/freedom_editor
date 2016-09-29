#!/usr/bin/env python

import freedom_editor

drawing_area = None
level_display_trans_x = 0.0
level_display_trans_y = 0.0

cursor_x_pos = cursor_y_pos = None

"""
Mouse dragging state.  This is entirely a function of the first button the user
held down when he began dragging the mouse cursor.

This can be either nothing (STATE_NORM), panning the view (STATE_PAN)
or moving an object (STATE_DRAG_OBJ)
"""
STATE_NORM = 0
STATE_PAN = 1
STATE_DRAG_OBJ = 2
mouse_state = STATE_NORM


def set_builder(builder):
    global drawing_area, level_display_trans_X, level_display_trans_y

    drawing_area = builder.get_object("level_display")
    level_display_trans_x = 0.0
    level_display_trans_y = 0.0

def on_click(widget, event):
    """
    called when the user clicks on the level_display drawing area
    """
    global cursor_x_pos, cursor_y_pos, mouse_state

    if mouse_state == STATE_NORM:
        # XXX Gtk probably has constants for mouse buttons, I just don't know
        #     what they are called.
        if event.button == 1 or event.button == 3:
            # left click
            cursor_x_pos = event.x
            cursor_y_pos = event.y

        if event.button == 1:
            mouse_state = STATE_PAN
        elif event.button == 3:
            mouse_state = STATE_DRAG_OBJ

            # need to find the object under the cursor.  This involves
            # converting the window-coordinates to world-coordinates
            world_cursor_x = cursor_x_pos - level_display_trans_x
            world_cursor_y = cursor_y_pos - level_display_trans_y

            world_cursor = (world_cursor_x, world_cursor_y)

            obj_idx = freedom_editor.get_object_at_pos(world_cursor)

            if obj_idx is not None:
                freedom_editor.select_object(obj_idx)

def on_unclick(widget, event):
    """
    called when the user releases a previously held-down moust button.
    """
    global mouse_state

    if mouse_state == STATE_PAN and event.button == 1:
        mouse_state = STATE_NORM
    elif mouse_state == STATE_DRAG_OBJ and event.button == 3:
        mouse_state = STATE_NORM

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

    if mouse_state == STATE_PAN:
        cursor_x_pos = event.x
        cursor_y_pos = event.y

        level_display_trans_x += rel_x
        level_display_trans_y += rel_y

        invalidate()
    elif mouse_state == STATE_DRAG_OBJ:
        cursor_x_pos = event.x
        cursor_y_pos = event.y

        selected_obj_idx = freedom_editor.get_selected_object()
        if selected_obj_idx is not None:
            obj = freedom_editor.get_object_by_index(selected_obj_idx)
            if obj is not None:
                freedom_editor.set_obj_pos(obj, (obj.pos_x + rel_x,
                                                 obj.pos_y + rel_y))

def invalidate():
    drawing_area.queue_draw()

def on_draw(widget, cr):
    cr.translate(level_display_trans_x, level_display_trans_y)
    if freedom_editor.cur_frame is not None:
        freedom_editor.cur_frame.draw(cr)
        cr.paint()
