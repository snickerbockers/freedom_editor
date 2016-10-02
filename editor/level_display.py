#!/usr/bin/env python

import freedom_editor

"""
Mouse dragging state.  This is entirely a function of the first button the user
held down when he began dragging the mouse cursor.

This can be either nothing (STATE_NORM), panning the view (STATE_PAN)
or moving an object (STATE_DRAG_OBJ)
"""
STATE_NORM = 0
STATE_PAN = 1
STATE_DRAG_OBJ = 2

class LevelDisplay:
    def __init__(self, builder, freedomEditor):
        self.drawing_area = builder.get_object("level_display")

        self.level_display_trans_x = 0.0
        self.level_display_trans_y = 0.0

        self.cursor_x_pos = 0
        self.cursor_y_pos = 0

        self.mouse_state = STATE_NORM

        self.freedomEditor = freedomEditor

    def on_click(self, widget, event):
        """
        called when the user clicks on the level_display drawing area
        """
        if self.mouse_state == STATE_NORM:
            # XXX Gtk probably has constants for mouse buttons, I just don't know
            #     what they are called.
            if event.button == 1 or event.button == 3:
                # left click
                self.cursor_x_pos = event.x
                self.cursor_y_pos = event.y

            if event.button == 1:
                self.mouse_state = STATE_PAN
            elif event.button == 3:
                self.mouse_state = STATE_DRAG_OBJ

                # need to find the object under the cursor.  This involves
                # converting the window-coordinates to world-coordinates
                world_cursor_x = self.cursor_x_pos - self.level_display_trans_x
                world_cursor_y = self.cursor_y_pos - self.level_display_trans_y

                world_cursor = (world_cursor_x, world_cursor_y)

                obj_idx = self.freedomEditor.get_object_at_pos(world_cursor)

                self.freedomEditor.select_object(obj_idx)

    def on_unclick(self, widget, event):
        """
        called when the user releases a previously held-down moust button.
        """
        if self.mouse_state == STATE_PAN and event.button == 1:
            self.mouse_state = STATE_NORM
        elif self.mouse_state == STATE_DRAG_OBJ and event.button == 3:
            self.mouse_state = STATE_NORM

    def on_mouse_motion(self, widget, event):
        """
        called when the user drags the level_display drawing area
        """
        if self.cursor_x_pos is None:
            rel_x = rel_y = 0
        else:
            rel_x = event.x - self.cursor_x_pos
            rel_y = event.y - self.cursor_y_pos

        if self.mouse_state == STATE_PAN:
            self.cursor_x_pos = event.x
            self.cursor_y_pos = event.y

            self.level_display_trans_x += rel_x
            self.level_display_trans_y += rel_y

            self.invalidate()
        elif self.mouse_state == STATE_DRAG_OBJ:
            self.cursor_x_pos = event.x
            self.cursor_y_pos = event.y

            selected_obj_idx = self.freedomEditor.get_selected_object()
            if selected_obj_idx is not None:
                obj = self.freedomEditor.get_object_by_index(selected_obj_idx)
                if obj is not None:
                    self.freedomEditor.set_obj_pos(obj, (obj.pos_x + rel_x,
                                                         obj.pos_y + rel_y))


    def invalidate(self):
        self.drawing_area.queue_draw()

    def on_draw(self, widget, cr):
        cr.translate(self.level_display_trans_x, self.level_display_trans_y)
        self.draw_grid(cr, widget.get_allocation().width,
                       widget.get_allocation().height)
        if self.freedomEditor.cur_frame is not None:
            self.draw_frame_borders(cr, self.freedomEditor.cur_frame.width,
                                    self.freedomEditor.cur_frame.height)
        if self.freedomEditor.cur_frame is not None:
            self.freedomEditor.cur_frame.draw(cr)
            cr.paint()

    def set_trans(self, trans_x, trans_y):
        """
        Set the translation of the level_display's drawing area.
        This does not queue a redraw, so make sure to call invalidate after
        """
        self.level_display_trans_x = trans_x
        self.level_display_trans_y = trans_y

    def draw_grid(self, cr, width, height):
        """
        draw an infinite grid to help players align their creations.
        cr - cairo context
        width - width of the level_display drawing area
        height - height of the level_display drawing area
        """
        cr.set_source_rgb(0, 0, 255)
        cr.set_line_width(0.5)

        # In the x_end/y_end calculations, GRID_WIDTH/GRID_HEIGHT is multiplied
        # by 2 because the range function will stop at the col/row *before* it
        # gets to x_end/y_end.
        x_start = (int(-self.level_display_trans_x) / \
                   freedom_editor.GRID_WIDTH) * freedom_editor.GRID_WIDTH
        x_end = x_start + (int(width) / freedom_editor.GRID_WIDTH) * \
                freedom_editor.GRID_WIDTH + freedom_editor.GRID_WIDTH * 2

        y_start = (int(-self.level_display_trans_y) / \
                   freedom_editor.GRID_HEIGHT) * freedom_editor.GRID_HEIGHT
        y_end = y_start + (int(height) / freedom_editor.GRID_HEIGHT) * \
                freedom_editor.GRID_HEIGHT + freedom_editor.GRID_HEIGHT * 2

        # draw vertical lines
        for col in range(int(x_start), x_end, freedom_editor.GRID_WIDTH):
            cr.move_to(col, y_start)
            cr.line_to(col, y_end)

        # draw horizontal lines
        for row in range(int(y_start), y_end, freedom_editor.GRID_HEIGHT):
            cr.move_to(x_start, row)
            cr.line_to(x_end, row)

        cr.stroke()

    def draw_frame_borders(self, cr, x_border, y_border):
        """
        draw a red box from (0, 0) to (x_border, y_border).
        This is used to correspond to the frame's own borders.
        """
        cr.set_source_rgb(255, 0, 0)
        cr.set_line_width(2.0)

        cr.move_to(0, 0)

        cr.line_to(0, y_border)
        cr.line_to(x_border,  y_border)
        cr.line_to(x_border, 0)
        cr.line_to(0, 0)

        cr.stroke()

    ############################################################################
    #
    # STUPID FUCKING HACK
    #
    # I tried putting this function in freedom_editor.py; it didn't work.
    # SOMEHOW the do_snap_to_grid variable wasn't getting updated (and I *DID*
    # remember to put in "global do_snap_to_grid" at the top of the function).
    # I have no fucking idea what went wrong, but I will remember this moment next
    # time I'm considering using Python for a project.
    #
    ############################################################################
    def on_toggle_snap_to_grid_button(self, widget):
        """
        Called when the user toggles the "Snap to Grid" togglebutton on the toolbar
        """
        self.freedomEditor.do_snap_to_grid = widget.get_active()
