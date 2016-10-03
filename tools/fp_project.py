#!/usr/bin/env python
import os
import sys
import shutil
from getopt import gnu_getopt, GetoptError
import subprocess
import fpassets
import dump_frames_linux_64
import write_frames_linux_64
import fp_render
import threading

usage_string = """\
%s create -i|--install-dir <path to game installation> <path to project>
%s launch <path to project>
%s build [--assets-only|--engine-only] <path to project>
%s render <path to project>
%s revert <path to project> -a|--all --frame|-f <frame_number> ...
""" % (sys.argv[0], sys.argv[0], sys.argv[0], sys.argv[0], sys.argv[0])

def do_log(msg):
    print msg

def create_project(project_name, project_path, game_path, n_jobs = 1,
                   log_fn = do_log, join_threads = True):
    """
    creates a project which is a hierarchy of directories including
    a copy of the game and the dumped assets and levels.

    Returns a list of all active threads.
    """
    active_threads = []

    # allow users to provide a path to an empty directory because the dialog
    # used by the editor will create the directory
    if os.path.exists(project_path) and len(os.listdir(project_path)) != 0:
        raise Exception("\"%s\" exists and is not empty" % project_path)

    if not os.path.exists(project_path):
        os.mkdir(project_path)

    log_fn("Copying game installation...")
    sys.stdout.flush()

    # the inst directory contains a copy of your installation of the game
    inst_path = os.path.join(project_path, "inst")
    os.mkdir(inst_path)

    raw_assets_dir = os.path.join(project_path, "assets")
    raw_level_dir = os.path.join(project_path, "levels")

    os.mkdir(os.path.join(inst_path, "bin64"))

    # the game subdir within the existing installation of the game
    game_path = os.path.join(game_path, "game")

    bin64_chowdren = os.path.join("bin64", "Chowdren")
    bin64_libsdl = os.path.join("bin64", "libSDL2-2.0.so.0")
    bin64_libopenal = os.path.join("bin64", "libopenal.so.1")
    assets_file = "Assets.dat"
    data_dir = "Data"

    path_to_inst_assets = os.path.join(inst_path, assets_file)
    path_to_inst_chowdren = os.path.join(inst_path, bin64_chowdren)

    shutil.copy2(os.path.join(game_path, bin64_chowdren),
                 path_to_inst_chowdren)
    shutil.copy2(os.path.join(game_path, assets_file),
                 path_to_inst_assets)
    shutil.copy2(os.path.join(game_path, bin64_libsdl),
                 os.path.join(inst_path, bin64_libsdl))
    shutil.copy2(os.path.join(game_path, bin64_libopenal),
                 os.path.join(inst_path, bin64_libopenal))
    shutil.copytree(os.path.join(game_path, data_dir),
                    os.path.join(inst_path, data_dir))

    # Make another copy of Chowdren and Assets.dat.  This may seem redundant,
    # but the user might update his installation so we can't rely on that
    # as a backup.  The copy in the installation directory will be the one that
    # gets edited.
    bkup_dir = os.path.join(project_path, "bkup")
    os.mkdir(bkup_dir)
    shutil.copy2(path_to_inst_chowdren, os.path.join(bkup_dir, "Chowdren"))
    shutil.copy2(path_to_inst_assets, os.path.join(bkup_dir, "Assets.dat"))

    # next dump the assets.  Ideally this would happen in another thread
    # parallel to the dump_all_levels call, but since multithreading has
    # proven itself to be counterproductive in this instance it doesn't
    # really matter.
    log_fn("Dumping Assets...")
    sys.stdout.flush()
    assets_thread = threading.Thread(target = fpassets.extract_all_assets,
                                     args=(path_to_inst_assets,
                                           raw_assets_dir,
                                           log_fn))
    assets_thread.start()

    # next dump the level data
    log_fn("Dumping level data...")
    sys.stdout.flush()
    active_threads += dump_frames_linux_64.dump_all_levels(path_to_inst_chowdren, raw_level_dir,
                                                           n_jobs = n_jobs, log_fn = log_fn,
                                                           join_threads = join_threads)

    bkup_lvl_dir = os.path.join(bkup_dir, "levels")
    shutil.copytree(src = raw_level_dir, dst = bkup_lvl_dir)
    for filename in os.listdir(bkup_lvl_dir):
        os.chmod(os.path.join(bkup_lvl_dir, filename), 0444)

    if join_threads:
        assets_thread.join()
    else:
        active_threads.append(assets_thread)

    return active_threads

def cmd_create(log_fn = do_log):
    install_dir = None
    n_jobs = 1

    try:
        opt_val, params = gnu_getopt(sys.argv[1:], "i:j:", ["install-dir=", "jobs="])
        for option, value in opt_val:
            if option == "-i" or option == "--install-dir":
                install_dir = value
            elif option == "-j" or option == "--jobs":
                n_jobs = int(value)
    except GetoptError:
        log_fn("%s" % usage_string)
        exit(1)

    if install_dir is None or len(params) < 1:
        log_fn("%s" % usage_string)
        exit(1)

    create_project(project_path = params[1],
                   project_name = os.path.basename(params[1]),
                   game_path = install_dir, n_jobs = n_jobs, log_fn = log_fn)

def launch_project(project_path, block=True, log_fn = do_log):
    game_dir = os.path.join(project_path, "inst")
    os.chdir(game_dir)

    cmd = os.path.join("bin64", "Chowdren")
    if block:
        subprocess.call(cmd)
    else:
        subprocess.Popen(cmd)

def cmd_launch(log_fn = do_log):
    params = sys.argv[1:]

    launch_project(project_path = params[1], log_fn = log_fn)

def build_project_engine(project_path, log_fn = do_log, join_threads = True):
    source_dir = os.path.join(project_path, "levels")
    engine_path = os.path.join(project_path, "inst", "bin64", "Chowdren")

    log_fn("rebuilding levels...")
    sys.stdout.flush()
    td = threading.Thread(target = write_frames_linux_64.write_all_frames,
                          args = (source_dir, engine_path, log_fn))
    td.start()

    if join_threads:
        td.join()
        return []

    return [td]

def build_project_assets(project_path, log_fn = do_log, join_threads = True):
    log_fn("rebuilding Assets.dat...")
    sys.stdout.flush()
    assets_file = os.path.join(project_path, "inst", "Assets.dat")
    assets_dir = os.path.join(project_path, "assets")
    td = threading.Thread(target = fpassets.write_assets_file,
                          args = (assets_file, assets_dir, log_fn))
    td.start()

    if join_threads:
        td.join()
        return []
    return [td]

def cmd_build(log_fn = do_log):
    build_assets_only = False
    build_engine_only = False

    try:
        opt_val, params = gnu_getopt(sys.argv[1:], "", \
                             ["assets-only", "engine-only"])
        for option, value in opt_val:
            if option == "--assets-only":
                build_assets_only = True
            elif option == "--engine-only":
                build_engine_only = True
    except GetoptError:
        log_fn("%s" % usage_string)
        exit(1)

    if build_engine_only and build_assets_only:
        raise Exception("You can't specify both --assets-only " + \
                        "AND --engine-only")

    if not build_assets_only:
        build_project_engine(params[1], log_fn = log_fn)

    if not build_engine_only:
        build_project_assets(params[1], log_fn = log_fn)

def cmd_render(log_fn = do_log):
    params = sys.argv[1:]

    img_dir = os.path.join(params[1], "renders")
    if not os.path.exists(img_dir):
        os.mkdir(img_dir)

    for frame_no in range(1, 88):
        img_path = os.path.join(img_dir, "frame_%d.png" % frame_no)
        fp_render.render_frame_to_png(proj_path = params[1],
                                      frame_no = frame_no,
                                      img_path = img_path)

def revert_frame(proj_path, frame_no, log_fn = do_log):
    """
    Undo all changes to the given frame by copying over its .lvl file from
    the bkup directory.
    """
    frame_path = os.path.join(proj_path, "levels", "%d.lvl" % frame_no)
    frame_bkup_path = os.path.join(proj_path, "bkup", "levels", "%d.lvl" % frame_no)

    shutil.copy2(frame_bkup_path, frame_path)
    os.chmod(frame_path, 0644)

def cmd_revert(log_fn = do_log):
    """
    undo changes to .lvl files by copying over the originals from the bkup
    directory.

    the --frame|-f parameter tells which frame to revert.  It can be specified
    more than once to revert more than one frames.  --all can be used to revert
    every frame.
    """
    params = sys.argv[1:]

    all_flag = False
    frames = []

    try:
        opt_val, params = gnu_getopt(sys.argv[1:], "f:a", \
                             ["frame=", "all"])
        for option, value in opt_val:
            if option == "-a" or option == "--all":
                all_flag = True
            elif option == "-f" or option == "--frame":
                frames.append(int(value))
    except GetoptError:
        log_fn("%s" % usage_string)
        exit(1)

    proj_path = params[1]

    if all_flag:
        if len(frames) == 0:
            for frame_no in range(1, 88):
                revert_frame(proj_path, frame_no, log_fn = log_fn)
            sys.exit(0)
        else:
            log_fn("Error: You cannot specify both the --frame and --all flags")
            sys.exit(1)
    else:
        if len(frames) == 0:
            # I don't consider this to be an error even though it is weird
            log_fn("Nothing done!")
            sys.exit(0)

        # validate frame numbers before trying anything
        for frame_no in frames:
            if frame_no < 1 or frame_no >= 88:
                log_fn("Error: %d is not a valid frame" % frame_no)
                sys.exit(1)

        for frame_no in frames:
            revert_frame(proj_path, frame_no, log_fn = log_fn)

    sys.exit(0)

if __name__ == "__main__":
    cmd = sys.argv[1]

    if cmd == "create":
        cmd_create()
    elif cmd == "launch":
        cmd_launch()
    elif cmd == "build":
        cmd_build()
    elif cmd == "render":
        cmd_render()
    elif cmd == "revert":
        cmd_revert()
    else:
        do_log("\"%s\" is not a recognized command" % cmd)
        do_log("%s" % usage_string)
        exit(1)
