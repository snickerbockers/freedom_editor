#!/usr/bin/env python
import os
import sys
import shutil
from getopt import gnu_getopt, GetoptError
import subprocess
import fpassets
import dump_frames_linux_64
import write_frames_linux_64

usage_string = """\
%s create -i|--install-dir <path to game installation> <path to project>
%s launch <path to project>
%s build [--assets-only|--engine-only] <path to project>
""" % (sys.argv[0], sys.argv[0], sys.argv[0])

def create_project(project_name, project_path, game_path):
    """
    creates a project which is a hierarchy of directories including
    a copy of the game and the dumped assets and levels.
    """

    # allow users to provide a path to an empty directory because the dialog
    # used by the editor will create the directory
    if os.path.exists(project_path) and len(os.listdir(project_path)) != 0:
        raise Exception("\"%s\" exists and is not empty" % project_path)

    if not os.path.exists(project_path):
        os.mkdir(project_path)

    print "Copying game installation..."
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

    # next dump the assets
    print "Dumping Assets..."
    sys.stdout.flush()
    fpassets.extract_all_assets(path_to_inst_assets, raw_assets_dir)

    # next dump the level data
    print "Dumping level data..."
    sys.stdout.flush()
    dump_frames_linux_64.dump_all_levels(path_to_inst_chowdren, raw_level_dir)

def cmd_create():
    install_dir = None

    try:
        opt_val, params = gnu_getopt(sys.argv[1:], "i:", ["install-dir="])
        for option, value in opt_val:
            if option == "-i" or option == "--install-dir":
                install_dir = value
    except GetoptError:
        print "%s" % usage_string
        exit(1)

    if install_dir is None or len(params) < 1:
        print "%s" % usage_string
        exit(1)

    create_project(project_path = params[1],
                   project_name = os.path.basename(params[1]),
                   game_path = install_dir)

def launch_project(project_path, block=True):
    game_dir = os.path.join(project_path, "inst")
    os.chdir(game_dir)

    cmd = os.path.join("bin64", "Chowdren")
    if block:
        subprocess.call(cmd)
    else:
        subprocess.Popen(cmd)

def cmd_launch():
    params = sys.argv[1:]

    launch_project(project_path = params[1])

def build_project_engine(project_path):
    source_dir = os.path.join(project_path, "levels")
    engine_path = os.path.join(project_path, "inst", "bin64", "Chowdren")

    print "rebuilding levels..."
    sys.stdout.flush()
    write_frames_linux_64.write_all_frames(source_dir = source_dir,
                                           engine_path = engine_path)

def build_project_assets(project_path):
    print "rebuilding Assets.dat..."
    sys.stdout.flush()
    assets_file = os.path.join(project_path, "inst", "Assets.dat")
    assets_dir = os.path.join(project_path, "assets")
    fpassets.write_assets_file(assets_file, assets_dir)

def cmd_build():
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
        print "%s" % usage_string
        exit(1)

    if build_engine_only and build_assets_only:
        raise Exception("You can't specify both --assets-only " + \
                        "AND --engine-only")

    if not build_assets_only:
        build_project_engine(params[1])

    if not build_engine_only:
        build_project_assets(params[1])

if __name__ == "__main__":
    cmd = sys.argv[1]

    if cmd == "create":
        cmd_create()
    elif cmd == "launch":
        cmd_launch()
    elif cmd == "build":
        cmd_build()
    else:
        print "\"%s\" is not a recognized command" % cmd
        print "%s" % usage_string
        exit(1)
