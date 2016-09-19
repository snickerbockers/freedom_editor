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
%s build <path to project>
""" % (sys.argv[0], sys.argv[0], sys.argv[0])

def create_project(project_name, project_path, game_path):
    """
    creates a project which is a hierarchy of directories including
    a copy of the game and the dumped assets and levels.
    """

    os.mkdir(project_path)

    print "Copying game installation..."

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
    fpassets.extract_all_assets(path_to_inst_assets, raw_assets_dir)

    # next dump the level data
    print "Dumping level data..."
    dump_frames_linux_64.dump_all_levels(path_to_inst_chowdren, raw_level_dir)

def cmd_create():
    install_dir = None

    try:
        opt_val, params = gnu_getopt(sys.argv[1:], "i:", ["install-dir="])
        for option, value in opt_val:
            print option
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
                   game_path = "/mnt/big/jay/gog_games/Freedom Planet")

def cmd_launch():
    params = sys.argv[1:]

    game_dir = os.path.join(params[1], "inst")
    os.chdir(game_dir)
    subprocess.call(os.path.join("bin64", "Chowdren"))

def cmd_build():
    params = sys.argv[1:]

    source_dir = os.path.join(params[1], "levels")
    engine_path = os.path.join(params[1], "inst", "bin64", "Chowdren")
    write_frames_linux_64.write_all_frames(source_dir = source_dir,
                                           engine_path = engine_path)

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
