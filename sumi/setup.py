# 20040712 notes: USAGE: python setup.py py2exe
# Run on a Windows machine

# If you get "error: Permission denied", stop editing the Python in vi

# the exe will be in dist, named sumiserv.exe, sumiget.exe, sumigetw.exe
# any errors will be saved in dist/*.log

# ATTENTION
# TODO: Fix this under windows. Its broken.
# -> NameError: name 'wxObjectPtr' is not defined
# when trying to run dist\sumiget.exe.
# dist\sumigetw.exe doesn't even show up!
# Find out whats wrong.
# At least, can still manually run python sumigetw.py and it works
# UPDATE 20040719(am):
#  Something wrong with X:\p2p\sumi. Compiled a test (wxfoo.py + setup.py)
# in C:\test, and ran fine. Compiled in X:\test, ran fine. Compiled in
# X:\p2p\sumi, didn't run - even if cwd is different. The library.zip wasn't
# being updated, for some reason, despite mode 777, chmod -R 777 * and ".".
# I don't know why. For now,have a kludge - setup.bat, that copies *.py to
# C:\sumidev then copies dist to X:\p2p\sumi. Works! Can actually run now.
# BUT, "ImportError: No module named transport.modmirc". Module paths messed
# up. TODO: Fix this.
# UPDATE 20040719(pm):
#  If wxObjectPtr is not found, delete the "build" directory.

from distutils.core import setup
import py2exe
import glob

setup(console=["sumiget.py"])
#setup(windows=["sumigetw.py"])
setup(windows=[
	{"script": "sumigetw.py",
# Icon from Keith Oakley 2004-08-11
	"icon_resources": [(1, "sumi.ico")]}
	], data_files=[
	("transports", glob.glob("transports/*")),
	(".", ["sumi.ico"])])
setup(console=["sumiserv.py"])
#setup(console=["wxfoo.py"])
