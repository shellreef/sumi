# 20040712 notes: USAGE: python setup.py py2exe
# Run on a Windows machine

# If you get "error: Permission denied", stop editing the Python in vi

# the exe will be in dist, named sumiserv.exe, sumiget.exe, sumigetw.exe
# any errors will be saved in dist/*.log

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
