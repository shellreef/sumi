# python C:\python23\installer\build.py sumigetw.spec

a = Analysis([os.path.join(HOMEPATH,'support\\_mountzlib.py'), os.path.join(HOMEPATH,'support\\useUnicode.py'), 'X:\\p2p\\sumi\\sumigetw.py'],
             pathex=['C:\\Python23\\Installer'])
pyz = PYZ(a.pure)
exe = EXE(pyz,
          a.scripts,
          exclude_binaries=1,
          name='buildsumigetw/sumigetw.exe',
          debug=0,
          strip=0,
          upx=0,
          console=1 , icon='X:\\p2p\\sumi\\sumi.ico')
coll = COLLECT( exe,
               a.binaries,
               strip=0,
               upx=0,
               name='distsumigetw')
