# $Id$

a = Analysis([os.path.join(HOMEPATH,'support\\_mountzlib.py'), os.path.join(HOMEPATH,'support\\useUnicode.py'), 'sumiserv.py'],
             pathex=['X:\\p2p\\sumi'])
pyz = PYZ(a.pure)
exe = EXE(pyz,
          a.scripts,
          exclude_binaries=1,
          name='buildsumiserv/sumiserv.exe',
          debug=0,
          strip=0,
          upx=0,
          console=1 , icon='sumi.ico')
coll = COLLECT( exe,
               a.binaries,
               strip=0,
               upx=0,
               name='distsumiserv')
