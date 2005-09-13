#!/usr/bin/env python

#
# Generated Tue Sep 13 00:10:37 2005 by generateDS.py.
#

import sys
import getopt
from xml.dom import minidom
from xml.dom import Node

#
# If you have installed IPython you can uncomment and use the following.
# IPython is available from http://ipython.scipy.org/.
#

## from IPython.Shell import IPShellEmbed
## args = ''
## ipshell = IPShellEmbed(args,
##     banner = 'Dropping into IPython',
##     exit_msg = 'Leaving Interpreter, back to program.')

# Then use the following line where and when you want to drop into the
# IPython shell:
#    ipshell('<some message> -- Entering ipshell.\nHit Ctrl-D to exit')

#
# Support/utility functions.
#

def showIndent(outfile, level):
    for idx in range(level):
        outfile.write('    ')

def quote_xml(inStr):
    s1 = inStr
    s1 = s1.replace('&', '&amp;')
    s1 = s1.replace('<', '&lt;')
    s1 = s1.replace('"', '&quot;')
    return s1

def quote_python(inStr):
    s1 = inStr
    if s1.find("'") == -1:
        if s1.find('\n') == -1:
            return "'%s'" % s1
        else:
            return "'''%s'''" % s1
    else:
        if s1.find('"') != -1:
            s1 = s1.replace('"', '\\"')
        if s1.find('\n') == -1:
            return '"%s"' % s1
        else:
            return '"""%s"""' % s1


class MixedContainer:
    # Constants for category:
    CategoryNone = 0
    CategoryText = 1
    CategorySimple = 2
    CategoryComplex = 3
    # Constants for content_type:
    TypeNone = 0
    TypeText = 1
    TypeString = 2
    TypeInteger = 3
    TypeFloat = 4
    TypeDecimal = 5
    TypeDouble = 6
    TypeBoolean = 7
    def __init__(self, category, content_type, name, value):
        self.category = category
        self.content_type = content_type
        self.name = name
        self.value = value
    def getCategory(self):
        return self.category
    def getContenttype(self, content_type):
        return self.content_type
    def getValue(self):
        return self.value
    def getName(self):
        return self.name
    def export(self, outfile, level, name):
        if self.category == MixedContainer.CategoryText:
            outfile.write(self.value)
        elif self.category == MixedContainer.CategorySimple:
            self.exportSimple(outfile, level, name)
        else:    # category == MixedContainer.CategoryComplex
            self.value.export(outfile, level, name)
    def exportSimple(self, outfile, level, name):
        if self.content_type == MixedContainer.TypeString:
            outfile.write('<%s>%s</%s>' % (self.name, self.value, self.name))
        elif self.content_type == MixedContainer.TypeInteger or \
                self.content_type == MixedContainer.TypeBoolean:
            outfile.write('<%s>%d</%s>' % (self.name, self.value, self.name))
        elif self.content_type == MixedContainer.TypeFloat or \
                self.content_type == MixedContainer.TypeDecimal:
            outfile.write('<%s>%f</%s>' % (self.name, self.value, self.name))
        elif self.content_type == MixedContainer.TypeDouble:
            outfile.write('<%s>%g</%s>' % (self.name, self.value, self.name))
    def exportLiteral(self, outfile, level, name):
        if self.category == MixedContainer.CategoryText:
            showIndent(outfile, level)
            outfile.write('MixedContainer(%d, %d, "%s", "%s"),\n' % \
                (self.category, self.content_type, self.name, self.value))
        elif self.category == MixedContainer.CategorySimple:
            showIndent(outfile, level)
            outfile.write('MixedContainer(%d, %d, "%s", "%s"),\n' % \
                (self.category, self.content_type, self.name, self.value))
        else:    # category == MixedContainer.CategoryComplex
            showIndent(outfile, level)
            outfile.write('MixedContainer(%d, %d, "%s",\n' % \
                (self.category, self.content_type, self.name,))
            self.value.exportLiteral(outfile, level + 1)
            showIndent(outfile, level)
            outfile.write(')\n')


#
# Data representation classes.
#

class client_config:
    subclass = None
    def __init__(self, maxwait=1, myport=None, data_chan_type='', crypt=0, irc_nick='', colwidths='', dl_dir='', mtu='', dchanmode='', interface='', bandwidth=1, myip='', rwinsz=1, allow_local=0, share=0, winsize=None):
        self.maxwait = maxwait
        self.myport = myport
        self.data_chan_type = data_chan_type
        self.crypt = crypt
        self.irc_nick = irc_nick
        self.colwidths = colwidths
        self.dl_dir = dl_dir
        self.mtu = mtu
        self.dchanmode = dchanmode
        self.interface = interface
        self.bandwidth = bandwidth
        self.myip = myip
        self.rwinsz = rwinsz
        self.allow_local = allow_local
        self.share = share
        self.winsize = winsize
    def factory(*args_, **kwargs_):
        if client_config.subclass:
            return client_config.subclass(*args_, **kwargs_)
        else:
            return client_config(*args_, **kwargs_)
    factory = staticmethod(factory)
    def getWinsize(self): return self.winsize
    def setWinsize(self, winsize): self.winsize = winsize
    def getMaxwait(self): return self.maxwait
    def setMaxwait(self, maxwait): self.maxwait = maxwait
    def getMyport(self): return self.myport
    def setMyport(self, myport): self.myport = myport
    def getData_chan_type(self): return self.data_chan_type
    def setData_chan_type(self, data_chan_type): self.data_chan_type = data_chan_type
    def getCrypt(self): return self.crypt
    def setCrypt(self, crypt): self.crypt = crypt
    def getIrc_nick(self): return self.irc_nick
    def setIrc_nick(self, irc_nick): self.irc_nick = irc_nick
    def getColwidths(self): return self.colwidths
    def setColwidths(self, colwidths): self.colwidths = colwidths
    def getDl_dir(self): return self.dl_dir
    def setDl_dir(self, dl_dir): self.dl_dir = dl_dir
    def getMtu(self): return self.mtu
    def setMtu(self, mtu): self.mtu = mtu
    def getDchanmode(self): return self.dchanmode
    def setDchanmode(self, dchanmode): self.dchanmode = dchanmode
    def getInterface(self): return self.interface
    def setInterface(self, interface): self.interface = interface
    def getBandwidth(self): return self.bandwidth
    def setBandwidth(self, bandwidth): self.bandwidth = bandwidth
    def getMyip(self): return self.myip
    def setMyip(self, myip): self.myip = myip
    def getRwinsz(self): return self.rwinsz
    def setRwinsz(self, rwinsz): self.rwinsz = rwinsz
    def getAllow_local(self): return self.allow_local
    def setAllow_local(self, allow_local): self.allow_local = allow_local
    def getShare(self): return self.share
    def setShare(self, share): self.share = share
    def export(self, outfile, level, name_='client-config'):
        showIndent(outfile, level)
        outfile.write('<%s' % (name_, ))
        self.exportAttributes(outfile, level, name_='client-config')
        outfile.write('>\n')
        self.exportChildren(outfile, level + 1, name_)
        showIndent(outfile, level)
        outfile.write('</%s>\n' % name_)
    def exportAttributes(self, outfile, level, name_='client-config'):
        if self.getMaxwait() is not None:
            outfile.write(' maxwait="%s"' % (self.getMaxwait(), ))
        if self.getMyport() is not None:
            outfile.write(' myport="%s"' % (self.getMyport(), ))
        if self.getData_chan_type() is not None:
            outfile.write(' data_chan_type="%s"' % (self.getData_chan_type(), ))
        if self.getCrypt() is not None:
            outfile.write(' crypt="%s"' % (self.getCrypt(), ))
        if self.getIrc_nick() is not None:
            outfile.write(' irc_nick="%s"' % (self.getIrc_nick(), ))
        if self.getColwidths() is not None:
            outfile.write(' colwidths="%s"' % (self.getColwidths(), ))
        if self.getDl_dir() is not None:
            outfile.write(' dl_dir="%s"' % (self.getDl_dir(), ))
        if self.getMtu() is not None:
            outfile.write(' mtu="%s"' % (self.getMtu(), ))
        if self.getDchanmode() is not None:
            outfile.write(' dchanmode="%s"' % (self.getDchanmode(), ))
        if self.getInterface() is not None:
            outfile.write(' interface="%s"' % (self.getInterface(), ))
        if self.getBandwidth() is not None:
            outfile.write(' bandwidth="%s"' % (self.getBandwidth(), ))
        if self.getMyip() is not None:
            outfile.write(' myip="%s"' % (self.getMyip(), ))
        if self.getRwinsz() is not None:
            outfile.write(' rwinsz="%s"' % (self.getRwinsz(), ))
        if self.getAllow_local() is not None:
            outfile.write(' allow_local="%s"' % (self.getAllow_local(), ))
        if self.getShare() is not None:
            outfile.write(' share="%s"' % (self.getShare(), ))
    def exportChildren(self, outfile, level, name_='client-config'):
        if self.winsize:
            self.winsize.export(outfile, level)
    def exportLiteral(self, outfile, level, name_='client-config'):
        level += 1
        self.exportLiteralAttributes(outfile, level, name_)
        self.exportLiteralChildren(outfile, level, name_)
    def exportLiteralAttributes(self, outfile, level, name_):
        showIndent(outfile, level)
        outfile.write('maxwait = "%s",\n' % (self.getMaxwait(),))
        showIndent(outfile, level)
        outfile.write('myport = "%s",\n' % (self.getMyport(),))
        showIndent(outfile, level)
        outfile.write('data_chan_type = "%s",\n' % (self.getData_chan_type(),))
        showIndent(outfile, level)
        outfile.write('crypt = "%s",\n' % (self.getCrypt(),))
        showIndent(outfile, level)
        outfile.write('irc_nick = "%s",\n' % (self.getIrc_nick(),))
        showIndent(outfile, level)
        outfile.write('colwidths = "%s",\n' % (self.getColwidths(),))
        showIndent(outfile, level)
        outfile.write('dl_dir = "%s",\n' % (self.getDl_dir(),))
        showIndent(outfile, level)
        outfile.write('mtu = "%s",\n' % (self.getMtu(),))
        showIndent(outfile, level)
        outfile.write('dchanmode = "%s",\n' % (self.getDchanmode(),))
        showIndent(outfile, level)
        outfile.write('interface = "%s",\n' % (self.getInterface(),))
        showIndent(outfile, level)
        outfile.write('bandwidth = "%s",\n' % (self.getBandwidth(),))
        showIndent(outfile, level)
        outfile.write('myip = "%s",\n' % (self.getMyip(),))
        showIndent(outfile, level)
        outfile.write('rwinsz = "%s",\n' % (self.getRwinsz(),))
        showIndent(outfile, level)
        outfile.write('allow_local = "%s",\n' % (self.getAllow_local(),))
        showIndent(outfile, level)
        outfile.write('share = "%s",\n' % (self.getShare(),))
    def exportLiteralChildren(self, outfile, level, name_):
        if self.winsize:
            showIndent(outfile, level)
            outfile.write('winsize=winsize(\n')
            self.winsize.exportLiteral(outfile, level)
            showIndent(outfile, level)
            outfile.write('),\n')
    def build(self, node_):
        attrs = node_.attributes
        self.buildAttributes(attrs)
        for child_ in node_.childNodes:
            nodeName_ = child_.nodeName.split(':')[-1]
            self.buildChildren(child_, nodeName_)
    def buildAttributes(self, attrs):
        if attrs.get('maxwait'):
            try:
                self.maxwait = int(attrs.get('maxwait').value)
            except ValueError:
                raise ValueError('Bad integer attribute (maxwait)')
            if self.maxwait <= 0:
                raise ValueError('Invalid PositiveInteger (maxwait)')
        if attrs.get('myport'):
            self.myport = attrs.get('myport').value
        if attrs.get('data_chan_type'):
            self.data_chan_type = attrs.get('data_chan_type').value
        if attrs.get('crypt'):
            if attrs.get('crypt').value in ('true', '1'):
                self.crypt = 1
            elif attrs.get('crypt').value in ('false', '0'):
                self.crypt = 0
            else:
                raise ValueError('Bad boolean attribute (crypt)')
        if attrs.get('irc_nick'):
            self.irc_nick = attrs.get('irc_nick').value
        if attrs.get('colwidths'):
            self.colwidths = attrs.get('colwidths').value
        if attrs.get('dl_dir'):
            self.dl_dir = attrs.get('dl_dir').value
        if attrs.get('mtu'):
            self.mtu = attrs.get('mtu').value
        if attrs.get('dchanmode'):
            self.dchanmode = attrs.get('dchanmode').value
        if attrs.get('interface'):
            self.interface = attrs.get('interface').value
        if attrs.get('bandwidth'):
            try:
                self.bandwidth = int(attrs.get('bandwidth').value)
            except ValueError:
                raise ValueError('Bad integer attribute (bandwidth)')
            if self.bandwidth <= 0:
                raise ValueError('Invalid PositiveInteger (bandwidth)')
        if attrs.get('myip'):
            self.myip = attrs.get('myip').value
        if attrs.get('rwinsz'):
            try:
                self.rwinsz = int(attrs.get('rwinsz').value)
            except ValueError:
                raise ValueError('Bad integer attribute (rwinsz)')
            if self.rwinsz <= 0:
                raise ValueError('Invalid PositiveInteger (rwinsz)')
        if attrs.get('allow_local'):
            if attrs.get('allow_local').value in ('true', '1'):
                self.allow_local = 1
            elif attrs.get('allow_local').value in ('false', '0'):
                self.allow_local = 0
            else:
                raise ValueError('Bad boolean attribute (allow_local)')
        if attrs.get('share'):
            if attrs.get('share').value in ('true', '1'):
                self.share = 1
            elif attrs.get('share').value in ('false', '0'):
                self.share = 0
            else:
                raise ValueError('Bad boolean attribute (share)')
    def buildChildren(self, child_, nodeName_):
        if child_.nodeType == Node.ELEMENT_NODE and \
            nodeName_ == 'winsize':
            obj_ = winsize.factory()
            obj_.build(child_)
            self.setWinsize(obj_)
# end class client_config


class winsize:
    subclass = None
    def __init__(self, y=1, x=1, valueOf_=''):
        self.y = y
        self.x = x
        self.valueOf_ = valueOf_
    def factory(*args_, **kwargs_):
        if winsize.subclass:
            return winsize.subclass(*args_, **kwargs_)
        else:
            return winsize(*args_, **kwargs_)
    factory = staticmethod(factory)
    def getY(self): return self.y
    def setY(self, y): self.y = y
    def getX(self): return self.x
    def setX(self, x): self.x = x
    def getValueOf_(self): return self.valueOf_
    def setValueOf_(self, valueOf_): self.valueOf_ = valueOf_
    def export(self, outfile, level, name_='winsize'):
        showIndent(outfile, level)
        outfile.write('<%s' % (name_, ))
        self.exportAttributes(outfile, level, name_='winsize')
        outfile.write('>\n')
        self.exportChildren(outfile, level + 1, name_)
        showIndent(outfile, level)
        outfile.write('</%s>\n' % name_)
    def exportAttributes(self, outfile, level, name_='winsize'):
        if self.getY() is not None:
            outfile.write(' y="%s"' % (self.getY(), ))
        if self.getX() is not None:
            outfile.write(' x="%s"' % (self.getX(), ))
    def exportChildren(self, outfile, level, name_='winsize'):
        outfile.write(self.valueOf_)
    def exportLiteral(self, outfile, level, name_='winsize'):
        level += 1
        self.exportLiteralAttributes(outfile, level, name_)
        self.exportLiteralChildren(outfile, level, name_)
    def exportLiteralAttributes(self, outfile, level, name_):
        showIndent(outfile, level)
        outfile.write('y = "%s",\n' % (self.getY(),))
        showIndent(outfile, level)
        outfile.write('x = "%s",\n' % (self.getX(),))
    def exportLiteralChildren(self, outfile, level, name_):
        showIndent(outfile, level)
        outfile.write('valueOf_ = "%s",\n' % (self.valueOf_,))
    def build(self, node_):
        attrs = node_.attributes
        self.buildAttributes(attrs)
        for child_ in node_.childNodes:
            nodeName_ = child_.nodeName.split(':')[-1]
            self.buildChildren(child_, nodeName_)
    def buildAttributes(self, attrs):
        if attrs.get('y'):
            try:
                self.y = int(attrs.get('y').value)
            except ValueError:
                raise ValueError('Bad integer attribute (y)')
            if self.y <= 0:
                raise ValueError('Invalid PositiveInteger (y)')
        if attrs.get('x'):
            try:
                self.x = int(attrs.get('x').value)
            except ValueError:
                raise ValueError('Bad integer attribute (x)')
            if self.x <= 0:
                raise ValueError('Invalid PositiveInteger (x)')
    def buildChildren(self, child_, nodeName_):
        self.valueOf_ = ''
        for child in child_.childNodes:
            if child.nodeType == Node.TEXT_NODE:
                self.valueOf_ += child.nodeValue
# end class winsize


from xml.sax import handler, make_parser

class SaxStackElement:
    def __init__(self, name='', obj=None):
        self.name = name
        self.obj = obj
        self.content = ''

#
# SAX handler
#
class SaxClient_configHandler(handler.ContentHandler):
    def __init__(self):
        self.stack = []
        self.root = None

    def getRoot(self):
        return self.root

    def setDocumentLocator(self, locator):
        self.locator = locator
    
    def showError(self, msg):
        print '*** (showError):', msg
        sys.exit(-1)

    def startElement(self, name, attrs):
        done = 0
        if name == 'client-config':
            obj = client-config.factory()
            stackObj = SaxStackElement('client-config', obj)
            self.stack.append(stackObj)
            done = 1
        elif name == 'winsize':
            obj = winsize.factory()
            val = attrs.get('y', None)
            if val is not None:
                obj.setY(val)
            val = attrs.get('x', None)
            if val is not None:
                obj.setX(val)
            stackObj = SaxStackElement('winsize', obj)
            self.stack.append(stackObj)
            done = 1
        if not done:
            self.reportError('"%s" element not allowed here.' % name)

    def endElement(self, name):
        done = 0
        if name == 'client-config':
            if len(self.stack) == 1:
                self.root = self.stack[-1].obj
                self.stack.pop()
                done = 1
        elif name == 'winsize':
            if len(self.stack) >= 2:
                self.stack[-2].obj.setWinsize(self.stack[-1].obj)
                self.stack.pop()
                done = 1
        if not done:
            self.reportError('"%s" element not allowed here.' % name)

    def characters(self, chrs, start, end):
        if len(self.stack) > 0:
            self.stack[-1].content += chrs[start:end]

    def reportError(self, mesg):
        locator = self.locator
        sys.stderr.write('Doc: %s  Line: %d  Column: %d\n' % \
            (locator.getSystemId(), locator.getLineNumber(), 
            locator.getColumnNumber() + 1))
        sys.stderr.write(mesg)
        sys.stderr.write('\n')
        sys.exit(-1)
        #raise RuntimeError

USAGE_TEXT = """
Usage: python <Parser>.py [ -s ] <in_xml_file>
Options:
    -s        Use the SAX parser, not the minidom parser.
"""

def usage():
    print USAGE_TEXT
    sys.exit(-1)


#
# SAX handler used to determine the top level element.
#
class SaxSelectorHandler(handler.ContentHandler):
    def __init__(self):
        self.topElementName = None
    def getTopElementName(self):
        return self.topElementName
    def startElement(self, name, attrs):
        self.topElementName = name
        raise StopIteration


def parseSelect(inFileName):
    infile = file(inFileName, 'r')
    topElementName = None
    parser = make_parser()
    documentHandler = SaxSelectorHandler()
    parser.setContentHandler(documentHandler)
    try:
        try:
            parser.parse(infile)
        except StopIteration:
            topElementName = documentHandler.getTopElementName()
        if topElementName is None:
            raise RuntimeError, 'no top level element'
        topElementName = topElementName.replace('-', '_').replace(':', '_')
        if topElementName not in globals():
            raise RuntimeError, 'no class for top element: %s' % topElementName
        topElement = globals()[topElementName]
        infile.seek(0)
        doc = minidom.parse(infile)
    finally:
        infile.close()
    rootNode = doc.childNodes[0]
    rootObj = topElement.factory()
    rootObj.build(rootNode)
    # Enable Python to collect the space used by the DOM.
    doc = None
    sys.stdout.write('<?xml version="1.0" ?>\n')
    rootObj.export(sys.stdout, 0)
    return rootObj


def saxParse(inFileName):
    parser = make_parser()
    documentHandler = SaxClient_configHandler()
    parser.setDocumentHandler(documentHandler)
    parser.parse('file:%s' % inFileName)
    root = documentHandler.getRoot()
    sys.stdout.write('<?xml version="1.0" ?>\n')
    root.export(sys.stdout, 0)
    return root


def saxParseString(inString):
    parser = make_parser()
    documentHandler = SaxClient_configHandler()
    parser.setDocumentHandler(documentHandler)
    parser.feed(inString)
    parser.close()
    rootObj = documentHandler.getRoot()
    #sys.stdout.write('<?xml version="1.0" ?>\n')
    #rootObj.export(sys.stdout, 0)
    return rootObj


def parse(inFileName):
    doc = minidom.parse(inFileName)
    rootNode = doc.childNodes[0]
    rootObj = client_config.factory()
    rootObj.build(rootNode)
    # Enable Python to collect the space used by the DOM.
    doc = None
    sys.stdout.write('<?xml version="1.0" ?>\n')
    rootObj.export(sys.stdout, 0, name_="client_config")
    return rootObj


def parseString(inString):
    doc = minidom.parseString(inString)
    rootNode = doc.childNodes[0]
    rootObj = client_config.factory()
    rootObj.build(rootNode)
    # Enable Python to collect the space used by the DOM.
    doc = None
    sys.stdout.write('<?xml version="1.0" ?>\n')
    rootObj.export(sys.stdout, 0, name_="client_config")
    return rootObj


def parseLiteral(inFileName):
    doc = minidom.parse(inFileName)
    rootNode = doc.childNodes[0]
    rootObj = client_config.factory()
    rootObj.build(rootNode)
    # Enable Python to collect the space used by the DOM.
    doc = None
    sys.stdout.write('from clientxml import *\n\n')
    sys.stdout.write('rootObj = client_config(\n')
    rootObj.exportLiteral(sys.stdout, 0, name_="client_config")
    sys.stdout.write(')\n')
    return rootObj


def main():
    args = sys.argv[1:]
    if len(args) == 2 and args[0] == '-s':
        saxParse(args[1])
    elif len(args) == 1:
        parse(args[0])
    else:
        usage()


if __name__ == '__main__':
    main()
    #import pdb
    #pdb.run('main()')

