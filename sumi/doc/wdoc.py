#!/usr/bin/env python
# MediaWiki Exporter

# Database can be exported, but then have to process low-level SQL details.
#ssh jeffconnelly@shell.berlios.de ./dump > wiki-`date +%Y%m%d`.sql
# See http://meta.wikimedia.org/wiki/Help:Export
# Best way is to use dumpBackup.php, but not supported on 1.4 (WikiExporter)

import os
import re
import urllib
import urllib2
import httplib
import gzip
from xml.sax import saxutils, handler, make_parser

#httplib.HTTPConnection.debuglevel=1

# Size in bytes to load into memory to write to disk
block_size = 1024 * 1024

def all_pages(site, exclude_namespaces=["Special", "SUMIWiki"]):
    """Return pages in a MediaWiki, excluding those in certain namespaces."""

    raw = urllib.urlopen("http://%s/Special:Allpages" % site).read()
    # XXX: hardcoded to wgScriptPath /wiki--change if needed!
    pages = re.findall('/wiki/([^"<]+)', raw)
    if not pages:
        print "couldn't find all pages"
        raise SystemExit

    # Remove duplicates by putting into a dictionary and back out
    d = {}
    for p in pages:
        parts = p.split(":")
        if len(parts) == 2 and parts[0] in exclude_namespaces:
            continue

        d[p] = True
    pages = d.keys()
    pages.sort()

    return pages

def fetch_xml(site, pages):
    """Get XML pages from a MediaWiki site. Returns filehandle for parser."""
    try:
        os.unlink("wiki.xml.gz")
        os.unlink("wiki.xml")
    except:
        pass

    url = "http://%s/Special:Export?action=submit&pages=" % (site,)
    url += urllib.urlencode(
            {"action": 'submit',
            "curonly": 'true',
            "pages": "\n".join(pages)})
    print url
    request = urllib2.Request(url)
    request.add_header("User-Agent", "Python Wiki document exporter")
    request.add_header("Accept-encoding", "gzip")
    f = urllib2.build_opener().open(request)
    is_gzip = f.headers.get("Content-Encoding") == "gzip"
    if is_gzip:
        save = file("wiki.xml.gz", "wb") 
    else:
        save = file("wiki.xml", "wb") 
    
    # Save to disk
    while True:
        block = f.read(block_size)
        if len(block) == 0:
            break
        save.write(block)
    save.close()

    # Need to write to disk for analysis without loading entirely into RAM;
    # can do this with gzip module without saving to disk first? Pipe thru?
    if is_gzip:
        fx  = gzip.GzipFile("wiki.xml.gz", "rb")
    else:
        fx = file("wiki.xml", "rb")

    # XML file handle
    return fx

# For spec, see http://meta.wikimedia.org/wiki/Help:Export#Export_format
# Need to extract the wikitext from the XML, using a SAX so don't have to
# read it all into memory at once.
#   Note: look at STX, stx.sf.net, a stream-based transform tool
#http://meta.wikimedia.org/wiki/Processing_MediaWiki_XML_with_STX

class MWXError(Exception):
    def __init__(self, msg):
        self.msg = msg
    def __str__(self):
        return self.msg

# XML SAX parser
class MediaWikiXML(handler.ContentHandler):
    def __init__(self):
        handler.ContentHandler.__init__(self)

        self._in_mediawiki = False
        self._in_page = False
        self._text = ""

    def _dispatch(self, prefix, name, attrs=None):
        """Call method prefix + ucfirst name, with attrs if not None."""
        f = prefix + name[0].upper() + name[1:]
        
        if hasattr(self, f):
            if attrs is None:
                getattr(self, f)()
            else:
                getattr(self, f)(attrs)
        else:
            attrs = {}
            #print "%s|%s|%s" % (prefix, name, attrs.keys())


    def startElement(self, name, attrs):
        self._dispatch("start", name, attrs)
    
    def endElement(self, name):
        self._dispatch("end", name)
        self._text = ""

    def startMediawiki(self, a):
        # Latest is 0.3, which we partially support.
        # MediaWiki 1.4 uses 0.1
        # MediaWiki 1.5 uses 0.3
        #if a["version"] != "0.1":
        #    raise MWXError("Can only process version 0.1, but got %s" % 
        #            a["version"])
        self._in_mediawiki = True

    def endMediawiki(self):
        self._in_mediawiki = False

    def startPage(self, a):
        self._in_page = True
        self._title = None
        self._pageId = None
        self._revision = None
        self._wikitext = None

    def endPage(self):
        self._in_page = False

    def endTitle(self):
        self._title = self._text.strip()

    def endId(self):
        if self._in_revision:
            self._revision_id = self._text.strip()
        elif self._in_page:
            self._page_id = self._text.strip()

    def startRevision(self, a):
        self._in_revision = True
        self._timestamp = None
        self._contributor = None
        self._comment = None
        self._wikitext = None

    def endRevision(self):
        self._in_revision = False

    def endTimestamp(self):
        self._timestamp = self._text.strip()

    def endIp(self):
        self._contributor = self._text.strip()

    def endUsername(self):
        self._contributor = self._text.strip()

    def endComment(self):
        self._comment = self._text.strip()

    def endText(self):
        # Preserve whitespace
        self._wikitext = self._text
        
        print "Title: %s" % self._title
        print "TS: %s" % self._timestamp
        print "Contributor: %s" % self._contributor
        print "Comment: %s" % self._comment
        print "Text: %s bytes" % len(self._wikitext)
        print
        # TODO: feed to wt2db

    def characters(self, content):
        self._text += content

    def ignorableWhitespace(self, whitespace):
        # Keep it for the wikitext
        self._text += content

site = "sumi.berlios.de/wiki";

#pages = all_pages(site)
#fx = fetch_xml(site, pages)
#XXX: Use old version for debug purposes
fx  = gzip.GzipFile("wiki.xml.gz", "rb")

parser = make_parser()
parser.setContentHandler(MediaWikiXML())
parser.parse(fx)

# TODO: Feed to wt2db.

