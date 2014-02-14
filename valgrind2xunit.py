import xml.etree.ElementTree as ET
doc = ET.parse('valgrind.xml')
errors = doc.findall('//error')
 
out = open("testsuite-valgrind.xml","w")
out.write('<?xml version="1.0" encoding="UTF-8"?>\n')
out.write('<testsuite name="memcheck" tests="1" errors="0" failures="'+str(len(errors))+'" skip="0">\n')
out.write('    <testcase classname="ValgrindMemoryCheck " \n')
out.write('              name="Memory check" time="0">\n')
for error in errors:
    kind = error.find('kind')
    what = error.find('what')
    if  what == None:
        what = error.find('xwhat/text')
 
    out.write('        <error type="'+kind.text+'">\n')
    out.write('            '+what.text+'\n')
    out.write('        </error>\n')
out.write('    </testcase>\n')
out.write('</testsuite>\n')
out.close()
# See more at: http://www.tonicebrian.com/2010/10/15/continuous-integration-for-c-using-hudson/#sthash.i3FzqwUS.dpuf
