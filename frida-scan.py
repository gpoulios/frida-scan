#!/usr/bin/env python3
import frida
import sys
import os
import json
import time
from optparse import OptionParser


CONFIG = {
    "dir": os.getcwd()
}

count = None

def on_message(message, data):
    global count
    count = message['payload'] if 'payload' in message else None

if __name__ == '__main__':
    try:
        parser = OptionParser(usage="usage: %prog [options] <process_to_hook> <pattern_to_search>",version="%prog 1.0")
        parser.add_option("-A", "--attach", action="store_true", default=False,help="Attach to a running process")
        parser.add_option("-S", "--spawn", action="store_true", default=False,help="Spawn a new process and attach")
        parser.add_option("-P", "--pid", action="store_true", default=False,help="Attach to a pid process")
        parser.add_option("-o", "--output", action="store_true", default=False,help="Output folder")
        parser.add_option("-v", "--verbose", action="store_true", default=False,help="Verbose")

        (options, args) = parser.parse_args()
        if (options.spawn):
            print ("[+] Spawning "+ str(args[0]))
            pid = frida.get_usb_device().spawn([args[0]])
            session = frida.get_usb_device().attach(pid)
        elif (options.attach):
            print ("[+] Attaching to process"+str(args[0]))
            session = frida.get_usb_device().attach(str(args[0]))
        elif (options.pid):
            print ("[+] Attaching to PID "+str(args[0]))
            session = frida.get_usb_device().attach(int(args[0]))
        elif (options.output):
            if os.path.isdir(args[0]) == false:
                os.mkdir(args[0])
                CONFIG.dir = args[0]
        else:
            print ("Error")
            print ("[!] Option not selected. View --help option.")
            sys.exit(-3)

        pattern = args[1]
        script = session.create_script("""
            var ranges = Process.enumerateRangesSync({protection: 'r--', coalesce: true});
            var range;
            var retval = (ranges.length > 0) ? 0 : -1;

            function toScanPatt(vStr) {
                return vStr.split('').map( c => c=c.charCodeAt(0).toString(16)).join(' ');
            }

            function processNext() {
                range = ranges.pop();
                if (!range) {
                    // we are done
                    return;
                }

                Memory.scan(range.base, range.size, toScanPatt('%s'), {
                    onMatch: function(address, size) {
                        retval += 1;
                        console.log('[+] Pattern found at: ' + address.toString()+', '+(range.file!=null && range.file.path != null ? range.file.path : "<unknow>" ));
                        if (%s) {
                            var length = %s;
                            console.log(hexdump(address.sub(length/2), { ascii:true, length: length }));
                        }
                    },
                    onError: function(reason) {
                        console.log('[!] There was an error scanning memory : '+reason);
                    },
                    onComplete: function() {
                        if (ranges.length > 0)
                            processNext();
                        else {
                            console.log('[!] Scan finished');
                            send(retval);
                        }
                    }
                });
            }
            processNext();

        """ % (pattern, str(options.verbose).lower(), 256))

        script.on('message', on_message)
        script.load()

        while count is None:
            time.sleep(0.2)

        script.unload()
        session.detach()
        sys.exit(count)

    except KeyboardInterrupt:
        sys.exit(-2)
