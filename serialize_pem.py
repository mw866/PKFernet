#!/usr/bin/env python3

import sys

def main():
    if len(sys.argv) <= 1:
        print("Usage: {} <file>".format(sys.argv[0]))
        return
    f = open(sys.argv[1], 'r')
    f.seek(0)
    text = f.read()
    print(text.replace('+', '-').replace('//', '_').replace('\n', '\\n'))
    f.close()

if __name__ == '__main__':
    main()