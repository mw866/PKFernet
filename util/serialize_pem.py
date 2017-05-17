"""Use to serialze the original key value in pem to URL-safe string for JSON"""
import sys

def main():
    if len(sys.argv) <= 1:
        print("Usage: {} <file>".format(sys.argv[0]))
        return
    f = open(sys.argv[1], 'r')
    f.seek(0)
    text = f.read()
    f.close()
    print(text.replace('+', '-').replace('/', '_').replace('\n', '\\n'))


if __name__ == '__main__':
    main()