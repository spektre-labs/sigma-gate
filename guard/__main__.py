import sys
from .guard import main


def _entry():
    main(sys.argv[1:])


if __name__ == "__main__":
    _entry()
