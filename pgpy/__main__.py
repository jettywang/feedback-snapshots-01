"""Allow ``python -m pgpy`` to invoke the certificate pruning CLI."""
from .certprune import main

if __name__ == '__main__':
    main()
