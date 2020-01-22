from msl.loadlib import Server32


class LibcServer(Server32):
    """A wrapper around a 32-bit C library, 'libc.so', that has an 'rand' and 'srand' functions."""
    def __init__(self, host, port, quiet, **kwargs):
         # Load the 'cpp_lib32' shared-library file using ctypes.CDLL.
        super(LibcServer, self).__init__('/lib/i386-linux-gnu/libc.so.6', 'cdll', host, port, quiet)

    def get_rand_values(self, n):
        self.lib.srand(self.lib.time(0))
        rvs = []
        for i in range(n):
            rvs.append(self.lib.rand())
        return rvs