r"""KELNET client class.

Based on RFC 854: TELNET Protocol Specification, by J. Postel and
J. Reynolds

Example:

>>> from kelnetlib import Kelnet
>>> tn = Kelnet('www.python.org', 79)   # connect to finger port
>>> tn.write(b'guido\r\n')
>>> print(tn.read_all())
Login       Name               TTY         Idle    When    Where
guido    Guido van Rossum      pts/2        <Dec  2 11:10> snag.cnri.reston..

>>>
"""


# Imported modules
import argparse
import asyncio
import logging
import re
import sqlite3
import sys
from time import monotonic as _time

try:
    import jelnet_package_hpe.constants as constants

    from .logger import getLogger
except:
    logging.warning("Are you running inside the library?")
    import constants
    from logger import getLogger

__all__ = ["Telnet"]

# Tunable parameters
DEBUGLEVEL = 0

# Telnet protocol defaults
TELNET_PORT = 23

# Telnet protocol characters (don't change)
IAC = bytes([255])  # "Interpret As Command"
DONT = bytes([254])
DO = bytes([253])
WONT = bytes([252])
WILL = bytes([251])
theNULL = bytes([0])

SE = bytes([240])  # Subnegotiation End
NOP = bytes([241])  # No Operation
DM = bytes([242])  # Data Mark
BRK = bytes([243])  # Break
IP = bytes([244])  # Interrupt process
AO = bytes([245])  # Abort output
AYT = bytes([246])  # Are You There
EC = bytes([247])  # Erase Character
EL = bytes([248])  # Erase Line
GA = bytes([249])  # Go Ahead
SB = bytes([250])  # Subnegotiation Begin


# Telnet protocol options code (don't change)
# These ones all come from arpa/telnet.h
BINARY = bytes([0])  # 8-bit data path
ECHO = bytes([1])  # echo
RCP = bytes([2])  # prepare to reconnect
SGA = bytes([3])  # suppress go ahead
NAMS = bytes([4])  # approximate message size
STATUS = bytes([5])  # give status
TM = bytes([6])  # timing mark
RCTE = bytes([7])  # remote controlled transmission and echo
NAOL = bytes([8])  # negotiate about output line width
NAOP = bytes([9])  # negotiate about output page size
NAOCRD = bytes([10])  # negotiate about CR disposition
NAOHTS = bytes([11])  # negotiate about horizontal tabstops
NAOHTD = bytes([12])  # negotiate about horizontal tab disposition
NAOFFD = bytes([13])  # negotiate about formfeed disposition
NAOVTS = bytes([14])  # negotiate about vertical tab stops
NAOVTD = bytes([15])  # negotiate about vertical tab disposition
NAOLFD = bytes([16])  # negotiate about output LF disposition
XASCII = bytes([17])  # extended ascii character set
LOGOUT = bytes([18])  # force logout
BM = bytes([19])  # byte macro
DET = bytes([20])  # data entry terminal
SUPDUP = bytes([21])  # supdup protocol
SUPDUPOUTPUT = bytes([22])  # supdup output
SNDLOC = bytes([23])  # send location
TTYPE = bytes([24])  # terminal type
EOR = bytes([25])  # end or record
TUID = bytes([26])  # TACACS user identification
OUTMRK = bytes([27])  # output marking
TTYLOC = bytes([28])  # terminal location number
VT3270REGIME = bytes([29])  # 3270 regime
X3PAD = bytes([30])  # X.3 PAD
NAWS = bytes([31])  # window size
TSPEED = bytes([32])  # terminal speed
LFLOW = bytes([33])  # remote flow control
LINEMODE = bytes([34])  # Linemode option
XDISPLOC = bytes([35])  # X Display Location
OLD_ENVIRON = bytes([36])  # Old - Environment variables
AUTHENTICATION = bytes([37])  # Authenticate
ENCRYPT = bytes([38])  # Encryption option
NEW_ENVIRON = bytes([39])  # New - Environment variables
# the following ones come from
# http://www.iana.org/assignments/telnet-options
# Unfortunately, that document does not assign identifiers
# to all of them, so we are making them up
TN3270E = bytes([40])  # TN3270E
XAUTH = bytes([41])  # XAUTH
CHARSET = bytes([42])  # CHARSET
RSP = bytes([43])  # Telnet Remote Serial Port
COM_PORT_OPTION = bytes([44])  # Com Port Control Option
SUPPRESS_LOCAL_ECHO = bytes([45])  # Telnet Suppress Local Echo
TLS = bytes([46])  # Telnet Start TLS
KERMIT = bytes([47])  # KERMIT
SEND_URL = bytes([48])  # SEND-URL
FORWARD_X = bytes([49])  # FORWARD_X
PRAGMA_LOGON = bytes([138])  # TELOPT PRAGMA LOGON
SSPI_LOGON = bytes([139])  # TELOPT SSPI LOGON
PRAGMA_HEARTBEAT = bytes([140])  # TELOPT PRAGMA HEARTBEAT
EXOPL = bytes([255])  # Extended-Options-List
NOOPT = bytes([0])


class Kelnet:

    """Telnet interface class. Read and write methods have been altered to use
    StreamReader and StreamWriter objects.

    An instance of this class represents a connection to a telnet
    server.  The instance is initially not connected; the open()
    method must be used to establish a connection.  Alternatively, the
    host name and optional port number can be passed to the
    constructor, too.

    Don't try to reopen an already connected instance.

    This class has many read_*() methods.  Note that some of them
    raise EOFError when the end of the connection is read, because
    they can return an empty string for other reasons.  See the
    individual doc strings.

    read_until(expected, [timeout])
        Read until the expected string has been seen, or a timeout is
        hit (default is no timeout); may block.

    read_all()
        Read all data until EOF; may block.

    read_some()
        Read at least one byte or EOF; may block.

    read_very_eager()
        Read all data available already queued or on the socket,
        without blocking.

    read_eager()
        Read either data already queued or some data available on the
        socket, without blocking.

    read_lazy()
        Read all data in the raw queue (processing it first), without
        doing any socket I/O.

    read_very_lazy()
        Reads all data in the cooked queue, without doing any socket
        I/O.

    read_sb_data()
        Reads available data between SB ... SE sequence. Don't block.

    set_option_negotiation_callback(callback)
        Each time a kelnet option is read on the input flow, this callback
        (if set) is called with the following parameters :
        callback(telnet socket, command, option)
            option will be chr(0) when there is no option.
        No other action is done afterwards by kelnetlib.

    """

    def __init__(self, host=None, port=0, timeout=15):
        """Constructor.

        When called without arguments, create an unconnected instance.
        With a hostname argument, it connects the instance; port number
        and timeout are optional.
        """
        self.debuglevel = DEBUGLEVEL
        self.host = host
        self.port = port
        self.timeout = timeout
        self.reader = None
        self.writer = None
        self.rawq = b""
        self.irawq = 0
        self.cookedq = b""
        self.eof = 0
        self.iacseq = b""  # Buffer for IAC sequence.
        self.sb = 0  # flag for SB and SE sequence.
        self.sbdataq = b""
        self.option_callback = None

    async def open(self, host, port=0, timeout=15):
        """Connect to a host.

        The optional second argument is the port number, which
        defaults to the standard telnet port (23).

        Don't try to reopen an already connected instance.
        """
        self.eof = 0
        if not port:
            port = TELNET_PORT
        self.host = host
        self.port = port
        self.timeout = timeout
        sys.audit("kelnetlib.Kelnet.open", self, host, port)
        try:
            self.reader, self.writer = await asyncio.wait_for(
                asyncio.streams.open_connection(host=host, port=port), timeout=timeout
            )

        except TimeoutError:
            raise TimeoutError

    def msg(self, msg, *args):
        """Print a debug message, when the debug level is > 0.

        If extra arguments are present, they are substituted in the
        message using the standard string formatting operator.

        """
        if self.debuglevel > 0:
            print("Telnet(%s,%s):" % (self.host, self.port), end=" ")
            if args:
                print(msg % args)
            else:
                print(msg)

    def set_debuglevel(self, debuglevel):
        """Set the debug level.

        The higher it is, the more debug output you get (on sys.stdout).

        """
        self.debuglevel = debuglevel

    async def close(self):
        """Close the connection."""
        stream = self.writer
        self.reader = None
        self.writer = None
        self.eof = True
        self.iacseq = b""
        self.sb = 0
        stream.close()
        await stream.wait_closed()

    async def s_write(self, buf: str, cr: str = constants.EOL) -> None:
        """
        Overrides write() to accept strings, add <cr> for remote device to interpret EOL and encode to bytes using ASCII.
        """
        buf = (buf + cr).encode(constants.ASCII)
        await self.write(buf)

    async def write(self, buffer):
        """Write bytes to the socket, doubling any IAC characters.

        Can block if the connection is blocked.  May raise
        OSError if the connection is closed.

        // hopefully no blocking using drain()

        """
        if IAC in buffer:
            buffer = buffer.replace(IAC, IAC + IAC)
        sys.audit("kelnetlib.Kelnet.write", self, buffer)
        self.msg("send %r", buffer)
        self.writer.write(buffer)
        await self.writer.drain()

    async def read_until(self, pattern, timeout=None):
        """Read until a given string is encountered or until timeout.

        When no match is found, return whatever is available instead,
        possibly the empty string.  Raise EOFError if the connection
        is closed and no cooked data is available.

        """
        n = len(pattern)
        await self.process_rawq()
        i = self.cookedq.find(pattern)
        if i >= 0:
            i = i + n
            buf = self.cookedq[:i]
            self.cookedq = self.cookedq[i:]
            return buf
        try:
            return await asyncio.wait_for(
                self.read_until_loop(pattern, n), timeout=timeout
            )
        except TimeoutError:
            return self.read_very_lazy()

    async def read_until_loop(self, pattern, n):
        """
        Possibly long-er running task.
        """
        while not self.eof:
            i = max(0, len(self.cookedq) - n)
            await self.fill_rawq()
            await self.process_rawq()
            i = self.cookedq.find(pattern, i)
            if i >= 0:
                i = i + n
                buf = self.cookedq[:i]
                self.cookedq = self.cookedq[i:]
                return buf

    async def read_all(self):
        """Read all data until EOF; block until connection closed."""
        await self.process_rawq()
        while not self.eof:
            await self.fill_rawq()
            await self.process_rawq()
        buf = self.cookedq
        self.cookedq = b""
        return buf

    async def read_some(self):
        """Read at least one byte of cooked data unless EOF is hit.

        Return b'' if EOF is hit.  Block if no data is immediately
        available.

        """
        await self.process_rawq()
        while not self.cookedq and not self.eof:
            await self.fill_rawq()
            await self.process_rawq()
        buf = self.cookedq
        self.cookedq = b""
        return buf

    async def read_very_eager(self):
        """Read everything that's possible without blocking in I/O (eager).

        Raise EOFError if connection closed and no cooked data
        available.  Return b'' if no cooked data available otherwise.
        Don't block unless in the midst of an IAC sequence.

        """
        await self.process_rawq()
        while not self.eof:
            await self.fill_rawq()
            await self.process_rawq()
        return self.read_very_lazy()

    async def read_eager(self):
        """Read readily available data.

        Raise EOFError if connection closed and no cooked data
        available.  Return b'' if no cooked data available otherwise.
        Don't block unless in the midst of an IAC sequence.

        """
        await self.process_rawq()
        while not self.cookedq and not self.eof:
            await self.fill_rawq()
            await self.process_rawq()
        return self.read_very_lazy()

    async def read_lazy(self):
        """Process and return data that's already in the queues (lazy).

        Raise EOFError if connection closed and no data available.
        Return b'' if no cooked data available otherwise.  Don't block
        unless in the midst of an IAC sequence.

        """
        await self.process_rawq()
        return self.read_very_lazy()

    def read_very_lazy(self):
        """Return any data available in the cooked queue (very lazy).

        Raise EOFError if connection closed and no data available.
        Return b'' if no cooked data available otherwise.  Don't block.

        """
        buf = self.cookedq
        self.cookedq = b""
        if not buf and self.eof and not self.rawq:
            raise EOFError("telnet connection closed")
        return buf

    def read_sb_data(self):
        """Return any data available in the SB ... SE queue.

        Return b'' if no SB ... SE available. Should only be called
        after seeing a SB or SE command. When a new SB command is
        found, old unread SB data will be discarded. Don't block.

        """
        buf = self.sbdataq
        self.sbdataq = b""
        return buf

    def set_option_negotiation_callback(self, callback):
        """Provide a callback function called after each receipt of a telnet option."""
        self.option_callback = callback

    async def process_rawq(self):
        """Transfer from raw queue to cooked queue.

        Set self.eof when connection is closed.  Don't block unless in
        the midst of an IAC sequence.

        """
        buf = [b"", b""]
        try:
            while self.rawq:
                c = await self.rawq_getchar()
                if not self.iacseq:
                    if c == theNULL:
                        continue
                    if c == b"\021":
                        continue
                    if c != IAC:
                        buf[self.sb] = buf[self.sb] + c
                        continue
                    else:
                        self.iacseq += c
                elif len(self.iacseq) == 1:
                    # 'IAC: IAC CMD [OPTION only for WILL/WONT/DO/DONT]'
                    if c in (DO, DONT, WILL, WONT):
                        self.iacseq += c
                        continue

                    self.iacseq = b""
                    if c == IAC:
                        buf[self.sb] = buf[self.sb] + c
                    else:
                        if c == SB:  # SB ... SE start.
                            self.sb = 1
                            self.sbdataq = b""
                        elif c == SE:
                            self.sb = 0
                            self.sbdataq = self.sbdataq + buf[1]
                            buf[1] = b""
                        if self.option_callback:
                            # Callback is supposed to look into
                            # the sbdataq
                            self.option_callback(self.writer, c, NOOPT)
                        else:
                            # We can't offer automatic processing of
                            # suboptions. Alas, we should not get any
                            # unless we did a WILL/DO before.
                            self.msg("IAC %d not recognized" % ord(c))
                elif len(self.iacseq) == 2:
                    cmd = self.iacseq[1:2]
                    self.iacseq = b""
                    opt = c
                    if cmd in (DO, DONT):
                        self.msg("IAC %s %d", cmd == DO and "DO" or "DONT", ord(opt))
                        if self.option_callback:
                            self.option_callback(self.writer, cmd, opt)
                        else:
                            self.writer.write(IAC + WONT + opt)
                            await self.writer.drain()
                    elif cmd in (WILL, WONT):
                        self.msg(
                            "IAC %s %d", cmd == WILL and "WILL" or "WONT", ord(opt)
                        )
                        if self.option_callback:
                            self.option_callback(self.writer, cmd, opt)
                        else:
                            self.writer.write(IAC + DONT + opt)
                            await self.writer.drain()
        except EOFError:  # raised by self.rawq_getchar()
            self.iacseq = b""  # Reset on EOF
            self.sb = 0
        self.cookedq = self.cookedq + buf[0]
        self.sbdataq = self.sbdataq + buf[1]

    async def rawq_getchar(self):
        """Get next char from raw queue.

        Block if no data is immediately available.  Raise EOFError
        when connection is closed.

        """
        if not self.rawq:
            await self.fill_rawq()
            if self.eof:
                raise EOFError
        c = self.rawq[self.irawq : self.irawq + 1]
        self.irawq = self.irawq + 1
        if self.irawq >= len(self.rawq):
            self.rawq = b""
            self.irawq = 0
        return c

    async def fill_rawq(self):
        """Fill raw queue from exactly one recv() system call.

        Block if no data is immediately available.  Set self.eof when
        connection is closed.

        """
        if self.irawq >= len(self.rawq):
            self.rawq = b""
            self.irawq = 0
        # The buffer size should be fairly small so as to avoid quadratic
        # behavior in process_rawq() above
        buf = await self.reader.read(50)
        self.msg("recv %r", buf)
        self.eof = not buf
        self.rawq = self.rawq + buf

    async def remote_listener(self):
        """
        Echoes remote stdin and writes to local stdout
        """
        while 1:
            try:
                data = await self.read_eager()
            except EOFError:
                print("*** Connection closed by remote host ***")
                return
            if data:
                sys.stdout.write(data.decode("ascii", "ignore"))
                sys.stdout.flush()

    async def local_listener(self):
        """
        Monitors and reads from local stdin, sending line to remote.
        """
        loop = asyncio.get_event_loop()
        while 1:
            line = await loop.run_in_executor(None, sys.stdin.readline)
            await self.write(line.encode(constants.ASCII))

    async def interact(self):
        """Interaction function, emulates a very dumb telnet client."""
        print(f"IP Address:Port => {self.host}:{self.port}")

        asyncio.create_task(self.local_listener())
        asyncio.create_task(self.remote_listener())
        await asyncio.Future()  # wait forever

    async def expect(self, patterns, timeout=None):
        """Read until one from a list of a regular expressions matches.

        The first argument is a list of regular expressions, either
        compiled (re.Pattern instances) or uncompiled (strings).
        The optional second argument is a timeout, in seconds; default
        is no timeout.

        Return a tuple of three items: the index in the list of the
        first regular expression that matches; the re.Match object
        returned; and the text read up till and including the match.

        If EOF is read and no text was read, raise EOFError.
        Otherwise, when nothing matches, return (-1, None, text) where
        text is the text received so far (may be the empty string if a
        timeout happened).

        If a regular expression ends with a greedy match (e.g. '.*')
        or if more than one expression can match the same input, the
        results are undeterministic, and may depend on the I/O timing.

        """
        if type(patterns) == str or type(patterns) == bytes:
            patterns = [patterns]
        indices = range(len(patterns))
        for i in indices:
            if not hasattr(patterns[i], "search"):
                patterns[i] = re.compile(patterns[i])
        try:
            if timeout:
                timeout += (
                    asyncio.get_running_loop().time()
                )  # get absolute time as measured by the event loop's clock + timeout
            return await asyncio.wait_for(
                self.expect_loop(indices, patterns), timeout=timeout
            )

        except TimeoutError:
            text = self.read_very_lazy()
            if not text and self.eof:
                raise EOFError
            return (-1, None, text)

    async def expect_loop(self, indices, patterns):
        while not self.eof:
            await self.process_rawq()
            for i in indices:
                m = patterns[i].search(self.cookedq)
                if m:
                    e = m.end()
                    text = self.cookedq[:e]
                    self.cookedq = self.cookedq[e:]
                    return (i, m, text)
            await self.fill_rawq()

    async def __aenter__(self):
        await self.open(self.host, self.port)
        return self

    async def __aexit__(self, type, value, traceback):
        await self.close()

    # Deprecated methods
    def mt_interact(self):
        """Multithreaded version of interact()."""
        raise NotImplementedError

    def sock_avail(self):
        """
        Test whether data is available on the socket. (deprecated)
        With async, there is no need to monitor sockets.
        """
        raise NotImplementedError

    def get_socket(self):
        """
        Return the socket object used internally.
        No sockets are available.
        """
        raise NotImplementedError

    def fileno(self):
        """
        Return the fileno() of the socket object used internally. (deprecated)
        No sockets are available.
        """
        raise NotImplementedError

    # def __del__(self):
    #     """
    #     Destructor -- close the connection. (deprecated)
    #     Destruction handled in async with context manager.
    #     __del__ method cannot exist as it will throw exceptions.
    #     """

    #     raise NotImplementedError


class Jelnet(Kelnet):

    """
    Aruba CX switch specific implementation of Kelnet.
    Specify a batch of commands to run.
    """

    def __init__(
        self,
        host,
        port,
        patterns,
        name="",
        lines=[],
        dbfile=None,
        log=None,
        loglevel=None,
        timeout=10,
    ):
        self.patterns = [
            (pattern).encode(constants.ASCII) for pattern in patterns
        ]  # bytes
        self.lines = lines
        self.ret = dict()  # CMD : data
        self.name = name
        self.logger = getLogger(
            name=self.name, dbfile=dbfile, logfile=log, loglevel=loglevel
        )
        super().__init__(host=host, port=port, timeout=timeout)

    async def execute(self, lines=None):
        """
        Executes commands. If none are provided in the arguments, execute the default lines provided on init.
        """
        lines = lines if lines else self.lines
        self.ret = dict()
        for line in lines:
            self.logger.debug("> " + str(line))
            try:
                assert isinstance(line, tuple)
                data = await self.sub_exec(*line)
                self.logger.debug("<")
                self.logger.debug(data.decode(constants.ASCII, "ignore"))
            except:
                raise

            self.ret[line] = data  # store returned bytes

    async def sub_exec(self, prompt: str, wr: str) -> bytes:
        """
        Executes a single line.
        Awaited by execute().
        Returns whatever bytes were read up until prompt.
        """
        try:
            await self.s_write(wr)
            _, _, text = await self.expect(
                patterns=prompt.encode(constants.ASCII), timeout=self.timeout
            )
            return text

        except EOFError:
            self.logger.error(constants.EOFMSG)
            raise

    async def gotoCenter(self, prompt: bytes, depth: int = 0) -> None:
        """
        Navigates to eXa given some prompt, or complains.

        """
        # check for excessive recursion (redundant)
        prompt = prompt.strip()
        err = f"*** Unknown prompt: {prompt} {len(prompt)}, recursion depth {depth}***"
        if isinstance(prompt, str):
            prompt = prompt.encode(constants.ASCII)
        if depth >= sys.getrecursionlimit():
            raise RecursionError(err)

        # check which pattern
        possible_matches = []
        for pattern in self.patterns:
            if not hasattr(pattern, "search"):
                pattern = re.compile(pattern)
            m = pattern.search(prompt)
            if m:
                possible_matches.append(m)

        # there should normally be only one match, but
        # in the case of user# and user:~#, '#' might map to both of them.
        # in this case we will take the longer match.
        try:
            best_match = sorted(
                possible_matches, key=lambda m: m.end() - m.start(), reverse=True
            )[0]

            p = best_match.re.pattern.decode(
                constants.ASCII
            )  # get back uncompiled pattern
        except:
            p = None

        # await asyncio.sleep(2)

        if p == constants.PASSWORD_P:
            lines = [(constants.LOGIN_P, constants.PASSWORD)]
            await self.execute(lines)
            # polyp = await self.get_prompt(inp= constants.PASSWORD, patterns= constants.LOGIN_P)
            await self.gotoCenter(constants.LOGIN_P, depth + 1)

        if p == constants.LOGIN_P:
            lines = [
                (
                    constants.PASSWORD_P,
                    constants.USER,
                ),  # write USER, expect PASSWORD_P
                (constants.CX_P, constants.PASSWORD),
            ]  # write PASSWORD, expect CX_P ]
            await self.execute(lines)
            await self.gotoCenter(constants.CX_P, depth + 1)

        if p == constants.ROOT_P:
            pass

        else:
            self.logger.error(f"{prompt}")

    async def get_prompt(self, inp: str = constants.EMPTY_STR, patterns=None) -> bytes:
        """
        Gets prompt by sending an empty string and checking the prompt that appears
        """
        try:
            if not patterns:
                patterns = self.patterns
            await self.s_write(inp)
            _, _, prompt = await self.expect(
                patterns, self.timeout
            )  # self.patterns is a list of bytes
            return prompt.strip()
        except EOFError as e:
            self.logger.error(constants.EOFMSG)
            raise e

    async def clean_exit(self):
        """
        Cleanly exits all shells.
        """
        prompt = await self.get_prompt()
        prompt = prompt.decode(constants.ASCII, "ignore")

        while not prompt.endswith(constants.LOGIN_P):
            self.logger.debug("> " + constants.EXIT)
            await self.s_write(constants.EXIT)

            _, _, prompt = await self.expect(self.patterns, self.timeout)
            prompt = prompt.decode(constants.ASCII, "ignore").strip()

    async def __aenter__(self):
        self.logger.debug("aenter.")
        self.start_time = _time()
        return await super().__aenter__()

    async def __aexit__(self, type, value, traceback):
        self.logger.debug("aexit.")
        await super().__aexit__(type, value, traceback)
        self.logger.debug(f"{self.name} time: {_time() - self.start_time}")


async def amain(args, loglevel):
    """
    Called by top level function main(). Runs execute().

    """
    async with Jelnet(
        host=constants.TEST_HOST,
        port=constants.TEST_PORT,
        lines=constants.COMMANDS,
        patterns=constants.SHELL_PROMPTS,
        loglevel=loglevel,
    ) as tn:
        if args.interact:
            await tn.interact()
        else:
            prompt = await tn.get_prompt()
            await tn.gotoCenter(prompt)
            await tn.execute()


def main():
    """
    Top level function. Decides the modes of operation based on arguments provided.
    """
    parser = argparse.ArgumentParser(description="Jelnet args")
    parser.add_argument(
        "-d",
        "--debug",
        default=False,
        action="store_true",
        help="prints DEBUG level logs to log file.",
    )
    parser.add_argument(
        "-i",
        "--interact",
        default=False,
        action="store_true",
        help="runs the classic telnetlib interact() method.",
    )

    args = parser.parse_args()
    if args.debug:
        loglevel = logging.DEBUG
    else:
        loglevel = None

    asyncio.run(amain(args, loglevel))


if __name__ == "__main__":
    main()
