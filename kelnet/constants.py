# Global variables
ASCII = "ascii"
EMPTY_STR = ""
EOL = "\r\0"  # end of line terminator, as observed from Tera Term. can be changed to "\n" for UNIX, "\r\n" for Windows.
TEST_HOST = "10.211.28.197"
TEST_PORT = 2016
USER = "user"
PASSWORD = EMPTY_STR
TIMEOUT = 10  # seconds
EOFMSG = "*** Connection closed by remote host ***"

# prompts
LOGIN_P = "login:"
LOGIN_INC_P = "Login incorrect"
PASSWORD_P = "Password:"
BASH_P = r":(.*)$"  # regex pattern
ROOT_P = r":(.*)#"
# Commands

COMMANDS = [  # (prompt, input, True if you want the return data)
    (LOGIN_P, USER),
    (PASSWORD_P, PASSWORD),

]
