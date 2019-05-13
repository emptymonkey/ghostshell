

/* XXX

	 - revamp broker for blocking tty flow.
	 - revamp broker for no keyboard til after first shell read.
	- add a pause switch to control the time between select timeout and entering the next line.
	- add priv drop to user on shell side

	 XXX */

#define _GNU_SOURCE

#include <errno.h>
#include <error.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>



/****************************************************************************** 
 *
 *  usmid - User Simulation Daemon
 *    @emptymonkey
 *    2019-05-09
 *
 *  The purpose of this program is to have an artificial user interaction with a 
 *  shell and tty in the background without requiring an actual login. This is
 *  useful for simulating a logged in user and bakeing that into an aws ami.
 *  I will be using this as part of a ctf to host the user shell / tty that is
 *  the ctf target. Yes, this is *very* close to what the expect program does.
 *  There are several differences that are important to this being a target in
 *  a ctf.
 *
 *  The setup will be as follows:
 *
 *    (file)            (UID root process)           (UID user process)
 *    Keyboard  <-fd->  Referee (Parent)    <-tty->  Shell (Child #2)
 *
 *  The Keyboard will be a file whose contents are sent down the tty as though
 *  typed by a user. The shell process will exec /bin/bash, with stdin, stdout,
 *  and stderr all tied to the tty as one would expect. 
 *
 ******************************************************************************/


#define DEFAULT_SHELL	"/bin/bash"
#define DEFAULT_MIMIC	"/bin/login --"
#define DEFAULT_TIMEOUT 0
#define DEFAULT_LOGFILE "/root/usimd.out"


int setup_shell(char *shell, struct termios *saved_termios_attrs);
void broker(FILE *keyboard, int shell_fd);

char *buff;
long buff_len;


void usage(){

	fprintf(stderr, "Usage: %s [-s SHELL][-m MIMIC][-t TIMEOUT][-k] KEYBOARD\n", program_invocation_short_name);
	fprintf(stderr, "\tKEYBOARD\t:\tKEYBOARD is the name of the program that will be executed to provide the user input that simulates keyboard interaction.\n");
	fprintf(stderr, "\t-s SHELL\t:\tSets the shell to use on the other end of the tty. (Default \"%s\".)\n", DEFAULT_SHELL);
	fprintf(stderr, "\t-m MIMIC\t:\tSets the name of the shell's parent process. (Default \"%s\".)\n", DEFAULT_MIMIC);
	fprintf(stderr, "\t-t TIMEOUT\t:\tSets a timeout (in seconds) for the interaction, at which point the tty is torn down. (Default \"%d\".)\n", DEFAULT_TIMEOUT);
	fprintf(stderr, "\t-k\t\t:\tSets keep-alive mode. After teardown of the tty, restart the interaction again. (Continues to respawn until killed.)\n");
	exit(1);
}


int main(int argc, char **argv){

	int opt;
	int retval;
	struct termios saved_termios_attrs;

	int shell_fd;
	FILE *keyboard;

	char *keyboard_file;
	char *shell = DEFAULT_SHELL;
	char *mimic = DEFAULT_MIMIC;
	unsigned int timeout = DEFAULT_TIMEOUT;
	unsigned short keepalive = 0;



	buff_len = sysconf(_SC_PAGESIZE);
	buff = (char *) malloc(buff_len);
	

	while((opt = getopt(argc, argv, "hs:m:t:k")) != -1){
		switch(opt){

			case 's':
				shell = optarg;
				break;

			case 'm':
				mimic = optarg;
				break;

			case 't':
				errno = 0;
				timeout = strtol(optarg, NULL, 10);
				if(errno){
					usage();
				}
				break;

			case 'k':
				keepalive = 1;
				break;

			case 'h':
			default:
				usage();

		}
	}

	if(optind >= argc){
		usage();
	}
	keyboard_file = argv[optind];


	/* Save our termio state for reuse later. */
	if(tcgetattr(STDIN_FILENO, &saved_termios_attrs) == -1){
		error(1, errno, "tcgetattr(%d, %lx)", STDIN_FILENO, (unsigned long) &saved_termios_attrs);
	}


	/* Quasi-daemonize, so we look like a normal login tty. */

	if((retval = fork()) == -1){
		error(1, errno, "fork()");
	}
	if(retval){
		return(0);
	}

	if((int) setsid() == -1){
		error(1, errno, "setsid()");
	}

	if(chdir("/") == -1){
		error(1, errno, "chdir(\"/\")");
	}

	umask(0);


	do {

		/* Setup shell. */
		shell_fd = setup_shell(shell, &saved_termios_attrs);

		/* Setup keyboard. */
		if((keyboard = fopen(keyboard_file, "r")) == NULL){
			error(1, errno, "fopen(\"%s\", \"r\")", keyboard_file);
		}

		/* Setup alarm() and handler. */


		/* Broker. */
		broker(keyboard, shell_fd);

		/* Clean up. */
		alarm(0);
		close(shell_fd);
		fclose(keyboard);

	} while(keepalive);

	return(0);
}

int setup_shell(char *shell, struct termios *saved_termios_attrs){

	int retval;
	char *tmp_vector[2];

	int shell_fd;
	char *shell_tty_name;

	if((shell_fd = posix_openpt(O_RDWR)) == -1){
		error(1, errno, "posix_openpt(O_RDWR)");
	}

	if(grantpt(shell_fd)){
		error(1, errno, "grantpt(%d)", shell_fd);
	}

	if(unlockpt(shell_fd)){
		error(1, errno, "unlockpt(%d)", shell_fd);
	}

	if(tcsetattr(shell_fd, TCSANOW, saved_termios_attrs) == -1){
		error(1, errno, "tcgetattr(%d, %lx)", shell_fd, (unsigned long) saved_termios_attrs);
	}

	if((shell_tty_name = ptsname(shell_fd)) == NULL){
		error(1, errno, "ptsname(%d)", shell_fd);
	}

	if((retval = fork()) == -1){
		error(1, errno, "fork()");
	}

	if(!retval){

		close(shell_fd);
		close(STDIN_FILENO);
		close(STDOUT_FILENO);
		close(STDERR_FILENO);

		if((retval = open(shell_tty_name, O_RDWR)) == -1){
			exit(2); // no stderr to write to, so uniq() exit code.
		}
		dup2(retval, STDIN_FILENO);
		dup2(retval, STDOUT_FILENO);
		dup2(retval, STDERR_FILENO);

		if(retval != STDIN_FILENO && retval != STDOUT_FILENO && retval != STDERR_FILENO){
			close(retval);
		}

		// setsid() again, so we can set the new tty as our controlling tty.
		// If these fail... well, let's be non-fatal. Maybe stuff will work out. :)
		setsid();
		ioctl(STDIN_FILENO, TIOCSCTTY, 1);

		tmp_vector[0] = shell;
		tmp_vector[1] = NULL;
		execve(shell, tmp_vector, NULL);
		exit(1);
	}

	return(shell_fd);
}

void broker(FILE *keyboard, int shell_fd){

	fd_set read_fds;

	int io_bytes;
	int keyboard_active;
	int retval;

	struct timeval tv;


	keyboard_active = 1;
	while(1){

		FD_ZERO(&read_fds);
		FD_SET(shell_fd, &read_fds);

		tv.tv_sec = 2;
		tv.tv_usec = 0;

		if((retval = select(shell_fd + 1, &read_fds, NULL, NULL, &tv)) == -1){
			error(1, errno, "select()");
		}

		if(FD_ISSET(shell_fd, &read_fds)){
			if((io_bytes = read(shell_fd, buff, buff_len - 1)) == -1){
				break;
			}
			if(!io_bytes){
				break;
			}else{
				buff[io_bytes] = '\0';
				printf("%s", buff);
			}

		}else{

			if(keyboard_active){
				if(fgets(buff, buff_len, keyboard) == NULL){
					keyboard_active = 0;
				}else{
					if(write(shell_fd, buff, strnlen(buff, buff_len)) == -1){
						error(1, errno, "write(%d, %lx, %ld)", shell_fd, (unsigned long) buff, strnlen(buff, buff_len));
					}
				}
			}

		}
	}
}
