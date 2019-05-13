
/****************************************************************************** 
 *
 *  ghostshell - @emptymonkey's User Simulation Daemon - 2019-05-09
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
 *  Any lines in the keyboard script that start with '#' followed by only 
 *  digits, then closed out with the newline, will be interpreted as a time
 *  for the keyboard to sleep() before moving on to the next line.
 *
 ******************************************************************************/

/* XXX

	 - add an alarm timeout
	 - add utmp and wtmp mangling. (man pututline / man updwtmp)

	 XXX */

#define _XOPEN_SOURCE 700

#include <ctype.h>
#include <errno.h>
#include <error.h>
#include <fcntl.h>
#include <pwd.h>
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


#define DEFAULT_SHELL	"/bin/bash"
#define DEFAULT_MIMIC	"/bin/login --"
#define DEFAULT_TIMEOUT 0
#define DEFAULT_PAUSE 2
#define DEFAULT_LOGFILE "/root/usimd.out"
#define DEFAULT_TERM "TERM=linux"


int setup_shell(char **shell, struct termios *saved_termios_attrs, char **envp, struct passwd *pwent);
void broker(FILE *keyboard, int shell_fd, int pause_secs);

char **string_to_vector(char *command_string);
//void free_vector(char **vector);
//int get_vector_size(char **vector);



char *buff;
long buff_len;

char *program_invocation_short_name;


void usage(){

	fprintf(stderr, "Usage: %s [-s SHELL][-m MIMIC][-t TIMEOUT][-p PAUSE][-e TERMINAL][-u USER][-k] KEYBOARD\n", program_invocation_short_name);
	fprintf(stderr, "\tKEYBOARD\t:\tKEYBOARD is the name of the \"keyboard script\" file that will simulate keyboard interaction.\n");
	fprintf(stderr, "\t-s SHELL\t:\tSets the shell to use on the other end of the tty. (Default \"%s\".)\n", DEFAULT_SHELL);
	fprintf(stderr, "\t-m MIMIC\t:\tSets the name of the shell's parent process. (Default \"%s\".)\n", DEFAULT_MIMIC);
	fprintf(stderr, "\t-t TIMEOUT\t:\tSets a timeout (in seconds) for the interaction, at which point the tty is torn down. (Default \"%d\".)\n", DEFAULT_TIMEOUT);
	fprintf(stderr, "\t-p PAUSE\t:\tSets the pause_secs (in seconds) between commands sent to the shell. (Default \"%d\".)\n", DEFAULT_PAUSE);
	fprintf(stderr, "\t-e TERMINAl\t:\tSets the TERM environment variable to TERM. (Default \"%s\".)\n", DEFAULT_TERM);
	fprintf(stderr, "\t-u USER\t\t:\tDrops privs to USER after forking child shell process.\n");
	fprintf(stderr, "\t-k\t\t:\tSets keep-alive mode. After teardown of the tty, restart the interaction again. (Continues to respawn until killed.)\n");
	fprintf(stderr, "\nNOTES:\n");
	fprintf(stderr, "\t* The -e flag expects the full assignment. (e.g. \"-e TERM=vt100\")\n");
	fprintf(stderr, "\t* %s will not attempt root things unless it is running as root. (e.g. uid changes, utmp/wtmp, etc.)\n", program_invocation_short_name);
	fprintf(stderr, "\n");
	exit(1);
}



int main(int argc, char **argv){

	int i;
	int opt;
	int retval;
	struct termios saved_termios_attrs;
	char **tmp_argv, **old_argv;
	char *term_envp[2];
	struct passwd *pwent = NULL;

	int shell_fd;
	FILE *keyboard;

	char *keyboard_file;
	char **shell = NULL;
	char *mimic = DEFAULT_MIMIC;
	unsigned int timeout = DEFAULT_TIMEOUT;
	int pause_secs = DEFAULT_PAUSE;
	unsigned short keepalive = 0;
	char *term = DEFAULT_TERM;
	char *user = NULL;


	// First, we will be setting up mimic on ourselves, so lets copy argv off to the heap for future use.
	if((tmp_argv = (char **) malloc((sizeof(char *)) * (argc + 1))) == NULL){
		fprintf(stderr, "%s: malloc(%d): %s\n", argv[0], (int) (sizeof(char *)) * (argc + 1), strerror(errno));
		exit(1);
	}

	i = 0;
	while(argv[i]){

		if((tmp_argv[i] = (char *) malloc(strlen(argv[i]) + 1)) == NULL){
			fprintf(stderr, "%s: malloc(%d): %s\n", argv[0], (int) strlen(argv[i]) + 1, strerror(errno));
			exit(1);
		}

		memcpy(tmp_argv[i], argv[i], strlen(argv[i]) + 1);
		// while we're here, go ahead and clear the old argv space.
		memset(argv[i], '\0', strlen(argv[i]) + 1);
		if(i){
			argv[i] = NULL;
		}
		i++;
	}
	old_argv = argv;
	argv = tmp_argv;

	program_invocation_short_name = strchr(argv[0], '/');
	if(!program_invocation_short_name){
		program_invocation_short_name = argv[0];
	}else{
		program_invocation_short_name++;
	}


	buff_len = sysconf(_SC_PAGESIZE);
	if((buff = (char *) malloc(buff_len)) == NULL){
		fprintf(stderr, "%s: malloc(%ld): %s\n", program_invocation_short_name, buff_len, strerror(errno));
		exit(1);
	}


	while((opt = getopt(argc, argv, "hs:m:t:kp:e:u:")) != -1){
		switch(opt){

			case 's':
				if((shell = string_to_vector(optarg)) == NULL){
					usage();
				}
				break;

			case 'm':
				mimic = optarg;
				break;

			case 'u':
				user = optarg;
				break;

			case 'e':
				term = optarg;
				break;

			case 't':
				errno = 0;
				timeout = strtol(optarg, NULL, 10);
				if(errno){
					usage();
				}
				break;

			case 'p':
				errno = 0;
				pause_secs = strtol(optarg, NULL, 10);
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

	if(!shell){
		if((shell = string_to_vector(DEFAULT_SHELL)) == NULL){
			fprintf(stderr, "%s: string_to_vector(\"%s\"): %s\n", program_invocation_short_name, DEFAULT_SHELL, strerror(errno));
			exit(1);
		}
	}

	// setup our mimic lie.
	memcpy(old_argv[0], mimic, strlen(mimic));


	if(!getuid()){
		if(user){
			if((pwent = getpwnam(user)) == NULL){
				if(errno){
					fprintf(stderr, "%s: getpwnam(\"%s\"): %s\n", program_invocation_short_name, user, strerror(errno));
				}else{
					fprintf(stderr, "%s: getpwnam(\"%s\"): No such user.\n", program_invocation_short_name, user);
				}
				exit(1);
			}
		}

	}else if(user){
		fprintf(stderr, "%s: -u USER specified, but not running as root!\n", program_invocation_short_name);
		exit(1);
	}


	/* Save our termio state for reuse later. */
	if(tcgetattr(STDIN_FILENO, &saved_termios_attrs) == -1){
		fprintf(stderr, "%s: tcgetattr(%d, %lx): %s\n", program_invocation_short_name, STDIN_FILENO, (unsigned long) &saved_termios_attrs, strerror(errno));
		exit(1);
	}

	/* Quasi-daemonize, so we look like a normal login tty. */

	if((retval = fork()) == -1){
		fprintf(stderr, "%s: fork(): %s\n", program_invocation_short_name, strerror(errno));
		exit(1);
	}
	if(retval){
		return(0);
	}

	if((int) setsid() == -1){
		fprintf(stderr, "%s: setsid(): %s\n", program_invocation_short_name, strerror(errno));
		exit(1);
	}

	if(chdir("/") == -1){
		fprintf(stderr, "%s: chdir(\"/\"): %s\n", program_invocation_short_name, strerror(errno));
		exit(1);
	}

	umask(0);

	if(signal(SIGCHLD, SIG_IGN) == SIG_ERR){
		fprintf(stderr, "%s: signal(SIGCHLD, SIG_IGN): %s\n", program_invocation_short_name, strerror(errno));
		exit(1);
	}


	do {

		/* Setup shell. */
		term_envp[0] = term;
		term_envp[1] = NULL;
		shell_fd = setup_shell(shell, &saved_termios_attrs, term_envp, pwent);

		/* Setup keyboard. */
		if((keyboard = fopen(keyboard_file, "r")) == NULL){
			fprintf(stderr, "%s: fopen(\"%s\", \"r\"): %s\n", program_invocation_short_name, keyboard_file, strerror(errno));
			exit(1);
		}

		/* Setup alarm() and handler. */


		/* Broker. */
		broker(keyboard, shell_fd, pause_secs);

		/* Clean up. */
		alarm(0);
		close(shell_fd);
		fclose(keyboard);

	} while(keepalive);

	return(0);
}



int setup_shell(char **shell, struct termios *saved_termios_attrs, char **envp, struct passwd *pwent){

	int retval;

	int shell_fd;
	char *shell_tty_name;

	if((shell_fd = posix_openpt(O_RDWR)) == -1){
		fprintf(stderr, "%s: posix_openpt(O_RDWR): %s\n", program_invocation_short_name, strerror(errno));
		exit(1);
	}

	if(grantpt(shell_fd)){
		fprintf(stderr, "%s: grantpt(%d): %s\n", program_invocation_short_name, shell_fd, strerror(errno));
		exit(1);
	}

	if(unlockpt(shell_fd)){
		fprintf(stderr, "%s: unlockpt(%d): %s\n", program_invocation_short_name, shell_fd, strerror(errno));
		exit(1);
	}

	if(tcsetattr(shell_fd, TCSANOW, saved_termios_attrs) == -1){
		fprintf(stderr, "%s: tcgetattr(%d, %lx): %s\n", program_invocation_short_name, shell_fd, (unsigned long) saved_termios_attrs, strerror(errno));
		exit(1);
	}

	if((shell_tty_name = ptsname(shell_fd)) == NULL){
		fprintf(stderr, "%s: ptsname(%d): %s\n", program_invocation_short_name, shell_fd, strerror(errno));
		exit(1);
	}

	if((retval = fork()) == -1){
		fprintf(stderr, "%s: fork(): %s\n", program_invocation_short_name, strerror(errno));
		exit(1);
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

		if(!getuid()){
			if(pwent){
				if(setregid(pwent->pw_gid, pwent->pw_gid) == -1){
					fprintf(stderr, "%s: setregid(%d, %d): %s\n", program_invocation_short_name, pwent->pw_gid, pwent->pw_gid, strerror(errno));
					exit(1);
				}
				if(setreuid(pwent->pw_uid, pwent->pw_uid) == -1){
					fprintf(stderr, "%s: setreuid(%d, %d): %s\n", program_invocation_short_name, pwent->pw_uid, pwent->pw_uid, strerror(errno));
					exit(1);
				}
			}
		}
		execve(shell[0], shell, envp);
		exit(1);
	}

	return(shell_fd);
}

void broker(FILE *keyboard, int shell_fd, int pause_secs){

	fd_set read_fds;

	int io_bytes;
	int keyboard_active;
	int retval;
	char *tmp_ptr;
	int keyboard_sleep;

	struct timeval tv;


	keyboard_active = 1;
	while(1){

		FD_ZERO(&read_fds);
		FD_SET(shell_fd, &read_fds);

		tv.tv_sec = pause_secs;
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
					tmp_ptr = buff;
					keyboard_sleep = 0;
					if(*tmp_ptr == '#'){
						tmp_ptr++;
						keyboard_sleep = strtol(tmp_ptr, NULL, 10);
						while(*tmp_ptr){
							if(!(isdigit(*tmp_ptr) || *tmp_ptr == '\n')){
								keyboard_sleep = 0;
								break;
							}
							tmp_ptr++;
						}
					}
					if(keyboard_sleep){
						sleep(keyboard_sleep);
					}else{
						if(write(shell_fd, buff, strnlen(buff, buff_len)) == -1){
							error(1, errno, "write(%d, %lx, %ld)", shell_fd, (unsigned long) buff, strnlen(buff, buff_len));
						}
					}
				}
			}

		}
	}
}
