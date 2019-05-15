
/****************************************************************************** 
 *
 *  ghostshell - @emptymonkey's User Simulation Daemon - 2019-05-09
 *
 *  The purpose of this program is to have an artificial user interaction with a 
 *  shell and tty in the background without requiring an actual login. This is
 *  useful for simulating a logged in user. This may be useful for ctfs and
 *  honeypots.
 *
 *  The setup will be as follows:
 *
 *    (file)           (UID root process)            (UID user process)
 *    Keyboard  -fd->  Referee (Parent)    <-tty->   Shell (Child)
 *
 *  The "Keyboard" should be a file of contents to be sent down the tty as
 *  though typed by a user. The "Shell" will exec /bin/bash, with stdin, stdout,
 *  and stderr all tied to the new tty as one would expect. 
 *
 *  Any lines in the keyboard script that start with '#' followed by only 
 *  digits, then closed out with the newline, will be interpreted as a time
 *  for the keyboard to sleep before moving on to the next line.
 *  
 *  See the test file in this repository for an example of what a keyboard
 *  script looks like.
 *
 ******************************************************************************/


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
#include <time.h>
#include <unistd.h>
#include <utmp.h>


#define DEFAULT_SHELL	"/bin/bash"
#define DEFAULT_MIMIC	"/bin/login --"
#define DEFAULT_TIMEOUT 0
#define DEFAULT_PAUSE 2
#define DEFAULT_LOGFILE "/root/usimd.out"
#define DEFAULT_TERM "TERM=linux"
#define DEFAULT_TTY_NAME "tty1"


void broker(FILE *keyboard, int shell_fd, int pause_secs);
char **string_to_vector(char *command_string);


char *buff;
long buff_len;
char *program_invocation_short_name;

volatile sig_atomic_t sig_found = 0;


void signal_handler(int signal){
	sig_found = signal;
}


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
	struct sigaction act;

	int shell_fd;
	char *shell_tty_name;
	int child_pid;
	FILE *keyboard;
	struct utmp ut;

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


	// Setup a global i/o buffer.
	buff_len = sysconf(_SC_PAGESIZE);
	if((buff = (char *) malloc(buff_len)) == NULL){
		fprintf(stderr, "%s: malloc(%ld): %s\n", program_invocation_short_name, buff_len, strerror(errno));
		exit(1);
	}


	// process the options
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

	// ensure that user is properly set, even if it is just us.
	if(user){
		if((pwent = getpwnam(user)) == NULL){
			if(errno){
				fprintf(stderr, "%s: getpwnam(\"%s\"): %s\n", program_invocation_short_name, user, strerror(errno));
			}else{
				fprintf(stderr, "%s: getpwnam(\"%s\"): No such user.\n", program_invocation_short_name, user);
			}
			exit(1);
		}
	}else{
		if((pwent = getpwuid(getuid())) == NULL){
			if(errno){
				fprintf(stderr, "%s: getpwuid(\"%d\"): %s\n", program_invocation_short_name, getuid(), strerror(errno));
			}else{
				fprintf(stderr, "%s: getpwuid(\"%d\"): Your system is having an existential crisis.\n", program_invocation_short_name, getuid());
			}
			exit(1);
		}
		user = pwent->pw_name;
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

	// When the shell exists, we won't be watching for it. Best ignore SIGCHLD.
	if(signal(SIGCHLD, SIG_IGN) == SIG_ERR){
		fprintf(stderr, "%s: signal(SIGCHLD, SIG_IGN): %s\n", program_invocation_short_name, strerror(errno));
		exit(1);
	}

	memset(&act, 0, sizeof(act));
	act.sa_handler = signal_handler;
	if(sigaction(SIGALRM, &act, NULL) == -1){
		fprintf(stderr, "%s: sigaction(SIGALRM, %lx, NULL): %s\n", program_invocation_short_name, (unsigned long) &act, strerror(errno));
		exit(1);
	}


	// Ready for the general handling loop.
	do {

		// Setup the new tty.
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

		if(tcsetattr(shell_fd, TCSANOW, &saved_termios_attrs) == -1){
			fprintf(stderr, "%s: tcgetattr(%d, %lx): %s\n", program_invocation_short_name, shell_fd, (unsigned long) &saved_termios_attrs, strerror(errno));
			exit(1);
		}

		if((shell_tty_name = ptsname(shell_fd)) == NULL){
			fprintf(stderr, "%s: ptsname(%d): %s\n", program_invocation_short_name, shell_fd, strerror(errno));
			exit(1);
		}


		// time to spawn child.
		if((retval = fork()) == -1){
			fprintf(stderr, "%s: fork(): %s\n", program_invocation_short_name, strerror(errno));
			exit(1);
		}

		if(!retval){

			// Child code:

			// Setup the fds so they look "normal" for a new shell connected to new tty.
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

			// If we're root, now is the time to switch to the target user.
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

			/* Setup the terminal environment variable. */
			term_envp[0] = term;
			term_envp[1] = NULL;

			// DO IT!
			execve(shell[0], shell, term_envp);
			exit(1);
		}


		// Parent code:

		child_pid = retval;

		// if we're root, time to show our login for 'w' and 'last'. (utmp/wtmp)
		if(!getuid()){
			memset(&ut, 0, sizeof(struct utmp));
			ut.ut_type = USER_PROCESS;
			ut.ut_pid = child_pid;

			strncpy(ut.ut_line, shell_tty_name + 5, sizeof(ut.ut_line));
			strncpy(ut.ut_id, shell_tty_name + (strlen(shell_tty_name) - 4), sizeof(ut.ut_id));
			if(time((time_t *) &ut.ut_tv.tv_sec) == -1){
				fprintf(stderr, "%s: time(%lx): %s\n", program_invocation_short_name, (unsigned long) &ut.ut_tv.tv_sec, strerror(errno));
				exit(1);
			}
			strncpy(ut.ut_user, user, sizeof(ut.ut_user));
			setutent();
			if(pututline(&ut) == NULL){
				fprintf(stderr, "%s: pututline(%lx): %s\n", program_invocation_short_name, (unsigned long) &ut, strerror(errno));
				exit(1);
			}
			updwtmp(WTMP_FILE, &ut);
			endutent();
		}

		/* Setup keyboard input. */
		if((keyboard = fopen(keyboard_file, "r")) == NULL){
			fprintf(stderr, "%s: fopen(\"%s\", \"r\"): %s\n", program_invocation_short_name, keyboard_file, strerror(errno));
			exit(1);
		}

		/* Setup alarm(). */
		alarm(timeout);

		/* Call the main broker() loop. Most of the actual work happens here. */
		broker(keyboard, shell_fd, pause_secs);

		// Record the logout in utmp/wtmp.
		if(!getuid()){
			ut.ut_type = DEAD_PROCESS;
			if(time((time_t *) &ut.ut_tv.tv_sec) == -1){
				fprintf(stderr, "%s: time(%lx): %s\n", program_invocation_short_name, (unsigned long) &ut.ut_tv.tv_sec, strerror(errno));
				exit(1);
			}
			memset(ut.ut_user, 0, sizeof(ut.ut_user));
			setutent();
			if(pututline(&ut) == NULL){
				fprintf(stderr, "%s: pututline(%lx): %s\n", program_invocation_short_name, (unsigned long) &ut, strerror(errno));
				exit(1);
			}
			updwtmp(WTMP_FILE, &ut);
			endutent();
		}

		/* Clean up. */
		alarm(0);
		close(shell_fd);
		fclose(keyboard);

	} while(keepalive);


	return(0);
}


// I/O loop code.
void broker(FILE *keyboard, int shell_fd, int pause_secs){

	fd_set read_fds;

	int io_bytes;
	int keyboard_active;
	int retval;
	char *tmp_ptr;
	int keyboard_sleep;

	struct timeval tv;
	struct timespec ts;


	keyboard_active = 1;
	while(1){

		FD_ZERO(&read_fds);
		FD_SET(shell_fd, &read_fds);

		tv.tv_sec = pause_secs;
		tv.tv_usec = 0;

		// fall through if we received a signal on the previous loop.
		if(!sig_found){
			if(((retval = select(shell_fd + 1, &read_fds, NULL, NULL, &tv)) == -1) && !sig_found){
				fprintf(stderr, "%s: select(%d + 1, %lx, NULL, NULL, %lx): %s\n", program_invocation_short_name, shell_fd, (unsigned long) &read_fds, (unsigned long) &tv, strerror(errno));
				exit(1);
			}
		}

		if(sig_found){

			sig_found = 0;
			// time to go home.
			return;

		}else if(FD_ISSET(shell_fd, &read_fds)){
			if((io_bytes = read(shell_fd, buff, buff_len - 1)) == -1){
				break;
			}
			if(!io_bytes){
				break;
			}else{
				buff[io_bytes] = '\0';
				printf("%s", buff);
				fflush(stdout);
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
						ts.tv_sec = keyboard_sleep;
						ts.tv_nsec = 0;
						nanosleep(&ts, NULL);
					}else{
						if(write(shell_fd, buff, strnlen(buff, buff_len)) == -1){
							fprintf(stderr, "%s: write(%d, %lx, %ld): %s\n", program_invocation_short_name, shell_fd, (unsigned long) buff, strnlen(buff, buff_len), strerror(errno));
							exit(1);
						}
					}
				}
			}

		}
	}
}
