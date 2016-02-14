/* shell */

#include "types.h"
#include "user.h"
#include "fcntl.h"

/* parsed command representation */
#define EXEC	1
#define REDIR	2
#define PIPE	3
#define LIST	4
#define BACK	5

#define MAXARGS	10

struct cmd {
	int type;
};

struct execcmd {
	int type;
	char *argv[MAXARGS];
	char *eargv[MAXARGS];
};

struct redircmd {
	int type;
	struct cmd *cmd;
	char *file;
	char *efile;
	int mode;
	int fd;
};

struct pipecmd {
	int type;
	struct cmd *left;
	struct cmd *right;
};

struct listcmd {
	int type;
	struct cmd *left;
	struct cmd *right;
};

struct backcmd {
	int type;
	struct cmd *cmd;
};

/* execute cmd, never returns */
void runcmd(struct cmd *cmd)
{
	int p[2];
	struct backcmd *bcmd;
	struct execcmd *ecmd;
	struct listcmd *lcmd;
	struct pipecmd *pcmd;
	struct redircmd *rcmd;

	if (cmd == 0)
		exit();

	switch (cmd->type) {
	default:
		panic("runcmd");

	case EXEC:
		ecmd = (struct execcmd *)cmd;
		if (ecmd->argv[0] == 0)
			exit();
		exec(ecmd->argv[0], ecmd->argv);
		printf(2, "exec %s failed\n", ecmd->argv[0]);
		break;

	case REDIR:
		rcmd = (struct redircmd *)cmd;
		close(rcmd->fd);
		if (open(rcmd->file, rcmd->mode) < 0) {
			printf(2, "open %s failed\n", rcmd->file);
			exit();
		}
		runcmd(rcmd->cmd);
		break;

	case LIST:
		lcmd = (struct listcmd *)cmd;
	}
}




int main(void)
{
	static char buf[100];
	int fd;

	/* assumes three file descriptors open */
	while ((fd = open("console", O_RDWR)) >= 0) {
		if (fd >= 3) {
			close(fd);
			break;
		}
	}

	/* read and run input commands */
	while (getcmd(buf, sizeof(buf)) >= 0) {
		if (buf[0] == 'c' && buf[1] == 'd' && buf[2] == ' ') {
			/* clumsy but will have to do for now */
			/* chdir has no effect on the parent
				if run in the child */
			/* chop \n */
			buf[strlen(buf)-1] = 0;
			if (chdir(buf+3) < 0)
				printf(2, "cannot cd %s\n", buf+3);
			continue;
		}
		if (fork1() == 0)
			runcmd(parsecmd(buf));
		wait();
	}
	exit();
}

void panic(char *s)
{
	printf(2, "panic: %s\n", s);
	exit();
}

/* fork but panics on failure */
int fork1(void)
{
	int pid;

	pid = fork();
	if (pid == -1)
		panic("fork");
	return pid;
}

/* constructors */

struct cmd *execcmd(void)
{
	struct execcmd *cmd;

	cmd = malloc(sizeof(*cmd));
	memset(cmd, 0, sizeof(*cmd));
	cmd->type = EXEC;
	return (struct cmd *)cmd;
}

struct cmd *redircmd(struct cmd *subcmd,
	char *file, char *efile, int mode, int fd)
{
	struct redircmd *cmd;

	cmd = malloc(sizeof(*cmd));
}

struct cmd *parsecmd(char *s)
{
	char *es;
	struct cmd *cmd;

	es = s + strlen(s);
	cmd = parseline(&s, es);
	peek(&s, es, "");
	if (s != es) {
		printf(2, "leftovers: %s\n", s);
		panic("syntax");
	}
	nulterminate(cmd);
	return cmd;
}









