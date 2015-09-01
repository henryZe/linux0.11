#include <stdio.h>
#include <regex.h>
#include <string.h>
#include <stdint.h>

#define	ARGU	3	

int main()
{
	int err, i, len;
	long time, thread;
	regex_t reg;
	regmatch_t pmatch[ARGU];
	char errbuf[1024];
	char command[1024];
	char match[2][1024];
	char *pattern = "([a-z]*)[ ]*([0-9]*)";

	uint8_t mem[1<<20];
	
	if(regcomp(&reg, pattern, REG_EXTENDED)<0){
		regerror(err, &reg, errbuf, sizeof(errbuf));
		printf("err:%s\n",errbuf);
	}

	while(1)
	{
		fgets(command, sizeof(command), stdin);
		err = regexec(&reg, command, ARGU, pmatch, 0);
		if(err == REG_NOMATCH){
 			printf("exec err:no match\n");
 		 	return -1;
 		}
		else if(err){
			regerror(err,&reg,errbuf,sizeof(errbuf));
 			printf("exec err:%s\n",errbuf);
 			return -1;
 		}

		for(i=1; (i<ARGU) && (pmatch[i].rm_so != -1); i++){
 			len = pmatch[i].rm_eo - pmatch[i].rm_so;
			if(len){
				memset(match[i-1], '\0', sizeof(match));
				memcpy(match[i-1], command+pmatch[i].rm_so, len);
			}
		}
		
		if(!strcmp(match[0], "time")){
			time = atol(match[1]);
			printf("time num:%ld\n", time);	
		}
		else if(!strcmp(match[0], "thread")){
			thread = atol(match[1]);
			printf("thread num:%ld\n", thread);	
		}
		else if(!strcmp(match[0], "go")){
		}
		else if(!strcmp(match[0], "status")){
			for(i=0; i<thread; i++){
				if(t_stat[i].run)
					printf("thread %d is running.(%d ~ %d, %d/%d)\n", i+1, t_stat[i].s_calc, t_stat[i].e_calc, t_stat[i].count, t_stat[i].sum);
				else
					printf("thread %d is exited.(%d ~ %d, %d/%d)\n", i+1, t_stat[i].s_calc, t_stat[i].e_calc, t_stat[i].count, t_stat[i].sum);
			}	
		}	
		else if(!strcmp(match[0], "abort")){
			printf("abort\n");	
		}	
		else if(!strcmp(match[0], "exit")){
			return 0;	
		}	
		else{
			printf("help:\t1.time+number\n");
			printf("\t2.thread+number\n");
			printf("\t3.go\n");
			printf("\t4.status\n");
			printf("\t5.abort\n");
			printf("\t6.exit\n");
		}
	}
	
	return 0;
}
