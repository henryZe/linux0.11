#include <stdio.h>
#include <regex.h>
#include <string.h>
#include <stdint.h>

#define	ARGU		2	
#define	MAX_THREAD	20	
#define TEST1		0x0
#define TEST2		0xff
#define TEST3		0xaa
#define TEST4		0x55

struct task_status{
	int run;
	int s_calc;
	int e_calc;
	int count;
	int sum;
};
struct task_status t_stat[MAX_THREAD];


int *memtest()
{
	for(i=t_stat[t_num].s_calc; i<e_calc; i++){
		mem[i] = TEST1;
		if(mem[i] != TEST1){
			
		}

		mem[i] = TEST2;
		if(mem[i] != TEST2){
		
		}

		mem[i] = TEST3;
		if(mem[i] != TEST3){
		
		}

		mem[i] = TEST4;
		if(mem[i] != TEST4){
		
		}
	
		rdm_num = random()%0x100;
		mem[i] = rdm_num;
		if(mem[i] != rdm_num){
			
		}
	}
}

int main()
{
	int err, i, j, len;
	long time, thread;
	regex_t reg;
	regmatch_t pmatch[ARGU+1];
	char errbuf[1024];
	char command[1024];
	char match[ARGU][1024];
	char *pattern = "([a-z]{1,})[ ]*([0-9]*)";

	uint8_t mem[1<<20];


	if(regcomp(&reg, pattern, REG_EXTENDED)<0){
		regerror(err, &reg, errbuf, sizeof(errbuf));
		printf("err:%s\n",errbuf);
 		return -1;
	}

	while(1)
	{
		fgets(command, sizeof(command), stdin);
		err = regexec(&reg, command, ARGU+1, pmatch, 0);
		if(err == REG_NOMATCH){
 			printf("exec err:no match\n");
 		 	goto help;
 		}
		else if(err){
			regerror(err,&reg,errbuf,sizeof(errbuf));
 			printf("exec err:%s\n",errbuf);
 			return -1;
 		}

		for(i=1; (i<=ARGU) && (pmatch[i].rm_so != -1); i++){
			memset(match[i-1], '\0', 1024);
 			
			len = pmatch[i].rm_eo - pmatch[i].rm_so;
			if(len){
				memcpy(match[i-1], command+pmatch[i].rm_so, len);
//				printf("match[%d] = %s\n", i-1, match[i-1]);
			}
		}
		
		if(!strcmp(match[0], "time")){
			if(!strlen(match[1])){
				printf("no num enter\n");
 		 		goto help;
			}
			time = atol(match[1]);
			printf("time num:%ld\n", time);	
		}
		else if(!strcmp(match[0], "thread")){
			if(!strlen(match[1])){
				printf("no num enter\n");
 		 		goto help;
			}
			thread = atol(match[1]);
			printf("thread num:%ld\n", thread);	
		}
		else if(!strcmp(match[0], "go")){
		}
		else if(!strcmp(match[0], "status")){
			for(j=0; j<thread; j++){
				if(t_stat[j].run)
					printf("thread %d is running.(%d ~ %d, %d/%d)\n", j+1, t_stat[j].s_calc, t_stat[j].e_calc, t_stat[j].count, t_stat[j].sum);
				else
					printf("thread %d is exited.(%d ~ %d, %d/%d)\n", j+1, t_stat[j].s_calc, t_stat[j].e_calc, t_stat[j].count, t_stat[j].sum);
			}	
		}	
		else if(!strcmp(match[0], "abort")){
			printf("abort\n");
		}	
		else if(!strcmp(match[0], "exit")){
			return 0;	
		}	
		else{
help:		printf("help:\t1.time+number\n");
			printf("\t2.thread+number\n");
			printf("\t3.go\n");
			printf("\t4.status\n");
			printf("\t5.abort\n");
			printf("\t6.exit\n");
		}
	}
	
	return 0;
}
