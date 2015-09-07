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
	pthread_t tid;

	int run;
	int s_calc;
	int e_calc;
	int count;
	int sum;

	int error_num;
};

uint8_t mem[1<<20];
static long time = 1;


void *memtest(void *stat)
{
	int i, j, rdm_num;
	struct task_status *t_stat = (struct task_status *)stat;

	t_stat->run = 1;
	for(i=t_stat->s_calc; i<=t_stat->e_calc; i++){
		for(j=0; j<time; j++){
			mem[i] = TEST1;
			if(mem[i] != TEST1){
				t_stat->error_num++;
			}

			mem[i] = TEST2;
			if(mem[i] != TEST2){
				t_stat->error_num++;
			}

			mem[i] = TEST3;
			if(mem[i] != TEST3){
				t_stat->error_num++;
			}

			mem[i] = TEST4;
			if(mem[i] != TEST4){
				t_stat->error_num++;
			}
		
			rdm_num = random()%0x100;
			mem[i] = rdm_num;
			if(mem[i] != rdm_num){
				t_stat->error_num++;
			}
		}
		t_stat->count++;
	}

	t_stat->run = 0;
	
	pthread_exit(NULL);
}

int main()
{
	int err, i, j, len, calc_thread;
	long thread = 1;
	regex_t reg;
	regmatch_t pmatch[ARGU+1];
	char errbuf[1024];
	char command[1024];
	char match[ARGU][1024];
	char *pattern = "([a-z]{1,})[ ]*([0-9]*)";
	struct task_status t_stat[MAX_THREAD];


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
			calc_thread = (1<<20)/thread;

			for(i=0; i<thread; i++){
				t_stat[i].s_calc = calc_thread*i;
				t_stat[i].error_num = 0;
				t_stat[i].count = 0;
				t_stat[i].sum = calc_thread;
				t_stat[i].run = 0;
				
				if(i>0){
					t_stat[i-1].e_calc = t_stat[i].s_calc-1;
				}
			}
			t_stat[thread-1].e_calc = (1<<20)-1;
			t_stat[thread-1].sum = t_stat[thread-1].e_calc-t_stat[thread-1].s_calc+1; 
		
			for(i=0; i<thread; i++){
				pthread_create(&(t_stat[i].tid), NULL, memtest, (void *)&(t_stat[i]));
			}
		}
		else if(!strcmp(match[0], "status")){
			for(j=0; j<thread; j++){
				if(t_stat[j].run){
					printf("thread %d is running.(%d ~ %d, %d/%d, error:%d)\n", \
						j+1, t_stat[j].s_calc, t_stat[j].e_calc, t_stat[j].count, t_stat[j].sum, t_stat[j].error_num);
				}else{
					printf("thread %d is exited.(%d ~ %d, %d/%d, error:%d)\n", \
						j+1, t_stat[j].s_calc, t_stat[j].e_calc, t_stat[j].count, t_stat[j].sum, t_stat[j].error_num);
				}
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
