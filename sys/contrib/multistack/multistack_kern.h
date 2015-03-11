#ifndef _MULTISTACK_KERN_H
#define _MULTISTACK_KERN_H
#define WITH_VALE
#define WITH_PIPES /* XXX Should get better from netmap side */
int ms_init(void);
void ms_fini(void);
int ms_getifname(struct sockaddr *, char *name);
int ms_pcb_clash(struct sockaddr *, uint8_t);
#endif
