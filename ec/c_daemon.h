/*!
\file c_daemon.h
\author kipway@outlook.com
\update 2018.5.15

eclib class cDaemonFrame , for linux daemon server

eclib Copyright (c) 2017-2018, kipway
source repository : https://github.com/kipway/eclib

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#pragma once

namespace ec {
    class cDaemon
    {
    public:
		virtual ~cDaemon() {};
        virtual bool start() = 0;
        virtual bool stop() = 0;
    };
}

#ifndef _WIN32
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <mntent.h>
#include<sys/types.h>
#include<fcntl.h>
#include<sys/statfs.h>
#include <sys/time.h>
#include<sys/ipc.h> 
#include<sys/msg.h> 
#include <termios.h>

extern ec::cDaemon* g_daemon;
namespace ec
{
    class cDaemonFrame
    {
    public:
		struct t_msg
		{
			long mtype;
			char mtext[];
		};
        class cIpcMsg
        {
        public:
            cIpcMsg(int key)
            {
                _qid = msgget(key, IPC_CREAT | 0666);
            }
			int snd(const char* str)
			{
				if (_qid < 0)
					return -1;
				t_msg *pmsg = (t_msg*)malloc(strlen(str) + sizeof(t_msg) + 1);
				if (!pmsg)
					return -1;
				pmsg->mtype = 1;
				memcpy(pmsg->mtext, str, strlen(str) + 1);
				int nr = msgsnd(_qid, pmsg, strlen(str) + 1, IPC_NOWAIT);
				free(pmsg);
				return nr;
			}

			int rcv(char* pbuf, size_t szbuf)
			{
				if (_qid < 0)
					return -1;
				t_msg *pmsg = (t_msg*)malloc(szbuf + sizeof(t_msg));
				if (!pmsg)
					return -1;
				ssize_t szr = msgrcv(_qid, pmsg, szbuf, 0, IPC_NOWAIT);
				if (szr < 0) {
					free(pmsg);
					return -1;
				}
				memcpy(pbuf, pmsg->mtext, szr);
				free(pmsg);
				return (int)szr;
			}
            int del()
            {
                if (_qid < 0)
                    return -1;
                return msgctl(_qid, IPC_RMID, NULL);
            }
        protected:
            int _qid;
        };

        class cFLock
        {
        public:
            cFLock()
            {
                m_sfile[0] = '\0';
                m_nlockfile = -1;
            }
            cFLock(const char* sfile)
            {
                Init(sfile);
            }
            ~cFLock()
            {
                if (m_nlockfile >= 0)
                    close(m_nlockfile);
                m_nlockfile = -1;
            }
        public:
            void Init(const char* sfile)
            {
                m_sfile[0] = '\0';
                strcpy(m_sfile, sfile);
                m_nlockfile = -1;
            }
            void Close()
            {
                if (m_nlockfile >= 0)
                    close(m_nlockfile);
                m_nlockfile = -1;
            }
            int     CheckLock()    //return 0 success
            {
                m_nlockfile = open(m_sfile, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
                if (m_nlockfile < 0)
                    return -1;
                struct flock fl;
                fl.l_start = 0;
                fl.l_whence = SEEK_SET;
                fl.l_len = 0;
                fl.l_type = F_WRLCK;
                if (fcntl(m_nlockfile, F_GETLK, &fl) < 0)
                    return -1;
                if (fl.l_type == F_UNLCK) // if unlock lock and return current pid
                    return Lock();
                return fl.l_pid; // return the pid
            }

            int     Lock() //lock and write pid to file
            {
                char buf[32];
                struct flock fl;
                fl.l_start = 0;
                fl.l_whence = SEEK_SET;
                fl.l_len = 0;
                fl.l_type = F_WRLCK;
                fl.l_pid = getpid();
                if (fcntl(m_nlockfile, F_SETLKW, &fl) < 0) //Blocking lock
                    return -1;
                if (ftruncate(m_nlockfile, 0))
                    return -1;
                lseek(m_nlockfile,0,SEEK_SET);
				sprintf(buf, "%ld\n", (long)getpid());
				if (write(m_nlockfile, buf, strlen(buf)) <= 0)
					return -1;
                return 0;
            }
            static  int GetLockPID(const char *spidfile)//get lock PID,ret  -1:err; 0:not lock; >0 PID;
            {
                int nlockfile = open(spidfile, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
                if (nlockfile < 0)
                    return -1;
                struct flock fl;
                fl.l_start = 0;
                fl.l_whence = SEEK_SET;
                fl.l_len = 0;
                fl.l_type = F_WRLCK;
                if (fcntl(nlockfile, F_GETLK, &fl) < 0)
                {
                    close(nlockfile);
                    return -1;
                }
                if (fl.l_type == F_UNLCK) //not lock
                {
                    close(nlockfile);
                    return 0;
                }
                close(nlockfile);
                return fl.l_pid; //return lock pid
            }
        protected:
            int     m_nlockfile;
            char    m_sfile[512];
        };
    protected:
        cFLock _flck;
        int _msgkey;
        char _spidfile[512];
        char _sDaemon[512];
        char _sVer[512];
    public:
        virtual cDaemon* CreateDaemon() = 0;
    public:
        cDaemonFrame()
        {
            memset(_spidfile, 0, sizeof(_spidfile));
            memset(_sDaemon, 0, sizeof(_sDaemon));
            memset(_sVer, 0, sizeof(_sVer));
        }
        void Init(const char* spidfile, const char* sDaemonName, const char* sver, int nmsgkey)
        {
            strcpy(_spidfile, spidfile);
            strcpy(_sDaemon, sDaemonName);
            strcpy(_sVer, sver);
            _msgkey = nmsgkey;
        }
        inline const char* pidfile()
        {
            return _spidfile;
        }
        inline const char* daemonname()
        {
            return _sDaemon;
        }
        static void CloseIO()
        {
            int fd = open("/dev/null", O_RDWR);
            if (fd < 0)
                return;
            dup2(fd, 0);
            dup2(fd, 1);
            dup2(fd, 2);
            close(fd);
        }
        static void exithandler(int ns)
        {
            if (!g_daemon)
                return;
            g_daemon->stop();
            g_daemon = NULL; //not free memery,exit will release the memory
            exit(0);
        }

        int start()
        {
            _flck.Init(_spidfile);
            int nlock = _flck.CheckLock();
            if (nlock == -1)
            {
                printf("Access Error! Please use root account!\n");
                return 1;
            }
            else if (nlock)
            {
                printf("%s alreay runging! pid = %d\n", _sDaemon, nlock);
                return 0;
            }

            pid_t pid = fork();
            if (pid < 0)
            {
                return (-1);
            }
            else if (pid > 0) //parent
            {
                _flck.Close();
                cIpcMsg msg(_msgkey); // send
                char smsg[512] = { 0 };

                int i, n = 30, nm = 0;
                for (i = 0; i < n; i++)
                {
                    sleep(1);
                    if (msg.rcv(smsg, sizeof(smsg)) > 0)
                    {
                        printf("%s", smsg);
                        fflush(stdout);
						if (!strcasecmp("finished", smsg)) {
							printf("\n");
							break;
						}
                        nm++;
                    }
                    if (!nm && i > 5)
                        n = 10;
                }
                msg.del();
                CloseIO();
                return 0;
            }
            else
            {
                cIpcMsg msg(_msgkey);
                setsid(); // become session leader
                if (chdir("/"))
                {
                    msg.snd("chdir failed\n");
                    msg.snd("finished");
                    return 2;
                }
                umask(0); // clear file mode creation mask
                _flck.Lock();//relock

                g_daemon = CreateDaemon();
                if (!g_daemon)
                {
                    msg.snd("Start failed! no enough memery!\n");
                    msg.snd("finished");
                    _flck.Close();
                    return 3;
                }
                if (msg.snd("\nstart...\r") < 0)
                    printf("send message failed\n");
                if (!g_daemon->start())
                {                    
                    msg.snd("Start failed!\n");
                    msg.snd("finished");
                    _flck.Close();
					exit(4);
                    return 4;
                }
                msg.snd("Start success!\n\n");
                msg.snd("finished");
                signal(SIGTERM, exithandler);
                pause();
            }
            return 0;
        }

        void stop(int nsec = 300)
        {
            int i, nlock = cFLock::GetLockPID(_spidfile);
            bool bexit = true;
            if (nlock == -1)
            {
                printf("Access Error! Please use root account!\n");
                printf("\n");
                return;
            }
            else if (nlock > 0)
            {
                printf("stop %s... pid = %d\n", _sDaemon, nlock);
                bexit = false;
                kill(nlock, SIGTERM); // send term sig
                for (i = 0; i < nsec; i++)
                {
                    if (cFLock::GetLockPID(_spidfile) <= 0)
                    {
                        bexit = true;
                        break;
                    }

                    sleep(1);
                }
                if (!bexit)
                {
                    kill(nlock, SIGKILL); //force kill
                    sleep(1);
                    printf("%d second Timeout,%s be killed!\n", nsec, _sDaemon);
                }
                else
                    printf("%s stoped gracefully!\n", _sDaemon);
                printf("\n");
                return;
            }
            printf("%s not run!\n", _sDaemon);
            printf("\n");
        }

        void status()
        {
            int nlock = cFLock::GetLockPID(_spidfile);
            if (nlock == 0)
                printf("%s not run!\n", _sDaemon);
            else if (nlock == -1)
                printf("Access Error! Please use root account!\n");
            else
                printf("%s is runing!\n", _sDaemon);
            printf("\n");
        }

        void usage()
        {
            printf("usage:%s [-start] | [-stop] | [-status] | [-ver]\n", _sDaemon);
            printf("demo:\n");
            printf("%s -start\n", _sDaemon);
            printf("%s -stop\n", _sDaemon);
            printf("%s -status\n", _sDaemon);
            printf("%s -ver\n", _sDaemon);
            printf("\n");
            printf("%s %s\n", _sDaemon, _sVer);
            printf("\n");
        }
    };
}
#endif// ifndef _WIN32

/* usage
class CRuncls : public ec::cDaemon
{
public:
	virtual bool start() 
	{ 
		//.......your code
		return true; 
	};
	virtual bool stop()
	{
		//.......your code
		return true;
	}
};

ec::cDaemon* g_daemon = 0;

class CRdbvFrame :public ec::cDaemonFrame
{
public:
	virtual ec::cDaemon* CreateDaemon()
	{
		return new CRuncls;
	}
}_server;

int main(int argc, char** argv)
{
	printf("\n");
	_server.Init("/var/run/yourserver.pid", "yourserver", "for Linux,Ver = 1.0.0.0,fileversion 1.0.0.0,build9029", 971);
	if (argc == 2)
	{
		if (strcasecmp(argv[1], "-start") == 0)  //后台服务进程模式
			_server.start();
		else if (strcasecmp(argv[1], "-stop") == 0)
			_server.stop();
		else if (strcasecmp(argv[1], "-status") == 0)
			_server.status();
		else if (strcasecmp(argv[1], "-ver") == 0 || strcasecmp(argv[1], "-version") == 0)
		{
			printf("%s ver 10.0\n", _server.daemonname());
		}
		else
			_server.usage();
	}
	else
		_server.usage();
	return 0;
}
*/
