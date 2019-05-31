#include <stdio.h>
#include <sys/inotify.h>
#include <sys/epoll.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <dirent.h>
#include <errno.h>

#include <vector>
#include <string>
#include <set>
#include <map>

using namespace std;

#define INVALID_FD (-1)

#define IN_MOVED_FROM	0x00000040 /* File was moved from X.  */
#define IN_MOVED_TO		0x00000080 /* File was moved to Y.  */

bool g_bContinue = true;

//////////////////////////////////////////////////////////////////////////
//

struct CStat
{
	uint32_t events;
	uint32_t creats;
	uint32_t modifies;
	uint32_t deletes;
	uint32_t errors;
	uint32_t ignores;

	CStat()
	{
		memset(this, 0, sizeof(*this));
	}
};


//////////////////////////////////////////////////////////////////////////
// base 
class CFD
{
	CFD(const CFD &);
	CFD &operator=(const CFD &);

public:
	CFD() : m_fd(INVALID_FD) {}

	virtual ~CFD()
	{
		clear();
	}

public:
	int GetFD() { return m_fd; }

	int IsValid() 
	{ 
		return m_fd != INVALID_FD ? 0 : -1;
	}

public:
	int SetCloseOnExec(bool valid)
	{
		return fcntl(m_fd, F_SETFD, valid ? FD_CLOEXEC : 0);
	}

	int SetNonBlock(bool valid)
	{
		int mod = fcntl(m_fd, F_GETFL, NULL);
		if (mod < 0) { return -1; }
		if (valid) { mod |= O_NONBLOCK; }
		else { mod &= ~O_NONBLOCK; }
		return fcntl(m_fd, F_SETFL, mod);
	}

public:
	int GetLength(int *plen)
	{
		return ioctl(m_fd, FIONREAD, plen);
	}

	int Read(void *pbuf, size_t _size)
	{
		return (int)read(m_fd, pbuf, _size);
	}

protected:
	void clear()
	{
		if (INVALID_FD != m_fd) { return; }
		close(m_fd);
		m_fd = INVALID_FD;
	}

protected:
	int m_fd;
};

//////////////////////////////////////////////////////////////////////////
//

class CEpoll
{
	CEpoll(const CEpoll &);
	CEpoll &operator=(const CEpoll &);

	enum 
	{
		EPOLL_MAX_EVENTS = 32,
		EPOOL_DEFAULT_TIMEOUT = 1000, // 1000 milliseconds = 1 second
	};

public:
	CEpoll() : m_epollfd(INVALID_FD), m_eventcnt(0), m_timeout(EPOOL_DEFAULT_TIMEOUT) { }
	~CEpoll() { clear(); }

public:
	int Initialize()
	{
		memset(m_events, 0, sizeof(m_events));

		int epollfd = epoll_create1(0);
		if (INVALID_FD == epollfd)
		{
			return -1;
		}

		m_epollfd = epollfd;
		return 0;
	}

public:
	int Register(CFD *pfd)
	{
		if (!pfd || -1 == pfd->IsValid()) { return -1; }

		epoll_event ev; memset(&ev, 0, sizeof(ev));
		ev.events = EPOLLIN;
		ev.data.fd = pfd->GetFD();
		return epoll_ctl(m_epollfd, EPOLL_CTL_ADD, pfd->GetFD(), &ev);
	}

	int Unregister(CFD *pfd)
	{
		if (!pfd || -1 == pfd->IsValid()) { return -1; }

		return epoll_ctl(m_epollfd, EPOLL_CTL_DEL, pfd->GetFD(), NULL);
	}

public:
	int Wait()
	{
		m_eventcnt = 0;
		int res = epoll_wait(m_epollfd, m_events, EPOLL_MAX_EVENTS, m_timeout);
		//int res = epoll_wait(m_epollfd, m_events, EPOLL_MAX_EVENTS, -1);
		if (res < 0) { return res; }
		m_eventcnt = res;
		return 0;
	}

	int EventCount()
	{
		return m_eventcnt;
	}

	int HasEvents(CFD *pfd)
	{
		for (int i = 0; i < m_eventcnt; i++)
		{
			if (m_events[i].data.fd == pfd->GetFD())
			{
				return 0;
			}
		}
		return -1;
	}

private:
	void clear()
	{
		if (INVALID_FD != m_epollfd)
		{
			close(m_epollfd);
			m_epollfd = INVALID_FD;
		}
	}

private:
	int m_epollfd;
	int m_eventcnt;
	int m_timeout;
	epoll_event m_events[EPOLL_MAX_EVENTS];

};

//////////////////////////////////////////////////////////////////////////
//

struct CInotifyEventHelper
{
	inotify_event *pev;

	CInotifyEventHelper(inotify_event *p) : pev(p) {}

	bool is_ignored() { return !!(pev->mask & IN_IGNORED); }
	bool is_dir() { return !!(pev->mask & IN_ISDIR); }
	bool is_create() { return !!(pev->mask & (IN_CREATE | IN_MOVED_TO)); }
	bool is_delete() { return !!(pev->mask & (IN_DELETE | IN_MOVED_FROM)); }
	bool is_modify() { return !!(pev->mask & (IN_MODIFY | IN_CLOSE_WRITE)); }
	bool is_del_self() { return !!(pev->mask & (IN_DELETE_SELF)); }
	bool is_mv_self() { return !!(pev->mask & (IN_MOVE_SELF)); }
	bool is_self() { return is_del_self() || is_mv_self(); }
	bool is_other() { return !(is_create() || is_modify() || is_delete() || is_self()); }

	uint32_t get_mask() { return pev->mask; }
	uint32_t get_cookie() { return pev->cookie; }
	const char *get_name() { return pev->name; }
	int get_wd() { return pev->wd; }
	int get_evlen() { return (int)sizeof(inotify_event) + pev->len; }
};


struct CInotifyEvents
{
	vector<uint8_t> buf;
	int evcnt;

	CInotifyEvents() { }

	uint8_t *begin() { return &buf[0]; }
	uint8_t *end() { return begin() + buf.size(); }

	int validate(int cbr)
	{
		if (cbr < (int)buf.size())
		{
			return -1;
		}

		int cnt = 0;
		uint8_t *p = &buf[0], *pend = (p + buf.size());
		for (; p < pend; )
		{ 
			CInotifyEventHelper ev((inotify_event *)p);
			p += ev.get_evlen();
			cnt++;
		}

		if (p != pend)
		{
			return -1;
		}
		evcnt = cnt;
		return 0;
	}

	void clear()
	{
		// todo: free memory when usage over quota
		buf.clear();
		evcnt = 0;
	}

	void resize(size_t len)
	{
		buf.resize(len);
	}

	int bundle(inotify_event *pev)
	{
		uint8_t *p = (uint8_t *)pev;
		return (begin() <= p && p < end()) ? 0 : -1;
	}

	inotify_event *get(inotify_event *pev)
	{
		if (NULL == pev)
		{
			return (inotify_event *)&buf[0];
		}

		if (bundle(pev) < 0) { return NULL; }

		pev = (inotify_event *)((uint8_t *)pev + CInotifyEventHelper(pev).get_evlen());
		//return 0 == pev->len ? NULL : pev;
		if ((uint8_t *)pev > end())
		{
			printf("Inotify: event over buffer\n");
		}
		return (uint8_t *)pev >= end() ? NULL : pev;
	}
};

class CInodify : public CFD
{
	CInodify(const CInodify &);
	CInodify &operator=(const CInodify &);

	enum
	{
		INOTIFY_DEFAULT_MASK = 
			IN_CREATE | IN_MOVED_TO |
			IN_DELETE | IN_MOVED_FROM | 
			IN_MODIFY | IN_CLOSE_WRITE |
			IN_DELETE_SELF | IN_MOVE_SELF,
	};

private:
	uint32_t m_mask;
	uint32_t m_watchs;

public:
	virtual ~CInodify() {}
	CInodify() : CFD() 
	{
		m_mask = INOTIFY_DEFAULT_MASK;
		m_watchs = 0;
	}

public:
	int Initialize()
	{
		m_watchs = 0;

		m_fd = inotify_init();
		if (INVALID_FD == m_fd) { return -1; }
		if (SetCloseOnExec(true) < 0) { clear(); return -1; }
		if (SetNonBlock(true) < 0) { clear(); return -1; }
		return 0;
	}

	int Watch(const char *pdir)
	{
		if (IsValid() < 0) { return -1; }

		return add_watch(pdir);
	}

	int Purge(int wd)
	{
		if (IsValid() < 0) { return -1; }

		return rm_watch(wd);
	}

public:
	inotify_event *GetEvent(inotify_event *pev = NULL)
	{
		if (NULL == pev)
		{
			int len = 0;
			int res = GetLength(&len);
			if (res < 0 || len <= 0) 
			{ 
				m_events.clear();
				return NULL;
			}

			m_events.resize(len);
			int cbr = Read(&m_events.buf[0], m_events.buf.size());
			if (m_events.validate(cbr) < 0)
			{
				printf("Inotify: events validate failed(cbr = %d)!\n", cbr);
				m_events.clear();
				return NULL;
			}
			//printf("debug: events count: %d\n", m_events.evcnt);
		}
		return m_events.get(pev);
	}

private:
	int add_watch(const char *pdir)
	{
		int res = inotify_add_watch(GetFD(), pdir, m_mask);
		return res < 0 ? res : m_watchs++, res;
	}

	int rm_watch(int wd)
	{
		int res = inotify_rm_watch(GetFD(), wd);
		return res < 0 ? res : m_watchs--, res;
	}

private:
	CInotifyEvents m_events;
};

//////////////////////////////////////////////////////////////////////////
//

class CWatchDB
{
	CWatchDB(const CWatchDB &);
	CWatchDB &operator=(const CWatchDB &);

	typedef map<string, int> PATHMAP;
	typedef map<int, const char *> WDMAP;

public:
	typedef WDMAP::iterator iterator_wd;
	typedef PATHMAP::iterator iterator_path;

public:
	CWatchDB() { }

public:
	size_t Count()
	{
		return m_pathmap.size();
	}

	int Insert(int wd, const char *pdir)
	{
		if (!pdir || !pdir[0]) { return -1; }

		string dir(pdir);
		pair<PATHMAP::iterator, bool> res_set = m_pathmap.insert(pair<string, int>(dir, wd));
		if (false == res_set.second) { return -1; }

		pair<WDMAP::iterator, bool> res_map = 
			m_wdmap.insert(pair<int, const char *>(wd, res_set.first->first.c_str()));
		if (false == res_map.second)
		{
			m_pathmap.erase(dir);
			return -1;
		}
		return 0;
	}

	int Erase(int wd)
	{
		WDMAP::iterator itr = m_wdmap.find(wd);
		if (itr == m_wdmap.end()) { return -1; }

		string dir(itr->second);
		PATHMAP::iterator itr_path = m_pathmap.find(dir);
		if (itr_path == m_pathmap.end()) { return -1; }

		m_pathmap.erase(itr_path);
		m_wdmap.erase(itr);
		return 0;
	}

	int Erase(const char *pdir)
	{
		return -1;
	}

	const char *Query(int wd)
	{
		WDMAP::iterator itr = m_wdmap.find(wd);
		if (itr == m_wdmap.end()) { return NULL; }
		return itr->second;
	}

	int Query(const char *pdir)
	{
		if (!pdir || !pdir[0]) { return -1; }
		string dir(pdir);
		return Query(dir);
	}

	int Query(string &dir)
	{
		PATHMAP::iterator itr = m_pathmap.find(dir);
		return itr->second;
	}

public:
	int Update(const char *poldname, const char *pnewname)
	{
		string oldname(poldname);
		string newname(pnewname);

		return Update(oldname, newname);
	}

	int Update(string &oldname, string &newname)
	{
		return -1;
	}

public:
	iterator_wd begin_wd() { return m_wdmap.begin(); }
	iterator_wd end_wd() { return m_wdmap.end(); }

	iterator_path begin_path() { return m_pathmap.begin(); }
	iterator_path end_path() { return m_pathmap.end(); }

private:
	PATHMAP m_pathmap;
	WDMAP m_wdmap;
};


//////////////////////////////////////////////////////////////////////////
//

int watch(CInodify &ino, CWatchDB &wdb, const char *pfilepath)
{
	int wd = ino.Watch(pfilepath);
	if (wd < 0)
	{
		printf("Inotify: add watch %s failed(%s)!\n", pfilepath, strerror(errno));
		return -1;
	}

	if (wdb.Insert(wd, pfilepath) < 0)
	{
		printf("WatchDB: insert wd %d dir %s failed\n", wd, pfilepath);
		return -1;
	}
	return wd;
}

int purge(CInodify &ino, CWatchDB &wdb, int wd, inotify_event **ppev = NULL)
{
	const char *pdir = wdb.Query(wd);
	if (!pdir)
	{
		printf("WatchDB: invalid wd: %d\n", wd);
		return -1;
	}

	if (wdb.Erase(wd) < 0)
	{
		printf("WatchDB: erase wd %d dir %s failed\n", wd, pdir);
		return -1;
	}

	int res = ino.Purge(wd);
	if (res == 0)
	{
		return res;
	}

	//for (inotify_event *p = pev; (p = ino.GetEvent(p)) != NULL; )
	if (ppev)
	{
		inotify_event *p = ino.GetEvent(*ppev);
		if (p && p->wd == wd && IN_DELETE_SELF == p->mask)
		{
			res = 0;
			*ppev = p;
			//break;
		}
	}
	if (res < 0)
	{
		printf("Inotify: purge %s wd %d failed!(%s)\n", pdir, wd, strerror(errno));
	}
	return res;
}

bool deal_dir(CInodify &ino, CWatchDB &wdb, const char *pfilepath)
{
	struct stat st; memset(&st, 0, sizeof(st));
	if ((int)-1 == lstat(pfilepath, &st))
	{
		printf("Get stat on %s Error: %s\n", pfilepath, strerror(errno));
		return false;
	}

	if (S_ISLNK(st.st_mode) || S_ISREG(st.st_mode))
	{
		return true;
	}
	if (!S_ISDIR(st.st_mode))
	{
		printf("Get stat %s unknown mode %x!\n", pfilepath, st.st_mode);
		return false;
	}

	int wd = watch(ino, wdb, pfilepath);
	if (wd < 0)
	{
		return false;
	}
	printf("**fmon: wd %d watch %s\n", wd, pfilepath);

	DIR *pdir;
	if (!(pdir = opendir(pfilepath)))
	{
		printf("Open dir %s Error: %s\n", pfilepath, strerror(errno));
		return false;
	}

	struct dirent *pdirent;
	while (!!(pdirent = readdir(pdir)))
	{
		if ('.' == pdirent->d_name[0] && '\0' == pdirent->d_name[1])
		{
			continue;
		}
		else if ('.' == pdirent->d_name[0] && '.' == pdirent->d_name[1] && '\0' == pdirent->d_name[2])
		{
			continue;
		}
		else
		{
			string filepath(pfilepath);
			filepath += '/';
			filepath += pdirent->d_name;
			if (!deal_dir(ino, wdb, filepath.c_str())) 
			{
				continue;
			}
		}
	}
	closedir(pdir);
	return g_bContinue;
}

void signal_handler(int sig)
{
	//printf("signal_handler, sig = %d\n", sig);
	if (SIGINT == sig)
	{
		g_bContinue = false;
	}
}

int main(int argc, char *argv[])
{
	signal(SIGINT, signal_handler);

	vector<char *> targs;
	for (int i = 1; i < argc; i++)
	{
		if ('-' != *argv[i])
		{
			targs.push_back(argv[i]);
			continue;
		}

		// todo:
	}

	if (targs.empty())
	{
		printf("Usage: %s <dir list>\n", argv[0]);
		return 0;
	}

	CStat st;

	CInodify ino;
	if (ino.Initialize() < 0)
	{
		printf("Inotify: initialize failed!\n");
		return 0;
	}

	CWatchDB wdb;

	for (size_t i = 0; i < targs.size(); i++)
	{
		const char *pdir = targs[i];
		deal_dir(ino, wdb, pdir);
	}

	CEpoll ep;
	if (ep.Initialize() < 0)
	{
		printf("Epoll: initialize failed!\n");
		return 0;
	}

	if (ep.Register(&ino) < 0)
	{
		printf("Epoll: register inotify failed!\n");
		return 0;
	}

	string filepath;
	vector<int> tmp_wds; tmp_wds.reserve(128);
	for (; g_bContinue;)
	{
		if ( ep.Wait() < 0)
		{
			//printf("Epoll: wait error!\n");
			break;
		}

		if (0 == ep.EventCount() || ep.HasEvents(&ino) < 0)
		{
			continue;
		}

		for (inotify_event *pev = NULL; (pev = ino.GetEvent(pev)) != NULL; )
		{
			st.events++;

			CInotifyEventHelper ev(pev);
			//printf("debug: event, wd %d, len %d, mask %x, cookie %x, name %x%x..., namelen %d\n",
			//	ev.get_wd(), ev.get_evlen(), ev.get_mask(), ev.get_cookie(), pev->name[0], pev->name[1], pev->len);
			if (ev.is_ignored())
			{
				//printf("ignore %s\n", ev.get_name());
				st.ignores++;
				continue;
			}

			filepath.clear();
			const char *pstr = wdb.Query(ev.get_wd());
			if (pstr) { filepath = pstr; filepath += '/'; }
			filepath += ev.get_name();

			if (ev.is_dir())
			{
				if (ev.is_create())
				{
					st.creats++;
					printf("create dir %s\n", filepath.c_str());
					// move subtree out of watch directory
					deal_dir(ino, wdb, filepath.c_str());
				}
				if (ev.is_modify())
				{
					st.modifies++;
					printf("modify dir %s\n", filepath.c_str());
				}
				if (ev.is_delete())
				{
					st.deletes++;
					printf("delete dir %s\n", filepath.c_str());

					// todo: move subtree out of watch directory
					int wd;
					tmp_wds.clear();
					for (CWatchDB::iterator_path itr = wdb.begin_path(); itr != wdb.end_path(); itr++)
					{
						const string &dir = itr->first;
						if (!strncmp(dir.c_str(), filepath.c_str(), filepath.size()))
						{
							wd = itr->second;
							tmp_wds.push_back(wd);
						}
					}

					if (tmp_wds.empty())
					{
						printf("WatchDB: query %s wd failed\n", filepath.c_str());
						continue;
					}

					for (size_t i = 1; i < tmp_wds.size(); i++)
					{
						wd = tmp_wds[i];
						if (purge(ino, wdb, wd) == 0)
						{
							printf("**fmon: wd %d purge subdir %s\n", wd, filepath.c_str());
						}
					}
					wd = tmp_wds[0];
					if (purge(ino, wdb, wd, &pev) == 0)
					{
						printf("**fmon: wd %d purge %s\n", wd, filepath.c_str());
					}
				}
				if (ev.is_other())
				{
					st.errors++;
					printf("unknown events: %x %s\n", ev.get_mask(), filepath.c_str());
				}
			}
			else
			{
				if (ev.is_create())
				{
					st.creats++;
					printf("create file %s\n", filepath.c_str());
				}
				if (ev.is_modify())
				{
					st.modifies++;
					printf("modify file %s\n", filepath.c_str());
				}
				if (ev.is_delete())
				{
					st.deletes++;
					printf("delete file %s\n", filepath.c_str());
				}
				if (ev.is_other())
				{
					st.errors++;
					printf("unknown events: %x %s\n", ev.get_mask(), filepath.c_str());
				}
			}
		}
	}

	printf("\n");
	for (CWatchDB::iterator_wd itr = wdb.begin_wd(); itr != wdb.end_wd(); itr++)
	{
		int wd = itr->first;
		filepath = itr->second;
		if (purge(ino, wdb, wd) == 0)
		{
			printf("**fmon: wd %d purge %s\n", wd, filepath.c_str());
		}
	}

	if (ep.Unregister(&ino) < 0)
	{
		printf("Epoll: unregister inotify failed!\n");
		return 0;
	}

	printf("\n\n**fmon statistics:\n");
	printf("  events: %d\n", st.events);
	printf("  create: %d\n", st.creats);
	printf("  modify: %d\n", st.modifies);
	printf("  delete: %d\n", st.deletes);
	printf("  ignore: %d\n", st.ignores);
	printf("   error: %d\n", st.errors);
    return 0;
}