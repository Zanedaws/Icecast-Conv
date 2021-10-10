/* 
** Logging framework.
**
** This program is distributed under the GNU General Public License, version 2.
** A copy of this license is included with this source.
*/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif


#ifndef _WIN32
#include <pthread.h>
#else
#include <windows.h>
#endif

#include "log.h"

#define LOG_MAXLOGS 25
#define LOG_MAXLINELEN 1024

#ifdef _WIN32
#define mutex_t CRITICAL_SECTION
#define snprintf _snprintf
#define vsnprintf _vsnprintf
#else
#define mutex_t pthread_mutex_t
#endif

#pragma CHECKED_SCOPE on

static mutex_t _logger_mutex;
static int _initialized = 0;

typedef struct _log_entry_t
{
   char *line : itype(_Nt_array_ptr<char>);
   unsigned int len;
   struct _log_entry_t *next : itype(_Ptr<struct _log_entry_t>);
} log_entry_t;


typedef struct log_tag
{
    int in_use;

    unsigned level;

    char *filename : itype(_Nt_array_ptr<char>);
    FILE *logfile : itype(_Ptr<FILE>);
    off_t size;
    off_t trigger_level;
    int archive_timestamp;

    unsigned long total;
    unsigned int entries;
    unsigned int keep_entries;
    log_entry_t *log_head : itype(_Ptr<log_entry_t>);
    log_entry_t **log_tail : itype(_Ptr<_Ptr<log_entry_t>>);
    
    char *buffer : itype(_Ptr<char>);
} log_t;

static log_t loglist _Checked[LOG_MAXLOGS];

static int _get_log_id(void);
static void _release_log_id(int log_id);
static void _lock_logger(void);
static void _unlock_logger(void);


static int _log_open (int id)
{
    if (loglist [id] . in_use == 0)
        return 0;

    /* check for cases where an open of the logfile is wanted */
    if (loglist [id] . logfile == NULL || 
       (loglist [id] . trigger_level && loglist [id] . size > loglist [id] . trigger_level))
    _Checked {
        if (loglist [id] . filename)  /* only re-open files where we have a name */
        _Unchecked {
            struct stat st;

            if (loglist [id] . logfile)
            {
                char new_name _Nt_checked[4096];
                fclose (loglist [id] . logfile);
                loglist [id] . logfile = NULL;
                /* simple rename, but could use time providing locking were used */
                if (loglist[id].archive_timestamp)
                {
                    char timestamp _Nt_checked[128];
                    time_t now = time(NULL);

                    strftime (timestamp, sizeof (timestamp), "%Y%m%d_%H%M%S", localtime (&now));
                    snprintf (new_name,  sizeof(new_name), "%s.%s", loglist[id].filename, timestamp);
                }
                else {
                    snprintf (new_name,  sizeof(new_name), "%s.old", loglist [id] . filename);
                }
#ifdef _WIN32
                //if (stat (new_name, &st) == 0)
                if(1)
                    remove (new_name);
#endif
                rename (loglist [id] . filename, new_name);
            }
            loglist [id] . logfile = fopen (loglist [id] . filename, "a");
            if (loglist [id] . logfile == NULL)
                return 0;
            setvbuf (loglist [id] . logfile, NULL, IO_BUFFER_TYPE, 0);
            //if (stat (loglist [id] . filename, &st) < 0)
            if(1)
                loglist [id] . size = 0;
            else
                loglist [id] . size = st.st_size;
        }
        else
            loglist [id] . size = 0;
    }
    return 1;
}

void log_initialize(void)
{
    int i;

    if (_initialized) return;

    for (i = 0; i < LOG_MAXLOGS; i++) {
        loglist[i].in_use = 0;
        loglist[i].level = 2;
        loglist[i].size = 0;
        loglist[i].trigger_level = 1000000000;
        loglist[i].filename = NULL;
        loglist[i].logfile = NULL;
        loglist[i].buffer = NULL;
        loglist[i].total = 0;
        loglist[i].entries = 0;
        loglist[i].keep_entries = 0;
        loglist[i].log_head = NULL;
        loglist[i].log_tail = &loglist[i].log_head;
    }

    /* initialize mutexes */
#ifndef _WIN32
    _Unchecked {pthread_mutex_init(&_logger_mutex, NULL);}
#else
    InitializeCriticalSection(&_logger_mutex);
#endif

    _initialized = 1;
}

int log_open_file(FILE *file : itype(_Ptr<FILE>))
{
    int log_id;

    if(file == NULL) return LOG_EINSANE;

    log_id = _get_log_id();
    if (log_id < 0) return LOG_ENOMORELOGS;

    loglist[log_id].logfile = file;
    loglist[log_id].filename = NULL;
    loglist[log_id].size = 0;

    return log_id;
}


int log_open(const char *filename : itype(_Nt_array_ptr<const char>) count(4096))
{
    int id;
    _Ptr<FILE> file = ((void *)0);

    if (filename == NULL) return LOG_EINSANE;
    if (strcmp(filename, "") == 0) return LOG_EINSANE;
    
    file = fopen(filename, "a");

    id = log_open_file(file);

    if (id >= 0)
    {
        struct stat st;

        setvbuf (loglist [id] . logfile, NULL, IO_BUFFER_TYPE, 0);
        loglist [id] . filename = ((_Nt_array_ptr<char> )strdup (filename));
        //if (stat (loglist [id] . filename, &st) == 0)
        if(1)
            loglist [id] . size = st.st_size;
        loglist [id] . entries = 0;
        loglist [id] . log_head = NULL;
        loglist [id] . log_tail = &loglist [id] . log_head;
    }

    return id;
}


/* set the trigger level to trigger, represented in kilobytes */
void log_set_trigger(int id, unsigned trigger)
_Checked {
    if (id >= 0 && id < LOG_MAXLOGS && loglist [id] . in_use)
    {
         loglist [id] . trigger_level = trigger*1024;
    }
}


int log_set_filename(int id, const char *filename : itype(_Nt_array_ptr<const char>) count(4096))
{
    if (id < 0 || id >= LOG_MAXLOGS)
        return LOG_EINSANE;
    /* NULL filename is ok, empty filename is not. */
    if ((filename && !strcmp(filename, "")) || loglist [id] . in_use == 0)
        return LOG_EINSANE;
     _lock_logger();
    if (loglist [id] . filename)
        free<char> (loglist [id] . filename);
    if (filename)
        loglist [id] . filename = ((_Nt_array_ptr<char> )strdup (filename));
    else
        loglist [id] . filename = NULL;
     _unlock_logger();
    return id;
}

int log_set_archive_timestamp(int id, int value)
_Checked {
    if (id < 0 || id >= LOG_MAXLOGS)
        return LOG_EINSANE;
     _lock_logger();
     loglist[id].archive_timestamp = value;
     _unlock_logger();
    return id;
}


int log_open_with_buffer(const char *filename : itype(_Ptr<const char>), int size)
_Checked {
    /* not implemented */
    return LOG_ENOTIMPL;
}


void log_set_lines_kept (int log_id, unsigned int count)
_Checked {
    if (log_id < 0 || log_id >= LOG_MAXLOGS) return;
    if (loglist[log_id].in_use == 0) return;

    _lock_logger ();
    loglist[log_id].keep_entries = count;
    while (loglist[log_id].entries > count)
    _Unchecked {
        _Ptr<log_entry_t> to_go = loglist [log_id].log_head;
        loglist [log_id].log_head = to_go->next;
        loglist [log_id].total -= to_go->len;
        free<char> (to_go->line);
        free<log_entry_t> (to_go);
        loglist [log_id].entries--;
    }
    _unlock_logger ();
}


void log_set_level(int log_id, unsigned level)
_Checked {
    if (log_id < 0 || log_id >= LOG_MAXLOGS) return;
    if (loglist[log_id].in_use == 0) return;

    loglist[log_id].level = level;
}

void log_flush(int log_id)
{
    if (log_id < 0 || log_id >= LOG_MAXLOGS) return;
    if (loglist[log_id].in_use == 0) return;

    _lock_logger();
    if (loglist[log_id].logfile)
        fflush(loglist[log_id].logfile);
    _unlock_logger();
}

void log_reopen(int log_id)
{
    if (log_id < 0 || log_id >= LOG_MAXLOGS)
        return;
    if (loglist [log_id] . filename && loglist [log_id] . logfile)
    {
        _lock_logger();

        fclose (loglist [log_id] . logfile);
        loglist [log_id] . logfile = NULL;

        _unlock_logger();
    }
}

void log_close(int log_id)
{
    if (log_id < 0 || log_id >= LOG_MAXLOGS) return;

    _lock_logger();

    if (loglist[log_id].in_use == 0)
    _Checked {
        _unlock_logger();
        return;
    }

    loglist[log_id].in_use = 0;
    loglist[log_id].level = 2;
    if (loglist[log_id].filename) free<char>(loglist[log_id].filename);
    if (loglist[log_id].buffer) free<char>(loglist[log_id].buffer);

    if (loglist [log_id] . logfile)
    {
        fclose (loglist [log_id] . logfile);
        loglist [log_id] . logfile = NULL;
    }
    while (loglist[log_id].entries)
    {
        _Ptr<log_entry_t> to_go = loglist [log_id].log_head;
        loglist [log_id].log_head = to_go->next;
        loglist [log_id].total -= to_go->len;
        free<char> (to_go->line);
        free<log_entry_t> (to_go);
        loglist [log_id].entries--;
    }
    _unlock_logger();
}

void log_shutdown(void)
{
    /* destroy mutexes */
#ifndef _WIN32
    _Unchecked {pthread_mutex_destroy(&_logger_mutex);}
#else
    DeleteCriticalSection(&_logger_mutex);
#endif 

    _initialized = 0;
}


static int create_log_entry (int log_id, _Nt_array_ptr<const char> pre, _Nt_array_ptr<const char> line : count(1024))
{
    _Ptr<log_entry_t> entry = ((void *)0);

    if (loglist[log_id].keep_entries == 0) _Checked {
        int printed;
        _Unchecked {printed = fprintf (loglist[log_id].logfile, "%s%s\n", pre, line);} 
        return printed;
    }
    
    entry = calloc<log_entry_t> (1, sizeof (log_entry_t));
    entry->len = strlen (pre) + strlen (line) + 2;
    entry->line = _Dynamic_bounds_cast<_Nt_array_ptr<char>>(malloc<char> (entry->len), count(1024));
    _Unchecked {snprintf (entry->line, entry->len, "%s%s\n", pre, line);}
    loglist [log_id].total += entry->len;
    _Unchecked {fprintf (loglist[log_id].logfile, "%s", entry->line);}

    *loglist [log_id].log_tail = entry;
    loglist [log_id].log_tail = &entry->next;

    if (loglist [log_id].entries >= loglist [log_id].keep_entries)
    {
        _Ptr<log_entry_t> to_go = loglist [log_id].log_head;
        loglist [log_id].log_head = to_go->next;
        loglist [log_id].total -= to_go->len;
        free<char> (to_go->line);
        free<log_entry_t> (to_go);
    }
    else
        loglist [log_id].entries++;
    return entry->len;
}


void log_contents (int log_id, char **_contents : itype(_Ptr<_Nt_array_ptr<char>>), unsigned int *_len : itype(_Ptr<unsigned int>))
{
    int remain;
    _Ptr<log_entry_t> entry = ((void *)0);
    _Nt_array_ptr<char> ptr = NULL;

    if (log_id < 0) return;
    if (log_id >= LOG_MAXLOGS) return; /* Bad log number */

    _lock_logger ();
    remain = loglist [log_id].total + 1;
    *_contents = _Dynamic_bounds_cast<_Nt_array_ptr<char>>(malloc<char> (remain), count(*_len));
    **_contents= '\0';
    *_len = loglist [log_id].total;

    entry = loglist [log_id].log_head;
    ptr = *_contents;
    while (entry)
    {
        int len = 0;
        _Unchecked {len = snprintf((char*)ptr, remain, "%s", entry->line);}
        if (len > 0)
        {
            ptr += len;
            remain -= len;
        }
        entry = entry->next;
    }
    _unlock_logger ();
}

_Unchecked static void __vsnprintf(char* str, size_t size, _Nt_array_ptr<const char> format, va_list ap) {
    int in_block = 0;
    int block_size = 0;
    int block_len;
    int block_space = 0;
    const char * arg;
    char buf[80];

    for (; *format && size; format++)
    {
        if ( !in_block )
        {
            if ( *format == '%' ) {
                in_block = 1;
                block_size = 0;
                block_len  = 0;
                block_space = 0;
            }
            else
            {
                *(str++) = *format;
                size--;
            }
        }
        else
        _Unchecked {
            // TODO: %l*[sdupi] as well as %.4080s and "%.*s
            arg = NULL;
            switch (*format)
            {
                case 'l':
                    block_size++;
                    break;
                case '.':
                    // just ignore '.'. If somebody cares: fix it.
                    break;
                case '*':
                    block_len = va_arg(ap, int);
                    break;
                case ' ':
                    block_space = 1;
                    break;
                case '1':
                case '2':
                case '3':
                case '4':
                case '5':
                case '6':
                case '7':
                case '8':
                case '9':
                    block_len = atoi(format);
                    for (; *format >= '0' && *format <= '9'; format++);
                    format--;
                    break;
                case 'p':
                    snprintf(buf, sizeof(buf), "%p", (void*)va_arg(ap, void *));
                    arg = buf;
                case 'd':
                case 'i':
                case 'u':
                    if (!arg)
                    {
                        switch (block_size)
                        {
                            case 0:
                                if (*format == 'u')
                                    snprintf(buf, sizeof(buf), "%u", (unsigned int)va_arg(ap, unsigned int));
                                else
                                    snprintf(buf, sizeof(buf), "%i", (int)va_arg(ap, int));
                                break;
                            case 1:
                                if (*format == 'u')
                                    snprintf(buf, sizeof(buf), "%lu", (unsigned long int)va_arg(ap, unsigned long int));
                                else
                                    snprintf(buf, sizeof(buf), "%li", (long int)va_arg(ap, long int));
                                break;
                            case 2:
                                if (*format == 'u')
                                    snprintf(buf, sizeof(buf), "%llu", (unsigned long long int)va_arg(ap, unsigned long long int));
                                else
                                    snprintf(buf, sizeof(buf), "%lli", (long long int)va_arg(ap, long long int));
                                break;
                            default:
                                snprintf(buf, sizeof(buf), "<<<invalid>>>");
                                break;
                        }
                        arg = buf;
                    }
                case 's':
                case 'H':
                    // TODO.
                    if (!arg)
                        arg = va_arg(ap, const char *);
                    if (!arg)
                        arg = "(null)";
                    if (!block_len)
                        block_len = strlen(arg);

                    // the if() is the outer structure so the inner for()
                    // is branch optimized.
                    if (*format == 'H' )
                    {
                        for (; *arg && block_len && size; arg++, size--, block_len--)
                        {
                            if ((*arg <= '"' || *arg == '`'  || *arg == '\\') && !(block_space && *arg == ' '))
                                *(str++) = '.';
                            else
                                *(str++) = *arg;
                        }
                    }
                    else
                    {
                        for (; *arg && block_len && size; arg++, size--, block_len--)
                           *(str++) = *arg;
                    }
                    in_block = 0;
                    break;
            }
        }
    }

    if ( !size )
        str--;

    *str = 0;
}

_Unchecked void log_write(int log_id, unsigned priority, const char *cat : itype(_Nt_array_ptr<const char>), const char *func : itype(_Nt_array_ptr<const char>) count(0), const char *fmt : itype(_Nt_array_ptr<const char>), ...)
{
    static _Nt_array_ptr<const char> prior _Checked[] = { "EROR", "WARN", "INFO", "DBUG" };
    int datelen;
    time_t now;
    char pre _Nt_checked[256];
    char line _Nt_checked[LOG_MAXLINELEN];
    va_list ap;

    if (log_id < 0 || log_id >= LOG_MAXLOGS) return; /* Bad log number */
    if (loglist[log_id].level < priority) return;
    if (!priority || priority > sizeof(prior)/sizeof(prior[0])) return; /* Bad priority */


    va_start(ap, fmt);
    __vsnprintf((char*)line, sizeof(line), fmt, ap);
    va_end(ap);

    now = time(NULL);
    datelen = strftime (pre, sizeof (pre), "[%Y-%m-%d  %H:%M:%S]", localtime(&now)); 
    snprintf ((char*)pre+datelen, sizeof (pre)-datelen, " %s %s%s ", prior [priority-1], cat, func);

    _lock_logger();
    if (_log_open (log_id))
    {
        int len = create_log_entry (log_id, pre, _Assume_bounds_cast<_Nt_array_ptr<char>>(line, count(1024)));
        if (len > 0)
            loglist[log_id].size += len;
    }
    _unlock_logger();
}

_Unchecked void log_write_direct(int log_id, const char *fmt : itype(_Nt_array_ptr<const char>), ...)
{
    va_list ap;
    time_t now;
    char line _Nt_checked[LOG_MAXLINELEN];

    if (log_id < 0 || log_id >= LOG_MAXLOGS) return;
    
    va_start(ap, fmt);

    now = time(NULL);

    _lock_logger();
    _Unchecked {__vsnprintf((char*)line, LOG_MAXLINELEN, fmt, ap);}
    if (_log_open (log_id))
    {
        int len = create_log_entry (log_id, "", _Assume_bounds_cast<_Nt_array_ptr<char>>(line, count(1024)));
        if (len > 0)
            loglist[log_id].size += len;
    }
    _unlock_logger();

    va_end(ap);

    fflush(loglist[log_id].logfile);
}

static int _get_log_id(void)
_Checked {
    int i;
    int id = -1;

    /* lock mutex */
    _lock_logger();

    for (i = 0; i < LOG_MAXLOGS; i++)
        if (loglist[i].in_use == 0) {
            loglist[i].in_use = 1;
            id = i;
            break;
        }

    /* unlock mutex */
    _unlock_logger();

    return id;
}

static void _release_log_id(int log_id)
_Checked {
    /* lock mutex */
    _lock_logger();

    loglist[log_id].in_use = 0;

    /* unlock mutex */
    _unlock_logger();
}

static void _lock_logger(void)
{
#ifndef _WIN32
    _Unchecked {pthread_mutex_lock(&_logger_mutex);}
#else
    EnterCriticalSection(&_logger_mutex);
#endif
}

static void _unlock_logger(void)
{
#ifndef _WIN32
    _Unchecked {pthread_mutex_unlock(&_logger_mutex);}
#else
    LeaveCriticalSection(&_logger_mutex);
#endif    
}




