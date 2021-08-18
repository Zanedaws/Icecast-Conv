/* 
** Logging framework.
**
** This program is distributed under the GNU General Public License, version 2.
** A copy of this license is included with this source.
*/

#ifndef __LOG_H__
#define __LOG_H__

#include <stdio.h>

#define LOG_EINSANE -1
#define LOG_ENOMORELOGS -2
#define LOG_ECANTOPEN -3
#define LOG_ENOTOPEN -4
#define LOG_ENOTIMPL -5

#ifdef _WIN32
#define IO_BUFFER_TYPE _IONBF
#else
#define IO_BUFFER_TYPE _IOLBF
#endif

void log_initialize(void);
int log_open_file(FILE *file : itype(_Ptr<FILE>));
int log_open(const char *filename : itype(_Nt_array_ptr<const char>) count(4096));
int log_open_with_buffer(const char *filename : itype(_Ptr<const char>), int size);
void log_set_level(int log_id, unsigned level);
void log_set_trigger(int id, unsigned trigger);
int  log_set_filename(int id, const char *filename : itype(_Nt_array_ptr<const char>) count(4096));
void log_set_lines_kept (int log_id, unsigned int count);
void log_contents (int log_id, char **_contents : itype(_Ptr<_Nt_array_ptr<char>>), unsigned int *_len : itype(_Ptr<unsigned int>));
int log_set_archive_timestamp(int id, int value);
void log_flush(int log_id);
void log_reopen(int log_id);
void log_close(int log_id);
void log_shutdown(void);

void log_write(int log_id, unsigned priority, const char *cat : itype(_Nt_array_ptr<const char>), const char *func : itype(_Nt_array_ptr<const char>) count(0), const char *fmt : itype(_Nt_array_ptr<const char>), ...);
void log_write_direct(int log_id, const char *fmt : itype(_Nt_array_ptr<const char>), ...);

#endif  /* __LOG_H__ */
