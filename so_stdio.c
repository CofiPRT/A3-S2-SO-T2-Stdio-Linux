#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include "so_stdio.h"

#define BUFSIZE (4096)
#define DEFAULT_PERMS	(0644)

#define TRUE	(1)
#define FALSE	(0)

// operation types
#define OP_TYPE_NONE	(0)
#define OP_TYPE_READ	(1)
#define OP_TYPE_WRITE	(2)

// define the struct
struct _so_file {
	int fd;
	int pid;
	off_t expected_cursor;

	// buffer related
	char *buffer;
	size_t buffer_cursor;
	size_t buffer_len;

	// operations
	int last_op;
	int err;
	int eof;

	// flags
	int can_read;
	int can_write;
	int update;
	int append;
};

// quick maintenance
typedef struct {
	char *mode;
	int flags;
} string_int_mapping;

/**
 * Create a new stream based on the given, precalculated parameters.
 * Returns the newly created stream on success, or 'NULL' otherwise.
 */
SO_FILE *init_stream(int fd, int pid, int flags)
{
	// init the struct
	SO_FILE *new_file = malloc(sizeof(SO_FILE));

	if (!new_file)
		return NULL;

	new_file->buffer = calloc(BUFSIZE, sizeof(char));

	if (!new_file->buffer) {
		free(new_file);
		return NULL;
	}

	// set details
	new_file->fd = fd;
	new_file->pid = pid;
	new_file->buffer_cursor = 0;
	new_file->buffer_len = 0;
	new_file->expected_cursor = 0;
	new_file->last_op = OP_TYPE_NONE;
	new_file->err = FALSE;
	new_file->eof = FALSE;

	// set flags
	int access = flags & O_ACCMODE;

	new_file->can_read = access == O_RDONLY || access == O_RDWR;
	new_file->can_write = access == O_WRONLY || access == O_RDWR;
	new_file->update = access & O_RDWR;
	new_file->append = flags & O_APPEND;

	return new_file;
}

/**
 * Resets a stream's buffer, nullifying its contents and its size.
 */
void reset_buffer(SO_FILE *stream)
{
	if (!stream)
		return;

	memset(stream->buffer, 0, BUFSIZE);
	stream->buffer_cursor = 0;
	stream->buffer_len = 0;
}

/**
 * Opens a new stream with the given parameters.
 * Returns the created stream on success, or 'NULL' otherwise.
 */
SO_FILE *so_fopen(const char *pathname, const char *mode)
{
	static const string_int_mapping flag_map[] = {
		{"r",	O_RDONLY},
		{"r+",	O_RDWR},
		{"w",	O_WRONLY | O_CREAT | O_TRUNC},
		{"w+",	O_RDWR | O_CREAT | O_TRUNC},
		{"a",	O_WRONLY | O_CREAT | O_APPEND},
		{"a+",	O_RDWR | O_CREAT | O_APPEND}
	};

	static const int modes_no = sizeof(flag_map) / sizeof(string_int_mapping);

	if (!pathname || !mode)
		return NULL;

	// compute the flags, based on the mode
	int flags = -1;

	for (int i = 0; i < modes_no; i++)
		if (!strcmp(flag_map[i].mode, mode))
			flags = flag_map[i].flags;

	if (flags == -1)
		return NULL;

	// open a new file descriptor
	int fd = open(pathname, flags, DEFAULT_PERMS);

	if (fd == -1)
		return NULL;

	return init_stream(fd, -1, flags);
}

/**
 * Closes the given stream and frees the used memory.
 * Returns '0' on success, or 'SO_EOF' otherwise.
 */
int so_fclose(SO_FILE *stream)
{
	if (!stream)
		return SO_EOF;

	int error = FALSE;

	// flush the stream if necessary
	if (stream->last_op == OP_TYPE_WRITE && so_fflush(stream))
		error = TRUE;

	if (close(stream->fd))
		error = TRUE;

	free(stream->buffer);
	free(stream);

	return error ? SO_EOF : 0;
}

/**
 * Returns the file descriptor of this stream, or '-1' in case of an error.
 */
int so_fileno(SO_FILE *stream)
{
	return stream ? stream->fd : -1;
}

/**
 * Flush this stream's buffer, writing its content to its file descriptor.
 * Returns '0' on success, or 'SO_EOF' otherwise.
 */
int so_fflush(SO_FILE *stream)
{
	if (!stream)
		return SO_EOF;

	// check permissions
	if (!stream->can_write) {
		stream->err = TRUE;
		return SO_EOF;
	}

	if (!stream->buffer_len)
		return 0; // nothing to do, buffer already flushed

	stream->buffer_cursor = 0;

	// write the buffer contents to the file
	while (stream->buffer_cursor < stream->buffer_len) {
		ssize_t bytes_written = write(stream->fd,
			stream->buffer + stream->buffer_cursor,
			stream->buffer_len - stream->buffer_cursor);

		// an error has occurred
		if (bytes_written == -1) {
			stream->err = TRUE;
			return SO_EOF;
		}

		stream->buffer_cursor += bytes_written;
	}

	reset_buffer(stream);

	// success
	return 0;
}

/**
 * Reposition the stream's offset.
 * Returns the new offset on success, or '-1' otherwise.
 */
int so_fseek(SO_FILE *stream, long offset, int whence)
{
	if (!stream)
		return -1;

	// preliminary checks
	if (stream->last_op == OP_TYPE_WRITE) {
		// flush the buffer from previous write operations
		if (so_fflush(stream)) {
			stream->err = TRUE;
			return -1;
		}
	} else if (stream->last_op == OP_TYPE_READ) {
		// reset the file descriptor cursor to the expected position
		if (whence == SEEK_CUR &&
			lseek(stream->fd, stream->expected_cursor, SEEK_SET) == -1) {

			stream->err = TRUE;
			return -1;
		}

		reset_buffer(stream);
	}

	// perform the operation
	off_t new_offset = lseek(stream->fd, offset, whence);

	if (new_offset == -1) {
		stream->err = TRUE;
		return -1;
	}

	// success
	stream->last_op = OP_TYPE_NONE;
	stream->expected_cursor = new_offset;

	return 0;
}

/**
 * Return the stream's file offset.
 */
long so_ftell(SO_FILE *stream)
{
	return stream->expected_cursor;
}

/**
 * Read from a stream into a given address.
 * Returns the number of elements read, or '0' in case of an error.
 */
size_t so_fread(void *ptr, size_t size, size_t nmemb, SO_FILE *stream)
{
	if (!stream)
		return 0;

	// preliminary checks
	if (!ptr || !size || !nmemb) {
		stream->err = TRUE;
		return 0;
	}

	// nothing to do, already at the end-of-file
	if (so_feof(stream))
		return 0;

	// perform the operation
	size_t bytesToRead = nmemb * size;
	size_t bytesRead = 0;

	while (bytesRead < bytesToRead) {
		int character = so_fgetc(stream);

		// make sure it is not a false positive (the char just happens to be -1)
		if (character == SO_EOF && stream->err)
			return 0;

		if (so_feof(stream)) // EOF reached, return the number of read elements
			return bytesRead / size;

		// write to the address, and advance the pointer
		*((char *) ptr + bytesRead++) = character;
	}

	return bytesRead / size;
}

/**
 * Writes from a given address into the stream.
 * Returns the number of elements written, or '0' in case of an error.
 */
size_t so_fwrite(const void *ptr, size_t size, size_t nmemb, SO_FILE *stream)
{
	if (!stream)
		return 0;

	// preliminary checks
	if (!ptr || !size || !nmemb) {
		stream->err = TRUE;
		return 0;
	}

	// perform the operation
	ssize_t bytesToWrite = nmemb * size;
	ssize_t bytesWritten = 0;

	while (bytesWritten < bytesToWrite) {
		int character = *((char *) ptr + bytesWritten++);

		// make sure it is not a false positive (the char just happens to be -1)
		if (so_fputc(character, stream) == SO_EOF && stream->err)
			return 0;
	}

	return bytesWritten / size;
}

/**
 * Get a character from the stream.
 * Returns the read character on success, or 'SO_EOF' otherwise.
 */
int so_fgetc(SO_FILE *stream)
{
	if (!stream)
		return SO_EOF;

	// preliminary checks
	if (!stream->can_read) {
		stream->err = TRUE;
		return SO_EOF;
	}

	// flush the buffer between a write and a read operation
	if (stream->update &&
		stream->last_op == OP_TYPE_WRITE &&
		so_fflush(stream)) {

		stream->err = TRUE;
		return SO_EOF;
	}

	// populate the buffer if necessary
	if (stream->buffer_cursor == stream->buffer_len) {
		if (stream->buffer_len)
			reset_buffer(stream);

		// this operation moves the fd cursor
		ssize_t bytes_read = read(stream->fd, stream->buffer, BUFSIZE);

		// an error has occurred
		if (bytes_read == -1) {
			stream->err = TRUE;
			return SO_EOF;
		}

		// end of file already reached, nothing more to read
		if (bytes_read == 0) {
			stream->eof = TRUE;
			return SO_EOF;
		}

		stream->buffer_len = bytes_read;
	}

	// perform the operation
	stream->last_op = OP_TYPE_READ;
	stream->expected_cursor++;
	stream->eof = FALSE;

	return stream->buffer[stream->buffer_cursor++];
}

/**
 * Write a character to the stream.
 * Returns the written character on success, or 'SO_EOF' otherwise.
 */
int so_fputc(int c, SO_FILE *stream)
{
	if (!stream)
		return SO_EOF;

	// preliminary checks
	if (!stream->can_write) {
		stream->err = TRUE;
		return SO_EOF;
	}

	// disregard the buffer between a read and a write operation
	if (stream->update && stream->last_op == OP_TYPE_READ) {
		// reset the file descriptor cursor to the expected position
		if (stream->append) {
			int result = lseek(stream->fd, 0, SEEK_END);

			if (result == -1) {
				stream->err = TRUE;
				return SO_EOF;
			}

			stream->expected_cursor = result;

		} else if (lseek(stream->fd, stream->expected_cursor, SEEK_SET) == -1) {
			stream->err = TRUE;
			return SO_EOF;
		}

		reset_buffer(stream);
	}

	// flush a full buffer
	if (stream->buffer_cursor == BUFSIZE && so_fflush(stream)) {
		stream->err = TRUE;
		return SO_EOF;
	}

	// perform the operation
	stream->last_op = OP_TYPE_WRITE;
	stream->expected_cursor++;
	stream->buffer_len++;
	stream->buffer[stream->buffer_cursor++] = c;

	return c;
}

/**
 * Check the end-of-file indicator of a stream.
 * Returns '1' if the end-of-file has been reached, or '0' otherwise.
 */
int so_feof(SO_FILE *stream)
{
	return stream->eof;
}

/**
 * Checks if the error code associated with the stream is set.
 * Returns '0' if no error has occurred, or any other number otherwise.
 */
int so_ferror(SO_FILE *stream)
{
	return stream->err;
}

/**
 * Pipe stream to or from a process.
 * Returns the created stream on succes, or 'NULL' otherwise.
 */
SO_FILE *so_popen(const char *command, const char *type)
{
	if (!command || !type || strlen(type) != 1)
		return NULL;

	char mode = type[0];

	// init the pipe
	int pipedes[2];

	pipe(pipedes);

	// better naming for the code below
	int first_pipedes = pipedes[0];
	int second_pipedes = pipedes[1];

	// fork the process
	int pid = fork();

	if (pid == -1)
		return NULL;

	// this is the parent process, its job is to return the struct
	if (pid) {
		// choose the pipedes the parent will work with
		int file_pipedes = -1;
		int pipedes_to_close = -1;
		int flags = -1;

		if (mode == 'r') {
			file_pipedes = first_pipedes;
			pipedes_to_close = second_pipedes;
			flags = O_RDONLY;
		} else if (mode == 'w') {
			file_pipedes = second_pipedes;
			pipedes_to_close = first_pipedes;
			flags = O_WRONLY;
		}

		// mode not found, or unable to close the pipedes
		if (pipedes_to_close == -1 || close(pipedes_to_close))
			return NULL;

		return init_stream(file_pipedes, pid, flags);
	}

	// this is the child process, its job is execute the command
	int pipedes_to_dup = -1;
	int pipedes_to_close = -1;
	int pipedes_new = -1;

	// choose the mode
	if (mode == 'r') {
		pipedes_to_dup = second_pipedes;
		pipedes_to_close = first_pipedes;
		pipedes_new = STDOUT_FILENO;
	} else if (mode == 'w') {
		pipedes_to_dup = first_pipedes;
		pipedes_to_close = second_pipedes;
		pipedes_new = STDIN_FILENO;
	}

	if (pipedes_to_dup == -1 || // invalid mode
		dup2(pipedes_to_dup, pipedes_new) == -1 ||
		close(pipedes_to_close) == -1)

		return NULL;

	// execute the command
	execlp("/bin/sh", "sh", "-c", command, NULL);

	// the 'execlp' only returns if an error has ocurred, anyway
	return NULL;
}

/**
 * Closes the given stream and frees the used memory.
 * Also waits for the associated process to finish execution.
 * Returns the aforementioned process's status on success, or '-1' otherwise.
 */
int so_pclose(SO_FILE *stream)
{
	if (!stream)
		return -1;

	int pid_to_wait = stream->pid;

	// free resources before waiting for the other process
	so_fclose(stream);

	// save the return status of the process
	int process_status;

	if (waitpid(pid_to_wait, &process_status, 0) == -1)
		return -1;

	return process_status;
}
