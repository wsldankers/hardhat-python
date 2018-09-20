#include <inttypes.h>
#include <stdbool.h>
#include <stdarg.h>
#include <fcntl.h>
#include <hardhat/reader.h>
#include <hardhat/maker.h>

#include "Python.h"
#include "pythread.h"

typedef struct {
	PyObject_HEAD
	uint64_t magic;
	hardhat_t *hh;
} Hardhat;

typedef struct {
	PyObject_HEAD
	uint64_t magic;
	Hardhat *hardhat;
	hardhat_cursor_t *hhc;
	// whether this is a recursive listing:
	bool recursive:1;
	// whether this listing returns keys:
	bool keys:1;
	// whether this listing returns values:
	bool values:1;
	// whether to include the parent node in this listing:
	bool initial:1;
	// whether this listing is finished:
	bool finished:1;
} HardhatCursor;

typedef struct {
	PyObject_HEAD
	uint64_t magic;
	// this lock protects everything below:
	PyThread_type_lock lock;
	// we set hhm to NULL to signal that it is closed
	hardhat_maker_t *hhm;
} HardhatMaker;

static struct PyModuleDef hardhat_module;
static PyTypeObject Hardhat_type;
static PyTypeObject HardhatCursor_type;
static PyTypeObject HardhatMaker_type;

#define HARDHAT_MAGIC (UINT64_C(0x36CCB37946C40BBF))
#define HARDHAT_CURSOR_MAGIC (UINT64_C(0xE0B0487F7D045047))
#define HARDHAT_MAKER_MAGIC (UINT64_C(0x5236CC4EFF9CAE19))

#define HARDHAT_INTERNAL_ERROR hardhat_module_exception("InternalError", NULL)
#define HARDHAT_FILE_FORMAT_ERROR hardhat_module_exception("FileFormatError", NULL)
#define HARDHAT_MAKER_ERROR hardhat_module_exception("MakerError", NULL)
#define HARDHAT_MAKER_FATAL_ERROR hardhat_module_exception("MakerFatalError", "MakerError")
#define HARDHAT_MAKER_VALUE_ERROR hardhat_module_exception("MakerValueError", "MakerError")

#ifdef WITH_THREAD
#define DECLARE_THREAD_SAVE PyThreadState *_save;
#else
#define DECLARE_THREAD_SAVE
#endif

static inline bool Hardhat_check(void *v) {
	return v && PyObject_TypeCheck(v, &Hardhat_type) && ((Hardhat *)v)->magic == HARDHAT_MAGIC;
}

static inline bool HardhatCursor_check(void *v) {
	return v && PyObject_TypeCheck(v, &HardhatCursor_type) && ((HardhatCursor *)v)->magic == HARDHAT_CURSOR_MAGIC;
}

static inline bool HardhatMaker_check(void *v) {
	return v && PyObject_TypeCheck(v, &HardhatMaker_type) && ((HardhatMaker *)v)->magic == HARDHAT_MAKER_MAGIC;
}

// hardhat module utility functions

__attribute__((unused))
static PyObject *hardhat_module_symbol(const char *name) {
	PyObject *module, *moduledict, *symbol = NULL, *type, *value, *traceback;
	PyErr_Fetch(&type, &value, &traceback);
	// modules = PyImport_GetModuleDict();
	module = PyState_FindModule(&hardhat_module);
	if(module) {
		moduledict = PyModule_GetDict(module);
		if(moduledict)
			symbol = PyDict_GetItemString(moduledict, name);
	}
	PyErr_Restore(type, value, traceback);
	return symbol;
}

static PyObject *hardhat_module_create_exception(PyObject *module, const char *name, PyObject *base) {
	PyObject *exception;
	char fullname[100];
	int printed = snprintf(fullname, sizeof fullname, "%s.%s", hardhat_module.m_name, name);
	if(printed > 0 && printed < sizeof fullname) {
		exception = PyErr_NewException(fullname, base, NULL);
		PyModule_AddObject(module, name, exception);
		return exception;
	}
	return NULL;
}

// to avoid using global variables
static PyObject *hardhat_module_exception(const char *name, const char *base) {
	PyObject *module, *exception = NULL, *base_exception = NULL, *type, *value, *traceback;
	PyErr_Fetch(&type, &value, &traceback);
	module = PyState_FindModule(&hardhat_module);
	if(module) {
		exception = PyObject_GetAttrString(module, name);
		if(!exception) {
			if(base) {
				base_exception = PyObject_GetAttrString(module, base);
				if(!base_exception)
					base_exception = hardhat_module_create_exception(module, base, NULL);
				if(base_exception)
					exception = hardhat_module_create_exception(module, name, base_exception);
			} else {
				exception = hardhat_module_create_exception(module, name, NULL);
			}
		}
	}
	PyErr_Restore(type, value, traceback);
	if(exception)
		return exception;
	return PyExc_Exception;
}

static PyObject *hardhat_module_filename(PyObject *filename_object) {
	PyObject *decoded_filename;
	if(PyUnicode_Check(filename_object)) {
		if(PyUnicode_FSConverter(filename_object, &decoded_filename))
			return decoded_filename;
		else
			return NULL;
	} else if(PyBytes_Check(filename_object)) {
		Py_IncRef(filename_object);
		return filename_object;
	} else {
		return PyBytes_FromObject(filename_object);
	}
}

static bool hardhat_module_object_to_buffer(PyObject *obj, Py_buffer *buffer) {
	char *str;
	Py_ssize_t len;

	if(PyUnicode_Check(obj)) {
		str = PyUnicode_AsUTF8AndSize(obj, &len);
		if(!str)
			return false;
		PyBuffer_FillInfo(buffer, obj, str, len, 1, 0);
	} else {
		if(PyObject_GetBuffer(obj, buffer, PyBUF_SIMPLE) == -1)
			return false;

		if(!PyBuffer_IsContiguous(buffer, 'C')) {
			PyBuffer_Release(buffer);
			PyErr_SetString(PyExc_BufferError, "buffer not contiguous");
			return false;
		}
	}
	return true;
}

__attribute__((unused))
static bool hardhat_module_lock(PyThread_type_lock lock) {
	PyLockStatus r;
	Py_BEGIN_ALLOW_THREADS
	r = PyThread_acquire_lock(lock, WAIT_LOCK);
	Py_END_ALLOW_THREADS
	if(r == PY_LOCK_ACQUIRED)
		return true;
	else
		return PyErr_SetString(PyExc_RuntimeError, "unable to acquire lock"), false;
}

#define hardhat_module_unlock(x) PyThread_release_lock((x))

// Hardhat class utility functions for methods

static PyObject *Hardhat_cursor(Hardhat *self, void *buf, size_t len, bool recursive, bool keys, bool values, bool initial) {
	hardhat_cursor_t *c;
	HardhatCursor *cursor;

	if(!Hardhat_check(self))
		return PyErr_SetString(PyExc_TypeError, "not a valid Hardhat object"), NULL;

	Py_BEGIN_ALLOW_THREADS
	c = hardhat_cursor(self->hh, buf, len);
	Py_END_ALLOW_THREADS

	if(c) {
		cursor = PyObject_New(HardhatCursor, &HardhatCursor_type);
		if(cursor) {
			Py_IncRef(&self->ob_base);
			cursor->hardhat = self;
			cursor->hhc = c;
			cursor->recursive = recursive;
			cursor->keys = keys;
			cursor->values = values;
			cursor->initial = initial;
			cursor->finished = false;
			cursor->magic = HARDHAT_CURSOR_MAGIC;
			return &cursor->ob_base;
		}
		hardhat_cursor_free(c);
	} else {
		PyErr_SetFromErrno(PyExc_OSError);
	}

	return NULL;
}

static PyObject *Hardhat_cursor_from_object(Hardhat *self, PyObject *keyobject, bool recursive, bool keys, bool values, bool initial) {
	Py_buffer key_buffer;
	PyObject *cursor = NULL;

	if(!hardhat_module_object_to_buffer(keyobject, &key_buffer))
		return NULL;

	if(key_buffer.len > UINT16_MAX)
		PyErr_SetString(PyExc_KeyError, "supplied key too long");
	else
		cursor = Hardhat_cursor(self, key_buffer.buf, key_buffer.len, recursive, keys, values, initial);

	PyBuffer_Release(&key_buffer);

	return cursor;
}

// Hardhat methods

static PyObject *Hardhat_ls(Hardhat *self, PyObject *args, PyObject *kwargs) {
	PyObject *keyobject;
	int parent = 0;
	static char *keywords[] = {"", "parent", NULL};
	if(!PyArg_ParseTupleAndKeywords(args, kwargs, "O|$p", keywords, &keyobject, &parent))
		return NULL;
	return (PyObject *)Hardhat_cursor_from_object(self, keyobject, false, true, true, parent);
}

static PyObject *Hardhat_find(Hardhat *self, PyObject *args, PyObject *kwargs) {
	PyObject *keyobject;
	int parent = 1;
	static char *keywords[] = {"", "parent", NULL};
	if(!PyArg_ParseTupleAndKeywords(args, kwargs, "O|$p", keywords, &keyobject, &parent))
		return NULL;
	return (PyObject *)Hardhat_cursor_from_object(self, keyobject, true, true, true, parent);
}

static PyObject *Hardhat_keys(Hardhat *self, PyObject *dummy) {
	return (PyObject *)Hardhat_cursor(self, NULL, 0, true, true, false, true);
}

static PyObject *Hardhat_values(Hardhat *self, PyObject *dummy) {
	return (PyObject *)Hardhat_cursor(self, NULL, 0, true, false, true, true);
}

static PyObject *Hardhat_items(Hardhat *self, PyObject *dummy) {
	return (PyObject *)Hardhat_cursor(self, NULL, 0, true, true, true, true);
}

static PyObject *Hardhat_enter(Hardhat *self, PyObject *dummy) {
	if(!Hardhat_check(self))
		return PyErr_SetString(PyExc_TypeError, "not a valid Hardhat object"), NULL;
	Py_IncRef(&self->ob_base);
	return &self->ob_base;
}

static PyObject *Hardhat_exit(Hardhat *self, PyObject *args, PyObject *kwds) {
	if(!Hardhat_check(self))
		return PyErr_SetString(PyExc_TypeError, "not a valid Hardhat object"), NULL;
	Py_RETURN_NONE;
}

static PyMethodDef Hardhat_methods[] = {
	{"ls", (PyCFunction)Hardhat_ls, METH_VARARGS|METH_KEYWORDS, "return a non-recursive iterator"},
	{"find", (PyCFunction)Hardhat_find, METH_VARARGS|METH_KEYWORDS, "return a recursive iterator"},
	{"keys", (PyCFunction)Hardhat_keys, METH_NOARGS, "iterator over all keys"},
	{"values", (PyCFunction)Hardhat_values, METH_NOARGS, "iterator over all values"},
	{"items", (PyCFunction)Hardhat_items, METH_NOARGS, "iterator over tuples of all keys and values"},
	{"__enter__", (PyCFunction)Hardhat_enter, METH_NOARGS, "return a context manager for 'with'"},
	{"__exit__", (PyCFunction)Hardhat_exit, METH_VARARGS, "callback for 'with' context manager"},
	{NULL}
};

#ifdef HAVE_HARDHAT_ALIGNMENT
static PyObject *Hardhat_get_alignment(Hardhat *self, void *userdata) {
	if(!Hardhat_check(self))
		return PyErr_SetString(PyExc_TypeError, "not a valid Hardhat object"), NULL;

	return PyLong_FromUnsignedLongLong(hardhat_alignment(self->hh));
}
#endif

#ifdef HAVE_HARDHAT_BLOCKSIZE
static PyObject *Hardhat_get_blocksize(Hardhat *self, void *userdata) {
	if(!Hardhat_check(self))
		return PyErr_SetString(PyExc_TypeError, "not a valid Hardhat object"), NULL;

	return PyLong_FromUnsignedLongLong(hardhat_blocksize(self->hh));
}
#endif

static PyGetSetDef Hardhat_getset[] = {
#ifdef HAVE_HARDHAT_ALIGNMENT
	{"alignment", (getter)Hardhat_get_alignment, NULL, "the alignment of values", NULL},
#endif
#ifdef HAVE_HARDHAT_BLOCKSIZE
	{"blocksize", (getter)Hardhat_get_blocksize, NULL, "the assumed block size", NULL},
#endif
	{NULL}
};

// Hardhat mapping functions

static PyObject *Hardhat_getitem(Hardhat *self, PyObject *keyobject) {
	PyObject *view = NULL;
	HardhatCursor *cursor;
	if(!Hardhat_check(self))
		return PyErr_SetString(PyExc_TypeError, "not a valid Hardhat object"), NULL;
	cursor = (HardhatCursor *)Hardhat_cursor_from_object(self, keyobject, false, false, true, true);
	if(!cursor)
		return NULL;
	if(cursor->hhc->data)
		view = PyMemoryView_FromObject(&cursor->ob_base);
	else
		PyErr_Format(PyExc_KeyError, "'%S'", keyobject);
	Py_DecRef(&cursor->ob_base);
	return view;
}

static PyMappingMethods Hardhat_as_mapping = {
	.mp_subscript = (binaryfunc)Hardhat_getitem,
};

static Hardhat *Hardhat_new(PyTypeObject *subtype, PyObject *args, PyObject *kwargs) {
	Hardhat *self = NULL;
	PyObject *filename_object, *decoded_filename;
	const char *filename;
	hardhat_t *hh;

#ifdef HAVE_HARDHAT_OPENAT
	int dirfd = AT_FDCWD;

	char *keywords[] = { "", "dir_fd", NULL };

	if(!PyArg_ParseTupleAndKeywords(args, kwargs, "O|$i:new", keywords, &filename_object, &dirfd))
		return NULL;
#else
	char *keywords[] = { "", NULL };

	if(!PyArg_ParseTupleAndKeywords(args, kwargs, "O:new", keywords, &filename_object))
		return NULL;
#endif

	decoded_filename = hardhat_module_filename(filename_object);
	if(!decoded_filename)
		return NULL;

	filename = PyBytes_AsString(decoded_filename);
	if(!filename) {
		Py_DecRef(decoded_filename);
		return NULL;
	}

	Py_BEGIN_ALLOW_THREADS
#ifdef HAVE_HARDHAT_OPENAT
	hh = hardhat_openat(dirfd, filename);
#else
	hh = hardhat_open(filename);
#endif
	Py_END_ALLOW_THREADS

	Py_DecRef(decoded_filename);

	if(hh) {
		self = PyObject_New(Hardhat, subtype);
		if(self) {
			self->magic = HARDHAT_MAGIC;
			self->hh = hh;
		}
	} else {
		if(errno == EPROTO) {
			PyErr_Format(HARDHAT_FILE_FORMAT_ERROR, "not a hardhat file: '%S'", filename_object);
		} else {
			PyErr_SetFromErrnoWithFilenameObject(PyExc_OSError, filename_object);
		}
	}

	return self;
}

static void Hardhat_dealloc(Hardhat *self) {
	if(Hardhat_check(self)) {
		self->magic = 0;
		Py_BEGIN_ALLOW_THREADS
		hardhat_close(self->hh);
		Py_END_ALLOW_THREADS
	}

	PyObject_Del(self);
}

static PyObject *Hardhat_iter(Hardhat *self) {
	return Hardhat_items(self, NULL);
}

static PyTypeObject Hardhat_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name = "hardhat.Hardhat",
	.tp_basicsize = sizeof(Hardhat),
	.tp_dealloc = (destructor)Hardhat_dealloc,
	.tp_as_mapping = &Hardhat_as_mapping,
	.tp_flags = Py_TPFLAGS_DEFAULT,
	.tp_iter = (getiterfunc)Hardhat_iter,
	.tp_methods = Hardhat_methods,
	.tp_getset = Hardhat_getset,
	.tp_new = (newfunc)Hardhat_new,
};

// HardhatCursor object protocol

static int HardhatCursor_getbuffer(HardhatCursor *self, Py_buffer *buffer, int flags) {
	hardhat_cursor_t *hhc;
	if(HardhatCursor_check(self)) {
		hhc = self->hhc;
		if(hhc->data)
			return PyBuffer_FillInfo(buffer, &self->hardhat->ob_base, (char *)hhc->data, hhc->datalen, 1, flags);
		if(self->finished)
			PyErr_SetString(PyExc_IndexError, "iterator already reached its end");
		else
			PyErr_SetString(PyExc_KeyError, "no parent entry found");
	} else {
		PyErr_SetString(PyExc_BufferError, "not a valid HardhatCursor object");
	}
	buffer->obj = NULL;
	return -1;
}

static PyBufferProcs HardhatCursor_as_buffer = {
	.bf_getbuffer = (getbufferproc)HardhatCursor_getbuffer,
};

static PyObject *HardhatCursor_get_key(HardhatCursor *self, void *userdata) {
	hardhat_cursor_t *hhc;
	if(HardhatCursor_check(self)) {
		hhc = self->hhc;
		if(hhc->data)
			return PyBytes_FromStringAndSize(hhc->key, hhc->keylen);
		if(self->finished)
			PyErr_SetString(PyExc_IndexError, "iterator already reached its end");
		else
			PyErr_SetString(PyExc_KeyError, "no parent entry found");
	} else {
		PyErr_SetString(PyExc_TypeError, "not a valid HardhatCursor object");
	}
	return NULL;
}

static PyObject *HardhatCursor_get_value(HardhatCursor *self, void *userdata) {
	if(HardhatCursor_check(self)) {
		if(self->hhc->data)
			return PyMemoryView_FromObject(&self->ob_base);
		if(self->finished)
			PyErr_SetString(PyExc_IndexError, "iterator already reached its end");
		else
			PyErr_SetString(PyExc_KeyError, "no parent entry found");
	} else {
		PyErr_SetString(PyExc_TypeError, "not a valid HardhatCursor object");
	}
	return NULL;
}

static PyObject *HardhatCursor_get_item(HardhatCursor *self, void *userdata) {
	PyObject *keyobject, *valueobject, *tupleobject;
	hardhat_cursor_t *hhc;
	if(HardhatCursor_check(self)) {
		hhc = self->hhc;
		if(hhc->data) {
			keyobject = PyBytes_FromStringAndSize(hhc->key, hhc->keylen);
			if(keyobject) {
				valueobject = PyMemoryView_FromObject(&self->ob_base);
				if(valueobject) {
					tupleobject = PyTuple_Pack(2, keyobject, valueobject);
					Py_DecRef(valueobject);
				} else {
					tupleobject = NULL;
				}
				Py_DecRef(keyobject);
				return tupleobject;
			}
		} else {
			if(self->finished)
				PyErr_SetString(PyExc_IndexError, "iterator already reached its end");
			else
				PyErr_SetString(PyExc_KeyError, "no parent entry found");
		}
	} else {
		PyErr_SetString(PyExc_TypeError, "not a valid HardhatCursor object");
	}
	return NULL;
}

static PyObject *HardhatCursor_get_inode(HardhatCursor *self, void *userdata) {
	hardhat_cursor_t *hhc;
	if(HardhatCursor_check(self)) {
		hhc = self->hhc;
		if(hhc->data)
			return PyLong_FromUnsignedLongLong(hhc->cur);
		if(self->finished)
			PyErr_SetString(PyExc_IndexError, "iterator already reached its end");
		else
			PyErr_SetString(PyExc_KeyError, "no parent entry found");
	} else {
		PyErr_SetString(PyExc_TypeError, "not a valid HardhatCursor object");
	}
	return NULL;
}

static PyGetSetDef HardhatCursor_getset[] = {
	{"key", (getter)HardhatCursor_get_key, NULL, "get the current key (bytes)", NULL},
	{"value", (getter)HardhatCursor_get_value, NULL, "get the current value (memoryview)", NULL},
	{"item", (getter)HardhatCursor_get_item, NULL, "get the current key and value (tuple)", NULL},
	{"inode", (getter)HardhatCursor_get_inode, NULL, "get the current inode (int)", NULL},
	{NULL}
};

static PyObject *HardhatCursor_iternext(HardhatCursor *self) {
	hardhat_cursor_t *hhc;
	PyObject *keyobject, *valueobject, *tupleobject;
	if(HardhatCursor_check(self)) {
		hhc = self->hhc;
		if(!self->finished && ((self->initial && hhc->data) || hardhat_fetch(hhc, self->recursive))) {
			self->initial = false;
			if(self->keys) {
				keyobject = PyBytes_FromStringAndSize(hhc->key, hhc->keylen);
				if(!keyobject)
					return NULL;
				if(self->values) {
					valueobject = PyMemoryView_FromObject(&self->ob_base);
					if(valueobject) {
						tupleobject = PyTuple_Pack(2, keyobject, valueobject);
						Py_DecRef(valueobject);
					} else {
						tupleobject = NULL;
					}
					Py_DecRef(keyobject);
					return tupleobject;
				} else {
					return keyobject;
				}
			} else {
				if(self->values)
					return PyMemoryView_FromObject(&self->ob_base);
				else
					return PyErr_SetString(HARDHAT_INTERNAL_ERROR,
						"internal error in HardhatCursor_iternext()"), NULL;
			}
		} else {
			self->finished = true;
		}
	} else {
		PyErr_SetString(PyExc_TypeError, "not a valid HardhatCursor object");
	}
	return NULL;
}

static void HardhatCursor_dealloc(HardhatCursor *self) {
	if(HardhatCursor_check(self)) {
		self->magic = 0;
		hardhat_cursor_free(self->hhc);
		Py_DecRef(&self->hardhat->ob_base);
	}

	PyObject_Del(self);
}

static PyTypeObject HardhatCursor_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name = "hardhat.HardhatCursor",
	.tp_basicsize = sizeof(HardhatCursor),
	.tp_dealloc = (destructor)HardhatCursor_dealloc,
	.tp_as_buffer = &HardhatCursor_as_buffer,
	.tp_flags = Py_TPFLAGS_DEFAULT,
	.tp_iter = PyObject_SelfIter,
	.tp_iternext = (iternextfunc)HardhatCursor_iternext,
	.tp_getset = HardhatCursor_getset,
};

static PyObject *HardhatMaker_add(HardhatMaker *self, PyObject *args, PyObject *kwds) {
	PyObject *key_object, *value_object, *ret = NULL;
	Py_buffer key_buffer, value_buffer;
	hardhat_maker_t *hhm;
	bool ok = false;
	DECLARE_THREAD_SAVE

	if(!PyArg_ParseTuple(args, "OO:add", &key_object, &value_object))
		return NULL;

	if(!HardhatMaker_check(self))
		return PyErr_SetString(PyExc_TypeError, "not a valid HardhatMaker object"), NULL;

	if(hardhat_module_object_to_buffer(key_object, &key_buffer)) {
		if(hardhat_module_object_to_buffer(value_object, &value_buffer)) {
			if(key_buffer.len > UINT16_MAX) {
				PyErr_Format(PyExc_ValueError, "key is too long (%zd > %llu)",
					key_buffer.len, (unsigned long long)UINT16_MAX);
			} else {
				if(value_buffer.len > INT32_MAX) {
					PyErr_Format(PyExc_ValueError, "value is too long (%zd > %llu)",
						value_buffer.len, (unsigned long long)INT32_MAX);
				} else {
					Py_UNBLOCK_THREADS
					if(PyThread_acquire_lock(self->lock, WAIT_LOCK) == PY_LOCK_ACQUIRED) {
						hhm = self->hhm;
						if(hhm) {
							ok = hardhat_maker_add(hhm,
								key_buffer.buf, key_buffer.len,
								value_buffer.buf, value_buffer.len);
							Py_BLOCK_THREADS
							if(ok) {
								ret = Py_None;
								Py_IncRef(ret);
							} else {
								if(hardhat_maker_fatal(hhm)) {
									self->hhm = NULL;
									PyErr_SetString(HARDHAT_MAKER_FATAL_ERROR, hardhat_maker_error(hhm));
									Py_UNBLOCK_THREADS
									hardhat_maker_free(hhm);
									Py_BLOCK_THREADS
								} else {
									PyErr_SetString(HARDHAT_MAKER_ERROR, hardhat_maker_error(hhm));
								}
							}
						} else {
							Py_BLOCK_THREADS
							PyErr_SetString(HARDHAT_MAKER_VALUE_ERROR, "HardhatMaker object already closed");
						}
						PyThread_release_lock(self->lock);
					} else {
						Py_BLOCK_THREADS
						PyErr_SetString(PyExc_RuntimeError, "unable to acquire lock");
					}
				}
			}
			PyBuffer_Release(&value_buffer);
		}
		PyBuffer_Release(&key_buffer);
	}

	return ret;
}

static PyObject *HardhatMaker_parents(HardhatMaker *self, PyObject *value_object) {
	PyObject *ret = NULL;
	Py_buffer value_buffer;
	hardhat_maker_t *hhm;
	bool ok = false;
	DECLARE_THREAD_SAVE

	if(!HardhatMaker_check(self))
		return PyErr_SetString(PyExc_TypeError, "not a valid HardhatMaker object"), NULL;

	if(hardhat_module_object_to_buffer(value_object, &value_buffer)) {
		if(value_buffer.len > INT32_MAX) {
			PyErr_Format(PyExc_ValueError, "value is too long (%zd > %llu)",
				value_buffer.len, (unsigned long long)INT32_MAX);
		} else {
			Py_UNBLOCK_THREADS
			if(PyThread_acquire_lock(self->lock, WAIT_LOCK) == PY_LOCK_ACQUIRED) {
				hhm = self->hhm;
				if(hhm) {
					ok = hardhat_maker_parents(hhm,
						value_buffer.buf, value_buffer.len);
					Py_BLOCK_THREADS
					if(ok) {
						ret = Py_None;
						Py_IncRef(ret);
					} else {
						if(hardhat_maker_fatal(hhm)) {
							self->hhm = NULL;
							PyErr_SetString(HARDHAT_MAKER_FATAL_ERROR, hardhat_maker_error(hhm));
							Py_UNBLOCK_THREADS
							hardhat_maker_free(hhm);
							Py_BLOCK_THREADS
						} else {
							PyErr_SetString(HARDHAT_MAKER_ERROR, hardhat_maker_error(hhm));
						}
					}
				} else {
					Py_BLOCK_THREADS
					PyErr_SetString(HARDHAT_MAKER_VALUE_ERROR, "HardhatMaker object already closed");
				}
				PyThread_release_lock(self->lock);
			} else {
				Py_BLOCK_THREADS
				PyErr_SetString(PyExc_RuntimeError, "unable to acquire lock");
			}
		}
		PyBuffer_Release(&value_buffer);
	}


	return ret;
}

static PyObject *HardhatMaker_close(HardhatMaker *self, PyObject *dummy) {
	hardhat_maker_t *hhm;
	bool ok = false;
	DECLARE_THREAD_SAVE

	if(!HardhatMaker_check(self))
		return PyErr_SetString(PyExc_TypeError, "not a valid HardhatMaker object"), NULL;

	Py_UNBLOCK_THREADS
	if(PyThread_acquire_lock(self->lock, WAIT_LOCK) == PY_LOCK_ACQUIRED) {
		hhm = self->hhm;
		self->hhm = NULL;
		PyThread_release_lock(self->lock);

		if(hhm) {
			ok = hardhat_maker_finish(hhm);

			if(!ok) {
				Py_BLOCK_THREADS
				PyErr_SetString(HARDHAT_MAKER_FATAL_ERROR, hardhat_maker_error(hhm));
				Py_UNBLOCK_THREADS
			}

			hardhat_maker_free(hhm);

			Py_BLOCK_THREADS
		} else {
			Py_BLOCK_THREADS
			PyErr_SetString(HARDHAT_MAKER_VALUE_ERROR, "HardhatMaker object already closed");
		}
	} else {
		Py_BLOCK_THREADS
		PyErr_SetString(PyExc_RuntimeError, "unable to acquire lock");
	}

	if(ok)
		Py_RETURN_NONE;
	else
		return NULL;
}

static PyObject *HardhatMaker_enter(HardhatMaker *self, PyObject *dummy) {
	if(!HardhatMaker_check(self))
		return PyErr_SetString(PyExc_TypeError, "not a valid HardhatMaker object"), NULL;
	Py_IncRef(&self->ob_base);
	return &self->ob_base;
}

static PyObject *HardhatMaker_exit(HardhatMaker *self, PyObject *args, PyObject *kwds) {
	hardhat_maker_t *hhm;
	bool ok = false;
	DECLARE_THREAD_SAVE

	if(!HardhatMaker_check(self))
		return PyErr_SetString(PyExc_TypeError, "not a valid HardhatMaker object"), NULL;

	Py_UNBLOCK_THREADS
	if(PyThread_acquire_lock(self->lock, WAIT_LOCK) == PY_LOCK_ACQUIRED) {
		hhm = self->hhm;
		self->hhm = NULL;
		PyThread_release_lock(self->lock);

		if(hhm) {
			ok = hardhat_maker_finish(hhm);

			if(!ok) {
				Py_BLOCK_THREADS
				PyErr_SetString(HARDHAT_MAKER_FATAL_ERROR, hardhat_maker_error(hhm));
				Py_UNBLOCK_THREADS
			}

			hardhat_maker_free(hhm);
		}

		Py_BLOCK_THREADS
	} else {
		Py_BLOCK_THREADS
		PyErr_SetString(PyExc_RuntimeError, "unable to acquire lock");
	}

	if(ok)
		Py_RETURN_NONE;
	else
		return NULL;
}

static PyMethodDef HardhatMaker_methods[] = {
	{"add", (PyCFunction)HardhatMaker_add, METH_VARARGS, "add an entry to the hardhat database"},
	{"parents", (PyCFunction)HardhatMaker_parents, METH_O, "add intermediate keys to the database"},
	{"close", (PyCFunction)HardhatMaker_close, METH_NOARGS, "finish and close the database"},
	{"__enter__", (PyCFunction)HardhatMaker_enter, METH_NOARGS, "return a context manager for 'with'"},
	{"__exit__", (PyCFunction)HardhatMaker_exit, METH_VARARGS, "callback for 'with' context manager"},
	{NULL}
};

#ifdef HAVE_HARDHAT_MAKER_ALIGNMENT
static PyObject *HardhatMaker_get_alignment(HardhatMaker *self, void *userdata) {
	hardhat_maker_t *hhm;
	uint64_t alignment;
	DECLARE_THREAD_SAVE

	if(!HardhatMaker_check(self))
		return PyErr_SetString(PyExc_TypeError, "not a valid HardhatMaker object"), NULL;

	Py_UNBLOCK_THREADS
	if(PyThread_acquire_lock(self->lock, WAIT_LOCK) == PY_LOCK_ACQUIRED) {
		hhm = self->hhm;
		if(hhm) {
			alignment = hardhat_maker_alignment(hhm, 0);
			PyThread_release_lock(self->lock);
			Py_BLOCK_THREADS
			if(alignment)
				return PyLong_FromUnsignedLongLong(alignment);
			else
				return PyErr_SetString(HARDHAT_MAKER_ERROR, hardhat_maker_error(hhm)), NULL;
		} else {
			PyThread_release_lock(self->lock);
			Py_BLOCK_THREADS
			return PyErr_SetString(HARDHAT_MAKER_VALUE_ERROR, "HardhatMaker object already closed"), NULL;
		}
	} else {
		Py_BLOCK_THREADS
		return PyErr_SetString(PyExc_RuntimeError, "unable to acquire lock"), NULL;
	}
}

static int HardhatMaker_set_alignment(HardhatMaker *self, PyObject *value, void *userdata) {
	hardhat_maker_t *hhm;
	uint64_t alignment;
	unsigned PY_LONG_LONG upll;
	DECLARE_THREAD_SAVE

	if(!HardhatMaker_check(self))
		return PyErr_SetString(PyExc_TypeError, "not a valid HardhatMaker object"), -1;

	PyErr_Clear();
	upll = PyLong_AsUnsignedLongLong(value);
	if(PyErr_Occurred())
		return -1;
	if(!upll)
		return PyErr_SetString(PyExc_ValueError, "alignment cannot be 0 (use 1 to disable alignment)"), -1;

	Py_UNBLOCK_THREADS
	if(PyThread_acquire_lock(self->lock, WAIT_LOCK) == PY_LOCK_ACQUIRED) {
		hhm = self->hhm;
		if(hhm) {
			alignment = hardhat_maker_alignment(hhm, upll);
			PyThread_release_lock(self->lock);
			Py_BLOCK_THREADS
			if(alignment)
				return 0;
			else
				return PyErr_SetString(HARDHAT_MAKER_ERROR, hardhat_maker_error(hhm)), -1;
		} else {
			PyThread_release_lock(self->lock);
			Py_BLOCK_THREADS
			return PyErr_SetString(HARDHAT_MAKER_VALUE_ERROR, "HardhatMaker object already closed"), -1;
		}
	} else {
		Py_BLOCK_THREADS
		return PyErr_SetString(PyExc_RuntimeError, "unable to acquire lock"), -1;
	}
}
#endif

#ifdef HAVE_HARDHAT_MAKER_BLOCKSIZE
static PyObject *HardhatMaker_get_blocksize(HardhatMaker *self, void *userdata) {
	hardhat_maker_t *hhm;
	uint64_t blocksize;
	DECLARE_THREAD_SAVE

	if(!HardhatMaker_check(self))
		return PyErr_SetString(PyExc_TypeError, "not a valid HardhatMaker object"), NULL;

	Py_UNBLOCK_THREADS
	if(PyThread_acquire_lock(self->lock, WAIT_LOCK) == PY_LOCK_ACQUIRED) {
		hhm = self->hhm;
		if(hhm) {
			blocksize = hardhat_maker_blocksize(hhm, 0);
			PyThread_release_lock(self->lock);
			Py_BLOCK_THREADS
			if(blocksize)
				return PyLong_FromUnsignedLongLong(blocksize);
			else
				return PyErr_SetString(HARDHAT_MAKER_ERROR, hardhat_maker_error(hhm)), NULL;
		} else {
			PyThread_release_lock(self->lock);
			Py_BLOCK_THREADS
			return PyErr_SetString(HARDHAT_MAKER_VALUE_ERROR, "HardhatMaker object already closed"), NULL;
		}
	} else {
		Py_BLOCK_THREADS
		return PyErr_SetString(PyExc_RuntimeError, "unable to acquire lock"), NULL;
	}
}


static int HardhatMaker_set_blocksize(HardhatMaker *self, PyObject *value, void *userdata) {
	hardhat_maker_t *hhm;
	uint64_t blocksize;
	unsigned PY_LONG_LONG upll;
	DECLARE_THREAD_SAVE

	if(!HardhatMaker_check(self))
		return PyErr_SetString(PyExc_TypeError, "not a valid HardhatMaker object"), -1;

	PyErr_Clear();
	upll = PyLong_AsUnsignedLongLong(value);
	if(PyErr_Occurred())
		return -1;
	if(!upll)
		return PyErr_SetString(PyExc_ValueError, "block size cannot be 0 (use 1 to disable block alignment)"), -1;

	Py_UNBLOCK_THREADS
	if(PyThread_acquire_lock(self->lock, WAIT_LOCK) == PY_LOCK_ACQUIRED) {
		hhm = self->hhm;
		if(hhm) {
			blocksize = hardhat_maker_blocksize(hhm, upll);
			PyThread_release_lock(self->lock);
			Py_BLOCK_THREADS
			if(blocksize)
				return 0;
			else
				return PyErr_SetString(HARDHAT_MAKER_ERROR, hardhat_maker_error(hhm)), -1;
		} else {
			PyThread_release_lock(self->lock);
			Py_BLOCK_THREADS
			return PyErr_SetString(HARDHAT_MAKER_VALUE_ERROR, "HardhatMaker object already closed"), -1;
		}
	} else {
		Py_BLOCK_THREADS
		return PyErr_SetString(PyExc_RuntimeError, "unable to acquire lock"), -1;
	}
}
#endif

static PyGetSetDef HardhatMaker_getset[] = {
#ifdef HAVE_HARDHAT_MAKER_ALIGNMENT
	{"alignment", (getter)HardhatMaker_get_alignment, (setter)HardhatMaker_set_alignment, "the alignment of values", NULL},
#endif
#ifdef HAVE_HARDHAT_MAKER_BLOCKSIZE
	{"blocksize", (getter)HardhatMaker_get_blocksize, (setter)HardhatMaker_set_blocksize, "the assumed block size", NULL},
#endif
	{NULL}
};

static HardhatMaker *HardhatMaker_new(PyTypeObject *subtype, PyObject *args, PyObject *kwargs) {
	PyObject *filename_object;

#ifdef HAVE_HARDHAT_MAKER_NEWAT
	char *keywords[] = { "", "mode", "dir_fd", NULL };

	int dirfd = AT_FDCWD;
	int mode = 0666;
	if(!PyArg_ParseTupleAndKeywords(args, kwargs, "O|$ii:new", keywords, &filename_object, &mode, &dirfd))
		return NULL;
#else
	char *keywords[] = { "", NULL };

	if(!PyArg_ParseTupleAndKeywords(args, kwargs, "O:new", keywords, &filename_object))
		return NULL;
#endif

	PyThread_type_lock lock = PyThread_allocate_lock();
	if(lock) {
		PyObject *decoded_filename = hardhat_module_filename(filename_object);
		if(decoded_filename) {
			const char *filename = PyBytes_AsString(decoded_filename);
			if(filename) {
				hardhat_maker_t *hhm;
				Py_BEGIN_ALLOW_THREADS
#ifdef HAVE_HARDHAT_MAKER_NEWAT
				hhm = hardhat_maker_newat(dirfd, filename, mode);
#else
				hhm = hardhat_maker_new(filename);
#endif
				Py_END_ALLOW_THREADS

				if(hhm) {
					HardhatMaker *self = PyObject_New(HardhatMaker, subtype);
					if(self) {
						self->magic = HARDHAT_MAKER_MAGIC;
						self->hhm = hhm;
						self->lock = lock;
						Py_DecRef(decoded_filename);
						return self;
					}
				} else {
					PyErr_SetFromErrnoWithFilenameObject(PyExc_OSError, filename_object);
				}
			}
			Py_DecRef(decoded_filename);
		}
		PyThread_free_lock(lock);
	}

	return NULL;
}

static void HardhatMaker_dealloc(HardhatMaker *self) {
	if(HardhatMaker_check(self)) {
		self->magic = 0;
		Py_BEGIN_ALLOW_THREADS
		PyThread_acquire_lock(self->lock, NOWAIT_LOCK);
		hardhat_maker_free(self->hhm);
		Py_END_ALLOW_THREADS
		PyThread_free_lock(self->lock);
	}

	PyObject_Del(self);
}

static PyTypeObject HardhatMaker_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
	.tp_name = "hardhat.HardhatMaker",
	.tp_basicsize = sizeof(HardhatMaker),
	.tp_dealloc = (destructor)HardhatMaker_dealloc,
	.tp_flags = Py_TPFLAGS_DEFAULT,
	.tp_methods = HardhatMaker_methods,
	.tp_getset = HardhatMaker_getset,
	.tp_new = (newfunc)HardhatMaker_new,
};

// Hardhat module functions

static PyObject *hardhat_module_normalize(PyObject *self, PyObject *obj) {
	Py_buffer buffer;
	PyObject *result;

	if(!hardhat_module_object_to_buffer(obj, &buffer))
		return NULL;

	// if you pass 0 for the length, you get a shared bytes object and
	//_PyBytes_Resize will fail.
	result = PyBytes_FromStringAndSize(NULL, buffer.len);
	if(result && buffer.len)
		_PyBytes_Resize(&result,
			hardhat_normalize(PyBytes_AS_STRING(result), buffer.buf, buffer.len));

	PyBuffer_Release(&buffer);

	return result;
}

static PyMethodDef hardhat_module_functions[] = {
	{"normalize", hardhat_module_normalize, METH_O, "return a normalized bytes object"},
	{NULL}
};

PyDoc_STRVAR(hardhat_module_doc, "Wrapper for the hardhat library");

static struct PyModuleDef hardhat_module = {
	PyModuleDef_HEAD_INIT,
	.m_name = "hardhat",
	.m_doc = hardhat_module_doc,
	.m_methods = hardhat_module_functions,
};

PyMODINIT_FUNC PyInit_hardhat(void) {
	if(PyType_Ready(&Hardhat_type) == -1)
		return NULL;
	if(PyType_Ready(&HardhatCursor_type) == -1)
		return NULL;
	if(PyType_Ready(&HardhatMaker_type) == -1)
		return NULL;

	PyObject *module = PyModule_Create(&hardhat_module);
	if(module) {
		if(PyModule_AddObject(module, "Hardhat", &Hardhat_type.ob_base.ob_base) != -1
		&& PyModule_AddObject(module, "HardhatCursor", &HardhatCursor_type.ob_base.ob_base) != -1
		&& PyModule_AddObject(module, "HardhatMaker", &HardhatMaker_type.ob_base.ob_base) != -1) {
			// try to ensure these exist:
			hardhat_module_create_exception(module, "InternalError", NULL);
			hardhat_module_create_exception(module, "FileFormatError", NULL);
			PyObject *maker_error = hardhat_module_create_exception(module, "MakerError", NULL);
			if(maker_error) {
				hardhat_module_create_exception(module, "MakerFatalError", maker_error);
				hardhat_module_create_exception(module, "MakerValueError", maker_error);
			}
			return module;
		}
		Py_DecRef(module);
	}
	return NULL;
}
