#define PY_SSIZE_T_CLEAN
#include <Python.h>

static PyObject *answer(PyObject *self, PyObject *args) {
    (void)self;
    (void)args;
    return PyLong_FromLong(42);
}

static PyMethodDef native_methods[] = {
    {"answer", answer, METH_NOARGS, "Return the approval constant."},
    {NULL, NULL, 0, NULL}
};

static struct PyModuleDef native_module = {
    PyModuleDef_HEAD_INIT,
    "_native",
    "Minimal native extension",
    -1,
    native_methods
};

PyMODINIT_FUNC PyInit__native(void) {
    return PyModule_Create(&native_module);
}
