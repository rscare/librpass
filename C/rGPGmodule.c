#include <Python.h>
#include <gpgme.h>
#include <stdio.h>

#include "rGPG.h"

static PyObject * encrypt_to_file(PyObject *self, PyObject *args) {
    return NULL;
}

static PyObject * decrypt_from_file(PyObject *self, PyObject *args) {
    gpgme_data_t plain_text = NULL;
    gpgme_data_t cipher_text = NULL;

    const char *filename = NULL;
    FILE *fp = NULL;

    size_t len = 0;

    PyObject * result = NULL;

    if (!PyArg_ParseTuple(args, "s", &filename)) 
        return NULL;
    if (!(fp = fopen(filename, "rb")))
        return NULL;
    if (!create_gpg_data(&plain_text, NULL, NULL, 0, 0))
        return NULL;
    if (!create_gpg_data(&cipher_text, fp, NULL, 0, 0))
        return NULL;
    if (!initialize_engine())
        return NULL;
    if (!decrypt_object(cipher_text, plain_text))
        return NULL;

    destroy_engine();
    gpgme_free(gpgme_data_release_and_get_mem(cipher_text, &len));
    fclose(fp);

    result = Py_BuildValue("s", gpg_object_to_string(plain_text));

    gpgme_data_release(plain_text);

    return result;
}

static PyMethodDef GPGMethods[] = {
    { "decrypt_file", decrypt_from_file, METH_VARARGS,
    "Decrypt info from a file into memory."},
    { NULL, NULL, 0, NULL }
};

static struct PyModuleDef rGPGmodule = {
    PyModuleDef_HEAD_INIT,
    "rGPG",
    NULL,
    -1,
    GPGMethods
};

PyMODINIT_FUNC PyInit_rGPG() {
    return PyModule_Create(&rGPGmodule);
}