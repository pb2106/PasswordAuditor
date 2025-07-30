# syscalls.pyx

# distutils: language = c++
# cython: language_level=3, boundscheck=False

from libc.stdint cimport uint32_t, int32_t
from libc.stdlib cimport malloc, free
from libc.stddef cimport wchar_t

# For making Python bytes from raw C buffers
from cpython.bytes cimport PyBytes_FromStringAndSize

# Explicitly declare missing Windows types
ctypedef unsigned char BYTE
ctypedef wchar_t WCHAR
ctypedef WCHAR* LPWSTR

cdef extern from "windows.h":
    ctypedef void* LPVOID
    ctypedef uint32_t DWORD
    ctypedef int32_t BOOL
    ctypedef void* PVOID
    ctypedef void* HANDLE

cdef extern from "wincrypt.h":
    ctypedef struct DATA_BLOB:
        DWORD cbData
        BYTE* pbData

    BOOL CryptUnprotectData(
        DATA_BLOB* pDataIn,
        LPWSTR* ppszDataDescr,
        DATA_BLOB* pOptionalEntropy,
        void* pvReserved,
        void* pPromptStruct,
        DWORD dwFlags,
        DATA_BLOB* pDataOut
    )

cpdef bytes decrypt_dpapi(bytes enc_data):
    cdef DATA_BLOB input_blob, output_blob
    cdef BYTE* input_ptr = <BYTE*> malloc(len(enc_data))
    if not input_ptr:
        raise MemoryError()

    # copy encrypted buffer
    for i in range(len(enc_data)):
        input_ptr[i] = enc_data[i]

    input_blob.cbData = len(enc_data)
    input_blob.pbData = input_ptr
    output_blob.cbData = 0
    output_blob.pbData = NULL

    cdef bytes result = b""
    if CryptUnprotectData(&input_blob, NULL, NULL, NULL, NULL, 0, &output_blob):
        result = PyBytes_FromStringAndSize(<char*>output_blob.pbData, output_blob.cbData)

    free(input_ptr)
    return result
