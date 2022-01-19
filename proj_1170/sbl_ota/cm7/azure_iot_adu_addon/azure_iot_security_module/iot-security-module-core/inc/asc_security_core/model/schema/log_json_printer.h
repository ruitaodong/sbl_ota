#ifndef LOG_JSON_PRINTER_H
#define LOG_JSON_PRINTER_H

/* Generated by flatcc 0.6.1-dev FlatBuffers schema compiler for C by dvide.com */

#include "flatcc/flatcc_json_printer.h"
#include "flatcc/flatcc_prologue.h"

static void AzureIoTSecurity_Record_print_json_table(flatcc_json_printer_t *ctx, flatcc_json_printer_table_descriptor_t *td);
static void AzureIoTSecurity_Log_print_json_table(flatcc_json_printer_t *ctx, flatcc_json_printer_table_descriptor_t *td);

static void AzureIoTSecurity_Level_print_json_enum(flatcc_json_printer_t *ctx, int8_t v)
{

    switch (v) {
    case 0: flatcc_json_printer_enum(ctx, "NOTSET", 6); break;
    case 1: flatcc_json_printer_enum(ctx, "FATAL", 5); break;
    case 2: flatcc_json_printer_enum(ctx, "ERROR", 5); break;
    case 3: flatcc_json_printer_enum(ctx, "WARN", 4); break;
    case 4: flatcc_json_printer_enum(ctx, "INFO", 4); break;
    case 5: flatcc_json_printer_enum(ctx, "DEBUG", 5); break;
    default: flatcc_json_printer_int8(ctx, v); break;
    }
}

static void AzureIoTSecurity_Record_print_json_table(flatcc_json_printer_t *ctx, flatcc_json_printer_table_descriptor_t *td)
{
    flatcc_json_printer_string_field(ctx, td, 0, "message", 7);
    flatcc_json_printer_int8_enum_field(ctx, td, 1, "level", 5, 0, AzureIoTSecurity_Level_print_json_enum);
    flatcc_json_printer_uint64_field(ctx, td, 2, "timestamp", 9, 0);
    flatcc_json_printer_uint32_field(ctx, td, 3, "line", 4, 0);
    flatcc_json_printer_string_field(ctx, td, 4, "filename", 8);
}

static inline int AzureIoTSecurity_Record_print_json_as_root(flatcc_json_printer_t *ctx, const void *buf, size_t bufsiz, const char *fid)
{
    return flatcc_json_printer_table_as_root(ctx, buf, bufsiz, fid, AzureIoTSecurity_Record_print_json_table);
}

static void AzureIoTSecurity_Log_print_json_table(flatcc_json_printer_t *ctx, flatcc_json_printer_table_descriptor_t *td)
{
    flatcc_json_printer_table_vector_field(ctx, td, 0, "logs", 4, AzureIoTSecurity_Record_print_json_table);
}

static inline int AzureIoTSecurity_Log_print_json_as_root(flatcc_json_printer_t *ctx, const void *buf, size_t bufsiz, const char *fid)
{
    return flatcc_json_printer_table_as_root(ctx, buf, bufsiz, fid, AzureIoTSecurity_Log_print_json_table);
}

#include "flatcc/flatcc_epilogue.h"
#endif /* LOG_JSON_PRINTER_H */
