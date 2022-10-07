/*
Copyright (c) 2014. The YARA Authors. All Rights Reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
this list of conditions and the following disclaimer in the documentation and/or
other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its contributors
may be used to endorse or promote products derived from this software without
specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include <yara/modules.h>
#include <yara/miniz.h>
#include <openssl/sha.h>

#define MODULE_NAME phishkit

define_function(file_match)
{
  YR_SCAN_CONTEXT *module_context = scan_context();
  char *file_name = string_argument(1);
  int64_t flag = integer_argument(2);
  if (module_context != NULL)
  {
    YR_MEMORY_BLOCK *block;

    block = first_memory_block(module_context);
    uint8_t *buffer = (uint8_t *)block->fetch_data(block);
    mz_zip_archive zip;
    memset(&zip, 0, sizeof(zip));

    if (!mz_zip_reader_init_mem(&zip, buffer, module_context->file_size, 0))
    {
      mz_zip_reader_end(&zip);
      return_integer(0);
    }

    int f = 0;
    if (flag == 1)
    {
      f = 0x200;
    }

    int file_index = mz_zip_reader_locate_file(&zip, file_name, 0, f);
    if (file_index < 0)
    {
      mz_zip_reader_end(&zip);
      return_integer(0);
    }
    else
    {
      mz_zip_reader_end(&zip);
      return_integer(1);
    }
    mz_zip_reader_end(&zip);
    return_integer(0);
  }
  return_integer(0);
}

define_function(dir_match)
{
  YR_SCAN_CONTEXT *module_context = scan_context();
  char *dir_name = string_argument(1);
  int64_t flag = integer_argument(2);
  if (module_context != NULL)
  {
    YR_MEMORY_BLOCK *block;

    block = first_memory_block(module_context);
    uint8_t *buffer = (uint8_t *)block->fetch_data(block);
    mz_zip_archive zip;
    mz_zip_archive_file_stat stat;
    // size_t size = 0;
    memset(&zip, 0, sizeof(zip));

    if (!mz_zip_reader_init_mem(&zip, buffer, module_context->file_size, 0))
    {
      mz_zip_reader_end(&zip);
      return_integer(0);
    }

    int return_result = 0;
    int fileCount = (int)mz_zip_reader_get_num_files(&zip);
    if (fileCount == 0)
    {
      mz_zip_reader_end(&zip);
      return_integer(0);
    }
    if (!mz_zip_reader_file_stat(&zip, 0, &stat))
    {
      mz_zip_reader_end(&zip);
      return_integer(0);
    }

    for (int i = 0; i < fileCount; i++)
    {
      if (!mz_zip_reader_file_stat(&zip, i, &stat))
        continue;
      if (!mz_zip_reader_is_file_a_directory(&zip, i))
        continue;

      if (flag == 0 && strcasecmp(stat.m_filename, dir_name) == 0)
      {
        return_result = 1;
        break;
      }
      else if (flag == 1 && strcasestr(stat.m_filename, dir_name))
      {
        return_result = 1;
        break;
      }
    }
    mz_zip_reader_end(&zip);
    return_integer(return_result);
  }
  return_integer(0);
}

define_function(string_match)
{
  YR_SCAN_CONTEXT *module_context = scan_context();
  char *search_string = string_argument(1);
  int64_t c_flag = integer_argument(2);
  if (module_context != NULL)
  {
    YR_MEMORY_BLOCK *block;

    block = first_memory_block(module_context);
    uint8_t *buffer = (uint8_t *)block->fetch_data(block);
    mz_zip_archive zip;
    mz_zip_archive_file_stat stat;
    size_t size = 0;
    memset(&zip, 0, sizeof(zip));

    if (!mz_zip_reader_init_mem(&zip, buffer, module_context->file_size, 0))
    {
      mz_zip_reader_end(&zip);
      return_integer(0);
    }

    int fileCount = (int)mz_zip_reader_get_num_files(&zip);
    if (fileCount == 0)
    {
      mz_zip_reader_end(&zip);
      return_integer(0);
    }
    if (!mz_zip_reader_file_stat(&zip, 0, &stat))
    {
      mz_zip_reader_end(&zip);
      return_integer(0);
    }

    int return_result = 0;
    for (int i = 0; i < fileCount; i++)
    {
      if (!mz_zip_reader_file_stat(&zip, i, &stat))
        continue;
      if (mz_zip_reader_is_file_a_directory(&zip, i))
        continue;

      if (stat.m_uncomp_size < 100 * 1024 * 1024)
      {
        void *p = mz_zip_reader_extract_to_heap(&zip, i, &size, 0);
        if (!p)
        {
          free(p);
          continue;
        }
        else
        {
          char *result = NULL;
          if (c_flag == 0)
            result = strstr(p, search_string);
          else
            result = strcasestr(p, search_string);
          if (result != NULL)
            return_result = ((void *)result - p);
          free(p);
          if (return_result >= 1)
            break;
        }
      }
    }

    mz_zip_reader_end(&zip);
    return_integer(return_result);
  }
  return_integer(0);
}

define_function(file_string_match)
{
  YR_SCAN_CONTEXT *module_context = scan_context();
  char *file_name = string_argument(1);
  char *search_string = string_argument(2);
  int64_t flag = integer_argument(3);
  int64_t c_flag = integer_argument(4);
  if (module_context != NULL)
  {
    YR_MEMORY_BLOCK *block;

    block = first_memory_block(module_context);
    uint8_t *buffer = (uint8_t *)block->fetch_data(block);
    mz_zip_archive zip;
    mz_zip_archive_file_stat stat;
    size_t size = 0;
    memset(&zip, 0, sizeof(zip));

    if (!mz_zip_reader_init_mem(&zip, buffer, module_context->file_size, 0))
    {
      mz_zip_reader_end(&zip);
      return_integer(0);
    }

    int return_result = 0;
    if (flag == 1)
    {
      int fileCount = (int)mz_zip_reader_get_num_files(&zip);
      if (fileCount == 0)
      {
        mz_zip_reader_end(&zip);
        return_integer(0);
      }
      if (!mz_zip_reader_file_stat(&zip, 0, &stat))
      {
        mz_zip_reader_end(&zip);
        return_integer(0);
      }

      for (int i = 0; i < fileCount; i++)
      {
        if (!mz_zip_reader_file_stat(&zip, i, &stat))
          continue;
        if (mz_zip_reader_is_file_a_directory(&zip, i))
          continue;

        if (strcasestr(stat.m_filename, file_name) && stat.m_uncomp_size < 100 * 1024 * 1024)
        {
          void *p = mz_zip_reader_extract_to_heap(&zip, i, &size, 0);
          if (!p)
          {
            free(p);
            continue;
          }
          else
          {
            char *result = NULL;
            if (c_flag == 0)
              result = strstr(p, search_string);
            else
              result = strcasestr(p, search_string);
            if (result != NULL)
              return_result = ((void *)result - p);
            free(p);
            if (return_result >= 1)
              break;
          }
        }
      }
    }
    else
    {
      int file_index = mz_zip_reader_locate_file(&zip, file_name, 0, 0);
      if (file_index < 0)
      {
        mz_zip_reader_end(&zip);
        return_integer(0);
      }

      if (!mz_zip_reader_file_stat(&zip, file_index, &stat))
      {
        mz_zip_reader_end(&zip);
        return_integer(0);
      }

      if (stat.m_uncomp_size < 100 * 1024 * 1024)
      {
        void *p = mz_zip_reader_extract_to_heap(&zip, file_index, &size, 0);
        if (!p)
        {
          mz_zip_reader_end(&zip);
          return_integer(0);
        }
        else
        {
          char *result = NULL;
          if (c_flag == 0)
            result = strstr(p, search_string);
          else
            result = strcasestr(p, search_string);
          if (result != NULL)
            return_result = ((void *)result - p);
          free(p);
        }
      }
    }
    mz_zip_reader_end(&zip);
    return_integer(return_result);
  }
  return_integer(0);
}

define_function(regex_match)
{
  YR_SCAN_CONTEXT *module_context = scan_context();
  RE *regex_string = regexp_argument(1);
  if (module_context != NULL)
  {
    YR_MEMORY_BLOCK *block;

    block = first_memory_block(module_context);
    uint8_t *buffer = (uint8_t *)block->fetch_data(block);
    mz_zip_archive zip;
    mz_zip_archive_file_stat stat;
    size_t size = 0;
    memset(&zip, 0, sizeof(zip));

    if (!mz_zip_reader_init_mem(&zip, buffer, module_context->file_size, 0))
    {
      mz_zip_reader_end(&zip);
      return_integer(0);
    }

    int fileCount = (int)mz_zip_reader_get_num_files(&zip);
    if (fileCount == 0)
    {
      mz_zip_reader_end(&zip);
      return_integer(0);
    }
    if (!mz_zip_reader_file_stat(&zip, 0, &stat))
    {
      mz_zip_reader_end(&zip);
      return_integer(0);
    }

    int return_result = 0;
    for (int i = 0; i < fileCount; i++)
    {
      if (!mz_zip_reader_file_stat(&zip, i, &stat))
        continue;
      if (mz_zip_reader_is_file_a_directory(&zip, i))
        continue;

      if (stat.m_uncomp_size < 100 * 1024 * 1024)
      {
        void *p = mz_zip_reader_extract_to_heap(&zip, i, &size, 0);
        if (!p)
        {
          free(p);
          continue;
        }
        else
        {
          int result = yr_re_match(module_context, regex_string, p);
          if (result > 0)
            return_result = 1;
          free(p);
          if (return_result >= 1)
            break;
        }
      }
    }

    mz_zip_reader_end(&zip);
    return_integer(return_result);
  }
  return_integer(0);
}

define_function(file_regex_match)
{
  YR_SCAN_CONTEXT *module_context = scan_context();
  char *file_name = string_argument(1);
  RE *regex_string = regexp_argument(2);
  int64_t flag = integer_argument(3);
  if (module_context != NULL)
  {
    YR_MEMORY_BLOCK *block;

    block = first_memory_block(module_context);
    uint8_t *buffer = (uint8_t *)block->fetch_data(block);
    mz_zip_archive zip;
    mz_zip_archive_file_stat stat;
    size_t size = 0;
    memset(&zip, 0, sizeof(zip));

    if (!mz_zip_reader_init_mem(&zip, buffer, module_context->file_size, 0))
    {
      mz_zip_reader_end(&zip);
      return_integer(0);
    }

    int f = 0;
    if (flag == 1)
    {
      f = 0x200;
    }

    int return_result = 0;
    int file_index = mz_zip_reader_locate_file(&zip, file_name, 0, f);
    if (file_index < 0)
    {
      mz_zip_reader_end(&zip);
      return_integer(0);
    }

    if (!mz_zip_reader_file_stat(&zip, file_index, &stat))
    {
      mz_zip_reader_end(&zip);
      return_integer(0);
    }

    if (stat.m_uncomp_size < 100 * 1024 * 1024)
    {
      void *p = mz_zip_reader_extract_to_heap(&zip, file_index, &size, 0);
      if (!p)
      {
        mz_zip_reader_end(&zip);
        return_integer(0);
      }
      else
      {
        int result = yr_re_match(module_context, regex_string, p);
        if (result > 0)
          return_result = 1;
        free(p);
      }
    }
    mz_zip_reader_end(&zip);
    return_integer(return_result);
  }
  return_integer(0);
}

define_function(sha1_match)
{
  YR_SCAN_CONTEXT *module_context = scan_context();
  char *hash = string_argument(1);
  if (module_context != NULL)
  {
    YR_MEMORY_BLOCK *block;
    block = first_memory_block(module_context);
    uint8_t *buffer = (uint8_t *)block->fetch_data(block);
    mz_zip_archive zip;
    mz_zip_archive_file_stat stat;
    size_t size = 0;
    memset(&zip, 0, sizeof(zip));
    if (!mz_zip_reader_init_mem(&zip, buffer, module_context->file_size, 0))
    {
      mz_zip_reader_end(&zip);
      return_integer(0);
    }
    int fileCount = (int)mz_zip_reader_get_num_files(&zip);
    if (fileCount == 0)
    {
      mz_zip_reader_end(&zip);
      return_integer(0);
    }
    if (!mz_zip_reader_file_stat(&zip, 0, &stat))
    {
      mz_zip_reader_end(&zip);
      return_integer(0);
    }
    int return_result = 0;
    for (int i = 0; i < fileCount; i++)
    {
      if (!mz_zip_reader_file_stat(&zip, i, &stat))
        continue;
      if (mz_zip_reader_is_file_a_directory(&zip, i))
        continue;
      if (stat.m_uncomp_size < 100 * 1024 * 1024)
      {
        void *p = mz_zip_reader_extract_to_heap(&zip, i, &size, 0);
        if (!p)
        {
          free(p);
          continue;
        }
        else
        {
          unsigned char result[SHA_DIGEST_LENGTH];
          SHA1(p, size, result);
          // cast result to string with sprintf
          char sha1[SHA_DIGEST_LENGTH * 2 + 1];
          for (int i = 0; i < SHA_DIGEST_LENGTH; i++)
            sprintf(sha1 + (i * 2), "%02x", result[i]);
          if (strcmp(sha1, hash) == 0)
          {
            return_result = 1;
            // free(sha1);
            free(p);
            break;
          }
          // free(sha1);
          free(p);
        }
      }
    }
    mz_zip_reader_end(&zip);
    return_integer(return_result);
  }
  return_integer(0);
}

define_function(file_sha1_match)
{
  YR_SCAN_CONTEXT *module_context = scan_context();
  char *file_name = string_argument(1);
  char *hash = string_argument(2);
  int64_t flag = integer_argument(3);
  if (module_context != NULL)
  {
    YR_MEMORY_BLOCK *block;
    block = first_memory_block(module_context);
    uint8_t *buffer = (uint8_t *)block->fetch_data(block);
    mz_zip_archive zip;
    mz_zip_archive_file_stat stat;
    size_t size = 0;
    memset(&zip, 0, sizeof(zip));
    if (!mz_zip_reader_init_mem(&zip, buffer, module_context->file_size, 0))
    {
      mz_zip_reader_end(&zip);
      return_integer(0);
    }
    int f = 0;
    if (flag == 1)
    {
      f = 0x200;
    }
    int return_result = 0;
    int file_index = mz_zip_reader_locate_file(&zip, file_name, 0, f);
    if (file_index < 0)
    {
      mz_zip_reader_end(&zip);
      return_integer(0);
    }
    if (!mz_zip_reader_file_stat(&zip, file_index, &stat))
    {
      mz_zip_reader_end(&zip);
      return_integer(0);
    }
    if (stat.m_uncomp_size < 100 * 1024 * 1024)
    {
      void *p = mz_zip_reader_extract_to_heap(&zip, file_index, &size, 0);
      if (!p)
      {
        mz_zip_reader_end(&zip);
        return_integer(0);
      }
      else
      {
        unsigned char result[SHA_DIGEST_LENGTH];
        SHA1(p, size, result);
        char sha1[SHA_DIGEST_LENGTH * 2 + 1];
        for (int i = 0; i < SHA_DIGEST_LENGTH; i++)
          sprintf(sha1 + (i * 2), "%02x", result[i]);
        if (strcmp(sha1, hash) == 0)
        {
          return_result = 1;
        }
        free(p);
      }
    }
    mz_zip_reader_end(&zip);
    return_integer(return_result);
  }
  return_integer(0);
}

begin_declarations;
declare_function("has_file", "si", "i", file_match);
declare_function("has_dir", "si", "i", dir_match);
declare_function("has_string", "si", "i", string_match);
declare_function("file_has_string", "ssii", "i", file_string_match);
declare_function("has_regex", "r", "i", regex_match);
declare_function("file_has_regex", "sri", "i", file_regex_match);
declare_function("has_sha1", "s", "i", sha1_match);
declare_function("file_has_sha1", "ssi", "i", file_sha1_match);
end_declarations;

int module_initialize(
    YR_MODULE *module)
{
  return ERROR_SUCCESS;
}

int module_finalize(
    YR_MODULE *module)
{
  return ERROR_SUCCESS;
}

int module_load(
    YR_SCAN_CONTEXT *context,
    YR_OBJECT *module_object,
    void *module_data,
    size_t module_data_size)
{
  return ERROR_SUCCESS;
}

int module_unload(
    YR_OBJECT *module_object)
{
  return ERROR_SUCCESS;
}

#undef MODULE_NAME